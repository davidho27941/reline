import AppKit
import Foundation
import RecoveryKit
import SwiftUI

/// Main-actor view model. Owns the session, drives operations on a background task, and keeps
/// every user-visible gate explicit. Secrets never enter `@Published` state except the
/// transient password field, which is wiped after use.
@MainActor
final class RecoveryModel: ObservableObject {
    enum Folder: String, CaseIterable { case old, current, workspace, destination }

    @Published var folders: [Folder: URL] = [:]
    @Published var status: SessionStatus?
    @Published var intake: [BackupRole: [String: Any]] = [:]
    @Published var ambiguousCandidates: [BackupRole: [[String: Any]]] = [:]
    @Published var selectedAccount: [BackupRole: String] = [:]
    @Published var plan: [String: Any]?
    @Published var diagnostics: [String: Any]?
    @Published var patchResult: [String: Any]?
    @Published var exportResult: [String: Any]?
    @Published var reportMarkdown: String?
    @Published var progress: ProgressEvent?
    @Published var running = false
    /// Stage whose operation is executing right now, so the stage list can announce "running"
    /// before the core's manifest is re-read at completion.
    @Published var activeStage: Stage?
    @Published var error: RecoveryError?
    /// Non-error outcome worth telling the user about (cancellation). Shown inline, not as an alert.
    @Published var notice: Notice?
    @Published var password = ""
    @Published var rememberPassword: Bool
    @Published var reviewAcknowledged = false
    @Published var typedCount = ""
    @Published var selectedStage: Stage? = .intake

    private var session: RecoverySession?
    let bookmarks = BookmarkStore()
    let keychain = KeychainStore()
    /// UI tests pass `--ui-test-progress-delay-ms N` to slow progress callbacks so a human-speed
    /// Cancel click lands while a stage is still running. Nil outside tests.
    private let uiTestProgressDelay: TimeInterval?

    /// `title` and `message` are English keys; the banner translates them.
    struct Notice: Identifiable, Equatable {
        let id = UUID()
        let title: String
        let message: String
    }

    init() {
        let args = ProcessInfo.processInfo.arguments
        if let i = args.firstIndex(of: "--ui-test-progress-delay-ms"), i + 1 < args.count, let ms = Double(args[i + 1]) {
            uiTestProgressDelay = ms / 1000
        } else {
            uiTestProgressDelay = nil
        }
        rememberPassword = keychain.rememberEnabled
        for f in Folder.allCases {
            if let url = try? bookmarks.resolve(f.rawValue) { folders[f] = url }
        }
        // UI tests cannot drive NSOpenPanel; `--ui-test-folders old=/p current=/p workspace=/p`
        // presets folders without touching bookmarks. Ignored unless the flag is present.
        if let i = args.firstIndex(of: "--ui-test-folders") {
            for pair in args[(i + 1)...] where pair.contains("=") {
                let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
                if let f = Folder(rawValue: parts[0]) { folders[f] = URL(fileURLWithPath: parts[1]) }
            }
        }
    }

    // MARK: Gates

    var gates: Gates {
        var g = Gates()
        g.operationRunning = running
        g.oldIntakeCommitted = status?.state(of: .intake) == .committed && intake[.old] != nil
        g.currentIntakeCommitted = status?.state(of: .intake) == .committed && intake[.current] != nil
        g.analysisCommitted = status?.state(of: .analysis) == .committed
        g.planActionable = (plan?["actionable"] as? Bool) ?? false
        g.currentPatchable = (intake[.current]?["patchable"] as? Bool) ?? false
        g.destinationSelected = folders[.destination] != nil
        g.reviewAcknowledged = reviewAcknowledged
        g.typedCountMatchesPlan = UInt64(typedCount) == predictedCount
        g.confirmationMatchesPlan = confirmation != nil
        g.verificationPassed = status?.state(of: .verification) == .committed && (patchResult?["status"] as? String) == "verified"
        return g
    }

    var predictedCount: UInt64? {
        (plan?["predicted_update_count"] as? NSNumber)?.uint64Value
    }

    var confirmation: PatchConfirmation? {
        guard let plan, let count = predictedCount, let id = plan["plan_id"] as? String,
              let dest = folders[.destination], let src = folders[.current] else { return nil }
        return PatchConfirmation(predictedUpdateCount: count, planId: id, destinationDir: dest.path, rollbackSourceDir: src.path)
    }

    // MARK: Folder selection (system picker, no privileges)

    func pick(_ folder: Folder) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = folder == .workspace || folder == .destination
        let lang = LanguageStore.shared
        panel.prompt = lang.t("Select")
        panel.message = lang.t(folder.pickerMessage)
        guard panel.runModal() == .OK, let url = panel.url else { return }
        folders[folder] = url
        try? bookmarks.save(url, as: folder.rawValue)
        if folder == .workspace { session = nil; status = nil; intake = [:]; plan = nil; patchResult = nil }
        if folder == .old || folder == .current { plan = nil; patchResult = nil; exportResult = nil }
    }

    /// Re-resolve a bookmark before use; stale bookmarks force a reselect.
    private func scopedURL(_ folder: Folder) throws -> URL {
        do {
            return try bookmarks.resolve(folder.rawValue)
        } catch BookmarkError.stale {
            folders[folder] = nil
            throw RecoveryError(code: "access_denied", message: "Access to the \(folder.rawValue) folder expired.", remedy: "Select the folder again.")
        } catch {
            if let u = folders[folder] { return u }
            throw RecoveryError(code: "invalid_argument", message: "Select the \(folder.rawValue) folder first.")
        }
    }

    private func ensureSession() throws -> RecoverySession {
        if let s = session { return s }
        let ws = try scopedURL(.workspace)
        let s = try bookmarks.withAccess(ws) { try RecoverySession(workspace: $0) }
        session = s
        return s
    }

    // MARK: Operations

    private func run(_ request: Request, password: Data? = nil, scoped: [Folder] = [], completion: @escaping @MainActor ([String: Any]) -> Void) {
        guard !running else { return }
        error = nil
        notice = nil
        progress = nil
        // Resolve the session and every scoped folder on the main actor before leaving it, so the
        // background task never touches model state.
        let session: RecoverySession
        let urls: [URL]
        do {
            session = try ensureSession()
            urls = try scoped.map { try scopedURL($0) }
        } catch let e as RecoveryError {
            error = e
            return
        } catch {
            self.error = RecoveryError(code: "internal", message: String(describing: error))
            return
        }
        running = true
        activeStage = request.stage
        let delay = uiTestProgressDelay
        let publishProgress: ProgressHandler = { [weak self] ev in
            if let delay { Thread.sleep(forTimeInterval: delay) }
            Task { @MainActor in self?.progress = ev }
        }
        Task.detached(priority: .userInitiated) { [weak self] in
            let outcome: Result<[String: Any], RecoveryError>
            do {
                var granted: [URL] = []
                for u in urls where u.startAccessingSecurityScopedResource() { granted.append(u) }
                defer { granted.forEach { $0.stopAccessingSecurityScopedResource() } }
                let result = try session.execute(request, password: password, progress: publishProgress)
                outcome = .success(result.object() ?? [:])
            } catch let e as RecoveryError {
                outcome = .failure(e)
            } catch {
                outcome = .failure(RecoveryError(code: "internal", message: String(describing: error)))
            }
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.running = false
                self.activeStage = nil
                self.progress = nil
                switch outcome {
                case let .success(obj): completion(obj)
                case let .failure(e) where e.isCancelled:
                    self.notice = Notice(
                        title: "Cancelled",
                        message: "The operation stopped at a safe boundary. Partial output was removed, the source backups were not touched, and the stage is not marked complete. You can run it again."
                    )
                case let .failure(e): self.error = e
                }
                self.refreshStatus()
            }
        }
    }

    /// State to display for a stage: the live operation wins over the last committed manifest.
    func displayState(of stage: Stage) -> StageState {
        if running, activeStage == stage { return .running }
        return status?.state(of: stage) ?? .pending
    }

    func refreshStatus() {
        guard let s = session, let r = try? s.execute(.status) else { return }
        status = try? r.decode(SessionStatus.self)
    }

    func cancel() { session?.cancel() }

    func runIntake(_ role: BackupRole) {
        guard let dir = folders[role == .old ? .old : .current] else { return }
        var pw = Data(password.utf8)
        if rememberPassword, let udid = (intake[role]?["backup"] as? [String: Any])?["udid"] as? String {
            try? keychain.save(password: pw, account: udid)
        }
        run(.intake(role: role, backupDir: dir.path, accountDir: selectedAccount[role]), password: pw, scoped: [role == .old ? .old : .current]) { [weak self] obj in
            guard let self else { return }
            if obj["status"] as? String == "ambiguous_account" {
                self.ambiguousCandidates[role] = obj["candidates"] as? [[String: Any]] ?? []
            } else {
                self.ambiguousCandidates[role] = nil
                self.intake[role] = obj["intake"] as? [String: Any]
                if self.rememberPassword, let udid = ((obj["intake"] as? [String: Any])?["backup"] as? [String: Any])?["udid"] as? String {
                    try? self.keychain.save(password: Data(self.password.utf8), account: udid)
                }
            }
            self.plan = nil
            self.patchResult = nil
        }
        pw.resetBytes(in: 0..<pw.count)
    }

    func runAnalysis() {
        run(.analyze) { [weak self] obj in
            self?.plan = obj["plan"] as? [String: Any]
            self?.diagnostics = obj["diagnostics"] as? [String: Any]
            self?.reviewAcknowledged = false
            self?.typedCount = ""
            self?.selectedStage = .review
        }
    }

    func runPatch() {
        guard gates.canRun(.patching), let confirm = confirmation, let dest = folders[.destination] else { return }
        let pw = password.isEmpty ? nil : Data(password.utf8)
        run(.patch(destinationDir: dest.path, confirm: confirm), password: pw, scoped: [.current, .destination]) { [weak self] obj in
            self?.patchResult = obj
            self?.selectedStage = .verification
        }
    }

    func runExport(overwrite: Bool = false) {
        guard gates.canRun(.export), let dest = folders[.destination] else { return }
        run(.export(destinationDir: dest.path, overwriteConfirmed: overwrite), scoped: [.destination]) { [weak self] obj in
            self?.exportResult = obj["export"] as? [String: Any]
        }
    }

    func runReport(redacted: Bool) {
        run(.report(redacted: redacted)) { [weak self] obj in
            self?.reportMarkdown = obj["markdown"] as? String
        }
    }

    func runCleanup() {
        run(.cleanup) { [weak self] _ in
            self?.intake = [:]; self?.plan = nil; self?.patchResult = nil
        }
    }

    func setRemember(_ on: Bool) {
        rememberPassword = on
        try? keychain.setRemember(on)
    }
}

extension RecoveryModel.Folder {
    var title: String {
        switch self {
        case .old: return "Old iPhone backup (copy)"
        case .current: return "Current iPhone backup (copy)"
        case .workspace: return "Session workspace"
        case .destination: return "Export destination"
        }
    }

    var pickerMessage: String {
        switch self {
        case .old, .current:
            return "Select a copy of the backup folder (named after the device UDID). Do not select MobileSync/Backup itself."
        case .workspace:
            return "Select an empty folder for decrypted working copies. It is cleaned up when you finish."
        case .destination:
            return "Select the folder that will receive the patched backup and reports."
        }
    }
}

extension Request {
    /// The workflow stage an operation belongs to, or nil for housekeeping requests.
    var stage: Stage? {
        switch self {
        case .intake: return .intake
        case .analyze: return .analysis
        case .patch: return .patching
        case .export: return .export
        case .ping, .status, .cleanup, .inspect, .report, .exportRepairedDatabase: return nil
        }
    }
}
