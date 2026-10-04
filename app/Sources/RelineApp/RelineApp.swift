import RecoveryKit
import SwiftUI

@main
struct RelineApp: App {
    @StateObject private var model = RecoveryModel()
    @StateObject private var lang = LanguageStore.shared

    var body: some Scene {
        WindowGroup(lang.t("Reline")) {
            ContentView()
                .environmentObject(model)
                .environmentObject(lang)
                .environment(\.locale, lang.locale)
                .frame(minWidth: 900, minHeight: 600)
        }
        .commands {
            CommandGroup(after: .toolbar) {
                Button(lang.t("Cancel Operation")) { model.cancel() }
                    .keyboardShortcut(".", modifiers: .command)
                    .disabled(!model.running)
            }
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var model: RecoveryModel
    @EnvironmentObject var lang: LanguageStore

    var body: some View {
        NavigationSplitView {
            List(Stage.allCases, selection: $model.selectedStage) { stage in
                StageRow(stage: stage)
                    .tag(stage)
            }
            .navigationTitle(lang.t("Stages"))
            .accessibilityLabel(lang.t("Recovery stages"))
        } detail: {
            VStack(spacing: 0) {
                if model.running {
                    ProgressBar(event: model.progress) { model.cancel() }
                }
                if let n = model.notice {
                    NoticeBanner(notice: n) { model.notice = nil }
                }
                ScrollView {
                    Group {
                        switch model.selectedStage ?? .intake {
                        case .intake: IntakeView()
                        case .analysis: AnalysisView()
                        case .review: ReviewView()
                        case .patching: PatchingView()
                        case .verification: VerificationView()
                        case .export: ExportView()
                        }
                    }
                    .padding(20)
                }
            }
        }
        .toolbar {
            // Language lives in the window itself, visible in every stage, rather than in the menu bar.
            ToolbarItem(placement: .primaryAction) {
                Picker(selection: $lang.choice) {
                    ForEach(LanguageStore.Choice.allCases) { c in
                        Text(lang.name(of: c)).tag(c)
                    }
                } label: {
                    Label(lang.t("Language"), systemImage: "globe")
                }
                .pickerStyle(.menu)
                .help(lang.t("Language"))
                .accessibilityLabel(lang.t("Language"))
                .accessibilityIdentifier("language-picker")
            }
        }
        .alert(item: $model.error) { err in
            Alert(
                title: Text(lang.errorTitle(code: err.code, fallback: err.title)),
                message: Text(errorBody(err)),
                dismissButton: .default(Text(lang.t("OK")))
            )
        }
    }

    /// Structured, secret-free body: localized explanation when one exists, then the core's
    /// own message, path, remedy and code so an expert can act on it.
    private func errorBody(_ e: RecoveryError) -> String {
        var parts: [String] = []
        if let help = lang.errorHelp(code: e.code) { parts.append(help) }
        parts.append(e.message)
        if let p = e.path { parts.append(lang.f("Path: %@", p)) }
        if let r = e.remedy { parts.append(lang.f("What to do: %@", r)) }
        parts.append(lang.f("Code: %@", e.code))
        return parts.joined(separator: "\n\n")
    }
}

extension RecoveryError: Identifiable {
    public var id: String { code + message }
}

struct StageRow: View {
    @EnvironmentObject var model: RecoveryModel
    @EnvironmentObject var lang: LanguageStore
    let stage: Stage

    var state: StageState { model.displayState(of: stage) }

    var body: some View {
        HStack {
            Image(systemName: icon)
                .foregroundStyle(color)
                .accessibilityHidden(true)
            Text(lang.t(stage.title))
            Spacer()
            if stage.isMutating { Image(systemName: "exclamationmark.shield").help(lang.t("This stage writes to the destination folder")).accessibilityHidden(true) }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("stage-\(stage.rawValue)")
        .accessibilityLabel("\(lang.t(stage.title)), \(lang.t("state." + state.rawValue))\(stage.isMutating ? ", " + lang.t("mutating stage") : "")")
    }

    private var icon: String {
        switch state {
        case .pending: return "circle"
        case .running: return "arrow.triangle.2.circlepath"
        case .committed: return "checkmark.circle.fill"
        case .failed: return "xmark.octagon.fill"
        case .cancelled: return "stop.circle"
        case .invalidated: return "arrow.uturn.backward.circle"
        }
    }

    private var color: Color {
        switch state {
        case .committed: return .green
        case .failed: return .red
        case .cancelled, .invalidated: return .orange
        default: return .secondary
        }
    }
}

struct ProgressBar: View {
    @EnvironmentObject var lang: LanguageStore
    let event: ProgressEvent?
    let cancel: () -> Void

    private var stageName: String { lang.t("stage." + (event?.stage ?? "operation")) }

    private var percent: Int? {
        guard let event, event.total > 0 else { return nil }
        return Int(Double(event.done) / Double(event.total) * 100)
    }

    var body: some View {
        HStack {
            if let event, event.total > 0 {
                ProgressView(value: Double(event.done), total: Double(event.total))
                    .accessibilityLabel(lang.f("%@ progress", stageName))
                    .accessibilityValue(lang.f("%d percent", percent ?? 0))
                    .accessibilityIdentifier("operation-progress")
                Text(lang.f("%@: %d%% (%@ of %@ bytes)", stageName, percent ?? 0, String(event.done), String(event.total)))
                    .font(.caption).foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            } else {
                ProgressView()
                    .accessibilityLabel(lang.f("%@ in progress", stageName))
                    .accessibilityIdentifier("operation-progress")
                Text(lang.f("%@ in progress…", stageName)).font(.caption).foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            }
            Spacer()
            Button(lang.t("Cancel"), action: cancel)
                .keyboardShortcut(.escape, modifiers: [])
                .accessibilityIdentifier("cancel-operation")
                .accessibilityHint(lang.t("Stops at a safe boundary and removes partial output. Also Escape or Command-Period."))
        }
        .padding(8)
        .background(.bar)
        .accessibilityElement(children: .contain)
    }
}

/// Inline, dismissible outcome that is not an error (cancellation). Read by VoiceOver as one
/// sentence; the Dismiss button stays separately focusable.
struct NoticeBanner: View {
    @EnvironmentObject var lang: LanguageStore
    let notice: RecoveryModel.Notice
    let dismiss: () -> Void

    var body: some View {
        HStack(alignment: .top) {
            Image(systemName: "stop.circle").foregroundStyle(.orange).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(lang.t(notice.title)).bold()
                Text(lang.t(notice.message)).font(.callout)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(lang.t(notice.title)). \(lang.t(notice.message))")
            .accessibilityIdentifier("notice")
            Spacer()
            Button(lang.t("Dismiss"), action: dismiss).accessibilityIdentifier("dismiss-notice")
        }
        .padding(8)
        .background(.quaternary)
        .accessibilityElement(children: .contain)
    }
}

struct FolderField: View {
    @EnvironmentObject var model: RecoveryModel
    @EnvironmentObject var lang: LanguageStore
    let folder: RecoveryModel.Folder

    var body: some View {
        HStack {
            Text(lang.t(folder.title)).frame(width: 220, alignment: .leading)
            Text(model.folders[folder]?.path ?? lang.t("Not selected"))
                .lineLimit(1).truncationMode(.middle)
                .foregroundStyle(model.folders[folder] == nil ? .secondary : .primary)
                .accessibilityLabel("\(lang.t(folder.title)): \(model.folders[folder]?.lastPathComponent ?? lang.t("not selected"))")
            Spacer()
            Button(lang.t("Choose…")) { model.pick(folder) }
                .disabled(model.running)
                .accessibilityLabel(lang.f("Choose %@", lang.t(folder.title)))
        }
    }
}

struct IntakeView: View {
    @EnvironmentObject var model: RecoveryModel
    @EnvironmentObject var lang: LanguageStore

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(lang.t("Intake")).font(.title)
            Text(lang.t("Select copies of your backups. The app reads them read-only and never touches MobileSync or the iPhone. No administrator rights or Full Disk Access are requested."))
                .foregroundStyle(.secondary)
            FolderField(folder: .workspace)
            FolderField(folder: .old)
            FolderField(folder: .current)
            HStack {
                Text(lang.t("Backup password")).frame(width: 220, alignment: .leading)
                SecureField(lang.t("Encrypted-backup password"), text: $model.password)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel(lang.t("Encrypted backup password"))
            }
            Toggle(lang.t("Remember password in Keychain (off by default; turning off deletes it)"), isOn: Binding(get: { model.rememberPassword }, set: { model.setRemember($0) }))
            HStack {
                Button(lang.t("Read old backup")) { model.runIntake(.old) }
                    .disabled(model.running || model.folders[.old] == nil || model.folders[.workspace] == nil || model.password.isEmpty)
                Button(lang.t("Read current backup")) { model.runIntake(.current) }
                    .disabled(model.running || model.folders[.current] == nil || model.folders[.workspace] == nil || model.password.isEmpty)
            }
            ForEach(BackupRole.allCases, id: \.self) { role in
                if let cands = model.ambiguousCandidates[role], !cands.isEmpty {
                    GroupBox(lang.f("Several LINE accounts in the %@ backup — choose one", lang.t("role." + role.rawValue))) {
                        Picker(lang.t("Account"), selection: Binding(get: { model.selectedAccount[role] ?? "" }, set: { model.selectedAccount[role] = $0 })) {
                            ForEach(cands.compactMap { $0["account_dir"] as? String }, id: \.self) { Text($0).tag($0) }
                        }
                        .accessibilityLabel(lang.f("LINE account for the %@ backup", lang.t("role." + role.rawValue)))
                    }
                }
                if let i = model.intake[role] {
                    IntakeSummary(role: role, intake: i)
                }
            }
            if let pa = model.status?.partialArtifacts, !pa.isEmpty {
                GroupBox(lang.t("Partial artifacts from an interrupted session")) {
                    Text(lang.t("This workspace contains uncommitted or plaintext files from a previous run. They are not treated as verified evidence."))
                    Button(lang.t("Clean up")) { model.runCleanup() }
                }
            }
        }
    }
}

struct IntakeSummary: View {
    @EnvironmentObject var lang: LanguageStore
    let role: BackupRole
    let intake: [String: Any]

    var body: some View {
        let backup = intake["backup"] as? [String: Any] ?? [:]
        let db = intake["line_db"] as? [String: Any] ?? [:]
        GroupBox(lang.f("%@ backup", lang.t("role." + role.rawValue))) {
            Grid(alignment: .leading) {
                GridRow { Text(lang.t("Device")); Text("\(backup["device_name"] as? String ?? "—") · iOS \(backup["product_version"] as? String ?? "—")") }
                GridRow { Text(lang.t("Backup date")); Text(backup["backup_date"] as? String ?? "—") }
                GridRow { Text("UDID"); Text(backup["udid"] as? String ?? "—").font(.system(.body, design: .monospaced)) }
                GridRow { Text("Line.sqlite SHA-256"); Text(db["sha256"] as? String ?? "—").font(.system(.caption, design: .monospaced)) }
                GridRow { Text(lang.t("Patchable")); Text((intake["patchable"] as? Bool) == true ? lang.t("Yes") : lang.t("No, analysis only")) }
            }
            if let issues = intake["patchability_issues"] as? [String], !issues.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Label(lang.t("This backup can be analyzed but not patched:"), systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                    ForEach(issues, id: \.self) { Text("• \($0)") }
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("\(lang.t("Unsupported for patching.")) \(issues.joined(separator: ". "))")
                .accessibilityIdentifier("unsupported-\(role.rawValue)")
            }
        }
    }
}

struct AnalysisView: View {
    @EnvironmentObject var model: RecoveryModel
    @EnvironmentObject var lang: LanguageStore

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(lang.t("Analysis")).font(.title)
            BlockerList(stage: .analysis)
            Button(lang.t("Analyze")) { model.runAnalysis() }.disabled(!model.gates.canRun(.analysis))
                .keyboardShortcut("a", modifiers: .command)
            if let plan = model.plan {
                PlanCounts(plan: plan)
            } else if let d = model.diagnostics {
                let reasons = d["reasons"] as? [String] ?? []
                GroupBox(lang.t("Unsupported: diagnostics only, no repair plan")) {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(reasons, id: \.self) { Text("• \($0)") }
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("\(lang.t("Analysis unsupported, diagnostics only.")) \(reasons.joined(separator: ". "))")
                .accessibilityIdentifier("unsupported-analysis")
            }
        }
    }
}

struct BlockerList: View {
    @EnvironmentObject var model: RecoveryModel
    @EnvironmentObject var lang: LanguageStore
    let stage: Stage

    var body: some View {
        let blockers = model.gates.blockers(for: stage).map { lang.t($0) }
        if !blockers.isEmpty {
            VStack(alignment: .leading) {
                ForEach(blockers, id: \.self) { Label($0, systemImage: "lock").foregroundStyle(.secondary) }
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(lang.f("%@ is blocked: %@", lang.t(stage.title), blockers.joined(separator: " ")))
            .accessibilityIdentifier("blockers-\(stage.rawValue)")
        }
    }
}

struct PlanCounts: View {
    @EnvironmentObject var lang: LanguageStore
    let plan: [String: Any]

    var body: some View {
        let counts = plan["counts"] as? [String: Any] ?? [:]
        GroupBox(lang.t("Repair plan")) {
            Grid(alignment: .leading) {
                GridRow { Text(lang.t("Rule")); Text("\(plan["adapter_id"] as? String ?? "") / \(plan["rule_version"] as? String ?? "")") }
                GridRow { Text(lang.t("Plan id")); Text(plan["plan_id"] as? String ?? "—").font(.system(.caption, design: .monospaced)) }
                GridRow { Text(lang.t("Actionable")); Text((plan["actionable"] as? Bool) == true ? lang.t("Yes") : lang.t("No — diagnostics only")) }
                GridRow { Text(lang.t("Predicted updates")); Text("\(plan["predicted_update_count"] ?? 0)").bold() }
                ForEach(["matched", "old_only", "current_only", "preserved_placeholders", "chat_conflicts", "timestamp_conflicts", "unknown_differences", "text_differences", "metadata_differences", "null_identity_rows_old", "null_identity_rows_current", "duplicate_identity_values"], id: \.self) { k in
                    GridRow { Text(lang.t("count." + k)); Text("\(counts[k] ?? 0)") }
                }
                GridRow { Text(lang.t("Authorized fields")); Text((plan["authorized_fields"] as? [String] ?? []).joined(separator: ", ")) }
            }
            if let w = plan["warnings"] as? [String], !w.isEmpty { ForEach(w, id: \.self) { Label($0, systemImage: "info.circle") } }
            if let b = plan["blockers"] as? [String], !b.isEmpty { ForEach(b, id: \.self) { Label($0, systemImage: "xmark.octagon").foregroundStyle(.red) } }
        }
    }
}

struct ReviewView: View {
    @EnvironmentObject var model: RecoveryModel
    @EnvironmentObject var lang: LanguageStore

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(lang.t("Review and confirm")).font(.title)
            BlockerList(stage: .review)
            if let plan = model.plan {
                PlanCounts(plan: plan)
                FolderField(folder: .destination)
                GroupBox(lang.t("Mutation consent")) {
                    Text(lang.f("Clone destination: %@", model.folders[.destination]?.path ?? lang.t("not selected")))
                    Text(lang.f("Rollback source (never modified): %@", model.folders[.current]?.path ?? "—"))
                    Toggle(lang.f("I understand that a clone of the current backup will be created in the destination and that only the fields above will change in %@ messages.", String(model.predictedCount ?? 0)), isOn: $model.reviewAcknowledged)
                    HStack {
                        Text(lang.t("Type the predicted update count to confirm:"))
                        TextField(lang.t("count"), text: $model.typedCount).frame(width: 100).textFieldStyle(.roundedBorder)
                            .accessibilityLabel(lang.t("Predicted update count confirmation"))
                    }
                }
                BlockerList(stage: .patching)
                Button(lang.t("Create patched clone")) { model.runPatch() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!model.gates.canRun(.patching))
                    .accessibilityHint(lang.t("Begins the only stage that writes outside the workspace"))
            }
        }
    }
}

struct PatchingView: View {
    @EnvironmentObject var model: RecoveryModel
    @EnvironmentObject var lang: LanguageStore

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(lang.t("Patching")).font(.title)
            if let p = model.patchResult?["patch"] as? [String: Any] {
                let repair = p["repair"] as? [String: Any] ?? [:]
                let enc = p["encryption"] as? [String: Any] ?? [:]
                GroupBox(lang.t("Result")) {
                    Text(lang.f("Updates applied: %@ (predicted %@)", "\(repair["actual_update_count"] ?? 0)", "\(repair["predicted_update_count"] ?? 0)"))
                    Text(lang.f("Repaired database SHA-256: %@", (p["validation"] as? [String: Any])?["repaired_sha256"] as? String ?? "—")).font(.system(.caption, design: .monospaced))
                    Text(lang.f("Payload: %@ bytes, round trip OK: %@", "\(enc["payload_size"] ?? 0)", enc["round_trip_ok"] as? Bool == true ? lang.t("yes") : lang.t("no")))
                    Text(lang.f("Clone differs from source only at: %@", (p["clone_differs_only_at"] as? [String] ?? []).joined(separator: ", ")))
                }
            } else {
                Text(lang.t("Nothing patched yet. Patching starts from the Review stage after explicit confirmation.")).foregroundStyle(.secondary)
                if let rec = model.status?.stages[Stage.patching.rawValue], let e = rec.error {
                    Label("\(lang.errorTitle(code: e.code, fallback: e.title)): \(e.message)", systemImage: "xmark.octagon").foregroundStyle(.red)
                }
            }
        }
    }
}

struct VerificationView: View {
    @EnvironmentObject var model: RecoveryModel
    @EnvironmentObject var lang: LanguageStore

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(lang.t("Verification")).font(.title)
            if let v = model.patchResult?["verification"] as? [String: Any], let gates = v["gates"] as? [[Any]] {
                ForEach(Array(gates.enumerated()), id: \.offset) { _, g in
                    Label(lang.t(g.first as? String ?? ""), systemImage: (g.last as? Bool) == true ? "checkmark.circle.fill" : "xmark.octagon.fill")
                        .foregroundStyle((g.last as? Bool) == true ? .green : .red)
                }
                Text(lang.f("Re-read SHA-256: %@", v["reread_sha256"] as? String ?? "—")).font(.system(.caption, design: .monospaced))
            } else {
                Text(lang.t("Runs automatically after patching: the clone is re-opened like a fresh backup and every gate must pass.")).foregroundStyle(.secondary)
            }
        }
    }
}

struct ExportView: View {
    @EnvironmentObject var model: RecoveryModel
    @EnvironmentObject var lang: LanguageStore

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(lang.t("Export")).font(.title)
            BlockerList(stage: .export)
            Button(lang.t("Export verified backup and reports")) { model.runExport() }
                .buttonStyle(.borderedProminent)
                .disabled(!model.gates.canRun(.export))
            if let e = model.exportResult {
                GroupBox(lang.t("Exported")) {
                    Text(lang.f("Patched backup: %@", e["exported_backup_dir"] as? String ?? "—")).textSelection(.enabled)
                    Text(lang.f("Preserved original: %@", e["rollback_source_dir"] as? String ?? "—")).textSelection(.enabled)
                    Text(lang.f("Instructions: %@", e["instructions"] as? String ?? "—")).textSelection(.enabled)
                    Text(lang.t("Next: follow the restore instructions manually in Finder. This app does not restore the device.")).bold()
                }
            }
            HStack {
                Button(lang.t("Show report")) { model.runReport(redacted: false) }.disabled(model.running || model.status == nil)
                Button(lang.t("Show redacted report")) { model.runReport(redacted: true) }.disabled(model.running || model.status == nil)
                Button(lang.t("Clean up workspace")) { model.runCleanup() }.disabled(model.running || model.status == nil)
            }
            if let md = model.reportMarkdown {
                TextEditor(text: .constant(md)).font(.system(.caption, design: .monospaced)).frame(minHeight: 300)
                    .accessibilityLabel(lang.t("Audit report"))
            }
        }
    }
}
