import Foundation

public enum Stage: String, CaseIterable, Codable, Sendable, Identifiable {
    case intake, analysis, review, patching, verification, export
    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .intake: return "Intake"
        case .analysis: return "Analysis"
        case .review: return "Review"
        case .patching: return "Patching"
        case .verification: return "Verification"
        case .export: return "Export"
        }
    }

    /// Stages that write anything outside the session workspace.
    public var isMutating: Bool { self == .patching || self == .export }
}

public enum StageState: String, Codable, Sendable {
    case pending, running, committed, failed, cancelled, invalidated
}

public struct StageRecord: Codable, Sendable {
    public var state: StageState
    public var startedAt: String?
    public var finishedAt: String?
    public var error: RecoveryError?

    enum CodingKeys: String, CodingKey {
        case state
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case error
    }
}

public struct PartialArtifacts: Codable, Sendable {
    public var interruptedStages: [String]
    public var stagingFiles: [String]
    public var unregisteredCommittedFiles: [String]
    public var plaintextFiles: [String]

    enum CodingKeys: String, CodingKey {
        case interruptedStages = "interrupted_stages"
        case stagingFiles = "staging_files"
        case unregisteredCommittedFiles = "unregistered_committed_files"
        case plaintextFiles = "plaintext_files"
    }

    public var isEmpty: Bool {
        interruptedStages.isEmpty && stagingFiles.isEmpty && unregisteredCommittedFiles.isEmpty && plaintextFiles.isEmpty
    }
}

/// Decoded `status` response.
public struct SessionStatus: Codable, Sendable {
    public var sessionId: String
    public var coreVersion: String
    public var stages: [String: StageRecord]
    public var partialArtifacts: PartialArtifacts
    public var warnings: [String]

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case coreVersion = "core_version"
        case stages
        case partialArtifacts = "partial_artifacts"
        case warnings
    }

    public func state(of stage: Stage) -> StageState { stages[stage.rawValue]?.state ?? .pending }
}

/// Pure gating rules: which stage the user may start given the evidence on hand.
public struct Gates: Equatable, Sendable {
    public var oldIntakeCommitted = false
    public var currentIntakeCommitted = false
    public var analysisCommitted = false
    public var planActionable = false
    public var currentPatchable = false
    public var destinationSelected = false
    public var reviewAcknowledged = false
    public var typedCountMatchesPlan = false
    public var confirmationMatchesPlan = false
    public var verificationPassed = false
    public var operationRunning = false

    public init() {}

    public func canRun(_ stage: Stage) -> Bool {
        if operationRunning { return false }
        switch stage {
        case .intake:
            return true
        case .analysis:
            return oldIntakeCommitted && currentIntakeCommitted
        case .review:
            return analysisCommitted
        case .patching:
            return analysisCommitted && planActionable && currentPatchable && destinationSelected
                && reviewAcknowledged && typedCountMatchesPlan && confirmationMatchesPlan
        case .verification:
            return false // automatic, never user-triggered
        case .export:
            return verificationPassed
        }
    }

    /// Why a stage is blocked, for the UI.
    public func blockers(for stage: Stage) -> [String] {
        var out: [String] = []
        if operationRunning { out.append("An operation is running.") }
        switch stage {
        case .intake: break
        case .analysis:
            if !oldIntakeCommitted { out.append("Old backup intake is not complete.") }
            if !currentIntakeCommitted { out.append("Current backup intake is not complete.") }
        case .review:
            if !analysisCommitted { out.append("Analysis has not run.") }
        case .patching:
            if !analysisCommitted { out.append("Analysis has not run.") }
            if !planActionable { out.append("The plan is diagnostic-only; nothing can be repaired safely.") }
            if !currentPatchable { out.append("The current backup's metadata is outside the supported policy.") }
            if !destinationSelected { out.append("Choose an export destination.") }
            if !reviewAcknowledged { out.append("Acknowledge the review statements.") }
            if !typedCountMatchesPlan { out.append("Type the predicted update count exactly.") }
            if !confirmationMatchesPlan { out.append("Confirmation does not match the plan on file.") }
        case .verification:
            out.append("Verification runs automatically after patching.")
        case .export:
            if !verificationPassed { out.append("The clone has not passed verification.") }
        }
        return out
    }
}
