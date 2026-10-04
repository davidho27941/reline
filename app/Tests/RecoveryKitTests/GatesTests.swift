import Foundation
@testable import RecoveryKit
import Testing

/// Task 7.3: mutating stages stay disabled until every prerequisite and explicit confirmation exists.
@Suite struct GatesTests {
    @Test func freshStateOnlyAllowsIntake() {
        let g = Gates()
        #expect(g.canRun(.intake))
        for s in Stage.allCases where s != .intake { #expect(!g.canRun(s), "\(s)") }
    }

    @Test func analysisNeedsBothIntakes() {
        var g = Gates()
        g.oldIntakeCommitted = true
        #expect(!g.canRun(.analysis))
        g.currentIntakeCommitted = true
        #expect(g.canRun(.analysis))
    }

    @Test func patchingRequiresEveryPrerequisiteAndConfirmation() {
        var g = Gates()
        g.oldIntakeCommitted = true
        g.currentIntakeCommitted = true
        g.analysisCommitted = true
        g.planActionable = true
        g.currentPatchable = true
        g.destinationSelected = true
        g.reviewAcknowledged = true
        g.typedCountMatchesPlan = true
        g.confirmationMatchesPlan = true
        #expect(g.canRun(.patching))
        let flips: [WritableKeyPath<Gates, Bool>] = [\.planActionable, \.currentPatchable, \.destinationSelected, \.reviewAcknowledged, \.typedCountMatchesPlan, \.confirmationMatchesPlan, \.analysisCommitted]
        for flip in flips {
            var h = g
            h[keyPath: flip] = false
            #expect(!h.canRun(.patching), "patching must be blocked when a prerequisite is false")
            #expect(!h.blockers(for: .patching).isEmpty)
        }
    }

    @Test func verificationIsNeverUserTriggered() {
        var g = Gates()
        g.verificationPassed = true
        #expect(!g.canRun(.verification))
        #expect(g.canRun(.export))
    }

    @Test func runningOperationBlocksEverything() {
        var g = Gates()
        g.operationRunning = true
        for s in Stage.allCases { #expect(!g.canRun(s)) }
    }

    @Test func statusDecoding() throws {
        let json = """
        {"session_id":"s","core_version":"0.1.0","stages":{"intake":{"state":"committed","started_at":"2026-10-04T00:00:00+00:00"},"analysis":{"state":"failed","error":{"code":"analysis_unsupported","message":"m"}}},"partial_artifacts":{"interrupted_stages":[],"staging_files":[],"unregistered_committed_files":[],"plaintext_files":["plaintext/old/Line.sqlite"]},"warnings":[],"inputs":null}
        """
        let st = try JSONDecoder().decode(SessionStatus.self, from: Data(json.utf8))
        #expect(st.state(of: .intake) == .committed)
        #expect(st.state(of: .analysis) == .failed)
        #expect(st.stages["analysis"]?.error?.code == "analysis_unsupported")
        #expect(st.state(of: .export) == .pending)
        #expect(!st.partialArtifacts.isEmpty)
    }
}
