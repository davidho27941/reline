import Darwin
import Foundation
@testable import RecoveryKit
import Testing

/// Task 1.2: Swift creates and releases Rust sessions without leaks or crashes.
@Suite struct FFILifecycleTests {
    private func tempDir() -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent("lr-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }

    private func residentBytes() -> UInt64 {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count) }
        }
        return kr == KERN_SUCCESS ? info.resident_size : 0
    }

    @Test func versionIsSemver() {
        let v = RecoverySession.coreVersion
        #expect(v.split(separator: ".").count == 3, "\(v)")
    }

    @Test func createExecuteFree() throws {
        let ws = tempDir()
        let s = try RecoverySession(workspace: ws)
        let r = try s.execute(.ping)
        #expect(r.object()?["core_version"] as? String == RecoverySession.coreVersion)
        let status = try s.execute(.status).decode(SessionStatus.self)
        #expect(status.state(of: .intake) == .pending)
        #expect(status.partialArtifacts.isEmpty)
        #expect(FileManager.default.fileExists(atPath: ws.appendingPathComponent("session.json").path))
    }

    private func caught(_ body: () throws -> ExecutionResult) -> RecoveryError? {
        do { _ = try body(); return nil } catch let e as RecoveryError { return e } catch { return nil }
    }

    @Test func structuredErrorsCrossTheBoundary() throws {
        let s = try RecoverySession(workspace: tempDir())
        let e1 = try #require(caught { try s.execute(.inspect(backupDir: "/nonexistent/backup")) })
        #expect(["io", "invalid_backup_structure"].contains(e1.code), "\(e1.code)")
        #expect(e1.path != nil)
        let e2 = try #require(caught { try s.execute(.analyze) })
        #expect(e2.code == "session_state")
        #expect(e2.remedy != nil)
        let e3 = try #require(caught { try s.execute(.intake(role: .current, backupDir: "/nonexistent", accountDir: nil)) })
        #expect(["io", "invalid_backup_structure", "invalid_argument"].contains(e3.code))
    }

    @Test func invalidWorkspaceFailsWithError() {
        #expect(throws: (any Error).self) { try RecoverySession(workspace: URL(fileURLWithPath: "/dev/null/impossible")) }
    }

    @Test func repeatedLifecycleDoesNotLeak() throws {
        for _ in 0..<50 {
            let s = try RecoverySession(workspace: tempDir())
            _ = try s.execute(.status)
        }
        let before = residentBytes()
        for _ in 0..<400 {
            let s = try RecoverySession(workspace: tempDir())
            _ = try s.execute(.ping, password: Data("not-used".utf8)) { _ in }
            _ = try s.execute(.status)
            s.cancel()
        }
        let after = residentBytes()
        let growth = Int64(after) - Int64(before)
        #expect(growth < 24 * 1024 * 1024, "resident memory grew by \(growth) bytes over 400 sessions")
    }

    @Test func cancelFromAnotherThreadIsSafe() throws {
        let s = try RecoverySession(workspace: tempDir())
        let group = DispatchGroup()
        for _ in 0..<20 {
            group.enter()
            DispatchQueue.global().async { s.cancel(); group.leave() }
        }
        group.wait()
        _ = try s.execute(.ping)
    }
}
