import Foundation
@testable import RecoveryKit
import Testing

/// Tasks 7.2 and 7.5.
@Suite struct BookmarkAndKeychainTests {
    private func defaults() -> UserDefaults { UserDefaults(suiteName: "lr-tests-\(UUID().uuidString)")! }

    @Test func bookmarkRoundTripAndScopeRelease() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("bm-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = BookmarkStore(defaults: defaults(), prefix: "t.")
        #expect(!store.hasBookmark("old"))
        try store.save(dir, as: "old")
        #expect(store.hasBookmark("old"))
        let resolved = try store.resolve("old")
        #expect(resolved.standardizedFileURL.path == dir.standardizedFileURL.path)
        let listed = try store.withAccess(resolved) { url in try FileManager.default.contentsOfDirectory(atPath: url.path) }
        #expect(listed.isEmpty)
        store.remove("old")
        #expect(throws: BookmarkError.missing("old")) { try store.resolve("old") }
    }

    @Test func staleOrDeletedTargetIsReportedNotSilentlyFixed() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("bm-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = BookmarkStore(defaults: defaults(), prefix: "t.")
        try store.save(dir, as: "cur")
        try FileManager.default.removeItem(at: dir)
        do {
            _ = try store.resolve("cur")
            #expect(!FileManager.default.fileExists(atPath: dir.path))
        } catch let e as BookmarkError {
            switch e {
            case .stale, .unresolvable: break
            default: Issue.record("unexpected \(e)")
            }
        }
        let d = defaults()
        d.set(Data([1, 2, 3]), forKey: "t.bad")
        let s2 = BookmarkStore(defaults: d, prefix: "t.")
        #expect(throws: BookmarkError.unresolvable("bad")) { try s2.resolve("bad") }
    }

    @Test func rememberDefaultsOffAndSaveIsNoOpWhenOff() throws {
        let kc = KeychainStore(service: "io.github.davidho27941.reline.tests.\(UUID().uuidString)", defaults: defaults())
        #expect(!kc.rememberEnabled)
        try kc.save(password: Data("pw".utf8), account: "udid")
        #expect(try kc.load(account: "udid") == nil, "nothing may be stored while the setting is off")
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["RELINE_KEYCHAIN_TESTS"] == "1", "set RELINE_KEYCHAIN_TESTS=1 to exercise the login keychain"))
    func enableStoreDisableDeletes() throws {
        let kc = KeychainStore(service: "io.github.davidho27941.reline.tests.\(UUID().uuidString)", defaults: defaults())
        try kc.setRemember(true)
        try kc.save(password: Data("secret-pw".utf8), account: "udid-1")
        #expect(try kc.load(account: "udid-1") == Data("secret-pw".utf8))
        try kc.setRemember(false)
        #expect(try kc.load(account: "udid-1") == nil, "disabling must delete the credential")
        try kc.setRemember(true)
        try kc.save(password: Data("x".utf8), account: "udid-2")
        try kc.delete(account: "udid-2")
        #expect(try kc.load(account: "udid-2") == nil)
        try kc.deleteAll()
    }
}
