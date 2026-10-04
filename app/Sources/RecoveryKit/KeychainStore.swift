import Foundation
import Security

public enum KeychainError: Error, Equatable {
    case status(OSStatus)
}

/// Optional "remember backup password" storage. Off by default; disabling deletes the item.
public struct KeychainStore: @unchecked Sendable {
    public let service: String
    private let defaults: UserDefaults
    public static let rememberKey = "rememberBackupPassword"

    public init(service: String = "io.github.davidho27941.reline.backup-password", defaults: UserDefaults = .standard) {
        self.service = service
        self.defaults = defaults
    }

    /// Defaults to `false` when never set.
    public var rememberEnabled: Bool { defaults.object(forKey: Self.rememberKey) as? Bool ?? false }

    /// Turning the setting off removes every stored credential for this service.
    public func setRemember(_ enabled: Bool) throws {
        defaults.set(enabled, forKey: Self.rememberKey)
        if !enabled { try deleteAll() }
    }

    private func query(account: String?) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        if let account { q[kSecAttrAccount as String] = account }
        return q
    }

    public func save(password: Data, account: String) throws {
        guard rememberEnabled else { return }
        try? delete(account: account)
        var q = query(account: account)
        q[kSecValueData as String] = password
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }

    public func load(account: String) throws -> Data? {
        var q = query(account: account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
        return out as? Data
    }

    public func delete(account: String) throws {
        let status = SecItemDelete(query(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError.status(status) }
    }

    public func deleteAll() throws {
        let status = SecItemDelete(query(account: nil) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError.status(status) }
    }
}
