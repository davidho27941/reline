import Foundation

/// Structured, secret-free error mirrored from the Rust core (`{code, message, path?, remedy?}`).
public struct RecoveryError: Error, Codable, Equatable, Sendable {
    public let code: String
    public let message: String
    public let path: String?
    public let remedy: String?

    public init(code: String, message: String, path: String? = nil, remedy: String? = nil) {
        self.code = code
        self.message = message
        self.path = path
        self.remedy = remedy
    }

    public var isCancelled: Bool { code == "cancelled" }

    /// Short user-facing title per code.
    public var title: String {
        switch code {
        case "access_denied": return "macOS blocked access"
        case "invalid_backup_structure": return "Not a Finder backup"
        case "unsupported_backup": return "Backup not supported"
        case "authentication_failed": return "Password rejected"
        case "ambiguous_account": return "Choose a LINE account"
        case "pending_journal": return "Pending write-ahead log"
        case "analysis_unsupported": return "Diagnostics only"
        case "plan_invalidated": return "Plan no longer valid"
        case "repair_mismatch": return "Repair rolled back"
        case "verification_failed": return "Verification failed"
        case "unsupported_metadata": return "Metadata outside the supported policy"
        case "crypto_failure": return "Cryptographic check failed"
        case "clone_failed": return "Clone failed"
        case "export_conflict": return "Export already exists"
        case "cancelled": return "Cancelled"
        case "session_state": return "Session needs attention"
        default: return "Recovery error"
        }
    }
}
