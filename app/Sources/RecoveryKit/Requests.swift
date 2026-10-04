import Foundation

public enum BackupRole: String, Codable, Sendable, CaseIterable {
    case old
    case current
}

/// Explicit mutation consent; every field must equal the plan on file.
public struct PatchConfirmation: Codable, Equatable, Sendable {
    public var predictedUpdateCount: UInt64
    public var planId: String
    public var destinationDir: String
    public var rollbackSourceDir: String

    public init(predictedUpdateCount: UInt64, planId: String, destinationDir: String, rollbackSourceDir: String) {
        self.predictedUpdateCount = predictedUpdateCount
        self.planId = planId
        self.destinationDir = destinationDir
        self.rollbackSourceDir = rollbackSourceDir
    }

    enum CodingKeys: String, CodingKey {
        case predictedUpdateCount = "predicted_update_count"
        case planId = "plan_id"
        case destinationDir = "destination_dir"
        case rollbackSourceDir = "rollback_source_dir"
    }
}

/// Mirrors `recovery_core::session::driver::Request` (JSON object tagged by `op`).
public enum Request: Equatable, Sendable {
    case ping
    case status
    case cleanup
    case inspect(backupDir: String)
    case intake(role: BackupRole, backupDir: String, accountDir: String?)
    case analyze
    case patch(destinationDir: String, confirm: PatchConfirmation)
    case export(destinationDir: String, overwriteConfirmed: Bool)
    case report(redacted: Bool)
    case exportRepairedDatabase(destinationFile: String, overwriteConfirmed: Bool)

    public var op: String {
        switch self {
        case .ping: return "ping"
        case .status: return "status"
        case .cleanup: return "cleanup"
        case .inspect: return "inspect"
        case .intake: return "intake"
        case .analyze: return "analyze"
        case .patch: return "patch"
        case .export: return "export"
        case .report: return "report"
        case .exportRepairedDatabase: return "export_repaired_database"
        }
    }

    public func jsonObject() -> [String: Any] {
        var o: [String: Any] = ["op": op]
        switch self {
        case .ping, .status, .cleanup, .analyze:
            break
        case let .inspect(backupDir):
            o["backup_dir"] = backupDir
        case let .intake(role, backupDir, accountDir):
            o["role"] = role.rawValue
            o["backup_dir"] = backupDir
            if let a = accountDir { o["account_dir"] = a }
        case let .patch(destinationDir, confirm):
            o["destination_dir"] = destinationDir
            o["confirm"] = [
                "predicted_update_count": confirm.predictedUpdateCount,
                "plan_id": confirm.planId,
                "destination_dir": confirm.destinationDir,
                "rollback_source_dir": confirm.rollbackSourceDir,
            ] as [String: Any]
        case let .export(destinationDir, overwriteConfirmed):
            o["destination_dir"] = destinationDir
            o["overwrite_confirmed"] = overwriteConfirmed
        case let .report(redacted):
            o["redacted"] = redacted
        case let .exportRepairedDatabase(destinationFile, overwriteConfirmed):
            o["destination_file"] = destinationFile
            o["overwrite_confirmed"] = overwriteConfirmed
        }
        return o
    }

    public func jsonData() throws -> Data {
        try JSONSerialization.data(withJSONObject: jsonObject(), options: [.sortedKeys])
    }
}
