import Foundation
@testable import RecoveryKit
import Testing

@Suite struct RequestTests {
    @Test func opNamesMatchRustContract() {
        #expect(Request.ping.op == "ping")
        #expect(Request.intake(role: .old, backupDir: "/x", accountDir: nil).op == "intake")
        #expect(Request.exportRepairedDatabase(destinationFile: "/f", overwriteConfirmed: false).op == "export_repaired_database")
    }

    @Test func intakeEncoding() throws {
        let obj = Request.intake(role: .current, backupDir: "/b", accountDir: "P_u1").jsonObject()
        #expect(obj["role"] as? String == "current")
        #expect(obj["backup_dir"] as? String == "/b")
        #expect(obj["account_dir"] as? String == "P_u1")
        let noAcct = Request.intake(role: .old, backupDir: "/b", accountDir: nil).jsonObject()
        #expect(noAcct["account_dir"] == nil)
    }

    @Test func patchConfirmationEncoding() throws {
        let c = PatchConfirmation(predictedUpdateCount: 227, planId: "abc", destinationDir: "/d", rollbackSourceDir: "/s")
        let data = try Request.patch(destinationDir: "/d", confirm: c).jsonData()
        let s = String(decoding: data, as: UTF8.self)
        #expect(s.contains("\"predicted_update_count\":227"))
        #expect(s.contains("\"rollback_source_dir\":\"\\/s\"") || s.contains("\"rollback_source_dir\":\"/s\""))
        #expect(s.contains("\"op\":\"patch\""))
    }

    @Test func exportDefaultsNeverOverwrite() {
        let obj = Request.export(destinationDir: "/d", overwriteConfirmed: false).jsonObject()
        #expect(obj["overwrite_confirmed"] as? Bool == false)
    }
}
