import CRecoveryCore
import Foundation

/// Progress event from the core. `total == 0` means unknown.
public struct ProgressEvent: Equatable, Sendable {
    public let stage: String
    public let done: UInt64
    public let total: UInt64
}

public typealias ProgressHandler = @Sendable (ProgressEvent) -> Void

/// Result of a successful request: the `ok` payload.
public struct ExecutionResult: Sendable {
    public let raw: Data
    public let okJSON: Data

    public func object() -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: okJSON)) as? [String: Any]
    }

    public func decode<T: Decodable>(_ type: T.Type) throws -> T {
        try JSONDecoder().decode(type, from: okJSON)
    }
}

private final class ProgressBox {
    let handler: ProgressHandler
    init(_ handler: @escaping ProgressHandler) { self.handler = handler }
}

private let progressTrampoline: RecoveryProgressFn = { stage, done, total, userData in
    guard let userData, let stage else { return }
    let box = Unmanaged<ProgressBox>.fromOpaque(userData).takeUnretainedValue()
    box.handler(ProgressEvent(stage: String(cString: stage), done: done, total: total))
}

/// Owns one Rust session handle. Thread-safe: `execute` serializes inside the core, `cancel`
/// may be called from any thread while an operation runs.
public final class RecoverySession: @unchecked Sendable {
    private let handle: OpaquePointer

    public static var coreVersion: String { String(cString: recovery_version()) }

    public init(workspace: URL) throws {
        var err: UnsafeMutablePointer<CChar>? = nil
        let h = workspace.path.withCString { ws in recovery_session_new(ws, &err) }
        guard let h else {
            defer { recovery_string_free(err) }
            if let err, let data = String(cString: err).data(using: .utf8) {
                throw RecoverySession.parseError(data) ?? RecoveryError(code: "internal", message: "session creation failed")
            }
            throw RecoveryError(code: "internal", message: "session creation failed")
        }
        handle = h
    }

    deinit { recovery_session_free(handle) }

    public func cancel() { recovery_session_cancel(handle) }

    private static func parseError(_ data: Data) -> RecoveryError? {
        struct Envelope: Decodable { let error: RecoveryError? }
        return (try? JSONDecoder().decode(Envelope.self, from: data))?.error
    }

    /// Executes a request. The password, when given, is passed as raw bytes and copied by the
    /// core into zeroizing memory; the Data is wiped here afterwards.
    public func execute(_ request: Request, password: Data? = nil, progress: ProgressHandler? = nil) throws -> ExecutionResult {
        let json = try request.jsonData()
        var cJSON = [CChar](json.map { CChar(bitPattern: $0) }) + [0]
        let box = progress.map { ProgressBox($0) }
        let userData = box.map { Unmanaged.passUnretained($0).toOpaque() }
        var pw = password ?? Data()
        defer { pw.resetBytes(in: 0..<pw.count) }
        let out: UnsafeMutablePointer<CChar>? = cJSON.withUnsafeMutableBufferPointer { jsonBuf in
            pw.withUnsafeBytes { pwBuf in
                recovery_session_execute(
                    handle,
                    jsonBuf.baseAddress,
                    pwBuf.isEmpty ? nil : pwBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    pwBuf.count,
                    box == nil ? nil : progressTrampoline,
                    userData
                )
            }
        }
        withExtendedLifetime(box) {}
        guard let out else { throw RecoveryError(code: "internal", message: "core returned NULL") }
        defer { recovery_string_free(out) }
        let raw = Data(bytes: out, count: strlen(out))
        if let err = RecoverySession.parseError(raw) { throw err }
        guard let obj = try JSONSerialization.jsonObject(with: raw) as? [String: Any], let ok = obj["ok"] else {
            throw RecoveryError(code: "internal", message: "core returned neither ok nor error")
        }
        let okData = try JSONSerialization.data(withJSONObject: ok, options: [.fragmentsAllowed])
        return ExecutionResult(raw: raw, okJSON: okData)
    }
}
