import Base
import Foundation

/// Abstraction over TCP or TLS connection so the worker doesn't care which.
public struct StreamIO: Sendable {
    public let read: @Sendable () async throws -> [UInt8]
    public let write: @Sendable ([UInt8]) async throws -> Void
    public let close: @Sendable () async -> Void

    public static func from(_ stream: SocketStream) -> StreamIO {
        StreamIO(
            read: { try await stream.read() },
            write: { try await stream.write($0) },
            close: { await stream.close() }
        )
    }

    #if canImport(Network)
    public static func from(_ stream: TLSStream) -> StreamIO {
        StreamIO(
            read: { try await stream.read() },
            write: { try await stream.write($0) },
            close: { await stream.close() }
        )
    }
    #endif
}

/// A connected Stratum mining worker with pool-level tracking.
public final class PoolWorker: @unchecked Sendable {
    public let id: UInt64
    public let stream: StreamIO
    public let extraNonce1: UInt32
    public let remoteAddress: String
    public let connectedAt: Date

    // Auth
    public var username: String?
    public var payoutAddress: String?
    public var workerName: String?
    public var isSubscribed = false
    public var isAuthorized = false

    // Share stats
    public var accepted: Int = 0
    public var rejected: Int = 0
    public var stale: Int = 0
    public var blocks: Int = 0
    public var lastShareTime: Date?

    // VarDiff state
    public var difficulty: Double = 1.0
    public var shareTimestamps: [Date] = []
    public var lastRetargetTime: Date

    // Duplicate detection: set of "jobId:nonce:en2:time"
    public var submittedShares: Set<String> = []
    public let maxSubmittedShares = 10000

    private let writeQueue: WriteQueue

    public init(id: UInt64, stream: StreamIO, extraNonce1: UInt32, remoteAddress: String) {
        self.id = id
        self.stream = stream
        self.extraNonce1 = extraNonce1
        self.remoteAddress = remoteAddress
        self.connectedAt = Date()
        self.lastRetargetTime = Date()
        self.writeQueue = WriteQueue(stream)
    }

    /// Record a share submission timestamp for vardiff calculation.
    public func recordShareTime() {
        let now = Date()
        shareTimestamps.append(now)
        lastShareTime = now
        // Keep last 100 timestamps
        if shareTimestamps.count > 100 {
            shareTimestamps.removeFirst(shareTimestamps.count - 100)
        }
    }

    /// Check and record a share fingerprint. Returns false if duplicate.
    public func checkDuplicate(jobId: String, nonce: String, en2: String, time: String) -> Bool {
        let key = "\(jobId):\(nonce):\(en2):\(time)"
        if submittedShares.contains(key) { return false }
        submittedShares.insert(key)
        // Evict old entries
        if submittedShares.count > maxSubmittedShares {
            submittedShares.removeAll()
        }
        return true
    }

    /// Average time between recent shares (seconds), or nil if insufficient data.
    public var averageShareTime: Double? {
        guard shareTimestamps.count >= 3 else { return nil }
        let first = shareTimestamps.first!
        let last = shareTimestamps.last!
        let elapsed = last.timeIntervalSince(first)
        return elapsed / Double(shareTimestamps.count - 1)
    }

    /// Estimated hashrate based on difficulty and share rate (H/s).
    public var estimatedHashrate: Double {
        guard let avgTime = averageShareTime, avgTime > 0 else { return 0 }
        // hashrate = difficulty * 2^32 / avgTime (for a standard double-SHA256 chain)
        // For BalloonHash the "hash" cost is much higher, but difficulty is still
        // defined as target = powLimit / difficulty, so this ratio holds for
        // comparing workers within the pool.
        return difficulty / avgTime
    }

    // MARK: - Sending

    /// Send a JSON-RPC response.
    public func sendResponse(id: JSONVal, result: JSONVal?, error: JSONVal? = nil) {
        var obj = "{\"id\":\(id.encode()),\"result\":\(result?.encode() ?? "null"),\"error\":\(error?.encode() ?? "null")}"
        obj.append("\n")
        sendRaw(obj)
    }

    /// Send a mining.set_difficulty notification.
    public func sendSetDifficulty(_ diff: Double) {
        let msg = "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[\(diff)]}\n"
        sendRaw(msg)
    }

    /// Send a mining.notify notification.
    public func sendNotify(job: PoolJob, clean: Bool) {
        let params = [
            str(job.id),
            str(job.prevBlockHash),
            str(job.merkleRoot),
            str(job.witnessRoot),
            str(job.treeRoot),
            str(job.reservedRoot),
            str(String(format: "%08x", job.version)),
            str(String(format: "%08x", job.bits)),
            str(HexEncoding.encode(withUnsafeBytes(of: job.time.littleEndian) { Array($0) })),
            str(HexEncoding.encode(job.poolExtraNonce)),
            clean ? "true" : "false",
        ]
        let msg = "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\(params.joined(separator: ","))]}\n"
        sendRaw(msg)
    }

    /// Close the connection.
    public func close() {
        Task { await stream.close() }
    }

    // MARK: - Private

    private func sendRaw(_ string: String) {
        let bytes = Array(string.utf8)
        Task {
            await writeQueue.write(bytes)
        }
    }

    private func str(_ s: String) -> String { "\"\(s)\"" }
}

// MARK: - Serialised write queue

/// Actor that serialises all writes to a worker's stream so that concurrent
/// `sendRaw` calls are always flushed in the order they were enqueued.
private actor WriteQueue {
    private let stream: StreamIO
    init(_ stream: StreamIO) { self.stream = stream }
    func write(_ bytes: [UInt8]) async { try? await stream.write(bytes) }
}

// MARK: - Minimal JSON value type for Stratum protocol

/// Lightweight JSON value for Stratum messages (avoids depending on fbd's RPC module's JSONValue).
public enum JSONVal {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([JSONVal])

    public func encode() -> String {
        switch self {
        case .null: return "null"
        case .bool(let b): return b ? "true" : "false"
        case .int(let n): return "\(n)"
        case .double(let d): return "\(d)"
        case .string(let s): return "\"\(escapeJSON(s))\""
        case .array(let arr): return "[\(arr.map { $0.encode() }.joined(separator: ","))]"
        }
    }

    public var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    public var intValue: Int64? {
        if case .int(let n) = self { return n }
        return nil
    }

    private func escapeJSON(_ s: String) -> String {
        var result = ""
        for ch in s {
            switch ch {
            case "\"": result += "\\\""
            case "\\": result += "\\\\"
            case "\n": result += "\\n"
            case "\r": result += "\\r"
            case "\t": result += "\\t"
            default: result.append(ch)
            }
        }
        return result
    }
}

/// Parse a JSON string into basic Foundation types.
/// Returns the parsed object or nil.
public func parseJSON(_ data: [UInt8]) -> [String: Any]? {
    guard let obj = try? JSONSerialization.jsonObject(with: Data(data)) as? [String: Any] else {
        return nil
    }
    return obj
}
