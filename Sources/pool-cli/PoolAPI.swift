import Base
import Foundation
import Logging

/// Minimal HTTP API server for pool statistics.
///
/// Endpoints:
///   GET /api/stats    — pool overview (hashrate, workers, blocks)
///   GET /api/workers  — connected worker list
///   GET /api/blocks   — blocks found by pool
public final class PoolAPI: @unchecked Sendable {
    private let stratum: StratumServer
    private let shareLog: ShareLog
    private let rpc: NodeRPC
    private let logger: Logger
    private let startTime: Date
    private var listener: TCPListener?
    private var networkHashrate: Double = -1
    private var blockTimeSeconds: Int = 0
    private var networkTask: Task<Void, Never>?

    public init(stratum: StratumServer, shareLog: ShareLog, rpc: NodeRPC, logger: Logger) {
        self.stratum = stratum
        self.shareLog = shareLog
        self.rpc = rpc
        self.logger = logger
        self.startTime = Date()
        startNetworkPoller()
    }

    public func start(host: String, port: Int) throws {
        let tcp = try TCPListener(host: host, port: port)
        self.listener = tcp

        tcp.accept { [self] stream, _, _ in
            await self.handleHTTP(stream: stream)
        }

        logger.info("Pool API listening on \(host):\(port)", source: "API")
    }

    public func shutdown() {
        networkTask?.cancel()
        listener?.shutdown()
        listener = nil
    }

    private func startNetworkPoller() {
        networkTask = Task { [weak self] in
            // Fetch immediately, then every 60 seconds
            while !Task.isCancelled {
                guard let self else { return }
                do {
                    let params = try await self.rpc.getProtocolParams()
                    let blockTime = params["blockTimeSeconds"] as? Int ?? 120

                    let info = try await self.rpc.getBlockchainInfo()
                    let difficulty = (info["difficulty"] as? Double)
                        ?? (info["difficulty"] as? Int).map(Double.init)
                        ?? 0

                    if difficulty > 0 && blockTime > 0 {
                        // hashrate = difficulty * 2^32 / blockTimeSeconds
                        self.networkHashrate = difficulty * 4294967296.0 / Double(blockTime)
                        self.blockTimeSeconds = blockTime
                    }
                } catch {
                    self.logger.debug("Network hashrate fetch failed: \(error)", source: "API")
                }
                try? await Task.sleep(nanoseconds: 60_000_000_000)
            }
        }
    }

    // MARK: - HTTP

    private func handleHTTP(stream: SocketStream) async {
        // Read the request (simple: just read until we see \r\n\r\n)
        var buf = [UInt8]()
        while buf.count < 8192 {
            guard let data = try? await stream.read(maxBytes: 4096) else { break }
            if data.isEmpty { break }
            buf.append(contentsOf: data)
            if let str = String(bytes: buf, encoding: .utf8), str.contains("\r\n\r\n") {
                break
            }
        }

        let request = String(bytes: buf, encoding: .utf8) ?? ""
        let path = parseRequestPath(request)

        let (status, body) = route(path)
        let response = formatHTTPResponse(status: status, body: body)
        try? await stream.write(Array(response.utf8))
        await stream.close()
    }

    private func route(_ path: String) -> (Int, String) {
        switch path {
        case "/api/stats":
            return (200, statsJSON())
        case "/api/workers":
            return (200, workersJSON())
        case "/api/blocks":
            return (200, blocksJSON())
        case "/api/balances":
            return (200, balancesJSON())
        case "/api/payouts":
            return (200, payoutsJSON())
        default:
            return (404, "{\"error\":\"not found\"}")
        }
    }

    // MARK: - JSON Responses

    private func statsJSON() -> String {
        let workers = stratum.workerSnapshots
        let shareStats = shareLog.stats
        let blockCount = shareLog.blockCount
        let totalHashrate = workers.reduce(0.0) { $0 + ($1.hashrate > 0 ? $1.hashrate : 0) }
        let uptime = Int(Date().timeIntervalSince(startTime))
        let fee = shareLog.feePercent

        return """
        {"workers":\(workers.count),\
        "hashrate":\(totalHashrate),\
        "network_hashrate":\(networkHashrate),\
        "block_time":\(blockTimeSeconds),\
        "blocks_found":\(blockCount),\
        "shares_in_window":\(shareStats.windowShares),\
        "window_difficulty":\(shareStats.windowDifficulty),\
        "fee":\(fee),\
        "uptime":\(uptime)}
        """
    }

    private func workersJSON() -> String {
        let workers = stratum.workerSnapshots
        let entries = workers.map { w in
            "{\"id\":\(w.id)," +
            "\"username\":\"\(w.username)\"," +
            "\"address\":\"\(w.remoteAddress)\"," +
            "\"difficulty\":\(w.difficulty)," +
            "\"accepted\":\(w.accepted)," +
            "\"rejected\":\(w.rejected)," +
            "\"stale\":\(w.stale)," +
            "\"blocks\":\(w.blocks)," +
            "\"hashrate\":\(w.hashrate)}"
        }
        return "[\(entries.joined(separator: ","))]"
    }

    private func blocksJSON() -> String {
        let blocks = shareLog.foundBlocks
        let entries = blocks.map { b in
            "{\"height\":\(b.height)," +
            "\"hash\":\"\(b.hash)\"," +
            "\"time\":\(Int(b.foundAt.timeIntervalSince1970))," +
            "\"reward\":\(b.reward)," +
            "\"confirmations\":\(b.confirmations)," +
            "\"status\":\"\(b.status)\"," +
            "\"credited\":\(b.credited)," +
            "\"found_by\":\"\(b.foundBy)\"}"
        }
        return "[\(entries.joined(separator: ","))]"
    }

    private func balancesJSON() -> String {
        let bals = shareLog.minerBalances
        let entries = bals.map { b in
            "{\"address\":\"\(b.address)\"," +
            "\"balance\":\(b.balance)," +
            "\"fbc\":\(String(format: "%.6f", Double(b.balance) / 1_000_000.0))," +
            "\"total_earned\":\(b.totalEarned)," +
            "\"total_paid\":\(b.totalPaid)}"
        }
        return "[\(entries.joined(separator: ","))]"
    }

    private func payoutsJSON() -> String {
        let payouts = shareLog.recentPayouts
        let entries = payouts.map { p in
            "{\"address\":\"\(p.address)\"," +
            "\"amount\":\(p.amount)," +
            "\"txid\":\"\(p.txid)\"," +
            "\"status\":\"\(p.status)\"," +
            "\"time\":\(Int(p.createdAt.timeIntervalSince1970))}"
        }
        return "[\(entries.joined(separator: ","))]"
    }

    // MARK: - Helpers

    private func parseRequestPath(_ request: String) -> String {
        // "GET /api/stats HTTP/1.1\r\n..."
        let parts = request.split(separator: " ", maxSplits: 3)
        guard parts.count >= 2 else { return "/" }
        let fullPath = String(parts[1])
        // Strip query string
        if let qIdx = fullPath.firstIndex(of: "?") {
            return String(fullPath[..<qIdx])
        }
        return fullPath
    }

    private func formatHTTPResponse(status: Int, body: String) -> String {
        let statusText = status == 200 ? "OK" : "Not Found"
        let bodyData = Array(body.utf8)
        return "HTTP/1.1 \(status) \(statusText)\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Length: \(bodyData.count)\r\n" +
            "Access-Control-Allow-Origin: *\r\n" +
            "Connection: close\r\n" +
            "\r\n" +
            body
    }
}
