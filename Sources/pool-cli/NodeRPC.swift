import Base
import Foundation

/// JSON-RPC client for communicating with a fbd node.
///
/// Uses `getblocktemplate` to fetch work and `submitblock` to push found blocks.
public final class NodeRPC: Sendable {
    private let url: URL
    private let apiKey: String?
    private let session: URLSession

    public init(url: String, apiKey: String?) {
        self.url = URL(string: url)!
        self.apiKey = apiKey
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        self.session = URLSession(configuration: config)
    }

    // MARK: - RPC Calls

    /// Fetch a block template for mining.
    public func getBlockTemplate(address: String) async throws -> BlockTemplateResult {
        let result = try await call(method: "getblocktemplate", params: [address])
        guard let dict = result as? [String: Any] else {
            throw PoolError.rpcError("invalid getblocktemplate response")
        }
        return try BlockTemplateResult.parse(dict)
    }

    /// Submit a hex-encoded block to the node.
    public func submitBlock(hex: String) async throws -> SubmitBlockResult {
        let result = try await call(method: "submitblock", params: [hex])
        guard let dict = result as? [String: Any] else {
            throw PoolError.rpcError("invalid submitblock response")
        }
        let hash = dict["hash"] as? String ?? ""
        let height = dict["height"] as? Int ?? 0
        return SubmitBlockResult(hash: hash, height: height)
    }

    /// Send a batch payout via wallet RPC.
    /// Uses `sendmany` with `none` actions: "none addr1 amount1, none addr2 amount2, ..."
    /// Amounts are in FBC (not bumps). Returns the txid.
    public func sendPayout(walletName: String, payouts: [(address: String, amountBumps: Int64)]) async throws -> String {
        // Build the sendmany argument string
        let segments = payouts.map { (addr, bumps) -> String in
            let fbc = Double(bumps) / 1_000_000.0
            return "none \(addr) \(fbc)"
        }
        let arg = segments.joined(separator: ", ")

        // sendmany is wallet-scoped: params are [walletName, "none addr amt, none addr amt, ..."]
        let result = try await call(method: "sendmany", params: [walletName, arg])
        guard let dict = result as? [String: Any],
              let txid = dict["txid"] as? String else {
            // Some wallets return just the txid as a string
            if let txid = result as? String { return txid }
            throw PoolError.rpcError("unexpected sendmany response")
        }
        return txid
    }

    /// Get basic blockchain info.
    public func getBlockchainInfo() async throws -> [String: Any] {
        let result = try await call(method: "getblockchaininfo", params: [])
        guard let dict = result as? [String: Any] else {
            throw PoolError.rpcError("invalid getblockchaininfo response")
        }
        return dict
    }

    // MARK: - Transport

    private func call(method: String, params: [Any]) async throws -> Any {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("pool/1.0", forHTTPHeaderField: "User-Agent")

        if let key = apiKey {
            let cred = "x:\(key)"
            let b64 = Data(cred.utf8).base64EncodedString()
            request.setValue("Basic \(b64)", forHTTPHeaderField: "Authorization")
        }

        let body: [String: Any] = [
            "method": method,
            "params": params,
            "id": 1,
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw PoolError.rpcError("non-HTTP response")
        }
        guard http.statusCode == 200 else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw PoolError.rpcError("HTTP \(http.statusCode): \(body)")
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PoolError.rpcError("invalid JSON response")
        }

        if let error = json["error"], !(error is NSNull) {
            let msg = (error as? [String: Any])?["message"] as? String ?? "\(error)"
            throw PoolError.rpcError(msg)
        }

        guard let result = json["result"] else {
            throw PoolError.rpcError("missing result")
        }
        return result
    }
}

// MARK: - Result Types

/// Parsed block template from fbd's `getblocktemplate` RPC.
public struct BlockTemplateResult: Sendable {
    public let height: Int
    public let bits: UInt32
    public let prevBlockHash: String
    public let curTime: UInt64
    public let coinbaseHex: String
    public let transactions: [TxEntry]
    public let merkleRoot: String
    public let witnessRoot: String
    public let treeRoot: String
    public let reservedRoot: String
    public let target: String
    public let fees: Int64
    public let version: UInt32

    public struct TxEntry: Sendable {
        public let data: String
        public let txid: String
        public let fee: Int64
    }

    static func parse(_ dict: [String: Any]) throws -> BlockTemplateResult {
        guard let height = dict["height"] as? Int,
              let bits = dict["bits"] as? Int,
              let prevBlockHash = dict["prevblockhash"] as? String,
              let curTime = dict["curtime"] as? Int,
              let coinbaseHex = dict["coinbase"] as? String,
              let merkleRoot = dict["merkleroot"] as? String,
              let witnessRoot = dict["witnessroot"] as? String,
              let treeRoot = dict["treeroot"] as? String,
              let target = dict["target"] as? String
        else {
            throw PoolError.rpcError("missing fields in block template")
        }

        let fees = dict["fees"] as? Int64 ?? (dict["fees"] as? Int).map(Int64.init) ?? 0
        let version = (dict["version"] as? Int).map(UInt32.init) ?? 0
        let reservedRoot = dict["reservedroot"] as? String ?? String(repeating: "0", count: 64)

        let txArray = dict["transactions"] as? [[String: Any]] ?? []
        let txs = txArray.compactMap { tx -> TxEntry? in
            guard let data = tx["data"] as? String,
                  let txid = tx["txid"] as? String else { return nil }
            let fee = tx["fee"] as? Int64 ?? (tx["fee"] as? Int).map(Int64.init) ?? 0
            return TxEntry(data: data, txid: txid, fee: fee)
        }

        return BlockTemplateResult(
            height: height,
            bits: UInt32(bits),
            prevBlockHash: prevBlockHash,
            curTime: UInt64(curTime),
            coinbaseHex: coinbaseHex,
            transactions: txs,
            merkleRoot: merkleRoot,
            witnessRoot: witnessRoot,
            treeRoot: treeRoot,
            reservedRoot: reservedRoot,
            target: target,
            fees: fees,
            version: version
        )
    }
}

public struct SubmitBlockResult: Sendable {
    public let hash: String
    public let height: Int
}

// MARK: - Errors

public enum PoolError: Error, CustomStringConvertible {
    case rpcError(String)
    case stratumError(String)
    case invalidShare(String)

    public var description: String {
        switch self {
        case .rpcError(let msg): return "RPC error: \(msg)"
        case .stratumError(let msg): return "Stratum error: \(msg)"
        case .invalidShare(let msg): return "Invalid share: \(msg)"
        }
    }
}
