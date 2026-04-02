import Base
import Consensus
import ExtCrypto
import Foundation
import Logging
import Protocol

/// Stratum v1 mining pool server.
///
/// Accepts miner connections over TCP, distributes work from block templates
/// fetched via fbd RPC, validates submitted shares via BalloonProof verification
/// against per-worker share difficulty, and submits valid blocks to fbd.
public final class StratumServer: @unchecked Sendable {
    private let config: PoolConfig
    private let rpc: NodeRPC
    private let vardiff: VarDiff
    private let shareLog: ShareLog
    private let logger: Logger

    private let lock = NSLock()
    private var listenerShutdown: (() -> Void)?
    private var workers: [UInt64: PoolWorker] = [:]
    private var nextWorkerId: UInt64 = 1
    private var nextExtraNonce1: UInt32 = 1
    private var nextJobId: UInt64 = 1
    private var currentJob: PoolJob?
    private var recentJobs: [String: PoolJob] = [:]
    private var jobNotifierTask: Task<Void, Never>?

    /// Consensus params for the configured network.
    private let params: ConsensusParams

    /// Maximum recent jobs for stale share tolerance.
    private let maxRecentJobs = 4

    /// Callback when a block is found (for stats).
    public var onBlockFound: (@Sendable (Int, String) -> Void)?

    public init(config: PoolConfig, rpc: NodeRPC, shareLog: ShareLog, logger: Logger) {
        self.config = config
        self.rpc = rpc
        self.vardiff = VarDiff(config: config)
        self.shareLog = shareLog
        self.logger = logger
        self.params = ConsensusParams.params(for: config.network)
    }

    // MARK: - Lifecycle

    public func start() throws {
        let port = Int(config.effectiveStratumPort)

        #if canImport(Network)
        if let p12Path = config.tlsCertPath {
            let tls = try TLSListener(
                host: config.stratumHost, port: port,
                p12Path: p12Path, p12Password: config.tlsCertPassword ?? "",
                logger: logger
            )
            self.listenerShutdown = { tls.shutdown() }
            tls.accept { [self] stream, ip, clientPort in
                await self.handleConnection(stream: .from(stream), ip: ip, port: clientPort)
            }
            logger.info("Stratum (TLS) listening on \(config.stratumHost):\(port)", source: "Stratum")
            startJobNotifier()
            return
        }
        #endif

        let tcp = try TCPListener(host: config.stratumHost, port: port)
        self.listenerShutdown = { tcp.shutdown() }

        tcp.accept { [self] stream, ip, clientPort in
            await self.handleConnection(stream: .from(stream), ip: ip, port: clientPort)
        }

        startJobNotifier()
        logger.info("Stratum listening on \(config.stratumHost):\(port)", source: "Stratum")
    }

    private func startJobNotifier() {
        jobNotifierTask = Task { [self] in
            do {
                let job = try await self.generateJob()
                self.setCurrentJob(job)
            } catch {
                self.logger.error("Failed to generate initial job: \(error)", source: "Stratum")
            }

            var lastPrevHash = ""
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                do {
                    let job = try await self.generateJob()
                    let isNewBlock = job.prevBlockHash != lastPrevHash
                    lastPrevHash = job.prevBlockHash
                    self.broadcastJob(job, clean: isNewBlock)
                } catch {
                    self.logger.error("Failed to generate job: \(error)", source: "Stratum")
                }
            }
        }
    }

    public func shutdown() {
        jobNotifierTask?.cancel()
        jobNotifierTask = nil
        listenerShutdown?()
        listenerShutdown = nil
        lock.lock()
        let allWorkers = workers.values
        lock.unlock()
        for worker in allWorkers {
            worker.close()
        }
    }

    // MARK: - Stats

    public var workerCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return workers.count
    }

    public var workerSnapshots: [WorkerSnapshot] {
        lock.lock()
        let all = Array(workers.values)
        lock.unlock()
        return all.map { w in
            WorkerSnapshot(
                id: w.id,
                username: w.username ?? "unknown",
                payoutAddress: w.payoutAddress ?? "unknown",
                workerName: w.workerName,
                remoteAddress: w.remoteAddress,
                difficulty: w.difficulty,
                accepted: w.accepted,
                rejected: w.rejected,
                stale: w.stale,
                blocks: w.blocks,
                hashrate: w.estimatedHashrate,
                connectedAt: w.connectedAt,
                lastShareTime: w.lastShareTime
            )
        }
    }

    // MARK: - Connection Handling

    private func handleConnection(stream: StreamIO, ip: String, port: Int) async {
        let workerId: UInt64
        let extraNonce1: UInt32
        lock.lock()
        workerId = nextWorkerId
        nextWorkerId += 1
        extraNonce1 = nextExtraNonce1
        nextExtraNonce1 += 1
        lock.unlock()

        let worker = PoolWorker(
            id: workerId, stream: stream, extraNonce1: extraNonce1,
            remoteAddress: "\(ip):\(port)"
        )

        lock.lock()
        workers[workerId] = worker
        lock.unlock()

        logger.debug("Miner connected", metadata: [
            "worker": "\(workerId)",
            "address": "\(ip):\(port)",
        ], source: "Stratum")

        await runWorker(worker)

        lock.lock()
        workers.removeValue(forKey: workerId)
        let remaining = workers.count
        lock.unlock()

        logger.debug("Miner disconnected", metadata: [
            "worker": "\(workerId)",
            "remaining": "\(remaining)",
        ], source: "Stratum")
    }

    private func runWorker(_ worker: PoolWorker) async {
        var accumulator = AccumulationBuffer()

        while true {
            do {
                let data = try await worker.stream.read()
                guard !data.isEmpty else { break }
                accumulator.append(data)
                guard accumulator.readableBytes <= 65536 else { return }
            } catch {
                break
            }

            while let line = accumulator.consumeLine() {
                guard !line.isEmpty else { continue }
                handleMessage(line, worker: worker)
            }

            // Check vardiff after processing messages
            if let newDiff = vardiff.retarget(worker: worker) {
                worker.difficulty = newDiff
                worker.lastRetargetTime = Date()
                worker.shareTimestamps.removeAll()
                worker.sendSetDifficulty(newDiff)
                logger.debug("Retarget", metadata: [
                    "worker": "\(worker.id)",
                    "difficulty": "\(newDiff)",
                ], source: "VarDiff")
            }
        }

        await worker.stream.close()
    }

    // MARK: - Message Dispatch

    private func handleMessage(_ data: [UInt8], worker: PoolWorker) {
        guard let json = parseJSON(data) else { return }

        let id: JSONVal
        if let n = json["id"] as? Int { id = .int(Int64(n)) }
        else if let n = json["id"] as? Int64 { id = .int(n) }
        else if let s = json["id"] as? String { id = .string(s) }
        else { id = .null }

        guard let method = json["method"] as? String else { return }
        let params = json["params"] as? [Any] ?? []

        switch method {
        case "mining.subscribe":
            handleSubscribe(worker: worker, id: id)
        case "mining.authorize":
            handleAuthorize(worker: worker, id: id, params: params)
        case "mining.submit":
            guard worker.isAuthorized else {
                worker.sendResponse(id: id, result: nil, error: .string("not authorized"))
                return
            }
            handleSubmit(worker: worker, id: id, params: params)
        default:
            worker.sendResponse(id: id, result: nil, error: .string("unknown method"))
        }
    }

    // MARK: - Protocol Handlers

    private func handleSubscribe(worker: PoolWorker, id: JSONVal) {
        let extraNonce1Hex = String(format: "%08x", worker.extraNonce1)
        let result = JSONVal.array([
            .array([.string("mining.notify"), .string("1")]),
            .string(extraNonce1Hex),
            .int(Int64(PoolJob.extraNonce2Size)),
        ])
        worker.sendResponse(id: id, result: result)
        worker.isSubscribed = true

        // Send initial difficulty
        worker.sendSetDifficulty(worker.difficulty)

        logger.debug("Miner subscribed", metadata: [
            "worker": "\(worker.id)",
            "extranonce1": "\(extraNonce1Hex)",
        ], source: "Stratum")
    }

    private func handleAuthorize(worker: PoolWorker, id: JSONVal, params: [Any]) {
        let username = (params.first as? String) ?? "unknown"
        let password = params.count > 1 ? params[1] as? String : nil

        if let required = config.stratumPassword, !required.isEmpty {
            guard password == required else {
                worker.sendResponse(id: id, result: nil, error: .string("unauthorized"))
                return
            }
        }

        // Parse username as "address.workername" or just "address"
        let (address, workerName) = parseUsername(username)

        // Validate payout address
        let hrp = config.network.addressHRP
        guard address.hasPrefix(hrp + "1") else {
            worker.sendResponse(id: id, result: nil, error: .string("invalid address: must start with \(hrp)1"))
            return
        }

        worker.username = username
        worker.payoutAddress = address
        worker.workerName = workerName
        worker.isAuthorized = true
        worker.sendResponse(id: id, result: .bool(true))

        logger.info("Miner authorized", metadata: [
            "worker": "\(worker.id)",
            "address": "\(address)",
            "rig": "\(workerName ?? "default")",
        ], source: "Stratum")

        // Send current job
        lock.lock()
        let job = currentJob
        lock.unlock()

        if let job = job {
            worker.sendNotify(job: job, clean: true)
        }
    }

    private func handleSubmit(worker: PoolWorker, id: JSONVal, params: [Any]) {
        // params: [username, jobId, extraNonce2Hex, nTimeHex, nonceHex, proofHex]
        guard params.count >= 6,
              let jobId = params[1] as? String,
              let extraNonce2Hex = params[2] as? String,
              let nTimeHex = params[3] as? String,
              let nonceHex = params[4] as? String,
              let proofHex = params[5] as? String else {
            worker.sendResponse(id: id, result: nil, error: .string("invalid params"))
            worker.rejected += 1
            return
        }

        // Duplicate check
        guard worker.checkDuplicate(jobId: jobId, nonce: nonceHex, en2: extraNonce2Hex, time: nTimeHex) else {
            worker.sendResponse(id: id, result: nil, error: .string("duplicate share"))
            worker.rejected += 1
            return
        }

        // Look up job
        lock.lock()
        let job = recentJobs[jobId]
        lock.unlock()

        guard let job = job else {
            worker.sendResponse(id: id, result: nil, error: .string("stale job"))
            worker.stale += 1
            return
        }

        // Decode hex values
        guard let extraNonce2 = try? HexEncoding.decode(extraNonce2Hex),
              extraNonce2.count == PoolJob.extraNonce2Size,
              let nTimeBytes = try? HexEncoding.decode(nTimeHex),
              nTimeBytes.count == 8,
              let nonceBytes = try? HexEncoding.decode(nonceHex),
              nonceBytes.count == 4,
              let proofBytes = try? HexEncoding.decode(proofHex),
              proofBytes.count == BalloonProof.serializedSize else {
            worker.sendResponse(id: id, result: nil, error: .string("invalid hex"))
            worker.rejected += 1
            return
        }

        // Reconstruct extraNonce: poolPrefix(8) || extraNonce1(4) || extraNonce2(12)
        var extraNonce = job.poolExtraNonce
        extraNonce.append(contentsOf: withUnsafeBytes(of: worker.extraNonce1.littleEndian) { Array($0) })
        extraNonce.append(contentsOf: extraNonce2)
        assert(extraNonce.count == 24)

        let nonce = nonceBytes.withUnsafeBytes { $0.load(as: UInt32.self) }
        let time = nTimeBytes.withUnsafeBytes { $0.load(as: UInt64.self) }

        // Reconstruct header
        let header = BlockHeader(
            nonce: nonce,
            time: time,
            prevBlock: (try? Hash256.fromHex(job.prevBlockHash)) ?? .zero,
            treeRoot: (try? Hash256.fromHex(job.treeRoot)) ?? .zero,
            extraNonce: extraNonce,
            reservedRoot: (try? Hash256.fromHex(job.reservedRoot)) ?? .zero,
            witnessRoot: (try? Hash256.fromHex(job.witnessRoot)) ?? .zero,
            merkleRoot: (try? Hash256.fromHex(job.merkleRoot)) ?? .zero,
            version: job.version,
            bits: job.bits
        )

        // Deserialize proof
        guard let proof = BalloonProof.deserialize(proofBytes) else {
            worker.sendResponse(id: id, result: nil, error: .string("invalid proof"))
            worker.rejected += 1
            return
        }

        // Verify proof and extract hash — reimplements ProofOfWork.verifyWithProof
        // but without the network target check (we check against share target instead).
        let hash: [UInt8]
        do {
            hash = try verifyShareProof(header: header, proof: proof)
        } catch {
            worker.sendResponse(id: id, result: nil, error: .string("proof verification failed"))
            worker.rejected += 1
            return
        }

        let hashTarget = Target256(bigEndian: hash)

        // Check share target (worker difficulty)
        let shareTarget = targetForDifficulty(worker.difficulty)
        guard hashTarget <= shareTarget else {
            worker.sendResponse(id: id, result: nil, error: .string("above target"))
            worker.rejected += 1
            return
        }

        // Valid share
        worker.accepted += 1
        worker.recordShareTime()
        worker.sendResponse(id: id, result: .bool(true))

        // Record share in PPLNS (keyed by payout address)
        shareLog.addShare(address: worker.payoutAddress ?? "unknown", difficulty: worker.difficulty)

        // Check if share also meets network target → block!
        let networkTarget = Target256.fromCompact(job.bits)
        if hashTarget <= networkTarget {
            worker.blocks += 1
            submitBlock(header: header, proof: proof, job: job)
        }
    }

    // MARK: - Share Verification

    /// Verify a BalloonProof for a header and return the hash.
    /// Does NOT check against any difficulty target.
    private func verifyShareProof(header: BlockHeader, proof: BalloonProof) throws -> [UInt8] {
        // Build password: same as ProofOfWork.buildPassword
        var pw = BufferWriter(capacity: 176)
        pw.writeBytes(header.prevBlock.bytes)     // 32
        pw.writeBytes(header.merkleRoot.bytes)    // 32
        pw.writeBytes(header.witnessRoot.bytes)   // 32
        pw.writeBytes(header.treeRoot.bytes)      // 32
        pw.writeBytes(header.reservedRoot.bytes)  // 32
        pw.writeUInt64LE(header.time)             // 8
        pw.writeUInt32LE(header.bits)             // 4
        pw.writeUInt32LE(header.version)          // 4
        let password = try Blake2bHash.hash(pw.data, size: 32)

        // Build salt: nonce(4) || extraNonce(24)
        var sl = BufferWriter(capacity: 28)
        sl.writeUInt32LE(header.nonce)
        sl.writeBytes(header.extraNonce)
        let salt = sl.data

        // Extract claimed hash from proof output sample
        guard let outputSample = proof.samples.first,
              outputSample.index == UInt32(params.balloonSlots - 1) else {
            throw PoolError.invalidShare("invalid proof output sample")
        }
        let outputHash = outputSample.mixedValue

        // Verify the proof
        guard proof.verify(
            outputHash: outputHash,
            password: password,
            salt: salt,
            slots: params.balloonSlots,
            rounds: params.balloonRounds,
            delta: params.balloonDelta
        ) else {
            throw PoolError.invalidShare("proof verification failed")
        }

        return outputHash
    }

    /// Convert a difficulty value to a 256-bit target.
    /// target = powLimit / difficulty
    private func targetForDifficulty(_ diff: Double) -> Target256 {
        guard diff > 0 else { return params.powLimit }
        if diff <= 1.0 { return params.powLimit }
        // Integer division: powLimit / diff
        // For simplicity, scale the powLimit bytes down by the difficulty factor.
        let limitBytes = params.powLimit.bigEndianBytes()
        // Convert to a double, divide, convert back.
        // This loses precision for very large targets but is fine for share difficulty.
        var value = 0.0
        for b in limitBytes {
            value = value * 256.0 + Double(b)
        }
        value /= diff
        // Convert back to 32 bytes big-endian
        var result = [UInt8](repeating: 0, count: 32)
        var remaining = value
        for i in stride(from: 31, through: 0, by: -1) {
            result[i] = UInt8(remaining.truncatingRemainder(dividingBy: 256))
            remaining = (remaining / 256).rounded(.down)
        }
        return Target256(bigEndian: result)
    }

    // MARK: - Block Submission

    private func submitBlock(header: BlockHeader, proof: BalloonProof, job: PoolJob) {
        Task {
            do {
                // Deserialize the coinbase and transactions from raw bytes
                var cbReader = BufferReader(job.coinbaseData)
                let coinbase = try Transaction.read(from: &cbReader)

                var txs = [coinbase]
                for txData in job.transactionData {
                    var txReader = BufferReader(txData)
                    let tx = try Transaction.read(from: &txReader)
                    txs.append(tx)
                }

                let block = Block(header: header, transactions: txs, balloonProof: proof)

                // Serialize to hex
                var writer = BufferWriter()
                block.write(to: &writer)
                let hex = HexEncoding.encode(writer.data)

                let result = try await rpc.submitBlock(hex: hex)

                logger.info("Block \(result.height) found!", metadata: [
                    "hash": "\(result.hash)",
                    "height": "\(result.height)",
                ], source: "Pool")

                // Calculate block reward from coinbase outputs
                let reward = Int64(coinbase.outputs.reduce(UInt64(0)) { $0 + $1.value })
                shareLog.recordBlock(height: result.height, hash: result.hash, blockReward: reward)
                onBlockFound?(result.height, result.hash)
            } catch {
                logger.error("Failed to submit block: \(error)", source: "Pool")
            }
        }
    }

    // MARK: - Job Management

    private func generateJob() async throws -> PoolJob {
        let template = try await rpc.getBlockTemplate(address: config.poolAddress)

        lock.lock()
        let jobId = String(format: "%x", nextJobId)
        nextJobId += 1
        lock.unlock()

        return PoolJob.from(template: template, jobId: jobId)
    }

    private func setCurrentJob(_ job: PoolJob) {
        lock.lock()
        currentJob = job
        recentJobs[job.id] = job
        trimJobs()
        lock.unlock()
    }

    private func broadcastJob(_ job: PoolJob, clean: Bool) {
        lock.lock()
        currentJob = job
        recentJobs[job.id] = job
        trimJobs()
        let allWorkers = Array(workers.values)
        lock.unlock()

        for worker in allWorkers where worker.isAuthorized {
            worker.sendNotify(job: job, clean: clean)
        }
    }

    private func trimJobs() {
        // Caller must hold lock
        if recentJobs.count > maxRecentJobs {
            let sortedKeys = recentJobs.keys.sorted()
            for key in sortedKeys.prefix(recentJobs.count - maxRecentJobs) {
                recentJobs.removeValue(forKey: key)
            }
        }
    }
}

// MARK: - Username Parsing

/// Parse a Stratum username as "address.workername" or just "address".
func parseUsername(_ username: String) -> (address: String, workerName: String?) {
    guard let dotIdx = username.lastIndex(of: ".") else {
        return (username, nil)
    }
    let address = String(username[..<dotIdx])
    let worker = String(username[username.index(after: dotIdx)...])
    // Only split if the part before the dot looks like an address (has "1" in it,
    // meaning it's bech32). Otherwise treat the whole thing as the address.
    if address.contains("1") && !worker.isEmpty {
        return (address, worker)
    }
    return (username, nil)
}

// MARK: - Worker Snapshot

public struct WorkerSnapshot: Sendable {
    public let id: UInt64
    public let username: String
    public let payoutAddress: String
    public let workerName: String?
    public let remoteAddress: String
    public let difficulty: Double
    public let accepted: Int
    public let rejected: Int
    public let stale: Int
    public let blocks: Int
    public let hashrate: Double
    public let connectedAt: Date
    public let lastShareTime: Date?
}

// MARK: - AccumulationBuffer line reading

extension AccumulationBuffer {
    mutating func consumeLine() -> [UInt8]? {
        let available = readableBytes
        guard available > 0 else { return nil }
        guard let bytes = peek(available) else { return nil }
        guard let nlIndex = bytes.firstIndex(of: UInt8(ascii: "\n")) else { return nil }
        let lineLen = bytes.distance(from: bytes.startIndex, to: nlIndex)
        let line = Array(bytes[..<nlIndex])
        _ = consume(lineLen + 1)
        compact()
        return line
    }
}
