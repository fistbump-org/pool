import Base
import CBalloon
import Consensus
import ExtCrypto
import Foundation
import Logging
import Protocol

/// Multi-threaded BalloonHash mining engine for Stratum pool mining.
///
/// Optimizations over the baseline implementation:
/// - Pre-computes the password hash once per job (not per nonce)
/// - Reuses 512 MB scratchpad buffers across nonce iterations (no alloc/dealloc/zeroing per hash)
/// - Randomizes extraNonce2 to avoid duplicate work with other miners on the same pool
/// - Submits shares asynchronously so mining threads are never blocked on I/O
/// - Non-clean jobs picked up between hashes (no thread restart, no wasted work)
final class MiningEngine: @unchecked Sendable {
    private let client: StratumClient
    private let params: ConsensusParams
    private let threads: Int
    private let logger: Logger

    private let lock = NSLock()
    private var currentResult: MiningResult?
    private var activeBuffers: [MiningBuffer] = []
    private var accepted: Int = 0
    private var rejected: Int = 0

    /// Semaphore limiting concurrent proof generations (each allocates 1 GB).
    /// Value of 1 also serializes client.submit() calls (socket is not thread-safe).
    private let proofSemaphore = DispatchSemaphore(value: 1)
    private var blocks: Int = 0
    private var totalHashes: UInt64 = 0
    private var miningStartTime: Date?

    /// Buffer pool — survives across job changes so threads reuse 512 MB allocations.
    private let bufferPool: BufferPool

    /// Prepared job data that threads pick up between hash iterations.
    /// Protected by `lock`. Updated on non-clean jobs without restarting threads.
    private var preparedJob: PreparedJob?
    /// Incremented every time preparedJob changes. Threads compare against their
    /// local copy to know when to switch.
    private var jobGeneration: UInt64 = 0

    /// Logical CPU IDs — one representative per physical core — for pinning.
    /// Empty on non-Linux. Threads pick a CPU by `tid % coreIds.count`.
    private let coreIds: [Int32]

    init(client: StratumClient, network: NetworkType, threads: Int, logger: Logger) {
        self.client = client
        self.params = ConsensusParams.params(for: network)
        // Default to one thread per *physical* core. BalloonHash is memory-bound,
        // so SMT siblings on the same core thrash L1/L2 and slow each other down.
        let physicalCores = max(1, Int(balloon_physical_core_count()))
        self.threads = threads > 0 ? threads : physicalCores
        self.logger = logger
        // Enumerate representative CPU IDs (one per physical core) for pinning.
        var ids = [Int32](repeating: 0, count: physicalCores)
        let n = ids.withUnsafeMutableBufferPointer { buf in
            Int(balloon_physical_core_cpu_ids(buf.baseAddress, Int32(physicalCores)))
        }
        self.coreIds = Array(ids.prefix(n))
        // Cap pooled buffers low — each is 512 MB. Threads allocate on demand if pool is empty.
        // The allocation cost is negligible vs the 10s BalloonHash computation.
        self.bufferPool = BufferPool(slots: ConsensusParams.params(for: network).balloonSlots, maxPooled: 4)
    }

    /// Update the share target when pool changes difficulty mid-job.
    func updateDifficulty(_ diff: Double) {
        let newTarget = targetForDifficulty(diff)
        lock.lock()
        if var job = preparedJob {
            job = PreparedJob(
                job: job.job, password: job.password,
                prevBlock: job.prevBlock, merkleRoot: job.merkleRoot,
                witnessRoot: job.witnessRoot, treeRoot: job.treeRoot,
                reservedRoot: job.reservedRoot,
                shareTarget: newTarget, networkTarget: job.networkTarget,
                extraNonce1: job.extraNonce1, en2Size: job.en2Size
            )
            preparedJob = job
            jobGeneration &+= 1
        }
        lock.unlock()
    }

    /// Start or update mining on a job.
    ///
    /// - `clean=true`: new block — hard restart all threads immediately.
    /// - `clean=false`: new transactions — threads pick up new job after current hash finishes.
    func mine(job: MinerJob, clean: Bool = true) {
        let extraNonce1 = client.extraNonce1
        let en2Size = client.extraNonce2Size
        let difficulty = client.difficulty

        // Parse header fields
        let prevBlock = (try? Hash256.fromHex(job.prevHash)) ?? .zero
        let merkleRoot = (try? Hash256.fromHex(job.merkleRoot)) ?? .zero
        let witnessRoot = (try? Hash256.fromHex(job.witnessRoot)) ?? .zero
        let treeRoot = (try? Hash256.fromHex(job.treeRoot)) ?? .zero
        let reservedRoot = (try? Hash256.fromHex(job.reservedRoot)) ?? .zero

        // Pre-compute the password hash for this job.
        let password: [UInt8]
        do {
            var pw = [UInt8]()
            pw.reserveCapacity(176)
            pw.append(contentsOf: prevBlock.bytes)
            pw.append(contentsOf: merkleRoot.bytes)
            pw.append(contentsOf: witnessRoot.bytes)
            pw.append(contentsOf: treeRoot.bytes)
            pw.append(contentsOf: reservedRoot.bytes)
            var time = job.time.littleEndian
            pw.append(contentsOf: withUnsafeBytes(of: &time) { Array($0) })
            var bits = job.bits.littleEndian
            pw.append(contentsOf: withUnsafeBytes(of: &bits) { Array($0) })
            var version = job.version.littleEndian
            pw.append(contentsOf: withUnsafeBytes(of: &version) { Array($0) })
            password = try Blake2bHash.hash(pw, size: 32)
        } catch {
            logger.error("Failed to hash password: \(error)", source: "Miner")
            return
        }

        let shareTarget = targetForDifficulty(difficulty)
        let networkTarget = Target256.fromCompact(job.bits)

        let prepared = PreparedJob(
            job: job,
            password: password,
            prevBlock: prevBlock,
            merkleRoot: merkleRoot,
            witnessRoot: witnessRoot,
            treeRoot: treeRoot,
            reservedRoot: reservedRoot,
            shareTarget: shareTarget,
            networkTarget: networkTarget,
            extraNonce1: extraNonce1,
            en2Size: en2Size
        )

        lock.lock()
        preparedJob = prepared
        jobGeneration &+= 1
        let needsRestart = clean || currentResult == nil
        if needsRestart {
            // Signal all in-flight C BalloonHash calls to bail out immediately
            // (~40ms worst case via the periodic cancelled flag check in the C loop).
            for buf in activeBuffers {
                buf.cancelled = 1
            }
            currentResult?.stop()
        }
        let result: MiningResult
        if needsRestart {
            result = MiningResult()
            currentResult = result
        } else {
            result = currentResult!
        }
        if miningStartTime == nil { miningStartTime = Date() }
        let gen = jobGeneration
        lock.unlock()

        guard needsRestart else {
            // Non-clean: threads will pick up the new preparedJob after their current hash
            logger.debug("Queued non-clean job \(job.id) (gen \(gen))", source: "Miner")
            return
        }

        let threadCount = self.threads
        let logger = self.logger
        let params = self.params
        let client = self.client
        let slots = params.balloonSlots
        let rounds = params.balloonRounds
        let delta = params.balloonDelta

        logger.info("Mining job \(job.id) (clean restart)", metadata: [
            "bits": "\(String(format: "0x%08x", job.bits))",
            "share_diff": "\(String(format: "%.4f", difficulty))",
            "threads": "\(threadCount)",
        ], source: "Miner")

        let coreIds = self.coreIds

        for tid in 0..<threadCount {
            let bufferPool = self.bufferPool
            let proofSemaphore = self.proofSemaphore
            // Pick this thread's CPU; wraps if threadCount > physical cores.
            let pinCpu: Int32? = coreIds.isEmpty
                ? nil : coreIds[tid % coreIds.count]

            Thread.detachNewThread { [weak self] in
                // Pin BEFORE allocating the scratchpad — first-touch lands pages on
                // the local NUMA node, which is the cheap path to NUMA locality on
                // multi-socket boxes (no libnuma dependency).
                if let pinCpu {
                    _ = balloon_pin_current_thread(pinCpu)
                }

                let buffer = bufferPool.checkout()
                self?.lock.lock()
                self?.activeBuffers.append(buffer)
                self?.lock.unlock()
                defer {
                    self?.lock.lock()
                    self?.activeBuffers.removeAll { $0 === buffer }
                    self?.lock.unlock()
                    bufferPool.checkin(buffer)
                }

                // Build randomized extraNonce2
                var extraNonce2 = [UInt8](repeating: 0, count: prepared.en2Size)
                extraNonce2[0] = UInt8(tid & 0xFF)
                extraNonce2[1] = UInt8((tid >> 8) & 0xFF)
                if prepared.en2Size > 2 {
                    for i in 2..<prepared.en2Size {
                        extraNonce2[i] = UInt8.random(in: 0...255)
                    }
                }

                var nonce = UInt32(tid)
                let stride = UInt32(threadCount)

                // Current job state (updated when generation changes)
                var curJob = prepared
                var curGen = gen
                var curExtraNonce = Self.buildExtraNonce(job: curJob, extraNonce2: extraNonce2)
                var salt = Self.buildSaltTemplate(extraNonce: curExtraNonce)
                var curPassword = curJob.password
                var curShareTarget = curJob.shareTarget
                var curNetworkTarget = curJob.networkTarget

                while !result.shouldStop {
                    // Check for non-clean job update between hash iterations
                    self?.lock.lock()
                    let latestGen = self?.jobGeneration ?? curGen
                    let latestJob = self?.preparedJob
                    self?.lock.unlock()

                    if latestGen != curGen, let latestJob {
                        curJob = latestJob
                        curGen = latestGen
                        curExtraNonce = Self.buildExtraNonce(job: curJob, extraNonce2: extraNonce2)
                        salt = Self.buildSaltTemplate(extraNonce: curExtraNonce)
                        curPassword = curJob.password
                        curShareTarget = curJob.shareTarget
                        curNetworkTarget = curJob.networkTarget
                        nonce = UInt32(tid)
                    }

                    buffer.cancelled = result.shouldStop ? 1 : 0

                    // Update nonce in salt (first 4 bytes, little-endian)
                    salt[0] = UInt8(truncatingIfNeeded: nonce)
                    salt[1] = UInt8(truncatingIfNeeded: nonce &>> 8)
                    salt[2] = UInt8(truncatingIfNeeded: nonce &>> 16)
                    salt[3] = UInt8(truncatingIfNeeded: nonce &>> 24)

                    let hashBytes: [UInt8]
                    do {
                        hashBytes = try FastBalloonHash.hash(
                            password: curPassword,
                            salt: salt,
                            buffer: buffer,
                            slots: slots,
                            rounds: rounds,
                            delta: delta,
                            isCancelled: { result.shouldStop }
                        )
                    } catch is FastBalloonHash.Cancelled {
                        break
                    } catch {
                        logger.error("Thread \(tid) error: \(error)", source: "Miner")
                        return
                    }
                    self?.addHashes(1)

                    let hashTarget = Target256(bigEndian: hashBytes)

                    if hashTarget <= curShareTarget {
                        let isBlock = hashTarget <= curNetworkTarget
                        let capturedNonce = nonce
                        // Limit concurrent proof generations to cap memory (each allocates 1 GB).
                        // Also serializes client.submit() (socket is not thread-safe).
                        // For block solutions: always wait (never lose a block).
                        // For regular shares: skip if busy (more will come).
                        if isBlock {
                            proofSemaphore.wait()
                        } else {
                            guard proofSemaphore.wait(timeout: .now()) == .success else {
                                let (next, overflow) = nonce.addingReportingOverflow(stride)
                                if overflow { break }
                                nonce = next
                                continue
                            }
                        }
                        defer { proofSemaphore.signal() }

                        // Bail out if engine was stopped while we waited for the
                        // semaphore — submitting now would send a stale job ID
                        // over a reconnected socket.
                        guard !result.shouldStop else { break }

                        let header = BlockHeader(
                            nonce: capturedNonce,
                            time: curJob.job.time,
                            prevBlock: curJob.prevBlock,
                            treeRoot: curJob.treeRoot,
                            extraNonce: curExtraNonce,
                            reservedRoot: curJob.reservedRoot,
                            witnessRoot: curJob.witnessRoot,
                            merkleRoot: curJob.merkleRoot,
                            version: curJob.job.version,
                            bits: curJob.job.bits
                        )

                        do {
                            let (_, proof) = try ProofOfWork.powHashWithProof(
                                for: header, params: params
                            )
                            let proofBytes = proof.serialize()

                            let accepted = try client.submit(
                                jobId: curJob.job.id,
                                extraNonce2: extraNonce2,
                                nTime: curJob.job.time,
                                nonce: capturedNonce,
                                proof: proofBytes
                            )

                            if accepted {
                                self?.recordAccepted()
                                if isBlock {
                                    self?.recordBlock()
                                    logger.info("Block found! nonce=\(capturedNonce)", source: "Miner")
                                } else {
                                    logger.info("Share accepted", metadata: [
                                        "nonce": "\(capturedNonce)",
                                        "thread": "\(tid)",
                                    ], source: "Miner")
                                }
                            } else {
                                self?.recordRejected()
                                let reason = client.rejectReason ?? "unknown"
                                logger.warning("Share rejected: \(reason)", source: "Miner")
                            }
                        } catch {
                            logger.error("Submit error: \(error)", source: "Miner")
                        }
                    }

                    let (next, overflow) = nonce.addingReportingOverflow(stride)
                    if overflow { break }
                    nonce = next
                }
            }
        }
    }

    /// Stop all mining threads.
    func stop() {
        lock.lock()
        for buf in activeBuffers {
            buf.cancelled = 1
        }
        currentResult?.stop()
        lock.unlock()
    }

    /// Get current mining stats.
    var stats: (accepted: Int, rejected: Int, blocks: Int, hashrate: Double) {
        lock.lock()
        defer { lock.unlock() }
        let elapsed = miningStartTime.map { Date().timeIntervalSince($0) } ?? 1
        let hr = elapsed > 0 ? Double(totalHashes) / elapsed : 0
        return (accepted, rejected, blocks, hr)
    }

    // MARK: - Private Helpers

    private static func buildExtraNonce(job: PreparedJob, extraNonce2: [UInt8]) -> [UInt8] {
        var en = job.job.poolExtraNonce
        en.append(contentsOf: job.extraNonce1)
        en.append(contentsOf: extraNonce2)
        if en.count < 24 {
            en.append(contentsOf: [UInt8](repeating: 0, count: 24 - en.count))
        }
        return en
    }

    private static func buildSaltTemplate(extraNonce: [UInt8]) -> [UInt8] {
        var salt = [UInt8](repeating: 0, count: 28)
        for i in 0..<min(extraNonce.count, 24) {
            salt[i + 4] = extraNonce[i]
        }
        return salt
    }

    private func recordAccepted() {
        lock.lock()
        accepted += 1
        lock.unlock()
    }

    private func recordRejected() {
        lock.lock()
        rejected += 1
        lock.unlock()
    }

    private func recordBlock() {
        lock.lock()
        blocks += 1
        lock.unlock()
    }

    private func addHashes(_ count: UInt64) {
        lock.lock()
        totalHashes += count
        lock.unlock()
    }

    /// Convert a difficulty value to a 256-bit target.
    private func targetForDifficulty(_ diff: Double) -> Target256 {
        guard diff > 0 else { return params.powLimit }
        if diff <= 1.0 { return params.powLimit }
        let limitBytes = params.powLimit.bigEndianBytes()
        var value = 0.0
        for b in limitBytes {
            value = value * 256.0 + Double(b)
        }
        value /= diff
        var result = [UInt8](repeating: 0, count: 32)
        var remaining = value
        for i in Swift.stride(from: 31, through: 0, by: -1) {
            result[i] = UInt8(remaining.truncatingRemainder(dividingBy: 256))
            remaining = (remaining / 256).rounded(.down)
        }
        return Target256(bigEndian: result)
    }
}

// MARK: - Prepared Job (pre-computed, shared across threads)

private struct PreparedJob: @unchecked Sendable {
    let job: MinerJob
    let password: [UInt8]         // Pre-hashed BLAKE2b-256 of header fields
    let prevBlock: Hash256
    let merkleRoot: Hash256
    let witnessRoot: Hash256
    let treeRoot: Hash256
    let reservedRoot: Hash256
    let shareTarget: Target256
    let networkTarget: Target256
    let extraNonce1: [UInt8]
    let en2Size: Int
}

// MARK: - Mining Result (thread coordination)

private final class MiningResult: @unchecked Sendable {
    private let lock = NSLock()
    private var _stopped = false

    func stop() {
        lock.lock()
        _stopped = true
        lock.unlock()
    }

    var shouldStop: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _stopped
    }
}
