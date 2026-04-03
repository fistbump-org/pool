import Base
import Foundation
#if canImport(Network)
import Network
#endif
#if canImport(Glibc)
import Glibc
private let _SOCK_STREAM = Int32(SOCK_STREAM.rawValue)
private let _IPPROTO_TCP = Int32(IPPROTO_TCP)
#elseif canImport(Musl)
import Musl
private let _SOCK_STREAM = Int32(SOCK_STREAM.rawValue)
private let _IPPROTO_TCP = Int32(IPPROTO_TCP)
#else
private let _SOCK_STREAM = SOCK_STREAM
private let _IPPROTO_TCP = IPPROTO_TCP
#endif

/// Stratum v1 client for connecting to a mining pool.
final class StratumClient: @unchecked Sendable {
    private let host: String
    private let port: Int
    private let username: String
    private let password: String
    private let useTLS: Bool

    private var fd: Int32 = -1
    private let lock = NSLock()
    private var nextId: Int = 1
    private var readBuffer = [UInt8]()

    // State from pool
    var extraNonce1: [UInt8] = []
    var extraNonce2Size: Int = 12
    var currentJob: MinerJob?
    var difficulty: Double = 1.0
    var isSubscribed = false
    var isAuthorized = false

    // Callback for new jobs
    var onNewJob: ((MinerJob, Bool) -> Void)?
    var onNewDifficulty: ((Double) -> Void)?

    init(host: String, port: Int, username: String, password: String, tls: Bool = false) {
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.useTLS = tls
    }

    #if canImport(Network)
    private var nwConnection: NWConnection?
    #endif

    // MARK: - Connection

    func connect() throws {
        #if canImport(Network)
        if useTLS {
            try connectTLS()
            return
        }
        #endif
        let sock = socket(AF_INET, _SOCK_STREAM, _IPPROTO_TCP)
        guard sock >= 0 else {
            throw MinerError.connectionFailed("socket() failed")
        }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian

        guard let hostent = gethostbyname(host) else {
            close(sock)
            throw MinerError.connectionFailed("cannot resolve \(host)")
        }
        memcpy(&addr.sin_addr, hostent.pointee.h_addr_list[0]!, Int(hostent.pointee.h_length))

        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Foundation.connect(sock, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connectResult == 0 else {
            close(sock)
            throw MinerError.connectionFailed("connect() failed: errno \(errno)")
        }

        // Recv timeout (5 min — covers idle periods between jobs)
        var timeout = timeval(tv_sec: 300, tv_usec: 0)
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        // TCP keepalive
        var on: Int32 = 1
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &on, socklen_t(MemoryLayout<Int32>.size))
        // TCP nodelay
        setsockopt(sock, _IPPROTO_TCP, Int32(TCP_NODELAY), &on, socklen_t(MemoryLayout<Int32>.size))

        self.fd = sock
        self.readBuffer.removeAll()
    }

    func disconnect() {
        #if canImport(Network)
        nwConnection?.cancel()
        nwConnection = nil
        #endif
        if fd >= 0 {
            Foundation.shutdown(fd, Int32(SHUT_RDWR))
            close(fd)
            fd = -1
        }
        readBuffer.removeAll()
    }

    // MARK: - Protocol

    func subscribe() throws {
        let id = nextMessageId()
        send("{\"id\":\(id),\"method\":\"mining.subscribe\",\"params\":[]}\n")
        let response = try readResponse()

        // Parse: {"id":N,"result":[["mining.notify","1"],"extranonce1_hex",en2_size],"error":null}
        guard let result = response["result"] as? [Any],
              result.count >= 3,
              let en1Hex = result[1] as? String,
              let en2Size = result[2] as? Int else {
            throw MinerError.protocolError("invalid subscribe response")
        }

        self.extraNonce1 = (try? HexEncoding.decode(en1Hex)) ?? []
        self.extraNonce2Size = en2Size
        self.isSubscribed = true
    }

    func authorize() throws {
        let id = nextMessageId()
        send("{\"id\":\(id),\"method\":\"mining.authorize\",\"params\":[\"\(username)\",\"\(password)\"]}\n")
        let response = try readResponse()

        if let error = response["error"], !(error is NSNull) {
            let msg = (error as? String) ?? "\(error)"
            throw MinerError.protocolError("authorize failed: \(msg)")
        }

        self.isAuthorized = true
    }

    /// Submit a share to the pool.
    func submit(
        jobId: String,
        extraNonce2: [UInt8],
        nTime: UInt64,
        nonce: UInt32,
        proof: [UInt8]
    ) throws -> Bool {
        let id = nextMessageId()
        let en2Hex = HexEncoding.encode(extraNonce2)
        let timeHex = HexEncoding.encode(withUnsafeBytes(of: nTime.littleEndian) { Array($0) })
        let nonceHex = HexEncoding.encode(withUnsafeBytes(of: nonce.littleEndian) { Array($0) })
        let proofHex = HexEncoding.encode(proof)

        send("{\"id\":\(id),\"method\":\"mining.submit\",\"params\":[\"\(username)\",\"\(jobId)\",\"\(en2Hex)\",\"\(timeHex)\",\"\(nonceHex)\",\"\(proofHex)\"]}\n")

        let response = try readResponse()
        if let result = response["result"] as? Bool {
            if !result, let error = response["error"] {
                rejectReason = "\(error)"
            }
            return result
        }
        rejectReason = "no result in response"
        return false
    }

    /// Reason for last rejected share (for logging).
    var rejectReason: String?

    /// Read and process incoming messages (notifications + responses).
    /// Call this in a loop from the read thread.
    func processMessages() throws {
        let line = try readLine()
        guard !line.isEmpty,
              let json = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any] else {
            return
        }

        // Check if it's a notification (id is null)
        if let method = json["method"] as? String {
            let params = json["params"] as? [Any] ?? []
            switch method {
            case "mining.notify":
                handleNotify(params)
            case "mining.set_difficulty":
                handleSetDifficulty(params)
            default:
                break
            }
        }
    }

    // MARK: - Notification Handlers

    private func handleNotify(_ params: [Any]) {
        // [jobId, prevhash, merkleroot, witnessroot, treeroot, reservedroot,
        //  version, bits, time, poolExtraNonce, cleanJobs]
        guard params.count >= 11,
              let jobId = params[0] as? String,
              let prevHash = params[1] as? String,
              let merkleRoot = params[2] as? String,
              let witnessRoot = params[3] as? String,
              let treeRoot = params[4] as? String,
              let reservedRoot = params[5] as? String,
              let versionHex = params[6] as? String,
              let bitsHex = params[7] as? String,
              let timeHex = params[8] as? String,
              let poolENHex = params[9] as? String else {
            return
        }
        let clean = (params[10] as? Bool) ?? true

        let version = UInt32(versionHex, radix: 16) ?? 0
        let bits = UInt32(bitsHex, radix: 16) ?? 0
        let timeBytes = (try? HexEncoding.decode(timeHex)) ?? []
        let time: UInt64 = timeBytes.count == 8
            ? timeBytes.withUnsafeBytes { $0.load(as: UInt64.self) }
            : 0
        let poolExtraNonce = (try? HexEncoding.decode(poolENHex)) ?? []

        let job = MinerJob(
            id: jobId,
            prevHash: prevHash,
            merkleRoot: merkleRoot,
            witnessRoot: witnessRoot,
            treeRoot: treeRoot,
            reservedRoot: reservedRoot,
            version: version,
            bits: bits,
            time: time,
            poolExtraNonce: poolExtraNonce
        )

        lock.lock()
        currentJob = job
        lock.unlock()

        onNewJob?(job, clean)
    }

    private func handleSetDifficulty(_ params: [Any]) {
        guard let diff = params.first as? Double ?? (params.first as? Int).map(Double.init) else {
            return
        }
        lock.lock()
        difficulty = diff
        lock.unlock()

        onNewDifficulty?(diff)
    }

    // MARK: - I/O

    private func send(_ string: String) {
        #if canImport(Network)
        if useTLS { sendTLS(string); return }
        #endif
        let bytes = Array(string.utf8)
        var sent = 0
        bytes.withUnsafeBufferPointer { buf in
            while sent < bytes.count {
                let n = Foundation.send(fd, buf.baseAddress! + sent, bytes.count - sent, 0)
                if n <= 0 { return }
                sent += n
            }
        }
    }

    private let maxReadBuffer = 131072 // 128KB

    private func readLine() throws -> [UInt8] {
        #if canImport(Network)
        if useTLS { return try readLineTLS() }
        #endif
        while true {
            if let nlIdx = readBuffer.firstIndex(of: UInt8(ascii: "\n")) {
                let line = Array(readBuffer[..<nlIdx])
                readBuffer.removeFirst(nlIdx - readBuffer.startIndex + 1)
                return line
            }
            // Protect against unbounded buffer growth
            guard readBuffer.count < maxReadBuffer else {
                readBuffer.removeAll()
                throw MinerError.protocolError("read buffer overflow")
            }
            var buf = [UInt8](repeating: 0, count: 4096)
            let n = recv(fd, &buf, buf.count, 0)
            if n < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    throw MinerError.connectionFailed("read timeout")
                }
                throw MinerError.connectionFailed("recv failed: errno \(errno)")
            }
            if n == 0 {
                throw MinerError.connectionFailed("connection closed by pool")
            }
            readBuffer.append(contentsOf: buf[..<n])
        }
    }

    /// Read a single JSON-RPC response (blocking).
    private func readResponse() throws -> [String: Any] {
        let line = try readLine()
        guard let json = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any] else {
            throw MinerError.protocolError("invalid JSON response")
        }
        // Process any notifications that arrived before the response
        if json["method"] != nil {
            let params = json["params"] as? [Any] ?? []
            if let method = json["method"] as? String {
                switch method {
                case "mining.notify": handleNotify(params)
                case "mining.set_difficulty": handleSetDifficulty(params)
                default: break
                }
            }
            return try readResponse() // keep reading for the actual response
        }
        return json
    }

    private func nextMessageId() -> Int {
        lock.lock()
        defer { lock.unlock() }
        let id = nextId
        nextId += 1
        return id
    }

    // MARK: - TLS (Network framework)

    #if canImport(Network)
    private func connectTLS() throws {
        let tlsParams = NWProtocolTLS.Options()
        // Accept self-signed certs for pool connections
        sec_protocol_options_set_verify_block(
            tlsParams.securityProtocolOptions, { _, trust, completion in
                completion(true)
            }, .global(qos: .utility)
        )
        let params = NWParameters(tls: tlsParams, tcp: NWProtocolTCP.Options())
        let conn = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: UInt16(port))!,
            using: params
        )

        let semaphore = DispatchSemaphore(value: 0)
        var connectError: Error?

        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                semaphore.signal()
            case .failed(let error):
                connectError = error
                semaphore.signal()
            case .cancelled:
                connectError = MinerError.connectionFailed("cancelled")
                semaphore.signal()
            default:
                break
            }
        }

        conn.start(queue: .global(qos: .utility))
        _ = semaphore.wait(timeout: .now() + 30)

        if let error = connectError {
            conn.cancel()
            throw MinerError.connectionFailed("TLS connect failed: \(error)")
        }

        self.nwConnection = conn
        self.readBuffer.removeAll()
    }

    private func sendTLS(_ string: String) {
        guard let conn = nwConnection else { return }
        let data = Data(string.utf8)
        let semaphore = DispatchSemaphore(value: 0)
        conn.send(content: data, completion: .contentProcessed { _ in
            semaphore.signal()
        })
        _ = semaphore.wait(timeout: .now() + 10)
    }

    private func readLineTLS() throws -> [UInt8] {
        while true {
            if let nlIdx = readBuffer.firstIndex(of: UInt8(ascii: "\n")) {
                let line = Array(readBuffer[..<nlIdx])
                readBuffer.removeFirst(nlIdx - readBuffer.startIndex + 1)
                return line
            }
            guard readBuffer.count < maxReadBuffer else {
                readBuffer.removeAll()
                throw MinerError.protocolError("read buffer overflow")
            }
            guard let conn = nwConnection else {
                throw MinerError.connectionFailed("not connected")
            }
            let semaphore = DispatchSemaphore(value: 0)
            var recvData: Data?
            var recvError: Error?
            conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, error in
                recvData = data
                recvError = error
                semaphore.signal()
            }
            let result = semaphore.wait(timeout: .now() + 300)
            if result == .timedOut {
                throw MinerError.connectionFailed("TLS read timeout")
            }
            if let error = recvError {
                throw MinerError.connectionFailed("TLS recv: \(error)")
            }
            guard let data = recvData, !data.isEmpty else {
                throw MinerError.connectionFailed("TLS connection closed")
            }
            readBuffer.append(contentsOf: data)
        }
    }
    #endif
}

// MARK: - Types

struct MinerJob: Sendable {
    let id: String
    let prevHash: String
    let merkleRoot: String
    let witnessRoot: String
    let treeRoot: String
    let reservedRoot: String
    let version: UInt32
    let bits: UInt32
    let time: UInt64
    let poolExtraNonce: [UInt8]
}

enum MinerError: Error, CustomStringConvertible {
    case connectionFailed(String)
    case protocolError(String)

    var description: String {
        switch self {
        case .connectionFailed(let msg): return "Connection failed: \(msg)"
        case .protocolError(let msg): return "Protocol error: \(msg)"
        }
    }
}
