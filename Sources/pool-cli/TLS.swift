#if canImport(Network)
import Network
import Foundation
import Logging

/// TLS-enabled TCP listener using the Network framework.
///
/// Drop-in replacement for TCPListener when TLS is configured.
/// Requires a PKCS12 identity file (.p12) with the server certificate and key.
public final class TLSListener: @unchecked Sendable {
    private var listener: NWListener?
    private let logger: Logger
    public let port: Int

    /// Create a TLS listener.
    /// - Parameters:
    ///   - host: Listen host.
    ///   - port: Listen port.
    ///   - p12Path: Path to PKCS12 identity file.
    ///   - p12Password: Password for the PKCS12 file.
    public init(host: String, port: Int, p12Path: String, p12Password: String, logger: Logger) throws {
        self.port = port
        self.logger = logger

        let p12Data = try Data(contentsOf: URL(fileURLWithPath: p12Path))

        var importResult: CFArray?
        let options: [String: Any] = [kSecImportExportPassphrase as String: p12Password]
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &importResult)
        guard status == errSecSuccess,
              let items = importResult as? [[String: Any]],
              let first = items.first,
              let identity = first[kSecImportItemIdentity as String] else {
            throw TLSError.invalidCertificate("failed to import PKCS12: \(status)")
        }

        let secIdentity = identity as! SecIdentity

        let tlsOptions = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(
            tlsOptions.securityProtocolOptions,
            sec_identity_create(secIdentity)!
        )
        sec_protocol_options_set_min_tls_protocol_version(
            tlsOptions.securityProtocolOptions,
            .TLSv12
        )

        let params = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        if let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) {
            params.requiredLocalEndpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host), port: nwPort)
        }

        let nwListener = try NWListener(using: params)
        self.listener = nwListener
    }

    /// Accept connections, calling the handler for each.
    public func accept(handler: @escaping @Sendable (TLSStream, String, Int) async -> Void) {
        guard let listener = listener else { return }

        listener.newConnectionHandler = { connection in
            let stream = TLSStream(connection: connection)
            let endpoint = connection.endpoint
            let (ip, port) = Self.parseEndpoint(endpoint)
            connection.start(queue: .global(qos: .utility))
            Task { await handler(stream, ip, port) }
        }

        listener.stateUpdateHandler = { [logger] state in
            switch state {
            case .failed(let error):
                logger.error("TLS listener failed: \(error)", source: "TLS")
            default:
                break
            }
        }

        listener.start(queue: .global(qos: .utility))
    }

    public func shutdown() {
        listener?.cancel()
        listener = nil
    }

    private static func parseEndpoint(_ endpoint: NWEndpoint) -> (String, Int) {
        switch endpoint {
        case .hostPort(let host, let port):
            return ("\(host)", Int(port.rawValue))
        default:
            return ("unknown", 0)
        }
    }
}

/// TLS-wrapped connection stream.
public final class TLSStream: @unchecked Sendable {
    private let connection: NWConnection
    private var isClosed = false

    public let remoteAddress: String

    init(connection: NWConnection) {
        self.connection = connection
        if case .hostPort(let host, let port) = connection.endpoint {
            self.remoteAddress = "\(host):\(port)"
        } else {
            self.remoteAddress = "unknown"
        }
    }

    public func read(maxBytes: Int = 65536) async throws -> [UInt8] {
        try await withCheckedThrowingContinuation { cont in
            connection.receive(minimumIncompleteLength: 1, maximumLength: maxBytes) { data, _, _, error in
                if let error = error {
                    cont.resume(throwing: error)
                } else if let data = data, !data.isEmpty {
                    cont.resume(returning: Array(data))
                } else {
                    cont.resume(returning: [])
                }
            }
        }
    }

    public func write(_ data: [UInt8]) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, any Error>) in
            connection.send(content: Data(data), completion: .contentProcessed { error in
                if let error = error {
                    cont.resume(throwing: error)
                } else {
                    cont.resume()
                }
            })
        }
    }

    public func close() async {
        guard !isClosed else { return }
        isClosed = true
        connection.cancel()
    }
}

public enum TLSError: Error, CustomStringConvertible {
    case invalidCertificate(String)

    public var description: String {
        switch self {
        case .invalidCertificate(let msg): return "TLS error: \(msg)"
        }
    }
}

#endif
