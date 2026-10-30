import CryptoKit
import Foundation
import Network
import os
import PhoneKeyCore

/// Listens on 127.0.0.1:20555 (usbmuxd delivers USB connections there) and
/// runs a PhoneSession per connection. Only runs while the app is in front.
/// Sendable because `listener` is only touched on the main thread and
/// `connections` only on `queue`.
final class PhoneServer: ObservableObject, @unchecked Sendable {
    enum State: Equatable {
        case stopped
        case listening
        case failed(String)
    }

    static let maxConnections = 4

    @Published private(set) var state: State = .stopped
    /// Keys of authenticated hosts, once per open connection.
    @Published private(set) var connectedHosts: [Data] = []

    private let identity: Curve25519.KeyAgreement.PrivateKey
    private let registry: HostRegistry
    private let hello: HelloMessage
    private let handler: PhoneSession.Handler
    private let queue = DispatchQueue(label: "net.geraldhofbauer.phonekey.server")
    private let log = Logger(subsystem: "net.geraldhofbauer.phonekey", category: "server")

    // Main thread only.
    private var listener: NWListener?
    private var wantsRunning = false
    // `queue` only.
    private var connections: [ObjectIdentifier: NWConnection] = [:]

    init(identity: Curve25519.KeyAgreement.PrivateKey, registry: HostRegistry, hello: HelloMessage,
         handler: @escaping PhoneSession.Handler) {
        self.identity = identity
        self.registry = registry
        self.hello = hello
        self.handler = handler
    }

    func start() {
        wantsRunning = true
        guard listener == nil else { return }
        do {
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: Wire.port)!)
            let listener = try NWListener(using: params)
            listener.stateUpdateHandler = { [weak self, weak listener] state in
                DispatchQueue.main.async { self?.listenerChanged(state, listener) }
            }
            listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
            listener.start(queue: queue)
            self.listener = listener
        } catch {
            log.error("Listener failed: \(String(describing: error), privacy: .public)")
            state = .failed(error.localizedDescription)
            retryLater()
        }
    }

    func stop() {
        wantsRunning = false
        listener?.cancel()
        listener = nil
        state = .stopped
        connectedHosts = []
        queue.async {
            self.connections.values.forEach { $0.cancel() }
            self.connections.removeAll()
        }
    }

    private func listenerChanged(_ newState: NWListener.State, _ source: NWListener?) {
        guard let source, source === listener else { return }
        switch newState {
        case .ready:
            log.info("Listening on 127.0.0.1:\(Wire.port)")
            state = .listening
        case let .failed(error):
            log.error("Listener failed: \(String(describing: error), privacy: .public)")
            state = .failed(error.localizedDescription)
            source.cancel()
            listener = nil
            retryLater()
        default:
            break
        }
    }

    private func retryLater() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self, self.wantsRunning, self.listener == nil else { return }
            self.start()
        }
    }

    // Runs on `queue`.
    private func accept(_ connection: NWConnection) {
        let id = ObjectIdentifier(connection)
        let busy = connections.count >= Self.maxConnections
        connections[id] = connection
        connection.start(queue: queue)

        let session = PhoneSession(stream: NWByteStream(connection), identity: identity, registry: registry)
        var authenticatedKey: Data?
        session.onAuthenticated = { [weak self] key in
            authenticatedKey = key
            DispatchQueue.main.async { self?.connectedHosts.append(key) }
        }
        Task { [hello, handler, log] in
            do {
                try await session.run(hello: hello, busy: busy, handler: handler)
            } catch {
                log.info("Connection ended: \(String(describing: error), privacy: .public)")
            }
            self.queue.async { self.connections[id] = nil }
            DispatchQueue.main.async {
                if let key = authenticatedKey, let i = self.connectedHosts.firstIndex(of: key) {
                    self.connectedHosts.remove(at: i)
                }
            }
        }
    }
}

/// ByteStream over an NWConnection.
final class NWByteStream: ByteStream {
    struct Closed: Error {}

    private let connection: NWConnection

    init(_ connection: NWConnection) {
        self.connection = connection
    }

    func read(exactly count: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let data, data.count == count {
                    continuation.resume(returning: data)
                } else {
                    continuation.resume(throwing: Closed())
                }
            }
        }
    }

    func write(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    func close() {
        connection.cancel()
    }
}
