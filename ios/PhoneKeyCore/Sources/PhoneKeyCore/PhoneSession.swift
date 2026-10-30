import CryptoKit
import Foundation

/// A bidirectional byte stream, e.g. a TCP connection.
public protocol ByteStream: AnyObject {
    /// Returns exactly `count` bytes or throws (also when the stream closes).
    func read(exactly count: Int) async throws -> Data
    func write(_ data: Data) async throws
    func close()
}

/// What the phone knows about hosts.
public protocol HostRegistry: AnyObject {
    func isPaired(hostKey: Data) -> Bool
    /// The invite the user confirmed and that has not expired yet.
    func pendingInvite() -> PairingInvite?
    func completePairing(_ invite: PairingInvite)
}

public enum SessionError: Error, Equatable {
    case notAPhonekeyClient
    case refused(Wire.PreambleStatus)
    case unknownHost
    case handshakeTimeout
}

/// The phone (responder) side of one connection: preamble, handshake, host
/// check, hello, then requests until the stream ends.
public final class PhoneSession {
    public typealias Handler = (Request, PhoneSession) async throws -> Void

    private let stream: ByteStream
    private let identity: Curve25519.KeyAgreement.PrivateKey
    private let registry: HostRegistry
    private var ciphers: TransportCiphers?

    public private(set) var mode: Wire.Mode?
    public private(set) var hostKey: Data?
    public private(set) var hostHello: HelloMessage?
    /// Called with the host key once the host is authenticated.
    public var onAuthenticated: ((Data) -> Void)?

    public init(stream: ByteStream, identity: Curve25519.KeyAgreement.PrivateKey, registry: HostRegistry) {
        self.stream = stream
        self.identity = identity
        self.registry = registry
    }

    /// Runs the connection to its end. `busy` answers the preamble with
    /// status busy and closes. Errors from `handler` that are ErrorMessage are
    /// sent to the host; others end the session.
    public func run(
        hello: HelloMessage,
        busy: Bool = false,
        handshakeTimeout: TimeInterval = 10,
        handler: @escaping Handler
    ) async throws {
        defer { stream.close() }
        let invite = try await negotiate(busy: busy)

        let expired = Flag()
        let timeout = Task { [stream] in
            try await Task.sleep(nanoseconds: UInt64(handshakeTimeout * 1_000_000_000))
            expired.set()
            stream.close()
        }
        let remoteKey: Data
        do {
            remoteKey = try await handshake(psk: invite?.psk)
            timeout.cancel()
        } catch {
            timeout.cancel()
            throw expired.isSet ? SessionError.handshakeTimeout : error
        }

        if let invite {
            guard remoteKey == invite.hostKey else { throw SessionError.unknownHost }
            registry.completePairing(invite)
        } else if !registry.isPaired(hostKey: remoteKey) {
            try? await send(ErrorMessage(id: nil, code: .notPaired, message: "This computer is not paired with PhoneKey."))
            throw SessionError.unknownHost
        }
        hostKey = remoteKey
        onAuthenticated?(remoteKey)
        try await send(hello)

        while true {
            guard case let .json(type, id, body) = try await receive() else { continue }
            if type == "hello" {
                hostHello = try? JSONDecoder().decode(HelloMessage.self, from: body)
                continue
            }
            guard let request = try? JSONDecoder().decode(Request.self, from: body) else {
                try await send(ErrorMessage(id: id, code: .badRequest))
                continue
            }
            if type == "ping" {
                try await send(PongMessage(id: id))
                continue
            }
            do {
                try await handler(request, self)
            } catch let error as ErrorMessage {
                try await send(error)
            }
        }
    }

    // MARK: Sending (for handlers)

    public func send<T: Encodable>(_ message: T) async throws {
        try await writeTransport(try TransportMessage.encodeJSON(message))
    }

    public func sendChunk(stream id: UInt32, data: Data) async throws {
        try await writeTransport(TransportMessage.encodeChunk(stream: id, data: data))
    }

    // MARK: Internals

    /// Reads the host preamble and answers it. Returns the pending invite in
    /// pairing mode.
    private func negotiate(busy: Bool) async throws -> PairingInvite? {
        let pre = try await stream.read(exactly: Wire.preambleSize)
        guard let (version, modeByte) = Wire.parsePreamble(pre) else { throw SessionError.notAPhonekeyClient }
        let mode = Wire.Mode(rawValue: modeByte)
        var invite: PairingInvite?
        let status: Wire.PreambleStatus
        if version != Wire.version {
            status = .unsupportedVersion
        } else if mode == nil {
            status = .unknownMode
        } else if busy {
            status = .busy
        } else if mode == .pairing {
            invite = registry.pendingInvite()
            status = invite == nil ? .noPairingPending : .ok
        } else {
            status = .ok
        }
        let answer = Wire.phonePreamble(status: status)
        try await stream.write(answer)
        guard status == .ok else { throw SessionError.refused(status) }
        self.mode = mode
        prologue = pre + answer
        return invite
    }

    private var prologue = Data()

    private func handshake(psk: Data?) async throws -> Data {
        var hs = XXHandshake(initiator: false, staticKey: identity, prologue: prologue, psk: psk)
        _ = try hs.readMessage(try await readFrame())
        try await stream.write(Wire.frame(try hs.writeMessage()))
        _ = try hs.readMessage(try await readFrame())
        ciphers = try hs.split()
        guard let remote = hs.remoteStatic else { throw NoiseError.handshakeIncomplete }
        return remote
    }

    private func readFrame() async throws -> Data {
        let header = try await stream.read(exactly: 2)
        let length = Int(header[header.startIndex]) << 8 | Int(header[header.startIndex + 1])
        guard length > 0 else { throw NoiseError.malformedMessage }
        return try await stream.read(exactly: length)
    }

    private func receive() async throws -> TransportMessage {
        let frame = try await readFrame()
        guard ciphers != nil else { throw NoiseError.handshakeIncomplete }
        return try TransportMessage.decode(try ciphers!.receive.decrypt(ciphertext: frame))
    }

    private func writeTransport(_ plaintext: Data) async throws {
        guard ciphers != nil else { throw NoiseError.handshakeIncomplete }
        let ciphertext = try ciphers!.send.encrypt(plaintext: plaintext)
        try await stream.write(Wire.frame(ciphertext))
    }
}

/// A thread-safe one-way flag.
private final class Flag {
    private let lock = NSLock()
    private var value = false

    var isSet: Bool {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func set() {
        lock.lock()
        value = true
        lock.unlock()
    }
}
