import CryptoKit
import XCTest
@testable import PhoneKeyCore

// MARK: In-memory pipe

private enum PipeError: Error { case closed }

private actor PipeBuffer {
    private var buffer = Data()
    private var closed = false
    private var waiter: (count: Int, continuation: CheckedContinuation<Data, Error>)?

    func write(_ data: Data) throws {
        guard !closed else { throw PipeError.closed }
        buffer += data
        resume()
    }

    func read(_ count: Int) async throws -> Data {
        if buffer.count >= count { return take(count) }
        guard !closed else { throw PipeError.closed }
        return try await withCheckedThrowingContinuation { waiter = (count, $0) }
    }

    func close() {
        closed = true
        resume()
    }

    private func resume() {
        guard let w = waiter else { return }
        if buffer.count >= w.count {
            waiter = nil
            w.continuation.resume(returning: take(w.count))
        } else if closed {
            waiter = nil
            w.continuation.resume(throwing: PipeError.closed)
        }
    }

    private func take(_ count: Int) -> Data {
        let out = Data(buffer.prefix(count))
        buffer.removeFirst(count)
        return out
    }
}

private final class PipeEnd: ByteStream {
    let inbox: PipeBuffer
    let outbox: PipeBuffer

    init(inbox: PipeBuffer, outbox: PipeBuffer) {
        self.inbox = inbox
        self.outbox = outbox
    }

    func read(exactly count: Int) async throws -> Data { try await inbox.read(count) }
    func write(_ data: Data) async throws { try await outbox.write(data) }
    func close() {
        Task { [inbox, outbox] in
            await inbox.close()
            await outbox.close()
        }
    }

    static func pair() -> (PipeEnd, PipeEnd) {
        let a = PipeBuffer(), b = PipeBuffer()
        return (PipeEnd(inbox: a, outbox: b), PipeEnd(inbox: b, outbox: a))
    }
}

// MARK: Test doubles

private final class TestRegistry: HostRegistry {
    var paired: Set<Data> = []
    var invite: PairingInvite?

    func isPaired(hostKey: Data) -> Bool { paired.contains(hostKey) }
    func pendingInvite() -> PairingInvite? { invite }
    func completePairing(_ invite: PairingInvite) {
        paired.insert(invite.hostKey)
        self.invite = nil
    }
}

/// The host side, written straight from the spec.
private final class TestHost {
    let stream: PipeEnd
    let key = Curve25519.KeyAgreement.PrivateKey()
    private var ciphers: TransportCiphers?

    init(stream: PipeEnd) { self.stream = stream }

    var publicKey: Data { key.publicKey.rawRepresentation }

    func connect(mode: Wire.Mode, psk: Data? = nil) async throws -> Wire.PreambleStatus {
        let pre = Wire.hostPreamble(mode: mode)
        try await stream.write(pre)
        let answer = try await stream.read(exactly: Wire.preambleSize)
        let status = Wire.PreambleStatus(rawValue: Wire.parsePreamble(answer)!.value)!
        guard status == .ok else { return status }
        var hs = XXHandshake(initiator: true, staticKey: key, prologue: pre + answer, psk: psk)
        try await stream.write(Wire.frame(try hs.writeMessage()))
        _ = try hs.readMessage(try await readFrame())
        try await stream.write(Wire.frame(try hs.writeMessage()))
        ciphers = try hs.split()
        return status
    }

    func send(json: String) async throws {
        let ct = try ciphers!.send.encrypt(plaintext: Data([0x01]) + Data(json.utf8))
        try await stream.write(Wire.frame(ct))
    }

    func receive() async throws -> TransportMessage {
        try TransportMessage.decode(try ciphers!.receive.decrypt(ciphertext: try await readFrame()))
    }

    func receiveJSON() async throws -> [String: Any] {
        guard case let .json(_, _, body) = try await receive() else { throw PipeError.closed }
        return try JSONSerialization.jsonObject(with: body) as! [String: Any]
    }

    private func readFrame() async throws -> Data {
        let h = try await stream.read(exactly: 2)
        return try await stream.read(exactly: Int(h[h.startIndex]) << 8 | Int(h[h.startIndex + 1]))
    }
}

// MARK: Tests

final class PhoneSessionTests: XCTestCase {
    private let hello = HelloMessage.phone(appVersion: "test",
                                           device: .init(model: "iPhone9,3", system: "iOS 15.8", name: "Test"),
                                           features: ["status", "photo"])
    private let photo = Data((0..<130_000).map { UInt8($0 % 251) })

    private func handler(_ request: Request, _ session: PhoneSession) async throws {
        switch request.t {
        case "status.get":
            try await session.send(StatusMessage(id: request.id, battery: .init(level: 0.5, state: "charging"),
                                                 thermal: "nominal", deskMode: true, guidedAccess: false,
                                                 camera: .init(enabled: true, available: true)))
        case "photo.capture":
            try await session.send(PhotoBeginMessage(id: request.id, stream: 1, size: photo.count, width: 4, height: 3))
            var offset = 0
            while offset < photo.count {
                let end = min(offset + Wire.maxChunkData, photo.count)
                try await session.sendChunk(stream: 1, data: photo[offset..<end])
                offset = end
            }
            try await session.send(PhotoEndMessage(id: request.id, stream: 1, sha256: ""))
        default:
            throw ErrorMessage(id: request.id, code: .unknownType)
        }
    }

    private func start(_ registry: TestRegistry, busy: Bool = false, timeout: TimeInterval = 10)
        -> (TestHost, Task<Void, Error>, PhoneSession)
    {
        let (hostEnd, phoneEnd) = PipeEnd.pair()
        let session = PhoneSession(stream: phoneEnd, identity: .init(), registry: registry)
        let task = Task { [hello] in
            try await session.run(hello: hello, busy: busy, handshakeTimeout: timeout, handler: self.handler)
        }
        return (TestHost(stream: hostEnd), task, session)
    }

    func testPairingThenRequests() async throws {
        let registry = TestRegistry()
        let (host, task, session) = start(registry)
        var authenticated: Data?
        session.onAuthenticated = { authenticated = $0 }
        let psk = Data(repeating: 9, count: 32)
        registry.invite = PairingInvite(hostKey: host.publicKey, psk: psk, hostName: "test")

        let status = try await host.connect(mode: .pairing, psk: psk)
        XCTAssertEqual(status, .ok)
        let phoneHello = try await host.receiveJSON()
        XCTAssertEqual(phoneHello["role"] as? String, "phone")
        XCTAssertEqual(authenticated, host.publicKey)
        XCTAssertTrue(registry.paired.contains(host.publicKey))
        XCTAssertNil(registry.invite)
        XCTAssertEqual(session.mode, .pairing)

        try await host.send(json: #"{"t":"hello","role":"host","protocol":1,"app_version":"t"}"#)
        try await host.send(json: #"{"t":"ping","id":1}"#)
        let pong = try await host.receiveJSON()
        XCTAssertEqual(pong["t"] as? String, "pong")
        XCTAssertEqual(pong["id"] as? Int, 1)

        try await host.send(json: #"{"t":"status.get","id":2}"#)
        let st = try await host.receiveJSON()
        XCTAssertEqual(st["id"] as? Int, 2)
        XCTAssertEqual((st["battery"] as? [String: Any])?["state"] as? String, "charging")
        XCTAssertEqual(session.hostHello?.appVersion, "t")

        try await host.send(json: #"{"t":"photo.capture","id":3}"#)
        let begin = try await host.receiveJSON()
        XCTAssertEqual(begin["size"] as? Int, photo.count)
        var received = Data()
        while true {
            let m = try await host.receive()
            if case let .chunk(_, data) = m { received += data; continue }
            break
        }
        XCTAssertEqual(received, photo)

        try await host.send(json: #"{"t":"teleport","id":4}"#)
        let err = try await host.receiveJSON()
        XCTAssertEqual(err["code"] as? String, "unknown_type")
        XCTAssertEqual(err["id"] as? Int, 4)

        host.stream.close()
        _ = await task.result
    }

    func testUnpairedHostGetsNotPairedAndIsClosed() async throws {
        let (host, task, _) = start(TestRegistry())
        let status = try await host.connect(mode: .session)
        XCTAssertEqual(status, .ok)
        let err = try await host.receiveJSON()
        XCTAssertEqual(err["code"] as? String, "not_paired")
        let result = await task.result
        XCTAssertThrowsError(try result.get()) { XCTAssertEqual($0 as? SessionError, .unknownHost) }
    }

    func testPairingWithoutInviteIsRefused() async throws {
        let (host, task, _) = start(TestRegistry())
        let status = try await host.connect(mode: .pairing, psk: Data(count: 32))
        XCTAssertEqual(status, .noPairingPending)
        _ = await task.result
    }

    func testPairingWithWrongHostKeyFails() async throws {
        let registry = TestRegistry()
        let (host, task, _) = start(registry)
        let psk = Data(repeating: 3, count: 32)
        registry.invite = PairingInvite(hostKey: Data(repeating: 1, count: 32), psk: psk, hostName: "other")
        _ = try await host.connect(mode: .pairing, psk: psk)
        let result = await task.result
        XCTAssertThrowsError(try result.get()) { XCTAssertEqual($0 as? SessionError, .unknownHost) }
        XCTAssertTrue(registry.paired.isEmpty)
        XCTAssertNotNil(registry.invite, "a failed attempt must not consume the invite")
    }

    func testBusyIsRefused() async throws {
        let (host, task, _) = start(TestRegistry(), busy: true)
        let status = try await host.connect(mode: .session)
        XCTAssertEqual(status, .busy)
        _ = await task.result
    }

    func testHandshakeTimeout() async throws {
        let (host, task, _) = start(TestRegistry(), timeout: 0.2)
        try await host.stream.write(Wire.hostPreamble(mode: .session))
        _ = try await host.stream.read(exactly: Wire.preambleSize)
        let result = await task.result
        XCTAssertThrowsError(try result.get()) { XCTAssertEqual($0 as? SessionError, .handshakeTimeout) }
    }
}
