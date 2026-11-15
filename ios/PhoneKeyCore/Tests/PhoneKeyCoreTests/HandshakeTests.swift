import CryptoKit
import XCTest
@testable import PhoneKeyCore

final class HandshakeTests: XCTestCase {
    private let prologue = Wire.hostPreamble(mode: .session) + Wire.phonePreamble(status: .ok)

    private func pair(hostPSK: Data? = nil, phonePSK: Data? = nil) -> (XXHandshake, XXHandshake) {
        (XXHandshake(initiator: true, staticKey: .init(), prologue: prologue, psk: hostPSK),
         XXHandshake(initiator: false, staticKey: .init(), prologue: prologue, psk: phonePSK))
    }

    func testTamperedMessageIsRejected() throws {
        var (host, phone) = pair()
        _ = try phone.readMessage(try host.writeMessage())
        var m2 = try phone.writeMessage()
        m2[m2.startIndex + 40] ^= 0x01 // inside the encrypted static key
        XCTAssertThrowsError(try host.readMessage(m2)) { XCTAssertEqual($0 as? NoiseError, .decryptFailed) }
    }

    func testMismatchedPSKFailsAtMessageThree() throws {
        let a = Data(repeating: 1, count: 32), b = Data(repeating: 2, count: 32)
        var (host, phone) = pair(hostPSK: a, phonePSK: b)
        // psk3 mixes the PSK in only with the last message, so messages 1 and
        // 2 succeed and the phone rejects message 3.
        _ = try phone.readMessage(try host.writeMessage())
        _ = try host.readMessage(try phone.writeMessage())
        let m3 = try host.writeMessage()
        XCTAssertThrowsError(try phone.readMessage(m3)) { XCTAssertEqual($0 as? NoiseError, .decryptFailed) }
    }

    func testDifferentProloguesFail() throws {
        var host = XXHandshake(initiator: true, staticKey: .init(), prologue: Data("a".utf8))
        var phone = XXHandshake(initiator: false, staticKey: .init(), prologue: Data("b".utf8))
        _ = try phone.readMessage(try host.writeMessage())
        XCTAssertThrowsError(try host.readMessage(try phone.writeMessage()))
    }

    func testOutOfTurnAndTruncated() throws {
        var (host, phone) = pair()
        XCTAssertThrowsError(try phone.writeMessage()) { XCTAssertEqual($0 as? NoiseError, .outOfTurn) }
        XCTAssertThrowsError(try host.readMessage(Data())) { XCTAssertEqual($0 as? NoiseError, .outOfTurn) }
        XCTAssertThrowsError(try phone.readMessage(Data(count: 10))) { XCTAssertEqual($0 as? NoiseError, .malformedMessage) }
        XCTAssertThrowsError(try host.split()) { XCTAssertEqual($0 as? NoiseError, .handshakeIncomplete) }
    }

    func testTransportRejectsReplay() throws {
        var (host, phone) = pair()
        _ = try phone.readMessage(try host.writeMessage())
        _ = try host.readMessage(try phone.writeMessage())
        _ = try phone.readMessage(try host.writeMessage())
        var h = try host.split(), p = try phone.split()
        let ct = try h.send.encrypt(plaintext: Data("one".utf8))
        XCTAssertEqual(try p.receive.decrypt(ciphertext: ct), Data("one".utf8))
        XCTAssertThrowsError(try p.receive.decrypt(ciphertext: ct)) { XCTAssertEqual($0 as? NoiseError, .decryptFailed) }
    }
}

final class WireTests: XCTestCase {
    func testPreambleAndFrame() {
        let pre = Wire.hostPreamble(mode: .pairing)
        XCTAssertEqual([UInt8](pre), [0x50, 0x48, 0x4b, 0x59, 1, 1, 0, 0])
        XCTAssertEqual(Wire.parsePreamble(pre)?.value, 1)
        XCTAssertNil(Wire.parsePreamble(Data("GET / HT".utf8)))
        XCTAssertEqual([UInt8](Wire.frame(Data(repeating: 7, count: 258)).prefix(2)), [0x01, 0x02])
    }

    func testTransportMessages() throws {
        let chunk = TransportMessage.encodeChunk(stream: 0x0102_0304, data: Data("x".utf8))
        XCTAssertEqual(try TransportMessage.decode(chunk), .chunk(stream: 0x0102_0304, data: Data("x".utf8)))
        let json = try TransportMessage.encodeJSON(PongMessage(id: 5))
        guard case let .json(type, id, _) = try TransportMessage.decode(json) else { return XCTFail() }
        XCTAssertEqual(type, "pong")
        XCTAssertEqual(id, 5)
        XCTAssertEqual(try TransportMessage.decode(Data([0x09, 1])), .unknown(kind: 9))
        XCTAssertThrowsError(try TransportMessage.decode(Data([0x02, 0, 1])))
    }

    func testStatusEncodesUnknownBatteryAsNull() throws {
        let status = StatusMessage(id: 1, battery: .init(level: nil, state: "unknown"), thermal: "nominal",
                                   deskMode: true, guidedAccess: false, camera: .init(enabled: false, available: true))
        let json = String(decoding: try JSONEncoder().encode(status), as: UTF8.self)
        XCTAssertTrue(json.contains("\"level\":null"), json)
        XCTAssertTrue(json.contains("\"desk_mode\":true"), json)
    }
}

final class PairingInviteTests: XCTestCase {
    func testParsesGoStyleURL() throws {
        let key = Data(repeating: 0xfe, count: 32), psk = Data(repeating: 0x01, count: 32)
        // Built like linux/internal/pairing: everything but unreserved is %XX.
        let url = URL(string: "phonekey://pair?v=1&k=\(key.base64URLEncodedString)&s=\(psk.base64URLEncodedString)"
            + "&n=Geralds%20Rechner%20%26%20Co%2B1%20%C3%A4")!
        let invite = try PairingInvite(url: url)
        XCTAssertEqual(invite, PairingInvite(hostKey: key, psk: psk, hostName: "Geralds Rechner & Co+1 ä"))
    }

    func testRejects() {
        let ok = Data(count: 32).base64URLEncodedString
        let cases: [(String, PairingInvite.ParseError)] = [
            ("https://pair?v=1", .notAPairingURL),
            ("phonekey://pair?v=2&k=\(ok)&s=\(ok)", .unsupportedVersion),
            ("phonekey://pair?v=1&k=AAAA&s=\(ok)", .badHostKey),
            ("phonekey://pair?v=1&k=\(ok)&s=", .badSecret),
        ]
        for (s, want) in cases {
            XCTAssertThrowsError(try PairingInvite(url: URL(string: s)!), s) {
                XCTAssertEqual($0 as? PairingInvite.ParseError, want, s)
            }
        }
    }
}
