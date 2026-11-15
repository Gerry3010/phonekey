import CryptoKit
import XCTest
@testable import PhoneKeyCore

/// Checks the Swift Noise implementation against docs/protocol-vectors.json,
/// which the Go side (flynn/noise) generates. Passing means both sides
/// interoperate byte for byte.
final class VectorTests: XCTestCase {
    struct VectorFile: Decodable {
        let vectors: [Vector]
    }

    struct Vector: Decodable {
        let name: String
        let protocol_name: String
        let prologue: String
        let host_static_private: String
        let host_static_public: String
        let host_ephemeral_private: String
        let phone_static_private: String
        let phone_static_public: String
        let phone_ephemeral_private: String
        let psk: String?
        let handshake_messages: [String]
        let handshake_hash: String
        let transport_messages: [Transport]
    }

    struct Transport: Decodable {
        let from: String
        let plaintext: String
        let ciphertext: String
    }

    static func loadVectors() throws -> [Vector] {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("docs/protocol-vectors.json"))
        return try JSONDecoder().decode(VectorFile.self, from: data).vectors
    }

    func testVectors() throws {
        let vectors = try Self.loadVectors()
        XCTAssertEqual(vectors.map(\.name), ["session", "pairing"])
        for v in vectors {
            try check(v)
        }
    }

    private func check(_ v: Vector) throws {
        let pairing = v.psk != nil
        XCTAssertEqual(XXHandshake.protocolName(pairing: pairing), v.protocol_name, v.name)
        let mode: Wire.Mode = pairing ? .pairing : .session
        XCTAssertEqual(Wire.hostPreamble(mode: mode) + Wire.phonePreamble(status: .ok), hex(v.prologue), v.name)

        let hostStatic = try key(v.host_static_private)
        let phoneStatic = try key(v.phone_static_private)
        XCTAssertEqual(hostStatic.publicKey.rawRepresentation, hex(v.host_static_public), "\(v.name): host public key")
        XCTAssertEqual(phoneStatic.publicKey.rawRepresentation, hex(v.phone_static_public), "\(v.name): phone public key")

        let psk = v.psk.map(hex)
        var host = XXHandshake(initiator: true, staticKey: hostStatic, prologue: hex(v.prologue), psk: psk,
                               ephemeral: try key(v.host_ephemeral_private))
        var phone = XXHandshake(initiator: false, staticKey: phoneStatic, prologue: hex(v.prologue), psk: psk,
                                ephemeral: try key(v.phone_ephemeral_private))

        let m1 = try host.writeMessage()
        XCTAssertEqual(m1, hex(v.handshake_messages[0]), "\(v.name): message 1")
        XCTAssertEqual(try phone.readMessage(m1), Data())
        let m2 = try phone.writeMessage()
        XCTAssertEqual(m2, hex(v.handshake_messages[1]), "\(v.name): message 2")
        XCTAssertEqual(try host.readMessage(m2), Data())
        let m3 = try host.writeMessage()
        XCTAssertEqual(m3, hex(v.handshake_messages[2]), "\(v.name): message 3")
        XCTAssertEqual(try phone.readMessage(m3), Data())

        XCTAssertEqual(host.handshakeHash, hex(v.handshake_hash), "\(v.name): handshake hash")
        XCTAssertEqual(phone.handshakeHash, host.handshakeHash)
        XCTAssertEqual(host.remoteStatic, phoneStatic.publicKey.rawRepresentation)
        XCTAssertEqual(phone.remoteStatic, hostStatic.publicKey.rawRepresentation)

        var hostCiphers = try host.split()
        var phoneCiphers = try phone.split()
        for (i, t) in v.transport_messages.enumerated() {
            let plain = hex(t.plaintext)
            let fromHost = t.from == "host"
            let ct = fromHost
                ? try hostCiphers.send.encrypt(plaintext: plain)
                : try phoneCiphers.send.encrypt(plaintext: plain)
            XCTAssertEqual(ct, hex(t.ciphertext), "\(v.name): transport \(i)")
            let back = fromHost
                ? try phoneCiphers.receive.decrypt(ciphertext: ct)
                : try hostCiphers.receive.decrypt(ciphertext: ct)
            XCTAssertEqual(back, plain)
            XCTAssertNoThrow(try TransportMessage.decode(plain))
        }
    }

    private func key(_ s: String) throws -> Curve25519.KeyAgreement.PrivateKey {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: hex(s))
    }
}

func hex(_ s: String) -> Data {
    var data = Data()
    var index = s.startIndex
    while index < s.endIndex {
        let next = s.index(index, offsetBy: 2)
        data.append(UInt8(s[index..<next], radix: 16)!)
        index = next
    }
    return data
}
