import CryptoKit
import XCTest
@testable import PhoneKeyCore

/// PIN/UV auth protocols one and two against known answers where possible.
final class PinUvAuthTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        Data(stride(from: 0, to: s.count, by: 2).map {
            UInt8(s[s.index(s.startIndex, offsetBy: $0)..<s.index(s.startIndex, offsetBy: $0 + 2)], radix: 16)!
        })
    }

    /// AES-256 of a zero block under a zero key (FIPS-197 style known answer);
    /// with a zero IV that is also the first CBC block.
    private let aesZero = "dc95c078a2408989ad48a21492842087"

    func testEncryptKnownAnswer() throws {
        XCTAssertEqual(try PinUvAuthProtocol.one.encrypt(key: Data(count: 32), Data(count: 16)), hex(aesZero))
        // Protocol two: AES key is the second half; the IV goes in front.
        let two = try PinUvAuthProtocol.two.encrypt(key: Data(count: 64), Data(count: 16), iv: Data(count: 16))
        XCTAssertEqual(two, Data(count: 16) + hex(aesZero))
    }

    func testRoundTrip() throws {
        for proto in PinUvAuthProtocol.allCases {
            let key = Data((0..<(proto == .one ? 32 : 64)).map { UInt8($0) })
            let plain = Data((0..<64).map { UInt8(255 - $0) })
            let sealed = try proto.encrypt(key: key, plain)
            XCTAssertEqual(sealed.count, proto == .one ? 64 : 80)
            XCTAssertEqual(try proto.decrypt(key: key, sealed), plain)
            XCTAssertThrowsError(try proto.decrypt(key: key, sealed.dropLast()), "not a block multiple")
        }
    }

    /// RFC 4231 test case 2.
    func testAuthenticateKnownAnswer() {
        let key = Data("Jefe".utf8)
        let message = Data("what do ya want for nothing?".utf8)
        let mac = hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        XCTAssertEqual(PinUvAuthProtocol.one.authenticate(key: key, message), mac.prefix(16))
        XCTAssertEqual(PinUvAuthProtocol.two.authenticate(key: key, message), mac)
        XCTAssertTrue(PinUvAuthProtocol.two.verify(key: key, message: message, signature: mac))
        XCTAssertFalse(PinUvAuthProtocol.two.verify(key: key, message: message, signature: mac.prefix(16)))
        var wrong = mac
        wrong[0] ^= 1
        XCTAssertFalse(PinUvAuthProtocol.two.verify(key: key, message: message, signature: wrong))
    }

    func testSharedSecret() throws {
        let a = P256.KeyAgreement.PrivateKey(), b = P256.KeyAgreement.PrivateKey()
        let z = try a.sharedSecretFromKeyAgreement(with: b.publicKey).withUnsafeBytes { Data($0) }
        XCTAssertEqual(z.count, 32)
        XCTAssertEqual(try PinUvAuthProtocol.one.sharedSecret(a, with: b.publicKey), Data(SHA256.hash(data: z)))
        for proto in PinUvAuthProtocol.allCases {
            XCTAssertEqual(try proto.sharedSecret(a, with: b.publicKey), try proto.sharedSecret(b, with: a.publicKey))
        }
        XCTAssertEqual(try PinUvAuthProtocol.two.sharedSecret(a, with: b.publicKey).count, 64)
    }
}
