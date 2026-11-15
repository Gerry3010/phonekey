import CommonCrypto
import CryptoKit
import Foundation

/// PIN/UV auth protocols one and two (CTAP 2.1 §6.5.6 and §6.5.7), as far as
/// the phone needs them: the shared secret with a platform key, encrypt and
/// decrypt, authenticate and verify.
public enum PinUvAuthProtocol: Int, CaseIterable, Sendable {
    case one = 1
    case two = 2

    /// The shared secret with `peer`: SHA-256 of the ECDH x coordinate (one,
    /// 32 bytes), or HKDF-SHA-256 into an HMAC key and an AES key (two, 64
    /// bytes: HMAC key || AES key).
    public func sharedSecret(_ own: P256.KeyAgreement.PrivateKey,
                             with peer: P256.KeyAgreement.PublicKey) throws -> Data {
        let z = try own.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
        switch self {
        case .one:
            return Data(SHA256.hash(data: z))
        case .two:
            func hkdf(_ info: String) -> Data {
                HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: z), salt: Data(count: 32),
                                       info: Data(info.utf8), outputByteCount: 32)
                    .withUnsafeBytes { Data($0) }
            }
            return hkdf("CTAP2 HMAC key") + hkdf("CTAP2 AES key")
        }
    }

    /// AES-256-CBC without padding: a zero IV (one), or a random IV sent in
    /// front of the ciphertext (two). `iv` is for tests.
    public func encrypt(key: Data, _ plaintext: Data, iv: Data? = nil) throws -> Data {
        switch self {
        case .one:
            return try Self.aesCBC(CCOperation(kCCEncrypt), key: key, iv: Data(count: 16), plaintext)
        case .two:
            let iv = iv ?? Data((0..<16).map { _ in UInt8.random(in: 0...255) })
            return iv + (try Self.aesCBC(CCOperation(kCCEncrypt), key: aesKey(key), iv: iv, plaintext))
        }
    }

    public func decrypt(key: Data, _ ciphertext: Data) throws -> Data {
        switch self {
        case .one:
            return try Self.aesCBC(CCOperation(kCCDecrypt), key: key, iv: Data(count: 16), ciphertext)
        case .two:
            guard ciphertext.count >= 16 else { throw CTAPStatus.invalidParameter }
            return try Self.aesCBC(CCOperation(kCCDecrypt), key: aesKey(key),
                                   iv: Data(ciphertext.prefix(16)), Data(ciphertext.dropFirst(16)))
        }
    }

    /// HMAC-SHA-256, the first 16 bytes (one) or all 32 (two).
    public func authenticate(key: Data, _ message: Data) -> Data {
        let mac = Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: hmacKey(key))))
        return self == .one ? Data(mac.prefix(16)) : mac
    }

    public func verify(key: Data, message: Data, signature: Data) -> Bool {
        let expected = authenticate(key: key, message)
        guard signature.count == expected.count else { return false }
        return zip(signature, expected).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    /// Protocol two splits the 64-byte secret; a 32-byte key (a
    /// pinUvAuthToken) is used as it is.
    private func hmacKey(_ key: Data) -> Data { self == .two ? Data(key.prefix(32)) : key }
    private func aesKey(_ key: Data) -> Data { key.count == 64 ? Data(key.suffix(32)) : key }

    private static func aesCBC(_ operation: CCOperation, key: Data, iv: Data, _ input: Data) throws -> Data {
        guard input.count % 16 == 0, key.count == 32 else { throw CTAPStatus.invalidParameter }
        var output = Data(count: input.count)
        var moved = 0
        let status = output.withUnsafeMutableBytes { out in
            input.withUnsafeBytes { inp in
                key.withUnsafeBytes { k in
                    iv.withUnsafeBytes { v in
                        CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), CCOptions(0),
                                k.baseAddress, key.count, v.baseAddress,
                                inp.baseAddress, input.count, out.baseAddress, input.count, &moved)
                    }
                }
            }
        }
        guard status == kCCSuccess, moved == input.count else { throw CTAPStatus.other }
        return output
    }

    /// A platform key agreement key as CTAP sends it (COSE, P-256).
    static func platformKey(_ cose: CBOR?) throws -> P256.KeyAgreement.PublicKey {
        guard let cose, cose[1]?.int == 2, cose[-1]?.int == 1,
              let x = cose[-2]?.bytes, let y = cose[-3]?.bytes, x.count == 32, y.count == 32
        else { throw CTAPStatus.invalidParameter }
        do {
            return try P256.KeyAgreement.PublicKey(x963Representation: Data([0x04]) + x + y)
        } catch {
            throw CTAPStatus.invalidParameter
        }
    }

    /// The phone's key agreement key as CTAP returns it: alg -25, which CTAP
    /// says is "not the algorithm actually used".
    static func coseKey(_ key: P256.KeyAgreement.PublicKey) -> CBOR {
        let raw = [UInt8](key.x963Representation)
        return .map([
            .int(1): .int(2),
            .int(3): .int(-25),
            .int(-1): .int(1),
            .int(-2): .bytes(Data(raw[1...32])),
            .int(-3): .bytes(Data(raw[33...64])),
        ])
    }
}

/// CTAP state that belongs to one connection with a host: CTAP calls it a
/// power cycle (docs/protocol.md §10, "Session state"). Dropped with the
/// connection; another host's connection has its own.
public final class CTAPSession: @unchecked Sendable {
    private let lock = NSLock()
    private var keyAgreement: P256.KeyAgreement.PrivateKey?

    public init() {}

    /// The key agreement key, created when first needed, never stored.
    func keyAgreementKey() -> P256.KeyAgreement.PrivateKey {
        lock.lock()
        defer { lock.unlock() }
        if let key = keyAgreement { return key }
        let key = P256.KeyAgreement.PrivateKey()
        keyAgreement = key
        return key
    }
}
