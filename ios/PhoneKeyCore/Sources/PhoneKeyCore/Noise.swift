import CryptoKit
import Foundation

// Noise Protocol Framework (revision 34), restricted to what phonekey needs:
// the XX pattern, optionally with psk3, over 25519 / ChaChaPoly / SHA256.

public enum NoiseError: Error, Equatable {
    case decryptFailed
    case nonceExhausted
    case malformedMessage
    case outOfTurn
    case handshakeIncomplete
}

/// A Noise CipherState: a ChaChaPoly key and a 64-bit nonce.
public struct CipherState {
    private var key: SymmetricKey?
    private var nonce: UInt64 = 0

    init(key: SymmetricKey? = nil) {
        self.key = key
    }

    var hasKey: Bool { key != nil }

    public mutating func encrypt(ad: Data = Data(), plaintext: Data) throws -> Data {
        guard let key else { return plaintext }
        guard nonce < UInt64.max else { throw NoiseError.nonceExhausted }
        let box = try ChaChaPoly.seal(plaintext, using: key, nonce: Self.nonce(nonce), authenticating: ad)
        nonce += 1
        return box.ciphertext + box.tag
    }

    public mutating func decrypt(ad: Data = Data(), ciphertext: Data) throws -> Data {
        guard let key else { return ciphertext }
        guard nonce < UInt64.max else { throw NoiseError.nonceExhausted }
        guard ciphertext.count >= 16 else { throw NoiseError.decryptFailed }
        let plaintext: Data
        do {
            let box = try ChaChaPoly.SealedBox(
                nonce: Self.nonce(nonce),
                ciphertext: ciphertext.dropLast(16),
                tag: ciphertext.suffix(16))
            plaintext = try ChaChaPoly.open(box, using: key, authenticating: ad)
        } catch {
            throw NoiseError.decryptFailed
        }
        nonce += 1
        return plaintext
    }

    /// 32 bits of zeros followed by the little-endian counter.
    private static func nonce(_ n: UInt64) -> ChaChaPoly.Nonce {
        var bytes = Data(count: 4)
        withUnsafeBytes(of: n.littleEndian) { bytes.append(contentsOf: $0) }
        return try! ChaChaPoly.Nonce(data: bytes)
    }
}

struct SymmetricState {
    var cipher = CipherState()
    var ck: Data
    var h: Data

    init(protocolName: String) {
        let name = Data(protocolName.utf8)
        if name.count <= 32 {
            h = name + Data(count: 32 - name.count)
        } else {
            h = Data(SHA256.hash(data: name))
        }
        ck = h
    }

    mutating func mixKey(_ ikm: Data) {
        let out = hkdf(ck, ikm, outputs: 2)
        ck = out[0]
        cipher = CipherState(key: SymmetricKey(data: out[1]))
    }

    mutating func mixHash(_ data: Data) {
        h = Data(SHA256.hash(data: h + data))
    }

    mutating func mixKeyAndHash(_ ikm: Data) {
        let out = hkdf(ck, ikm, outputs: 3)
        ck = out[0]
        mixHash(out[1])
        cipher = CipherState(key: SymmetricKey(data: out[2]))
    }

    mutating func encryptAndHash(_ plaintext: Data) throws -> Data {
        let ciphertext = try cipher.encrypt(ad: h, plaintext: plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    mutating func decryptAndHash(_ ciphertext: Data) throws -> Data {
        let plaintext = try cipher.decrypt(ad: h, ciphertext: ciphertext)
        mixHash(ciphertext)
        return plaintext
    }

    func split() -> (CipherState, CipherState) {
        let out = hkdf(ck, Data(), outputs: 2)
        return (CipherState(key: SymmetricKey(data: out[0])), CipherState(key: SymmetricKey(data: out[1])))
    }

    private func hkdf(_ chainingKey: Data, _ ikm: Data, outputs: Int) -> [Data] {
        func hmac(_ key: Data, _ data: Data) -> Data {
            Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
        }
        let tempKey = hmac(chainingKey, ikm)
        var out = [hmac(tempKey, Data([1]))]
        for i in 2...outputs {
            out.append(hmac(tempKey, out[i - 2] + Data([UInt8(i)])))
        }
        return out
    }
}

/// The two transport cipher states after a handshake.
public struct TransportCiphers {
    public var send: CipherState
    public var receive: CipherState
}

/// One side of a Noise_XX (or Noise_XXpsk3) handshake.
public struct XXHandshake {
    private enum Token { case e, s, ee, es, se, psk }

    public static func protocolName(pairing: Bool) -> String {
        pairing ? "Noise_XXpsk3_25519_ChaChaPoly_SHA256" : "Noise_XX_25519_ChaChaPoly_SHA256"
    }

    public let isInitiator: Bool
    private var symmetric: SymmetricState
    private let staticKey: Curve25519.KeyAgreement.PrivateKey
    private var ephemeralKey: Curve25519.KeyAgreement.PrivateKey?
    private let fixedEphemeral: Curve25519.KeyAgreement.PrivateKey?
    private let psk: Data?
    private let patterns: [[Token]]
    private var messageIndex = 0
    private var remoteEphemeral: Data?
    public private(set) var remoteStatic: Data?

    /// - Parameters:
    ///   - psk: 32 bytes switch to XXpsk3 (pairing); nil is plain XX.
    ///   - ephemeral: fixes the ephemeral key; only for test vectors.
    public init(
        initiator: Bool,
        staticKey: Curve25519.KeyAgreement.PrivateKey,
        prologue: Data,
        psk: Data? = nil,
        ephemeral: Curve25519.KeyAgreement.PrivateKey? = nil
    ) {
        precondition(psk == nil || psk?.count == 32, "PSK must be 32 bytes")
        isInitiator = initiator
        self.staticKey = staticKey
        self.psk = psk
        fixedEphemeral = ephemeral
        var patterns: [[Token]] = [[.e], [.e, .ee, .s, .es], [.s, .se]]
        if psk != nil { patterns[2].append(.psk) }
        self.patterns = patterns
        symmetric = SymmetricState(protocolName: Self.protocolName(pairing: psk != nil))
        symmetric.mixHash(prologue)
    }

    public var isComplete: Bool { messageIndex == patterns.count }

    /// The handshake hash; final once the handshake is complete.
    public var handshakeHash: Data { symmetric.h }

    private var isOurTurn: Bool { (messageIndex % 2 == 0) == isInitiator }

    public mutating func writeMessage(payload: Data = Data()) throws -> Data {
        guard !isComplete, isOurTurn else { throw NoiseError.outOfTurn }
        var out = Data()
        for token in patterns[messageIndex] {
            switch token {
            case .e:
                let e = fixedEphemeral ?? Curve25519.KeyAgreement.PrivateKey()
                ephemeralKey = e
                let pub = e.publicKey.rawRepresentation
                out += pub
                symmetric.mixHash(pub)
                if psk != nil { symmetric.mixKey(pub) }
            case .s:
                out += try symmetric.encryptAndHash(staticKey.publicKey.rawRepresentation)
            default:
                try mix(token)
            }
        }
        out += try symmetric.encryptAndHash(payload)
        messageIndex += 1
        return out
    }

    public mutating func readMessage(_ message: Data) throws -> Data {
        guard !isComplete, !isOurTurn else { throw NoiseError.outOfTurn }
        var rest = message[...]
        func take(_ n: Int) throws -> Data {
            guard rest.count >= n else { throw NoiseError.malformedMessage }
            defer { rest = rest.dropFirst(n) }
            return Data(rest.prefix(n))
        }
        for token in patterns[messageIndex] {
            switch token {
            case .e:
                let re = try take(32)
                remoteEphemeral = re
                symmetric.mixHash(re)
                if psk != nil { symmetric.mixKey(re) }
            case .s:
                let encrypted = try take(symmetric.cipher.hasKey ? 48 : 32)
                remoteStatic = try symmetric.decryptAndHash(encrypted)
            default:
                try mix(token)
            }
        }
        let payload = try symmetric.decryptAndHash(Data(rest))
        messageIndex += 1
        return payload
    }

    /// Splits into transport ciphers once the handshake is complete.
    public func split() throws -> TransportCiphers {
        guard isComplete else { throw NoiseError.handshakeIncomplete }
        let (c1, c2) = symmetric.split()
        return isInitiator ? TransportCiphers(send: c1, receive: c2) : TransportCiphers(send: c2, receive: c1)
    }

    private mutating func mix(_ token: Token) throws {
        switch token {
        case .ee:
            symmetric.mixKey(try dh(ephemeralKey, remoteEphemeral))
        case .es:
            symmetric.mixKey(try isInitiator ? dh(ephemeralKey, remoteStatic) : dh(staticKey, remoteEphemeral))
        case .se:
            symmetric.mixKey(try isInitiator ? dh(staticKey, remoteEphemeral) : dh(ephemeralKey, remoteStatic))
        case .psk:
            symmetric.mixKeyAndHash(psk!)
        case .e, .s:
            break
        }
    }

    private func dh(_ priv: Curve25519.KeyAgreement.PrivateKey?, _ pub: Data?) throws -> Data {
        guard let priv, let pub else { throw NoiseError.malformedMessage }
        let shared = try priv.sharedSecretFromKeyAgreement(
            with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: pub))
        return shared.withUnsafeBytes { Data($0) }
    }
}
