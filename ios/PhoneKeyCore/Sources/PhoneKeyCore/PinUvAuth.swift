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

/// The Touch ID a pinUvAuthToken carries; in the app an `LAContext`. It is
/// invalidated as soon as the token can no longer use it, not only when it
/// happens to be released (docs/protocol.md §10, "Where the token's Touch ID
/// goes").
public protocol TouchIDAuthorization: AnyObject {
    func invalidate()
}

/// CTAP state that belongs to one connection with a host: CTAP calls it a
/// power cycle (docs/protocol.md §10, "Session state"). Ended with the
/// connection; another host's connection has its own.
public final class CTAPSession: @unchecked Sendable {
    private let lock = NSLock()
    private var keyAgreement: P256.KeyAgreement.PrivateKey?
    private var token: Token?
    private var sites: [Site]?
    private var credentials: [StoredCredential]?

    public init() {}

    deinit {
        token?.authorization?.invalidate()
    }

    /// The connection is gone: the token and its Touch ID, the key agreement
    /// key and any enumeration go with it.
    public func end() {
        lock.lock()
        defer { lock.unlock() }
        token?.authorization?.invalidate()
        token = nil
        keyAgreement = nil
        sites = nil
        credentials = nil
    }

    /// The key agreement key, created when first needed, never stored.
    func keyAgreementKey() -> P256.KeyAgreement.PrivateKey {
        lock.lock()
        defer { lock.unlock() }
        if let key = keyAgreement { return key }
        let key = P256.KeyAgreement.PrivateKey()
        keyAgreement = key
        return key
    }

    // MARK: pinUvAuthToken

    /// The session's pinUvAuthToken (§10, "getPinUvAuthTokenUsingUvWithPermissions").
    struct Token {
        let value: Data
        /// The PIN/UV auth protocol it was issued over; CTAP keeps a token per
        /// protocol, so it verifies only with this one.
        let proto: PinUvAuthProtocol
        var permissions: UInt8
        /// Its permissions RP ID; a token without one is bound at first use.
        var rpId: String?
        let issued: Date
        var used = false
        /// The token's Touch ID when it signs: one key operation.
        var authorization: TouchIDAuthorization?

        init(value: Data, proto: PinUvAuthProtocol, permissions: UInt8, rpId: String?, issued: Date,
             authorization: TouchIDAuthorization?) {
            self.value = value
            self.proto = proto
            self.permissions = permissions
            self.rpId = rpId
            self.issued = issued
            self.authorization = authorization
        }
    }

    /// What a request may reach with the token.
    enum TokenScope {
        /// One site: makeCredential, getAssertion, delete and update.
        case rpId(String)
        /// enumerateCredentialsBegin names the site by its hash.
        case rpIdHash(Data)
        /// getCredsMetadata and enumerateRPsBegin need a token without RP ID.
        case unscoped
        /// deleteCredential or updateUserInformation for an unknown credential:
        /// only the token is checked, then NO_CREDENTIALS, as in CTAP.
        case any
    }

    struct TokenUse {
        let authorization: TouchIDAuthorization?
    }

    static let initialUsageLimit: TimeInterval = 30
    static let maxUsagePeriod: TimeInterval = 600

    /// A new token replaces any earlier one of this session, for every
    /// protocol; the earlier one's Touch ID is invalidated.
    func setToken(_ new: Token) {
        lock.lock()
        defer { lock.unlock() }
        if let old = token?.authorization, old !== new.authorization { old.invalidate() }
        token = new
    }

    /// Checks `param` = authenticate(token, message) and the token's
    /// protocol, permission and scope. Any failure: PIN_AUTH_INVALID.
    /// `silent`: a getAssertion with up = false, allowed only within the
    /// first 30 s and not counted as a use, so it never extends them (§10).
    func useToken(param: Data, protocolNumber: Int?, message: Data, permission: UInt8,
                  scope: TokenScope, silent: Bool = false, now: Date) throws -> TokenUse {
        guard let number = protocolNumber else { throw CTAPStatus.missingParameter }
        guard let proto = PinUvAuthProtocol(rawValue: number) else { throw CTAPStatus.invalidParameter }
        lock.lock()
        defer { lock.unlock() }
        guard var current = token else { throw CTAPStatus.pinAuthInvalid }
        let age = now.timeIntervalSince(current.issued)
        guard age >= 0, age < Self.maxUsagePeriod, current.used || age < Self.initialUsageLimit else {
            current.authorization?.invalidate()
            token = nil
            throw CTAPStatus.pinAuthInvalid
        }
        guard proto == current.proto,
              proto.verify(key: current.value, message: message, signature: param),
              current.permissions & permission != 0,
              !silent || age < Self.initialUsageLimit
        else { throw CTAPStatus.pinAuthInvalid }
        let signs = permission & (TokenPrompt.makeCredential | TokenPrompt.getAssertion) != 0
        switch scope {
        case let .rpId(rpId):
            if let bound = current.rpId {
                guard bound == rpId else { throw CTAPStatus.pinAuthInvalid }
            } else if signs {
                // Only makeCredential and getAssertion bind a token without
                // RP ID to the site of its first use (CTAP 2.1).
                current.rpId = rpId
            }
        case let .rpIdHash(hash):
            if let bound = current.rpId, Authenticator.rpIdHash(bound) != hash { throw CTAPStatus.pinAuthInvalid }
        case .unscoped:
            if current.rpId != nil { throw CTAPStatus.pinAuthInvalid }
        case .any:
            break
        }
        if !silent { current.used = true }
        token = current
        return TokenUse(authorization: signs ? current.authorization : nil)
    }

    /// After a makeCredential or getAssertion with user presence, whatever
    /// its outcome: the token keeps no permission for another one (CTAP 2.1),
    /// and its Touch ID is invalidated.
    func consumeSigningPermissions() {
        lock.lock()
        defer { lock.unlock() }
        token?.permissions &= ~(TokenPrompt.makeCredential | TokenPrompt.getAssertion)
        token?.authorization?.invalidate()
        token?.authorization = nil
    }

    // MARK: Credential management enumeration

    struct Site {
        let id: String
        let name: String?
    }

    func beginEnumeration(sites rest: [Site]) {
        lock.lock()
        defer { lock.unlock() }
        sites = rest
        credentials = nil
    }

    func beginEnumeration(credentials rest: [StoredCredential]) {
        lock.lock()
        defer { lock.unlock() }
        credentials = rest
        sites = nil
    }

    func nextSite() -> Site? {
        lock.lock()
        defer { lock.unlock() }
        guard var rest = sites, !rest.isEmpty else { sites = nil; return nil }
        let next = rest.removeFirst()
        sites = rest
        return next
    }

    func nextCredential() -> StoredCredential? {
        lock.lock()
        defer { lock.unlock() }
        guard var rest = credentials, !rest.isEmpty else { credentials = nil; return nil }
        let next = rest.removeFirst()
        credentials = rest
        return next
    }

    func endEnumeration() {
        lock.lock()
        defer { lock.unlock() }
        sites = nil
        credentials = nil
    }
}
