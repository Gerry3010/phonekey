import CryptoKit
import Foundation

// Step 3c: a PIN that only works together with Touch ID (docs/protocol.md §10,
// "PIN (3c)"). It exists because OpenSSH and Chrome's key management insist
// on one; every token issued against it also needs Touch ID on the phone.

/// What the phone keeps of the PIN: CTAP's LEFT(SHA-256(PIN), 16), encrypted
/// to a Secure Enclave key of its own that is usable only after Touch ID, and
/// the retries left. Never the PIN itself.
public struct PinRecord: Codable, Equatable, Sendable {
    public var sealedHash: Data
    public var retries: Int

    public init(sealedHash: Data, retries: Int) {
        self.sealedHash = sealedHash
        self.retries = retries
    }
}

/// Where the record lives (in the app: the Keychain, this device only).
public protocol PinStorage: AnyObject {
    /// nil: no PIN set. Throws when the storage cannot be read, so a locked
    /// keychain never reads as "no PIN".
    func loadPin() throws -> PinRecord?
    /// nil removes the PIN.
    func savePin(_ record: PinRecord?) throws
}

/// What a PIN request asks the phone to do; every one needs Touch ID.
public enum PinPrompt: Equatable {
    /// setPIN: the computer sets the first PIN.
    case set
    /// changePIN: the old PIN is checked after Touch ID.
    case change
    /// getPinUvAuthTokenUsingPinWithPermissions: a token for a purpose.
    case token(TokenPrompt)
    /// getPinToken (CTAP 2.0): registering and signing in at a site that the
    /// token's first operation names.
    case legacyToken
}

public enum PinState: Equatable {
    case notSet
    case set(retries: Int)
}

/// Bumped whenever the PIN changes or goes: every token of every session
/// issued before that is invalid (§10, changePIN).
final class PinEpoch: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    var current: Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func bump() {
        lock.lock()
        defer { lock.unlock() }
        value += 1
    }
}

extension Authenticator {
    public static let maxPinRetries = 8
    public static let minPinLength = 4
    /// Wrong PINs in a row that block the session until the host reconnects.
    static let wrongPinsPerSession = 3
    /// Names the PIN's own Secure Enclave key among the credential keys. A
    /// credential ID is 32 random bytes and never equals it.
    public static let pinKeyId = Data(SHA256.hash(data: Data("net.geraldhofbauer.phonekey.pin".utf8)))

    // MARK: State

    /// Unknown (unreadable storage) counts as set, so nothing assumes there
    /// is no PIN to protect.
    var pinIsSet: Bool {
        do {
            return try pins.loadPin() != nil
        } catch {
            return true
        }
    }

    public func pinState() throws -> PinState {
        guard let record = try pins.loadPin() else { return .notSet }
        return .set(retries: record.retries)
    }

    // MARK: In the app (after Touch ID in the app's own UI)

    /// Sets or replaces the PIN from the app. Retries start over; tokens
    /// issued before are invalid.
    public func setPinOnPhone(_ pin: String) throws {
        let bytes = Data(pin.utf8)
        try Self.checkPolicy(bytes)
        try storePin(bytes)
        pinEpoch.bump()
    }

    /// Removes the PIN, for a forgotten or blocked one. The keys stay.
    public func removePin() throws {
        try pins.savePin(nil)
        keys.deleteKey(id: Self.pinKeyId)
        pinEpoch.bump()
    }

    // MARK: clientPIN subcommands

    /// getPINRetries (0x01).
    func getPinRetries(session: CTAPSession) throws -> CBOR {
        guard let record = try pins.loadPin() else { throw CTAPStatus.pinNotSet }
        var answer: [CBOR.Pair] = [.init(.int(3), .int(record.retries))]
        if session.pinAuthBlocked { answer.append(.init(.int(4), .bool(true))) }
        return .map(answer)
    }

    /// setPIN (0x03): only while no PIN is set.
    func setPin(_ p: CBOR, proto: PinUvAuthProtocol, session: CTAPSession) async throws {
        guard let newPinEnc = p[5]?.bytes, let param = p[4]?.bytes else { throw CTAPStatus.missingParameter }
        let shared = try sharedSecret(p, proto: proto, session: session)
        guard try pins.loadPin() == nil else { throw CTAPStatus.pinAuthInvalid } // CTAP 2.1 §6.5.5.5
        guard proto.verify(key: shared, message: newPinEnc, signature: param) else {
            throw CTAPStatus.pinAuthInvalid
        }
        let pin = try Self.newPin(newPinEnc, shared: shared, proto: proto)
        if ui.touchIDLocked { throw CTAPStatus.uvBlocked }
        let authorization = try await askForPin(.set)
        authorization?.invalidate() // storing needs no key operation
        try Task.checkCancellation()
        try storePin(pin)
    }

    /// changePIN (0x04): Touch ID, then the old PIN, then the new one.
    func changePin(_ p: CBOR, proto: PinUvAuthProtocol, session: CTAPSession) async throws {
        guard let newPinEnc = p[5]?.bytes, let pinHashEnc = p[6]?.bytes, let param = p[4]?.bytes else {
            throw CTAPStatus.missingParameter
        }
        let shared = try sharedSecret(p, proto: proto, session: session)
        try checkPinUsable(session: session)
        guard proto.verify(key: shared, message: newPinEnc + pinHashEnc, signature: param) else {
            throw CTAPStatus.pinAuthInvalid
        }
        let offered = try Self.pinHash(pinHashEnc, shared: shared, proto: proto)
        // Refused before anything is shown: costs no try and no Touch ID.
        let pin = try Self.newPin(newPinEnc, shared: shared, proto: proto)
        if ui.touchIDLocked { throw CTAPStatus.uvBlocked }
        let authorization = try await askForPin(.change)
        defer { authorization?.invalidate() }
        try await checkPin(offered, session: session, authorization: authorization)
        try Task.checkCancellation()
        try storePin(pin)
        pinEpoch.bump()
    }

    /// getPinToken (0x05) and getPinUvAuthTokenUsingPinWithPermissions (0x09).
    func tokenUsingPin(_ p: CBOR, proto: PinUvAuthProtocol, session: CTAPSession,
                       withPermissions: Bool) async throws -> CBOR {
        guard let pinHashEnc = p[6]?.bytes else { throw CTAPStatus.missingParameter }
        let prompt: TokenPrompt
        let pinPrompt: PinPrompt
        if withPermissions {
            prompt = try Self.tokenPrompt(p)
            pinPrompt = .token(prompt)
        } else {
            // CTAP 2.0: mc and ga, bound to the site of the first use.
            prompt = TokenPrompt(permissions: TokenPrompt.makeCredential | TokenPrompt.getAssertion, rpId: nil)
            pinPrompt = .legacyToken
        }
        let shared = try sharedSecret(p, proto: proto, session: session)
        try checkPinUsable(session: session)
        let offered = try Self.pinHash(pinHashEnc, shared: shared, proto: proto)
        if ui.touchIDLocked { throw CTAPStatus.uvBlocked }
        let authorization = try await askForPin(pinPrompt)
        do {
            try await checkPin(offered, session: session, authorization: authorization)
        } catch {
            authorization?.invalidate()
            throw error
        }
        return try issueToken(prompt, proto: proto, shared: shared, session: session,
                              authorization: authorization, confirmFirstUse: !withPermissions)
    }

    // MARK: Shared steps

    /// The shared secret with the platform's `keyAgreement` (key 3).
    func sharedSecret(_ p: CBOR, proto: PinUvAuthProtocol, session: CTAPSession) throws -> Data {
        guard p[3] != nil else { throw CTAPStatus.missingParameter }
        let platform = try PinUvAuthProtocol.platformKey(p[3])
        return try proto.sharedSecret(session.keyAgreementKey(), with: platform)
    }

    /// `permissions` (key 9) and `rpId` (key 10), checked as for 0x06.
    static func tokenPrompt(_ p: CBOR) throws -> TokenPrompt {
        guard let permissions = p[9]?.int else { throw CTAPStatus.missingParameter }
        guard permissions != 0 else { throw CTAPStatus.invalidParameter }
        guard permissions & ~0x07 == 0 else { throw CTAPStatus.unauthorizedPermission }
        let prompt = TokenPrompt(permissions: UInt8(permissions), rpId: p[10]?.text)
        if prompt.signs, prompt.rpId == nil { throw CTAPStatus.missingParameter }
        return prompt
    }

    /// A new token replaces the session's earlier one. Only a token that
    /// signs keeps the Touch ID, and only once it is issued.
    func issueToken(_ prompt: TokenPrompt, proto: PinUvAuthProtocol, shared: Data, session: CTAPSession,
                    authorization: TouchIDAuthorization?, confirmFirstUse: Bool = false) throws -> CBOR {
        let kept = prompt.signs ? authorization : nil
        if kept == nil { authorization?.invalidate() }
        do {
            try Task.checkCancellation()
            let value = random(32)
            let answer = try proto.encrypt(key: shared, value)
            session.setToken(CTAPSession.Token(value: value, proto: proto, permissions: prompt.permissions,
                                               rpId: prompt.rpId, issued: now(), authorization: kept,
                                               epoch: pinEpoch.current, confirmFirstUse: confirmFirstUse))
            return .map([.int(2): .bytes(answer)])
        } catch {
            kept?.invalidate()
            throw error
        }
    }

    /// The card and Touch ID for a PIN request.
    private func askForPin(_ prompt: PinPrompt) async throws -> TouchIDAuthorization? {
        switch await ui.authorizePin(prompt) {
        case let .approved(authorization): return authorization
        case .denied: throw CTAPStatus.operationDenied
        case .timedOut: throw CTAPStatus.userActionTimeout
        case .blocked: throw CTAPStatus.uvBlocked
        }
    }

    /// A PIN is set and neither blocked nor blocked for this session.
    private func checkPinUsable(session: CTAPSession) throws {
        guard let record = try pins.loadPin() else { throw CTAPStatus.pinNotSet }
        guard record.retries > 0 else { throw CTAPStatus.pinBlocked }
        if session.pinAuthBlocked { throw CTAPStatus.pinAuthBlocked }
    }

    /// Compares the offered LEFT(SHA-256(PIN), 16) with the stored one, which
    /// only the Touch ID just given can decrypt. As in CTAP the try is counted
    /// before the comparison, so cutting the connection never saves one.
    private func checkPin(_ offered: Data, session: CTAPSession,
                          authorization: TouchIDAuthorization?) async throws {
        guard var record = try pins.loadPin() else { throw CTAPStatus.pinNotSet }
        guard record.retries > 0 else { throw CTAPStatus.pinBlocked }
        record.retries -= 1
        try pins.savePin(record)
        let stored: Data
        do {
            stored = try await keys.decrypt(id: Self.pinKeyId, ciphertext: record.sealedHash,
                                            reason: "Check the PIN", authorization: authorization)
        } catch let status as CTAPStatus {
            throw status
        } catch {
            throw CTAPStatus.operationDenied
        }
        guard stored.count == offered.count,
              zip(stored, offered).reduce(UInt8(0), { $0 | ($1.0 ^ $1.1) }) == 0
        else {
            session.pinFailed()
            if record.retries == 0 { throw CTAPStatus.pinBlocked }
            if session.pinAuthBlocked { throw CTAPStatus.pinAuthBlocked }
            throw CTAPStatus.pinInvalid
        }
        record.retries = Self.maxPinRetries
        try pins.savePin(record)
        session.pinSucceeded()
    }

    /// Stores LEFT(SHA-256(PIN), 16) encrypted to the PIN key, which is made
    /// when first needed. Encrypting needs no Touch ID.
    private func storePin(_ pin: Data) throws {
        let publicKey: Data
        if let existing = try? keys.publicKey(id: Self.pinKeyId) {
            publicKey = existing
        } else {
            publicKey = try keys.createKey(id: Self.pinKeyId)
        }
        let sealed = try keys.encrypt(toPublicKey: publicKey, plaintext: Self.leftHash(pin))
        try pins.savePin(PinRecord(sealedHash: sealed, retries: Self.maxPinRetries))
    }

    // MARK: PIN formats

    static func leftHash(_ pin: Data) -> Data {
        Data(SHA256.hash(data: pin).prefix(16))
    }

    /// `pinHashEnc`: LEFT(SHA-256(PIN), 16), encrypted with the shared secret.
    static func pinHash(_ pinHashEnc: Data, shared: Data, proto: PinUvAuthProtocol) throws -> Data {
        let hash = try proto.decrypt(key: shared, pinHashEnc)
        guard hash.count == 16 else { throw CTAPStatus.invalidParameter }
        return hash
    }

    /// `newPinEnc`: the PIN padded with zeros to 64 bytes, encrypted.
    static func newPin(_ newPinEnc: Data, shared: Data, proto: PinUvAuthProtocol) throws -> Data {
        let padded = try proto.decrypt(key: shared, newPinEnc)
        guard padded.count == 64 else { throw CTAPStatus.invalidParameter }
        let pin = Data(padded.prefix { $0 != 0 })
        try checkPolicy(pin)
        return pin
    }

    /// At least 4 code points, at most 63 bytes of UTF-8 (§10, "Policy").
    static func checkPolicy(_ pin: Data) throws {
        guard pin.count <= 63, let text = String(data: pin, encoding: .utf8),
              text.unicodeScalars.count >= minPinLength
        else { throw CTAPStatus.pinPolicyViolation }
    }
}
