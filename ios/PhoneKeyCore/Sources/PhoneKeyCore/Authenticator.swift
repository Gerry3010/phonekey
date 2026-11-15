import CryptoKit
import Foundation

/// CTAP status codes (CTAP 2.1 §8.2).
public enum CTAPStatus: UInt8, Error {
    case ok = 0x00
    case invalidCommand = 0x01
    case invalidParameter = 0x02
    case invalidLength = 0x03
    case channelBusy = 0x06
    case cborUnexpectedType = 0x11
    case invalidCBOR = 0x12
    case missingParameter = 0x14
    case credentialExcluded = 0x19
    case unsupportedAlgorithm = 0x26
    case operationDenied = 0x27
    case keyStoreFull = 0x28
    case unsupportedOption = 0x2B
    case invalidOption = 0x2C
    case keepaliveCancel = 0x2D
    case noCredentials = 0x2E
    case userActionTimeout = 0x2F
    case notAllowed = 0x30
    case pinAuthInvalid = 0x33
    case pinNotSet = 0x35
    case invalidSubcommand = 0x3E
    case other = 0x7F
}

/// A credential as the phone stores it. The private key lives elsewhere
/// (Secure Enclave), named by `id`.
public struct StoredCredential: Codable, Equatable, Identifiable {
    public var id: Data
    public var rpId: String
    public var rpName: String?
    public var userId: Data
    public var userName: String?
    public var userDisplayName: String?
    public var discoverable: Bool
    public var created: Date
    public var signCount: UInt32
    /// credProtect level 1–3, if the platform asked for one.
    public var credProtect: Int?
    /// When it last signed in. App bookkeeping; absent in data from before.
    public var lastUsed: Date?
    /// The user wants this account suggested first on its site (app UI).
    public var suggested: Bool?
    /// The user's own name for the account, only on the phone (app UI).
    public var localName: String?
    /// `hmac-secret`: the credential's 32-byte random secret, encrypted to its
    /// own key (`CredentialKeys.encrypt`). Absent if the site did not ask.
    public var hmacSecret: Data?

    public init(id: Data, rpId: String, rpName: String?, userId: Data, userName: String?,
                userDisplayName: String?, discoverable: Bool, created: Date, signCount: UInt32,
                credProtect: Int? = nil, lastUsed: Date? = nil, suggested: Bool? = nil,
                localName: String? = nil, hmacSecret: Data? = nil) {
        self.id = id
        self.rpId = rpId
        self.rpName = rpName
        self.userId = userId
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.discoverable = discoverable
        self.created = created
        self.signCount = signCount
        self.credProtect = credProtect
        self.lastUsed = lastUsed
        self.suggested = suggested
        self.localName = localName
        self.hmacSecret = hmacSecret
    }

    /// The best label for the account.
    public var accountLabel: String {
        localName ?? userName ?? userDisplayName ?? "Unnamed account"
    }
}

public protocol CredentialStore: AnyObject {
    func credentials(rpId: String) -> [StoredCredential]
    func credential(id: Data) -> StoredCredential?
    /// Adds `credential` and removes the credentials in `replacing`, in one
    /// step, so there is never a moment with none or both of them.
    func save(_ credential: StoredCredential, replacing: [Data]) throws
    /// Increments and returns the new counter.
    func incrementCounter(id: Data) throws -> UInt32
}

/// Creates and uses P-256 keys. In the app: Secure Enclave, Touch ID per signature.
public protocol CredentialKeys: AnyObject {
    /// Creates a key named `id` and returns its public key (x963, 65 bytes).
    func createKey(id: Data) throws -> Data
    /// Signs `data` (ECDSA P-256 SHA-256, DER). May ask for Touch ID; throws
    /// CTAPStatus.operationDenied when the user declines.
    func sign(id: Data, data: Data, reason: String) async throws -> Data
    /// Encrypts to a public key (x963) with ECIES. Needs no Touch ID.
    func encrypt(toPublicKey x963: Data, plaintext: Data) throws -> Data
    /// Decrypts with the key. Like `sign`, it needs Touch ID; within one
    /// sign-in the same Touch ID covers both (docs/protocol.md §10).
    func decrypt(id: Data, ciphertext: Data, reason: String) async throws -> Data
    func deleteKey(id: Data)
}

public enum UserDecision: Equatable {
    case approved
    case denied
    case timedOut
}

public struct RegistrationPrompt: Equatable {
    public let rpId: String
    public let rpName: String?
    public let userName: String?
    public let userDisplayName: String?
    public let passkey: Bool
}

public struct SignInPrompt: Equatable {
    public let rpId: String
    public let candidates: [StoredCredential]
}

/// The phone's screen. Implementations must return promptly when the calling
/// task is cancelled (`Task.isCancelled`); the result is then ignored.
public protocol AuthenticatorUI: AnyObject {
    /// Shows the registration and verifies the user (Touch ID).
    func confirmRegistration(_ prompt: RegistrationPrompt) async -> UserDecision
    /// Lets the user pick and approve one candidate.
    func chooseCredential(_ prompt: SignInPrompt) async -> (UserDecision, StoredCredential?)
    /// "Already registered on this site": waits for a tap.
    func acknowledgeExcluded(rpId: String) async -> UserDecision
    /// Authenticator selection: waits for a tap.
    func confirmSelection() async -> UserDecision
}

/// A CTAP 2.0 authenticator with Phase 3a: PIN/UV auth protocols and
/// `hmac-secret` (docs/protocol.md §10).
public final class Authenticator {
    public static let aaguid = Data([
        0x4E, 0x3B, 0x1F, 0xE3, 0xC7, 0x5C, 0x40, 0x55, 0xB7, 0x91, 0xC9, 0x99, 0xFF, 0x91, 0x59, 0x51,
    ])
    public static let maxMessageSize = 1200
    /// Without these two, Chrome probes every allowList entry on its own with
    /// `up = false`, which a Secure Enclave key cannot answer (§10). 16
    /// descriptors of 32-byte IDs fit well within `maxMessageSize`.
    public static let maxCredentialCountInList = 16
    public static let credentialIdLength = 32

    enum Command: UInt8 {
        case makeCredential = 0x01
        case getAssertion = 0x02
        case getInfo = 0x04
        case clientPIN = 0x06
        case reset = 0x07
        case getNextAssertion = 0x08
    }

    private let store: CredentialStore
    private let keys: CredentialKeys
    private let ui: AuthenticatorUI
    private let random: (Int) -> Data

    public init(store: CredentialStore, keys: CredentialKeys, ui: AuthenticatorUI,
                random: @escaping (Int) -> Data = { n in Data((0..<n).map { _ in UInt8.random(in: 0...255) }) }) {
        self.store = store
        self.keys = keys
        self.ui = ui
        self.random = random
    }

    /// Handles one CTAPHID CBOR message (command byte + parameters) from the
    /// host connection `session` and returns status byte + CBOR response.
    /// Never throws.
    public func handle(_ message: Data, session: CTAPSession) async -> Data {
        guard let byte = message.first else { return Data([CTAPStatus.invalidLength.rawValue]) }
        let params = Data(message.dropFirst())
        do {
            let response: CBOR
            switch Command(rawValue: byte) {
            case .getInfo:
                response = getInfo()
            case .makeCredential:
                response = try await makeCredential(try Self.parameters(params))
            case .getAssertion:
                response = try await getAssertion(try Self.parameters(params), session: session)
            case .clientPIN:
                response = try clientPIN(try Self.parameters(params), session: session)
            case .getNextAssertion, .reset:
                throw CTAPStatus.notAllowed
            case nil:
                throw CTAPStatus.invalidCommand
            }
            try Task.checkCancellation()
            return Data([CTAPStatus.ok.rawValue]) + response.encoded
        } catch let status as CTAPStatus {
            return Data([status.rawValue])
        } catch is CancellationError {
            return Data([CTAPStatus.keepaliveCancel.rawValue])
        } catch {
            return Data([CTAPStatus.other.rawValue])
        }
    }

    private static func parameters(_ data: Data) throws -> CBOR {
        guard !data.isEmpty else { throw CTAPStatus.missingParameter }
        let params: CBOR
        do {
            params = try CBOR.decode(data)
        } catch {
            throw CTAPStatus.invalidCBOR
        }
        guard params.isMap else { throw CTAPStatus.cborUnexpectedType }
        return params
    }

    // MARK: getInfo

    func getInfo() -> CBOR {
        .map([
            .int(1): .array([.text("FIDO_2_0")]),
            .int(2): .array([.text("credProtect"), .text("hmac-secret")]),
            .int(3): .bytes(Self.aaguid),
            .int(4): .map([.text("rk"): .bool(true), .text("up"): .bool(true),
                           .text("uv"): .bool(true), .text("plat"): .bool(false)]),
            .int(5): .int(Self.maxMessageSize),
            .int(6): .array([.int(2), .int(1)]),
            .int(7): .int(Self.maxCredentialCountInList),
            .int(8): .int(Self.credentialIdLength),
            .int(9): .array([.text("usb")]),
            .int(10): .array([.map([.text("alg"): .int(-7), .text("type"): .text("public-key")])]),
        ])
    }

    // MARK: makeCredential

    private func makeCredential(_ p: CBOR) async throws -> CBOR {
        let clientDataHash = try required(p[1]?.bytes)
        guard let rp = p[2], rp.isMap, let user = p[3], user.isMap else { throw CTAPStatus.missingParameter }
        let rpId = try required(rp["id"]?.text)
        let userId = try required(user["id"]?.bytes)
        guard userId.count <= 64 else { throw CTAPStatus.invalidParameter }
        guard let params = p[4]?.array else { throw CTAPStatus.missingParameter }
        let options = p[7]
        if options?["up"]?.bool == false { throw CTAPStatus.invalidOption }
        let passkey = options?["rk"]?.bool ?? false
        // credProtect: every use needs Touch ID anyway, so all levels hold;
        // the level is stored and echoed. Other extensions are ignored.
        let credProtect = p[6]?["credProtect"]?.int.flatMap { (1...3).contains($0) ? $0 : nil }
        let wantsHmacSecret = p[6]?["hmac-secret"]?.bool == true

        if let pinAuth = p[8] {
            guard pinAuth.bytes?.isEmpty == true else { throw CTAPStatus.pinAuthInvalid }
            try check(await ui.confirmSelection())
            throw CTAPStatus.pinNotSet
        }

        guard params.contains(where: { $0["alg"]?.int == -7 && $0["type"]?.text == "public-key" }) else {
            throw CTAPStatus.unsupportedAlgorithm
        }

        let excluded = (p[5]?.array ?? []).compactMap { $0["id"]?.bytes }.contains { id in
            store.credential(id: id)?.rpId == rpId
        }
        if excluded {
            try check(await ui.acknowledgeExcluded(rpId: rpId))
            throw CTAPStatus.credentialExcluded
        }

        try check(await ui.confirmRegistration(RegistrationPrompt(
            rpId: rpId, rpName: rp["name"]?.text, userName: user["name"]?.text,
            userDisplayName: user["displayName"]?.text, passkey: passkey)))
        try Task.checkCancellation()

        let credentialId = random(Self.credentialIdLength)
        let publicKey: Data
        do {
            publicKey = try keys.createKey(id: credentialId)
        } catch {
            throw CTAPStatus.keyStoreFull
        }
        guard publicKey.count == 65, publicKey.first == 0x04 else { throw CTAPStatus.other }
        // hmac-secret: CredRandomWithUV only, since no assertion is made
        // without UV; stored encrypted to the credential's own key.
        var hmacSecret: Data?
        if wantsHmacSecret {
            do {
                hmacSecret = try keys.encrypt(toPublicKey: publicKey, plaintext: random(32))
            } catch {
                keys.deleteKey(id: credentialId)
                throw CTAPStatus.other
            }
        }
        // A new passkey for an account that already has one replaces it
        // (CTAP 2.1 §6.1.2: same RP ID and user ID). Non-discoverable
        // credentials are never replaced: the site keeps their IDs.
        let replaced = passkey
            ? store.credentials(rpId: rpId).filter { $0.discoverable && $0.userId == userId }
            : []
        try store.save(StoredCredential(
            id: credentialId, rpId: rpId, rpName: rp["name"]?.text, userId: userId,
            userName: user["name"]?.text, userDisplayName: user["displayName"]?.text,
            discoverable: passkey, created: Date(), signCount: 0, credProtect: credProtect,
            suggested: replaced.contains { $0.suggested == true } ? true : nil,
            localName: replaced.lazy.compactMap(\.localName).first, hmacSecret: hmacSecret),
            replacing: replaced.map(\.id))
        // Only after the metadata is gone: a failure leaves an unused key, never
        // an entry without its key.
        for old in replaced { keys.deleteKey(id: old.id) }

        var extensions: [CBOR.Pair] = []
        if let credProtect { extensions.append(.init(.text("credProtect"), .int(credProtect))) }
        if wantsHmacSecret { extensions.append(.init(.text("hmac-secret"), .bool(true))) }

        var authData = Self.rpIdHash(rpId)
        authData.append(Flags.up | Flags.uv | Flags.at | (extensions.isEmpty ? 0 : Flags.ed))
        authData += Self.counterBytes(0)
        authData += Self.aaguid
        authData += [UInt8(credentialId.count >> 8), UInt8(credentialId.count & 0xFF)]
        authData += credentialId
        authData += Self.coseKey(x963: publicKey).encoded
        if !extensions.isEmpty {
            authData += CBOR.map(extensions).encoded
        }
        _ = clientDataHash // not signed with attestation "none"

        return .map([
            .int(1): .text("none"),
            .int(2): .bytes(authData),
            .int(3): .map([]),
        ])
    }

    // MARK: getAssertion

    private func getAssertion(_ p: CBOR, session: CTAPSession) async throws -> CBOR {
        let rpId = try required(p[1]?.text)
        let clientDataHash = try required(p[2]?.bytes)
        if let pinAuth = p[6] {
            // Zero length: authenticator selection, as for makeCredential.
            guard pinAuth.bytes?.isEmpty == true else { throw CTAPStatus.pinAuthInvalid }
            try check(await ui.confirmSelection())
            throw CTAPStatus.pinNotSet
        }

        let allowList = (p[3]?.array ?? []).compactMap { $0["id"]?.bytes }
        let candidates: [StoredCredential]
        if allowList.isEmpty {
            candidates = store.credentials(rpId: rpId).filter(\.discoverable)
        } else {
            candidates = allowList.compactMap { store.credential(id: $0) }.filter { $0.rpId == rpId }
        }
        guard !candidates.isEmpty else { throw CTAPStatus.noCredentials }
        // A silent check (up = false) for existing credentials, as OpenSSH does
        // before enrolling a resident key, is answered above. A silent
        // signature is impossible: the key needs Touch ID.
        if p[5]?["up"]?.bool == false { throw CTAPStatus.unsupportedOption }
        // Checked before anything is shown, so a bad request never prompts.
        let hmacRequest = try p[4]?["hmac-secret"].map { try HmacSecretRequest($0, session: session) }

        let (decision, chosen) = await ui.chooseCredential(SignInPrompt(rpId: rpId, candidates: candidates))
        try check(decision)
        try Task.checkCancellation()
        guard let credential = chosen, candidates.contains(where: { $0.id == credential.id }) else {
            throw CTAPStatus.operationDenied
        }

        // The same Touch ID decrypts the secret and then signs (§10).
        var extensions: [CBOR.Pair] = []
        if let hmacRequest, let sealed = credential.hmacSecret {
            let credRandom: Data
            do {
                credRandom = try await keys.decrypt(id: credential.id, ciphertext: sealed,
                                                    reason: "Sign in to \(rpId)")
            } catch let status as CTAPStatus {
                throw status
            } catch {
                throw CTAPStatus.operationDenied
            }
            try Task.checkCancellation()
            extensions.append(.init(.text("hmac-secret"), .bytes(try hmacRequest.output(credRandom))))
        }

        let counter = try store.incrementCounter(id: credential.id)
        var authData = Self.rpIdHash(rpId)
        authData.append(Flags.up | Flags.uv | (extensions.isEmpty ? 0 : Flags.ed))
        authData += Self.counterBytes(counter)
        if !extensions.isEmpty {
            authData += CBOR.map(extensions).encoded
        }
        let signature = try await keys.sign(id: credential.id, data: authData + clientDataHash,
                                            reason: "Sign in to \(rpId)")

        var response: [CBOR.Pair] = [
            .init(.int(1), .map([.text("id"): .bytes(credential.id), .text("type"): .text("public-key")])),
            .init(.int(2), .bytes(authData)),
            .init(.int(3), .bytes(signature)),
        ]
        if credential.discoverable {
            var user: [CBOR.Pair] = [.init(.text("id"), .bytes(credential.userId))]
            if let name = credential.userName { user.append(.init(.text("name"), .text(name))) }
            if let display = credential.userDisplayName { user.append(.init(.text("displayName"), .text(display))) }
            response.append(.init(.int(4), .map(user)))
        }
        return .map(response)
    }

    // MARK: clientPIN

    /// Phase 3a: only getKeyAgreement. The PIN subcommands come in 3c, the
    /// token via Touch ID in 3b; until then they answer INVALID_SUBCOMMAND.
    private func clientPIN(_ p: CBOR, session: CTAPSession) throws -> CBOR {
        guard let number = p[1]?.int else { throw CTAPStatus.missingParameter }
        guard PinUvAuthProtocol(rawValue: number) != nil else { throw CTAPStatus.invalidParameter }
        guard let subCommand = p[2]?.int else { throw CTAPStatus.missingParameter }
        switch subCommand {
        case 0x02: // getKeyAgreement
            return .map([.int(1): PinUvAuthProtocol.coseKey(session.keyAgreementKey().publicKey)])
        default:
            throw CTAPStatus.invalidSubcommand
        }
    }

    /// A checked `hmac-secret` input of getAssertion (CTAP 2.1 §12.5).
    struct HmacSecretRequest {
        let pinUvAuthProtocol: PinUvAuthProtocol
        let sharedSecret: Data
        /// One or two 32-byte salts.
        let salts: [Data]

        init(_ input: CBOR, session: CTAPSession) throws {
            guard input.isMap else { throw CTAPStatus.invalidParameter }
            guard let proto = PinUvAuthProtocol(rawValue: input[4]?.int ?? 1) else {
                throw CTAPStatus.invalidParameter
            }
            let peer = try PinUvAuthProtocol.platformKey(input[1])
            guard let saltEnc = input[2]?.bytes, let saltAuth = input[3]?.bytes else {
                throw CTAPStatus.missingParameter
            }
            let shared = try proto.sharedSecret(session.keyAgreementKey(), with: peer)
            guard proto.verify(key: shared, message: saltEnc, signature: saltAuth) else {
                throw CTAPStatus.pinAuthInvalid
            }
            let plain = try proto.decrypt(key: shared, saltEnc)
            guard plain.count == 32 || plain.count == 64 else { throw CTAPStatus.invalidParameter }
            pinUvAuthProtocol = proto
            sharedSecret = shared
            salts = plain.count == 32 ? [plain] : [Data(plain.prefix(32)), Data(plain.suffix(32))]
        }

        /// encrypt(shared secret, HMAC-SHA-256(CredRandom, salt1) [|| … salt2]).
        func output(_ credRandom: Data) throws -> Data {
            let key = SymmetricKey(data: credRandom)
            let outputs = salts.map { Data(HMAC<SHA256>.authenticationCode(for: $0, using: key)) }
            return try pinUvAuthProtocol.encrypt(key: sharedSecret, outputs.reduce(Data(), +))
        }
    }

    // MARK: Helpers

    enum Flags {
        static let up: UInt8 = 0x01
        static let uv: UInt8 = 0x04
        static let at: UInt8 = 0x40
        static let ed: UInt8 = 0x80
    }

    private func required<T>(_ value: T?) throws -> T {
        guard let value else { throw CTAPStatus.missingParameter }
        return value
    }

    private func check(_ decision: UserDecision) throws {
        try Task.checkCancellation()
        switch decision {
        case .approved: return
        case .denied: throw CTAPStatus.operationDenied
        case .timedOut: throw CTAPStatus.userActionTimeout
        }
    }

    static func rpIdHash(_ rpId: String) -> Data {
        Data(SHA256.hash(data: Data(rpId.utf8)))
    }

    static func counterBytes(_ n: UInt32) -> Data {
        withUnsafeBytes(of: n.bigEndian) { Data($0) }
    }

    /// COSE_Key for an ES256 public key in x963 form (0x04 || x || y).
    static func coseKey(x963: Data) -> CBOR {
        let raw = [UInt8](x963)
        return .map([
            .int(1): .int(2),   // kty: EC2
            .int(3): .int(-7),  // alg: ES256
            .int(-1): .int(1),  // crv: P-256
            .int(-2): .bytes(Data(raw[1...32])),
            .int(-3): .bytes(Data(raw[33...64])),
        ])
    }
}
