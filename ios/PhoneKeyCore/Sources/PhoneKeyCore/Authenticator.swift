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
    case pinInvalid = 0x31
    case pinBlocked = 0x32
    case pinAuthInvalid = 0x33
    case pinAuthBlocked = 0x34
    case pinNotSet = 0x35
    case puatRequired = 0x36
    case pinPolicyViolation = 0x37
    case uvBlocked = 0x3C
    case invalidSubcommand = 0x3E
    case unauthorizedPermission = 0x40
    case other = 0x7F
}

/// A credential as the phone stores it. The private key lives elsewhere
/// (Secure Enclave), named by `id`.
public struct StoredCredential: Codable, Equatable, Identifiable, Sendable {
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
    /// Every stored credential (credential management).
    func allCredentials() -> [StoredCredential]
    /// Replaces the stored credential with the same ID.
    func update(_ credential: StoredCredential) throws
    /// Removes the metadata; the caller deletes the key.
    func delete(id: Data) throws
}

/// Creates and uses P-256 keys. In the app: Secure Enclave, Touch ID per signature.
public protocol CredentialKeys: AnyObject {
    /// Creates a key named `id` and returns its public key (x963, 65 bytes).
    func createKey(id: Data) throws -> Data
    /// Signs `data` (ECDSA P-256 SHA-256, DER). May ask for Touch ID; throws
    /// CTAPStatus.operationDenied when the user declines. `authorization` is
    /// the Touch ID of a pinUvAuthToken (from `AuthenticatorUI.authorizeToken`):
    /// with it, no new prompt; it serves this one operation and is used up.
    func sign(id: Data, data: Data, reason: String, authorization: TouchIDAuthorization?) async throws -> Data
    /// Encrypts to a public key (x963) with ECIES. Needs no Touch ID.
    func encrypt(toPublicKey x963: Data, plaintext: Data) throws -> Data
    /// Decrypts with the key. Like `sign`, it needs Touch ID; within one
    /// sign-in the same Touch ID covers both (docs/protocol.md §10). Called
    /// before `sign` in the same request, so it leaves `authorization` alive.
    func decrypt(id: Data, ciphertext: Data, reason: String, authorization: TouchIDAuthorization?) async throws -> Data
    /// The public key (x963) of a stored key, without Touch ID.
    func publicKey(id: Data) throws -> Data
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
    /// A pinUvAuthToken already carried the Touch ID: nothing to ask, only
    /// to note for the confirmation.
    public var verified = false
    /// A token from getPinToken, whose prompt could not name the site: show
    /// it and wait for a tap, no second Touch ID (§10).
    public var confirmByTap = false
}

public struct SignInPrompt: Equatable {
    public let rpId: String
    public let candidates: [StoredCredential]
    /// A pinUvAuthToken already carried the Touch ID: with one candidate
    /// nothing to ask, with several only which account (a tap).
    public var verified = false
    /// As for registration: a getPinToken token's first use shows the site.
    public var confirmByTap = false
}

/// getPinUvAuthTokenUsingUvWithPermissions: what the token is for.
public struct TokenPrompt: Equatable {
    public static let makeCredential: UInt8 = 0x01
    public static let getAssertion: UInt8 = 0x02
    public static let credentialManagement: UInt8 = 0x04

    public let permissions: UInt8
    public let rpId: String?

    /// Registering or signing in: the token's Touch ID must also unlock a
    /// signature, so it is evaluated for the keys' rule (§10).
    public var signs: Bool { permissions & (Self.makeCredential | Self.getAssertion) != 0 }
}

public enum TokenDecision {
    /// `authorization` unlocks one key operation when the token signs.
    case approved(authorization: TouchIDAuthorization?)
    case denied
    case timedOut
    /// iOS has locked Touch ID after failed attempts.
    case blocked
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
    /// A pinUvAuthToken via Touch ID: shows host, site and purpose, asks.
    func authorizeToken(_ prompt: TokenPrompt) async -> TokenDecision
    /// A PIN request (3c): shows what it is for and asks for Touch ID, which
    /// must be able to decrypt the stored PIN hash (and, for a token that
    /// signs, to sign once).
    func authorizePin(_ prompt: PinPrompt) async -> TokenDecision
    /// Credential management deletes a passkey: shows it, waits for a tap.
    func confirmDeletion(_ credential: StoredCredential) async -> UserDecision
    /// iOS has locked Touch ID after failed attempts.
    var touchIDLocked: Bool { get }
}

/// A CTAP 2.1 authenticator (docs/protocol.md §10, steps 3a to 3c):
/// `hmac-secret`, pinUvAuthToken via Touch ID, credential management, and a
/// PIN that only works together with Touch ID.
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
        case credentialManagement = 0x0A
        case selection = 0x0B
    }

    private let store: CredentialStore
    let keys: CredentialKeys
    let ui: AuthenticatorUI
    let pins: PinStorage
    let pinEpoch = PinEpoch()
    let random: (Int) -> Data
    let now: () -> Date

    public init(store: CredentialStore, keys: CredentialKeys, ui: AuthenticatorUI, pins: PinStorage,
                random: @escaping (Int) -> Data = { n in Data((0..<n).map { _ in UInt8.random(in: 0...255) }) },
                now: @escaping () -> Date = Date.init) {
        self.store = store
        self.keys = keys
        self.ui = ui
        self.pins = pins
        self.random = random
        self.now = now
    }

    /// Handles one CTAPHID CBOR message (command byte + parameters) from the
    /// host connection `session` and returns status byte + CBOR response.
    /// Never throws.
    public func handle(_ message: Data, session: CTAPSession) async -> Data {
        guard let byte = message.first else { return Data([CTAPStatus.invalidLength.rawValue]) }
        let params = Data(message.dropFirst())
        // Any other command ends a credential management enumeration.
        if byte != Command.credentialManagement.rawValue { session.endEnumeration() }
        do {
            let response: CBOR?
            switch Command(rawValue: byte) {
            case .getInfo:
                response = getInfo()
            case .makeCredential:
                response = try await makeCredential(try Self.parameters(params), session: session)
            case .getAssertion:
                response = try await getAssertion(try Self.parameters(params), session: session)
            case .clientPIN:
                response = try await clientPIN(try Self.parameters(params), session: session)
            case .credentialManagement:
                response = try await credentialManagement(try Self.parameters(params), raw: params, session: session)
            case .selection:
                try check(await ui.confirmSelection())
                response = nil
            case .getNextAssertion, .reset:
                throw CTAPStatus.notAllowed
            case nil:
                throw CTAPStatus.invalidCommand
            }
            try Task.checkCancellation()
            return Data([CTAPStatus.ok.rawValue]) + (response?.encoded ?? Data())
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
            .int(1): .array([.text("FIDO_2_0"), .text("FIDO_2_1")]),
            .int(2): .array([.text("credProtect"), .text("hmac-secret")]),
            .int(3): .bytes(Self.aaguid),
            .int(4): .map([.text("rk"): .bool(true), .text("up"): .bool(true),
                           .text("uv"): .bool(true), .text("plat"): .bool(false),
                           .text("clientPin"): .bool(pinIsSet),
                           .text("pinUvAuthToken"): .bool(true), .text("credMgmt"): .bool(true)]),
            .int(5): .int(Self.maxMessageSize),
            .int(6): .array([.int(2), .int(1)]),
            .int(7): .int(Self.maxCredentialCountInList),
            .int(8): .int(Self.credentialIdLength),
            .int(9): .array([.text("usb")]),
            .int(10): .array([.map([.text("alg"): .int(-7), .text("type"): .text("public-key")])]),
            .int(13): .int(Self.minPinLength),
            .int(17): .int(1), // preferredPlatformUvAttempts: Touch ID retries on its own
            .int(18): .int(2), // uvModality: fingerprint
        ])
    }

    // MARK: makeCredential

    private func makeCredential(_ p: CBOR, session: CTAPSession) async throws -> CBOR {
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

        var token: CTAPSession.TokenUse?
        // The token's mc/ga permissions serve this one operation, whatever
        // its outcome (CTAP 2.1 clears them on success; declining too).
        defer { if token != nil { session.consumeSigningPermissions() } }
        if let pinAuth = p[8] {
            guard let param = pinAuth.bytes else { throw CTAPStatus.invalidParameter }
            if param.isEmpty {
                // Zero length: authenticator selection.
                try check(await ui.confirmSelection())
                throw pinIsSet ? CTAPStatus.pinInvalid : CTAPStatus.pinNotSet
            }
            token = try session.useToken(param: param, protocolNumber: p[9]?.int, message: clientDataHash,
                                         permission: TokenPrompt.makeCredential, scope: .rpId(rpId),
                                         epoch: pinEpoch.current, now: now())
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

        var registration = RegistrationPrompt(
            rpId: rpId, rpName: rp["name"]?.text, userName: user["name"]?.text,
            userDisplayName: user["displayName"]?.text, passkey: passkey)
        registration.verified = token != nil
        registration.confirmByTap = token?.needsTap == true
        try check(await ui.confirmRegistration(registration))
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
        let silent = p[5]?["up"]?.bool == false
        var token: CTAPSession.TokenUse?
        // A silent assertion leaves the token's permissions (CTAP 2.1 clears
        // them only once user presence was collected).
        defer { if token != nil, !silent { session.consumeSigningPermissions() } }
        if let pinAuth = p[6] {
            guard let param = pinAuth.bytes else { throw CTAPStatus.invalidParameter }
            if param.isEmpty {
                // Zero length: authenticator selection, as for makeCredential.
                try check(await ui.confirmSelection())
                throw pinIsSet ? CTAPStatus.pinInvalid : CTAPStatus.pinNotSet
            }
            token = try session.useToken(param: param, protocolNumber: p[7]?.int, message: clientDataHash,
                                         permission: TokenPrompt.getAssertion, scope: .rpId(rpId),
                                         silent: silent, epoch: pinEpoch.current, now: now())
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
        // before enrolling a resident key, is answered above. Without a
        // token's Touch ID a silent signature is impossible: the key needs it.
        if silent, token?.authorization == nil { throw CTAPStatus.unsupportedOption }
        // Checked before anything is shown, so a bad request never prompts.
        let hmacRequest = try p[4]?["hmac-secret"].map { try HmacSecretRequest($0, session: session) }

        let credential: StoredCredential
        if silent {
            // Signed with the token's Touch ID, no card (Firefox checks this
            // way before signing in; §10, "Silent assertions").
            credential = candidates[0]
        } else {
            var signIn = SignInPrompt(rpId: rpId, candidates: candidates)
            signIn.verified = token != nil
            signIn.confirmByTap = token?.needsTap == true
            let (decision, chosen) = await ui.chooseCredential(signIn)
            try check(decision)
            try Task.checkCancellation()
            guard let chosen, candidates.contains(where: { $0.id == chosen.id }) else {
                throw CTAPStatus.operationDenied
            }
            credential = chosen
        }

        // The same Touch ID decrypts the secret and then signs (§10).
        var extensions: [CBOR.Pair] = []
        if let hmacRequest, let sealed = credential.hmacSecret {
            let credRandom: Data
            do {
                credRandom = try await keys.decrypt(id: credential.id, ciphertext: sealed,
                                                    reason: "Sign in to \(rpId)",
                                                    authorization: token?.authorization)
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
        authData.append((silent ? 0 : Flags.up) | Flags.uv | (extensions.isEmpty ? 0 : Flags.ed))
        authData += Self.counterBytes(counter)
        if !extensions.isEmpty {
            authData += CBOR.map(extensions).encoded
        }
        let signature = try await keys.sign(id: credential.id, data: authData + clientDataHash,
                                            reason: "Sign in to \(rpId)", authorization: token?.authorization)

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

    /// getKeyAgreement (3a), the token via Touch ID and getUVRetries (3b),
    /// and the PIN subcommands (3c, in ClientPin.swift).
    private func clientPIN(_ p: CBOR, session: CTAPSession) async throws -> CBOR? {
        guard let number = p[1]?.int else { throw CTAPStatus.missingParameter }
        guard let proto = PinUvAuthProtocol(rawValue: number) else { throw CTAPStatus.invalidParameter }
        guard let subCommand = p[2]?.int else { throw CTAPStatus.missingParameter }
        switch subCommand {
        case 0x01: // getPINRetries
            return try getPinRetries(session: session)
        case 0x02: // getKeyAgreement
            return .map([.int(1): PinUvAuthProtocol.coseKey(session.keyAgreementKey().publicKey)])
        case 0x03: // setPIN
            try await setPin(p, proto: proto, session: session)
            return nil
        case 0x04: // changePIN
            try await changePin(p, proto: proto, session: session)
            return nil
        case 0x05: // getPinToken
            return try await tokenUsingPin(p, proto: proto, session: session, withPermissions: false)
        case 0x06: // getPinUvAuthTokenUsingUvWithPermissions
            return try await tokenUsingTouchID(p, proto: proto, session: session)
        case 0x07: // getUVRetries: iOS counts Touch ID failures itself
            return .map([.int(5): .int(ui.touchIDLocked ? 0 : 8)])
        case 0x09: // getPinUvAuthTokenUsingPinWithPermissions
            return try await tokenUsingPin(p, proto: proto, session: session, withPermissions: true)
        default:
            throw CTAPStatus.invalidSubcommand
        }
    }

    private func tokenUsingTouchID(_ p: CBOR, proto: PinUvAuthProtocol, session: CTAPSession) async throws -> CBOR {
        guard p[3] != nil else { throw CTAPStatus.missingParameter }
        let prompt = try Self.tokenPrompt(p)
        if ui.touchIDLocked { throw CTAPStatus.uvBlocked }
        let shared = try sharedSecret(p, proto: proto, session: session)

        switch await ui.authorizeToken(prompt) {
        case let .approved(authorization):
            return try issueToken(prompt, proto: proto, shared: shared, session: session, authorization: authorization)
        case .denied:
            throw CTAPStatus.operationDenied
        case .timedOut:
            throw CTAPStatus.userActionTimeout
        case .blocked:
            throw CTAPStatus.uvBlocked
        }
    }

    // MARK: credentialManagement

    /// Lists and deletes discoverable credentials with a token that has the
    /// `cm` permission (§10). Only `deleteCredential` asks on the phone.
    private func credentialManagement(_ p: CBOR, raw: Data, session: CTAPSession) async throws -> CBOR? {
        guard let subCommand = p[1]?.int else { throw CTAPStatus.missingParameter }
        let params = p[2]
        // The MAC covers subCommandParams as the host encoded them.
        let rawParams = try? CBOR.rawValue(forKey: .int(2), inMap: raw)
        func authorize(_ scope: CTAPSession.TokenScope) throws {
            guard let param = p[4]?.bytes else { throw CTAPStatus.puatRequired }
            var message = Data([UInt8(truncatingIfNeeded: subCommand)])
            if let rawParams { message += rawParams }
            _ = try session.useToken(param: param, protocolNumber: p[3]?.int, message: message,
                                     permission: TokenPrompt.credentialManagement, scope: scope,
                                     epoch: pinEpoch.current, now: now())
        }
        let discoverable = store.allCredentials().filter(\.discoverable)

        switch subCommand {
        case 0x01: // getCredsMetadata
            try authorize(.unscoped)
            session.endEnumeration()
            return .map([.int(1): .int(discoverable.count), .int(2): .int(100)])

        case 0x02: // enumerateRPsBegin
            try authorize(.unscoped)
            let sites = Dictionary(grouping: discoverable, by: \.rpId)
                .map { CTAPSession.Site(id: $0.key, name: $0.value.lazy.compactMap(\.rpName).first) }
                .sorted { $0.id < $1.id }
            guard let first = sites.first else { session.endEnumeration(); throw CTAPStatus.noCredentials }
            session.beginEnumeration(sites: Array(sites.dropFirst()))
            return .map(Self.siteEntry(first) + [.init(.int(5), .int(sites.count))])

        case 0x03: // enumerateRPsGetNextRP
            guard let site = session.nextSite() else { throw CTAPStatus.notAllowed }
            return .map(Self.siteEntry(site))

        case 0x04: // enumerateCredentialsBegin
            guard let rpIdHash = params?[1]?.bytes else { throw CTAPStatus.missingParameter }
            try authorize(.rpIdHash(rpIdHash))
            let credentials = discoverable.filter { Self.rpIdHash($0.rpId) == rpIdHash }
                .sorted { $0.created < $1.created }
            guard let first = credentials.first else { session.endEnumeration(); throw CTAPStatus.noCredentials }
            let entry = try credentialEntry(first) + [.init(.int(9), .int(credentials.count))]
            session.beginEnumeration(credentials: Array(credentials.dropFirst()))
            return .map(entry)

        case 0x05: // enumerateCredentialsGetNextCredential
            guard let credential = session.nextCredential() else { throw CTAPStatus.notAllowed }
            return .map(try credentialEntry(credential))

        case 0x06: // deleteCredential
            session.endEnumeration()
            guard let id = params?[2]?["id"]?.bytes else { throw CTAPStatus.missingParameter }
            // The token first, so only an authorised host learns whether the ID exists.
            let found = store.credential(id: id).flatMap { $0.discoverable ? $0 : nil }
            try authorize(found.map { .rpId($0.rpId) } ?? .any)
            guard let credential = found else { throw CTAPStatus.noCredentials }
            // Deleting is final and keys have no backup: the phone asks.
            try check(await ui.confirmDeletion(credential))
            try store.delete(id: id)
            keys.deleteKey(id: id)
            return nil

        case 0x07: // updateUserInformation
            session.endEnumeration()
            guard let id = params?[2]?["id"]?.bytes, let user = params?[3], user.isMap else {
                throw CTAPStatus.missingParameter
            }
            let found = store.credential(id: id).flatMap { $0.discoverable ? $0 : nil }
            try authorize(found.map { .rpId($0.rpId) } ?? .any)
            guard var credential = found else { throw CTAPStatus.noCredentials }
            guard user["id"]?.bytes == credential.userId else { throw CTAPStatus.invalidParameter }
            credential.userName = user["name"]?.text
            credential.userDisplayName = user["displayName"]?.text
            try store.update(credential)
            return nil

        default:
            session.endEnumeration()
            throw CTAPStatus.invalidSubcommand
        }
    }

    private static func siteEntry(_ site: CTAPSession.Site) -> [CBOR.Pair] {
        var rp: [CBOR.Pair] = [.init(.text("id"), .text(site.id))]
        if let name = site.name { rp.append(.init(.text("name"), .text(name))) }
        return [.init(.int(3), .map(rp)), .init(.int(4), .bytes(rpIdHash(site.id)))]
    }

    /// user as the site stored it (names given on the phone stay there),
    /// credential ID, public key and credProtect.
    private func credentialEntry(_ credential: StoredCredential) throws -> [CBOR.Pair] {
        var user: [CBOR.Pair] = [.init(.text("id"), .bytes(credential.userId))]
        if let name = credential.userName { user.append(.init(.text("name"), .text(name))) }
        if let display = credential.userDisplayName { user.append(.init(.text("displayName"), .text(display))) }
        var entry: [CBOR.Pair] = [
            .init(.int(6), .map(user)),
            .init(.int(7), .map([.text("id"): .bytes(credential.id), .text("type"): .text("public-key")])),
            .init(.int(8), Self.coseKey(x963: try keys.publicKey(id: credential.id))),
        ]
        if let credProtect = credential.credProtect { entry.append(.init(.int(10), .int(credProtect))) }
        return entry
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
