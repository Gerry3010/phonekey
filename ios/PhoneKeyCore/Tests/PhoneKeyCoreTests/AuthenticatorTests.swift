import CryptoKit
import XCTest
@testable import PhoneKeyCore

// MARK: Test doubles

final class MemoryStore: CredentialStore {
    var items: [StoredCredential] = []

    func credentials(rpId: String) -> [StoredCredential] { items.filter { $0.rpId == rpId } }
    func credential(id: Data) -> StoredCredential? { items.first { $0.id == id } }
    func save(_ credential: StoredCredential, replacing: [Data]) throws {
        items.removeAll { replacing.contains($0.id) }
        items.append(credential)
    }
    func incrementCounter(id: Data) throws -> UInt32 {
        guard let i = items.firstIndex(where: { $0.id == id }) else { throw CTAPStatus.noCredentials }
        items[i].signCount += 1
        return items[i].signCount
    }
    func allCredentials() -> [StoredCredential] { items }
    func update(_ credential: StoredCredential) throws {
        guard let i = items.firstIndex(where: { $0.id == credential.id }) else { throw CTAPStatus.noCredentials }
        items[i] = credential
    }
    func delete(id: Data) throws { items.removeAll { $0.id == id } }
}

final class SoftwareKeys: CredentialKeys {
    var keys: [Data: P256.Signing.PrivateKey] = [:]
    var denySigning = false

    func createKey(id: Data) throws -> Data {
        let key = P256.Signing.PrivateKey()
        keys[id] = key
        return key.publicKey.x963Representation
    }

    /// The authorization the last sign/decrypt got (a token's Touch ID).
    var lastAuthorization: AnyObject?

    func sign(id: Data, data: Data, reason: String, authorization: TouchIDAuthorization?) async throws -> Data {
        lastAuthorization = authorization
        if denySigning { throw CTAPStatus.operationDenied }
        guard let key = keys[id] else { throw CTAPStatus.noCredentials }
        return try key.signature(for: data).derRepresentation
    }

    /// Stands in for ECIES: the "ciphertext" is a random handle for the
    /// plaintext, so tests can check which secret was used.
    var sealed: [Data: Data] = [:]
    var denyDecrypt = false
    var decryptCalls = 0

    func encrypt(toPublicKey x963: Data, plaintext: Data) throws -> Data {
        guard keys.values.contains(where: { $0.publicKey.x963Representation == x963 }) else {
            throw CTAPStatus.noCredentials
        }
        let handle = Data((0..<48).map { _ in UInt8.random(in: 0...255) })
        sealed[handle] = plaintext
        return handle
    }

    func decrypt(id: Data, ciphertext: Data, reason: String, authorization: TouchIDAuthorization?) async throws -> Data {
        decryptCalls += 1
        if denyDecrypt { throw CTAPStatus.operationDenied }
        guard keys[id] != nil, let plain = sealed[ciphertext] else { throw CTAPStatus.noCredentials }
        return plain
    }

    func publicKey(id: Data) throws -> Data {
        guard let key = keys[id] else { throw CTAPStatus.noCredentials }
        return key.publicKey.x963Representation
    }

    func deleteKey(id: Data) { keys[id] = nil }
}

final class ScriptedUI: AuthenticatorUI {
    var decision: UserDecision = .approved
    /// Picks a candidate by index; nil picks nothing.
    var pick: Int? = 0
    var registrations: [RegistrationPrompt] = []
    var signIns: [SignInPrompt] = []
    var waitForCancel = false

    func confirmRegistration(_ prompt: RegistrationPrompt) async -> UserDecision {
        registrations.append(prompt)
        if waitForCancel {
            while !Task.isCancelled { try? await Task.sleep(nanoseconds: 5_000_000) }
            return .denied
        }
        return decision
    }

    func chooseCredential(_ prompt: SignInPrompt) async -> (UserDecision, StoredCredential?) {
        signIns.append(prompt)
        return (decision, pick.map { prompt.candidates[$0] })
    }

    func acknowledgeExcluded(rpId: String) async -> UserDecision { decision }
    func confirmSelection() async -> UserDecision { decision }

    /// Stands in for the LAContext of the token's Touch ID.
    final class Authorization: TouchIDAuthorization {
        var invalidated = false
        func invalidate() { invalidated = true }
    }
    var tokenDecision: TokenDecision = .approved(authorization: Authorization())
    var tokenPrompts: [TokenPrompt] = []
    var deletions: [StoredCredential] = []
    var touchIDLocked = false

    func authorizeToken(_ prompt: TokenPrompt) async -> TokenDecision {
        tokenPrompts.append(prompt)
        return tokenDecision
    }

    func confirmDeletion(_ credential: StoredCredential) async -> UserDecision {
        deletions.append(credential)
        return decision
    }
}

// MARK: Tests

final class AuthenticatorTests: XCTestCase {
    private var store: MemoryStore!
    private var keys: SoftwareKeys!
    private var ui: ScriptedUI!
    private var authenticator: Authenticator!
    private var session: CTAPSession!
    private let clientDataHash = Data(SHA256.hash(data: Data("client data".utf8)))

    override func setUp() {
        store = MemoryStore()
        keys = SoftwareKeys()
        ui = ScriptedUI()
        authenticator = Authenticator(store: store, keys: keys, ui: ui, now: { [unowned self] in self.clock })
        session = CTAPSession()
    }

    /// The authenticator's clock, for token lifetimes.
    private var clock = Date(timeIntervalSince1970: 1_000_000)

    private func call(_ command: UInt8, _ params: CBOR?) async -> (UInt8, CBOR?) {
        let response = await authenticator.handle(Data([command]) + (params?.encoded ?? Data()), session: session)
        let body = response.count > 1 ? try? CBOR.decode(Data(response.dropFirst())) : nil
        return (response[0], body)
    }

    private func makeCredentialParams(rk: Bool, user: String = "gerry", exclude: [Data] = [],
                                      algs: [Int] = [-7], hmacSecret: Bool = false) -> CBOR {
        var pairs: [CBOR.Pair] = [
            .init(.int(1), .bytes(clientDataHash)),
            .init(.int(2), .map([.text("id"): .text("github.com"), .text("name"): .text("GitHub")])),
            .init(.int(3), .map([.text("id"): .bytes(Data(user.utf8)), .text("name"): .text(user),
                                 .text("displayName"): .text(user.capitalized)])),
            .init(.int(4), .array(algs.map { .map([.text("alg"): .int($0), .text("type"): .text("public-key")]) })),
            .init(.int(7), .map([.text("rk"): .bool(rk)])),
        ]
        if !exclude.isEmpty {
            pairs.append(.init(.int(5), .array(exclude.map { .map([.text("id"): .bytes($0), .text("type"): .text("public-key")]) })))
        }
        if hmacSecret {
            pairs.append(.init(.int(6), .map([.text("hmac-secret"): .bool(true)])))
        }
        return .map(pairs)
    }

    private func register(rk: Bool, user: String = "gerry") async throws -> (credentialId: Data, publicKey: P256.Signing.PublicKey) {
        let (status, body) = await call(0x01, makeCredentialParams(rk: rk, user: user))
        XCTAssertEqual(status, 0x00)
        let authData = try XCTUnwrap(body?[2]?.bytes)
        XCTAssertEqual(body?[1]?.text, "none")
        XCTAssertEqual(body?[3], .map([]))

        let bytes = [UInt8](authData)
        XCTAssertEqual(Data(bytes[0..<32]), Authenticator.rpIdHash("github.com"))
        XCTAssertEqual(bytes[32], 0x45, "flags UP|UV|AT")
        XCTAssertEqual(Array(bytes[33..<37]), [0, 0, 0, 0], "counter")
        XCTAssertEqual(Data(bytes[37..<53]), Authenticator.aaguid)
        let idLength = Int(bytes[53]) << 8 | Int(bytes[54])
        XCTAssertEqual(idLength, 32)
        let credentialId = Data(bytes[55..<55 + idLength])
        let cose = try CBOR.decode(Data(bytes[(55 + idLength)...]))
        XCTAssertEqual(cose[1]?.int, 2)
        XCTAssertEqual(cose[3]?.int, -7)
        XCTAssertEqual(cose[-1]?.int, 1)
        let x963 = Data([0x04]) + (try XCTUnwrap(cose[-2]?.bytes)) + (try XCTUnwrap(cose[-3]?.bytes))
        return (credentialId, try P256.Signing.PublicKey(x963Representation: x963))
    }

    func testGetInfo() async throws {
        let (status, info) = await call(0x04, nil)
        XCTAssertEqual(status, 0)
        XCTAssertEqual(info?[1], .array([.text("FIDO_2_0"), .text("FIDO_2_1")]))
        XCTAssertEqual(info?[3]?.bytes, Authenticator.aaguid)
        XCTAssertEqual(info?[4]?["rk"], .bool(true))
        XCTAssertEqual(info?[4]?["uv"], .bool(true))
        XCTAssertNil(info?[4]?["clientPin"])
        XCTAssertEqual(info?[10]?.array?.first?["alg"]?.int, -7)
        // Chrome batches allow lists only with both of these (§10).
        XCTAssertEqual(info?[7]?.int, 16)
        XCTAssertEqual(info?[8]?.int, 32)
    }

    /// Credentials saved before `lastUsed` and `suggested` existed still load.
    func testStoredCredentialDecodesOlderData() throws {
        let old = #"{"id":"AQI=","rpId":"github.com","userId":"Aw==","userName":"gerry","discoverable":true,"created":700000000,"signCount":3}"#
        let credential = try JSONDecoder().decode(StoredCredential.self, from: Data(old.utf8))
        XCTAssertEqual(credential.rpId, "github.com")
        XCTAssertEqual(credential.signCount, 3)
        XCTAssertNil(credential.lastUsed)
        XCTAssertNil(credential.suggested)
    }

    /// Registering a passkey again for the same account replaces the old one
    /// (CTAP 2.1); another account and non-discoverable keys stay.
    func testNewPasskeyReplacesSameAccount() async throws {
        let (first, _) = try await register(rk: true)
        store.items[0].suggested = true
        store.items[0].localName = "Private"
        let (other, _) = try await register(rk: true, user: "other")
        let (nonResident, _) = try await register(rk: false)
        let (second, _) = try await register(rk: true)

        let ids = store.credentials(rpId: "github.com").map(\.id)
        XCTAssertFalse(ids.contains(first), "the old passkey is replaced")
        XCTAssertTrue(ids.contains(second))
        XCTAssertTrue(ids.contains(other))
        XCTAssertTrue(ids.contains(nonResident))
        XCTAssertEqual(store.credentials(rpId: "github.com").filter { $0.discoverable && $0.userName == "gerry" }.count, 1)
        XCTAssertNil(keys.keys[first], "its key is deleted")
        XCTAssertNotNil(keys.keys[second])
        XCTAssertEqual(store.credential(id: second)?.suggested, true, "keeps the suggestion")
        XCTAssertEqual(store.credential(id: second)?.accountLabel, "Private", "keeps the user's own name")
    }

    /// A full batch, as Chrome sends it after reading getInfo 7 and 8, fits the
    /// message size and finds the credential among foreign IDs.
    func testFullAllowListBatch() async throws {
        let (credentialId, _) = try await register(rk: false)
        XCTAssertEqual(credentialId.count, Authenticator.credentialIdLength)
        func descriptor(_ id: Data) -> CBOR { .map([.text("id"): .bytes(id), .text("type"): .text("public-key")]) }
        let foreign = (0..<(Authenticator.maxCredentialCountInList - 1)).map { _ in
            Data((0..<Authenticator.credentialIdLength).map { _ in UInt8.random(in: 0...255) })
        }
        let allow = CBOR.array((foreign + [credentialId]).map(descriptor))

        let (status, body) = await call(0x02, .map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash),
                                                    .int(3): allow]))
        XCTAssertEqual(status, 0)
        XCTAssertEqual(body?[1]?["id"]?.bytes, credentialId)

        // Even with the longest possible RP ID the request stays within maxMsgSize.
        let longest = CBOR.map([.int(1): .text(String(repeating: "a", count: 253)), .int(2): .bytes(clientDataHash),
                                .int(3): allow, .int(5): .map([.text("up"): .bool(true)])])
        XCTAssertLessThan(1 + longest.encoded.count, Authenticator.maxMessageSize)
    }

    func testPasskeyRegistrationAndSignIn() async throws {
        let (credentialId, publicKey) = try await register(rk: true)
        XCTAssertEqual(ui.registrations.first?.passkey, true)
        XCTAssertEqual(ui.registrations.first?.userName, "gerry")

        for expectedCounter in [UInt8(1), 2] {
            let (status, body) = await call(0x02, .map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash)]))
            XCTAssertEqual(status, 0)
            XCTAssertEqual(body?[1]?["id"]?.bytes, credentialId)
            let authData = try XCTUnwrap(body?[2]?.bytes)
            XCTAssertEqual(authData.count, 37)
            XCTAssertEqual(authData[authData.startIndex + 32], 0x05, "flags UP|UV")
            XCTAssertEqual(authData.last, expectedCounter)
            let signature = try P256.Signing.ECDSASignature(derRepresentation: try XCTUnwrap(body?[3]?.bytes))
            XCTAssertTrue(publicKey.isValidSignature(signature, for: authData + clientDataHash))
            XCTAssertEqual(body?[4]?["id"]?.bytes, Data("gerry".utf8))
            XCTAssertEqual(body?[4]?["name"]?.text, "gerry")
            XCTAssertNil(body?[5], "no numberOfCredentials: the phone picks")
        }
    }

    func testSecurityKeyNeedsAllowList() async throws {
        let (credentialId, publicKey) = try await register(rk: false)
        let (status, _) = await call(0x02, .map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash)]))
        XCTAssertEqual(status, CTAPStatus.noCredentials.rawValue, "not discoverable")

        let allow = CBOR.array([.map([.text("id"): .bytes(credentialId), .text("type"): .text("public-key")])])
        let (ok, body) = await call(0x02, .map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash), .int(3): allow]))
        XCTAssertEqual(ok, 0)
        XCTAssertNil(body?[4], "no user for non-discoverable credentials")
        let signature = try P256.Signing.ECDSASignature(derRepresentation: try XCTUnwrap(body?[3]?.bytes))
        XCTAssertTrue(publicKey.isValidSignature(signature, for: try XCTUnwrap(body?[2]?.bytes) + clientDataHash))

        let (other, _) = await call(0x02, .map([.int(1): .text("evil.example"), .int(2): .bytes(clientDataHash), .int(3): allow]))
        XCTAssertEqual(other, CTAPStatus.noCredentials.rawValue, "credential bound to its rpId")
    }

    func testSeveralPasskeysThePhonePicks() async throws {
        _ = try await register(rk: true, user: "alice")
        let (bobId, _) = try await register(rk: true, user: "bob")
        ui.pick = 1
        let (status, body) = await call(0x02, .map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash)]))
        XCTAssertEqual(status, 0)
        XCTAssertEqual(ui.signIns.last?.candidates.count, 2)
        XCTAssertEqual(body?[1]?["id"]?.bytes, bobId)
    }

    func testExcludeList() async throws {
        let (credentialId, _) = try await register(rk: false)
        let (status, _) = await call(0x01, makeCredentialParams(rk: false, exclude: [credentialId]))
        XCTAssertEqual(status, CTAPStatus.credentialExcluded.rawValue)
        XCTAssertEqual(store.items.count, 1)
    }

    func testSilentLookup() async throws {
        let silent = CBOR.map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash),
                               .int(5): .map([.text("up"): .bool(false)])])
        var (status, _) = await call(0x02, silent)
        XCTAssertEqual(status, CTAPStatus.noCredentials.rawValue, "lookup without credentials needs no signature")
        XCTAssertTrue(ui.signIns.isEmpty, "and no prompt")
        _ = try await register(rk: true)
        (status, _) = await call(0x02, silent)
        XCTAssertEqual(status, CTAPStatus.unsupportedOption.rawValue)
        XCTAssertTrue(ui.signIns.isEmpty)
    }

    func testErrors() async throws {
        var (status, _) = await call(0x01, makeCredentialParams(rk: false, algs: [-8]))
        XCTAssertEqual(status, CTAPStatus.unsupportedAlgorithm.rawValue)

        ui.decision = .denied
        (status, _) = await call(0x01, makeCredentialParams(rk: true))
        XCTAssertEqual(status, CTAPStatus.operationDenied.rawValue)
        ui.decision = .timedOut
        (status, _) = await call(0x01, makeCredentialParams(rk: true))
        XCTAssertEqual(status, CTAPStatus.userActionTimeout.rawValue)
        XCTAssertTrue(store.items.isEmpty)
        ui.decision = .approved

        _ = try await register(rk: true)
        (status, _) = await call(0x02, .map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash),
                                             .int(5): .map([.text("up"): .bool(false)])]))
        XCTAssertEqual(status, CTAPStatus.unsupportedOption.rawValue)
        keys.denySigning = true
        (status, _) = await call(0x02, .map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash)]))
        XCTAssertEqual(status, CTAPStatus.operationDenied.rawValue)

        (status, _) = await call(0x07, nil)
        XCTAssertEqual(status, CTAPStatus.notAllowed.rawValue, "reset only in the app")
        (status, _) = await call(0x08, nil)
        XCTAssertEqual(status, CTAPStatus.notAllowed.rawValue)
        (status, _) = await call(0x06, .map([.int(1): .int(1)]))
        XCTAssertEqual(status, CTAPStatus.missingParameter.rawValue, "clientPIN without subCommand (3a)")
        (status, _) = await call(0x42, nil)
        XCTAssertEqual(status, CTAPStatus.invalidCommand.rawValue)
        let raw = await authenticator.handle(Data([0x01, 0xA1, 0x01]), session: session)
        XCTAssertEqual(raw, Data([CTAPStatus.invalidCBOR.rawValue]))
        (status, _) = await call(0x02, .map([.int(1): .text("github.com")]))
        XCTAssertEqual(status, CTAPStatus.missingParameter.rawValue)
        (status, _) = await call(0x01, .array([]))
        XCTAssertEqual(status, CTAPStatus.cborUnexpectedType.rawValue)
    }

    func testCredProtectIsStoredAndEchoed() async throws {
        var params = makeCredentialParams(rk: true)
        if case var .map(pairs) = params {
            pairs.append(.init(.int(6), .map([.text("credProtect"): .int(2), .text("hmac-secret"): .bool(true)])))
            params = .map(pairs)
        }
        let (status, body) = await call(0x01, params)
        XCTAssertEqual(status, 0)
        let authData = [UInt8](try XCTUnwrap(body?[2]?.bytes))
        XCTAssertEqual(authData[32], 0xC5, "flags UP|UV|AT|ED")
        // Extensions follow the COSE key: {"credProtect": 2, "hmac-secret": true} (3a).
        XCTAssertEqual(Data(authData.suffix(27)),
                       hex("a2" + "6b6372656450726f74656374" + "02" + "6b686d61632d736563726574" + "f5"))
        XCTAssertEqual(store.items.first?.credProtect, 2)

        let (info, getInfo) = await call(0x04, nil)
        XCTAssertEqual(info, 0)
        XCTAssertEqual(getInfo?[2], .array([.text("credProtect"), .text("hmac-secret")]))

        // A level-2 passkey is still found without an allow list: Touch ID is always done.
        let (signIn, _) = await call(0x02, .map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash)]))
        XCTAssertEqual(signIn, 0)
    }

    func testAuthenticatorSelection() async throws {
        var params = makeCredentialParams(rk: false)
        if case var .map(pairs) = params {
            pairs.append(.init(.int(8), .bytes(Data())))
            pairs.append(.init(.int(9), .int(1)))
            params = .map(pairs)
        }
        let (status, _) = await call(0x01, params)
        XCTAssertEqual(status, CTAPStatus.pinNotSet.rawValue)
        XCTAssertTrue(store.items.isEmpty)
    }

    func testCancelWhileWaiting() async throws {
        ui.waitForCancel = true
        let params = makeCredentialParams(rk: true).encoded
        let session = self.session!
        let task = Task { await self.authenticator.handle(Data([0x01]) + params, session: session) }
        try await Task.sleep(nanoseconds: 50_000_000)
        task.cancel()
        let response = await task.value
        XCTAssertEqual(response, Data([CTAPStatus.keepaliveCancel.rawValue]))
        XCTAssertTrue(store.items.isEmpty)
    }
    // MARK: Phase 3a: PIN/UV auth protocols and hmac-secret

    func testGetInfoPhase3() async {
        let (_, info) = await call(0x04, nil)
        XCTAssertEqual(info?[1], .array([.text("FIDO_2_0"), .text("FIDO_2_1")]))
        XCTAssertEqual(info?[6], .array([.int(2), .int(1)]))
        XCTAssertNil(info?[4]?["clientPin"], "no PIN before 3c")
        XCTAssertEqual(info?[4]?["pinUvAuthToken"], .bool(true))
        XCTAssertEqual(info?[4]?["credMgmt"], .bool(true))
        XCTAssertNil(info?[4]?["alwaysUv"])
        XCTAssertNil(info?[4]?["makeCredUvNotRqd"])
        XCTAssertEqual(info?[17]?.int, 1)
        XCTAssertEqual(info?[18]?.int, 2)
    }

    func testGetKeyAgreementPerSession() async throws {
        let params = CBOR.map([.int(1): .int(2), .int(2): .int(2)])
        let (status, body) = await call(0x06, params)
        XCTAssertEqual(status, 0)
        let cose = try XCTUnwrap(body?[1])
        XCTAssertEqual(cose[1]?.int, 2)
        XCTAssertEqual(cose[3]?.int, -25)
        XCTAssertEqual(cose[-1]?.int, 1)
        let (_, again) = await call(0x06, .map([.int(1): .int(1), .int(2): .int(2)]))
        XCTAssertEqual(again?[1], cose, "same key within the session, for both protocols")
        session = CTAPSession()
        let (_, other) = await call(0x06, params)
        XCTAssertNotEqual(other?[1], cose, "a new session has its own key")
    }

    func testClientPINErrors() async {
        var (status, _) = await call(0x06, .map([.int(2): .int(2)]))
        XCTAssertEqual(status, CTAPStatus.missingParameter.rawValue)
        (status, _) = await call(0x06, .map([.int(1): .int(3), .int(2): .int(2)]))
        XCTAssertEqual(status, CTAPStatus.invalidParameter.rawValue)
        (status, _) = await call(0x06, .map([.int(1): .int(2)]))
        XCTAssertEqual(status, CTAPStatus.missingParameter.rawValue)
        for subCommand in [0x01, 0x03, 0x04, 0x05, 0x09] {
            (status, _) = await call(0x06, .map([.int(1): .int(1), .int(2): .int(subCommand)]))
            XCTAssertEqual(status, CTAPStatus.invalidSubcommand.rawValue, "subCommand \(subCommand)")
        }
    }

    /// Phase 2 answered 0x36 (PUAT_REQUIRED) here; PIN_AUTH_INVALID is 0x33.
    func testNonEmptyPinUvAuthParamIsPinAuthInvalid() async throws {
        var params = makeCredentialParams(rk: true)
        if case var .map(pairs) = params {
            pairs.append(.init(.int(8), .bytes(Data(repeating: 1, count: 16))))
            pairs.append(.init(.int(9), .int(1)))
            params = .map(pairs)
        }
        var (status, _) = await call(0x01, params)
        XCTAssertEqual(status, 0x33)
        (status, _) = await call(0x02, .map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash),
                                             .int(6): .bytes(Data(repeating: 1, count: 16)), .int(7): .int(1)]))
        XCTAssertEqual(status, 0x33)
        (status, _) = await call(0x02, .map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash),
                                             .int(6): .bytes(Data())]))
        XCTAssertEqual(status, CTAPStatus.pinNotSet.rawValue, "zero length: authenticator selection")
    }

    /// What a platform sends for hmac-secret: its key agreement key and the
    /// salts, encrypted and authenticated with the shared secret.
    private func hmacSecretInput(_ proto: PinUvAuthProtocol, salts: [Data],
                                 tamper: Bool = false) async throws -> (input: CBOR, shared: Data) {
        let (_, ka) = await call(0x06, .map([.int(1): .int(proto.rawValue), .int(2): .int(2)]))
        let cose = try XCTUnwrap(ka?[1])
        let x963 = Data([0x04]) + (try XCTUnwrap(cose[-2]?.bytes)) + (try XCTUnwrap(cose[-3]?.bytes))
        let phoneKey = try P256.KeyAgreement.PublicKey(x963Representation: x963)
        let platform = P256.KeyAgreement.PrivateKey()
        let shared = try proto.sharedSecret(platform, with: phoneKey)
        let saltEnc = try proto.encrypt(key: shared, salts.reduce(Data(), +))
        var saltAuth = proto.authenticate(key: shared, saltEnc)
        if tamper { saltAuth[saltAuth.startIndex] ^= 1 }
        let raw = [UInt8](platform.publicKey.x963Representation)
        let platformKey = CBOR.map([.int(1): .int(2), .int(3): .int(-25), .int(-1): .int(1),
                                    .int(-2): .bytes(Data(raw[1...32])), .int(-3): .bytes(Data(raw[33...64]))])
        var input: [CBOR.Pair] = [.init(.int(1), platformKey), .init(.int(2), .bytes(saltEnc)),
                                  .init(.int(3), .bytes(saltAuth))]
        if proto == .two { input.append(.init(.int(4), .int(2))) }
        return (.map(input), shared)
    }

    private func registerWithHmacSecret() async throws -> (id: Data, publicKey: P256.Signing.PublicKey) {
        let (status, body) = await call(0x01, makeCredentialParams(rk: true, hmacSecret: true))
        XCTAssertEqual(status, 0)
        let authData = try XCTUnwrap(body?[2]?.bytes)
        XCTAssertEqual(authData[authData.startIndex + 32], 0xC5, "flags UP|UV|AT|ED")
        XCTAssertTrue(authData.suffix(from: authData.startIndex)
            .ends(with: CBOR.map([.text("hmac-secret"): .bool(true)]).encoded))
        let stored = try XCTUnwrap(store.items.last)
        XCTAssertNotNil(stored.hmacSecret)
        let x963 = try XCTUnwrap(keys.keys[stored.id]?.publicKey.x963Representation)
        return (stored.id, try P256.Signing.PublicKey(x963Representation: x963))
    }

    private func assertion(hmac input: CBOR) async -> (UInt8, CBOR?) {
        await call(0x02, .map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash),
                               .int(4): .map([.text("hmac-secret"): input])]))
    }

    func testHmacSecretBothProtocols() async throws {
        for proto in PinUvAuthProtocol.allCases {
            // Fresh state per protocol (setUp() would pick XCTest's async variant here).
            store = MemoryStore()
            keys = SoftwareKeys()
            ui = ScriptedUI()
            authenticator = Authenticator(store: store, keys: keys, ui: ui)
            session = CTAPSession()
            let (id, publicKey) = try await registerWithHmacSecret()
            let credRandom = try XCTUnwrap(keys.sealed[try XCTUnwrap(store.credential(id: id)?.hmacSecret)])
            let salt1 = Data(repeating: 0xA1, count: 32), salt2 = Data(repeating: 0xB2, count: 32)
            func expected(_ salt: Data) -> Data {
                Data(HMAC<SHA256>.authenticationCode(for: salt, using: SymmetricKey(data: credRandom)))
            }

            var outputs: [Data] = []
            for salts in [[salt1], [salt1], [salt1, salt2]] {
                let (input, shared) = try await hmacSecretInput(proto, salts: salts)
                let (status, body) = await assertion(hmac: input)
                XCTAssertEqual(status, 0, "\(proto)")
                let authData = try XCTUnwrap(body?[2]?.bytes)
                XCTAssertEqual(authData[authData.startIndex + 32], 0x85, "flags UP|UV|ED")
                let extensions = try CBOR.decode(Data(authData.dropFirst(37)))
                let encrypted = try XCTUnwrap(extensions["hmac-secret"]?.bytes)
                let output = try proto.decrypt(key: shared, encrypted)
                XCTAssertEqual(output, salts.map(expected).reduce(Data(), +), "\(proto)")
                outputs.append(output)
                // The extension is part of the signed data.
                let signature = try P256.Signing.ECDSASignature(derRepresentation: try XCTUnwrap(body?[3]?.bytes))
                XCTAssertTrue(publicKey.isValidSignature(signature, for: authData + clientDataHash))
            }
            XCTAssertEqual(outputs[0], outputs[1], "same salt, same secret: stable for LUKS")
            XCTAssertEqual(outputs[2].count, 64)
            XCTAssertEqual(keys.decryptCalls, 3)
        }
    }

    func testHmacSecretBadInput() async throws {
        _ = try await registerWithHmacSecret()
        let (tampered, _) = try await hmacSecretInput(.two, salts: [Data(count: 32)], tamper: true)
        var (status, _) = await assertion(hmac: tampered)
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue)
        let (short, _) = try await hmacSecretInput(.one, salts: [Data(count: 16)])
        (status, _) = await assertion(hmac: short)
        XCTAssertEqual(status, CTAPStatus.invalidParameter.rawValue)
        XCTAssertTrue(ui.signIns.isEmpty, "bad input never prompts")
        XCTAssertEqual(keys.decryptCalls, 0)
    }

    func testHmacSecretDecryptDeclined() async throws {
        _ = try await registerWithHmacSecret()
        keys.denyDecrypt = true
        let (input, _) = try await hmacSecretInput(.two, salts: [Data(count: 32)])
        let (status, _) = await assertion(hmac: input)
        XCTAssertEqual(status, CTAPStatus.operationDenied.rawValue)
    }

    func testHmacSecretWithoutRegistrationExtension() async throws {
        _ = try await register(rk: true)
        let (input, _) = try await hmacSecretInput(.one, salts: [Data(count: 32)])
        let (status, body) = await assertion(hmac: input)
        XCTAssertEqual(status, 0)
        let authData = try XCTUnwrap(body?[2]?.bytes)
        XCTAssertEqual(authData.count, 37, "no extension output")
        XCTAssertEqual(authData[authData.startIndex + 32], 0x05)
        XCTAssertEqual(keys.decryptCalls, 0)
    }

    // MARK: Phase 3b: pinUvAuthToken via Touch ID, selection, credential management

    /// What a platform does for a token: key agreement, then
    /// getPinUvAuthTokenUsingUvWithPermissions, then decrypting the token.
    private func getToken(_ proto: PinUvAuthProtocol = .two, permissions: Int,
                          rpId: String? = "github.com") async throws -> (UInt8, Data?) {
        let (_, ka) = await call(0x06, .map([.int(1): .int(proto.rawValue), .int(2): .int(2)]))
        let cose = try XCTUnwrap(ka?[1])
        let x963 = Data([0x04]) + (try XCTUnwrap(cose[-2]?.bytes)) + (try XCTUnwrap(cose[-3]?.bytes))
        let platform = P256.KeyAgreement.PrivateKey()
        let shared = try proto.sharedSecret(platform, with: try P256.KeyAgreement.PublicKey(x963Representation: x963))
        let raw = [UInt8](platform.publicKey.x963Representation)
        var params: [CBOR.Pair] = [
            .init(.int(1), .int(proto.rawValue)), .init(.int(2), .int(6)),
            .init(.int(3), .map([.int(1): .int(2), .int(3): .int(-25), .int(-1): .int(1),
                                 .int(-2): .bytes(Data(raw[1...32])), .int(-3): .bytes(Data(raw[33...64]))])),
            .init(.int(9), .int(permissions)),
        ]
        if let rpId { params.append(.init(.int(10), .text(rpId))) }
        let (status, body) = await call(0x06, .map(params))
        guard status == 0 else { return (status, nil) }
        let token = try proto.decrypt(key: shared, try XCTUnwrap(body?[2]?.bytes))
        XCTAssertEqual(token.count, 32)
        return (status, token)
    }

    private func withToken(_ params: CBOR, key: Int, token: Data, proto: PinUvAuthProtocol = .two,
                           message: Data? = nil) -> CBOR {
        guard case var .map(pairs) = params else { return params }
        pairs.append(.init(.int(key), .bytes(proto.authenticate(key: token, message ?? clientDataHash))))
        pairs.append(.init(.int(key + 1), .int(proto.rawValue)))
        return .map(pairs)
    }

    func testTokenIssuanceChecks() async throws {
        var (status, _) = try await getToken(permissions: 0)
        XCTAssertEqual(status, CTAPStatus.invalidParameter.rawValue)
        (status, _) = try await getToken(permissions: 0x08) // be: not supported
        XCTAssertEqual(status, CTAPStatus.unauthorizedPermission.rawValue)
        (status, _) = try await getToken(permissions: 0x01, rpId: nil)
        XCTAssertEqual(status, CTAPStatus.missingParameter.rawValue, "mc needs an RP ID")
        ui.touchIDLocked = true
        (status, _) = try await getToken(permissions: 0x02)
        XCTAssertEqual(status, CTAPStatus.uvBlocked.rawValue)
        XCTAssertTrue(ui.tokenPrompts.isEmpty, "nothing shown for these")
        ui.touchIDLocked = false
        for (decision, expected) in [(TokenDecision.denied, CTAPStatus.operationDenied),
                                     (.timedOut, .userActionTimeout), (.blocked, .uvBlocked)] {
            ui.tokenDecision = decision
            (status, _) = try await getToken(permissions: 0x02)
            XCTAssertEqual(status, expected.rawValue)
        }
        XCTAssertEqual(ui.tokenPrompts.last, TokenPrompt(permissions: 0x02, rpId: "github.com"))
    }

    func testGetUVRetries() async {
        var (status, body) = await call(0x06, .map([.int(1): .int(2), .int(2): .int(7)]))
        XCTAssertEqual(status, 0)
        XCTAssertEqual(body?[5]?.int, 8)
        ui.touchIDLocked = true
        (status, body) = await call(0x06, .map([.int(1): .int(2), .int(2): .int(7)]))
        XCTAssertEqual(body?[5]?.int, 0)
    }

    func testRegistrationAndSignInWithToken() async throws {
        for proto in PinUvAuthProtocol.allCases {
            var (_, token) = try await getToken(proto, permissions: 0x01)
            var (status, _) = await call(0x01, withToken(makeCredentialParams(rk: true), key: 8,
                                                         token: try XCTUnwrap(token), proto: proto))
            XCTAssertEqual(status, 0, "\(proto)")
            XCTAssertEqual(ui.registrations.last?.verified, true, "no second Touch ID")
            // mc and ga serve one operation.
            (status, _) = await call(0x01, withToken(makeCredentialParams(rk: true, user: "x"), key: 8,
                                                     token: try XCTUnwrap(token), proto: proto))
            XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue)

            (_, token) = try await getToken(proto, permissions: 0x02)
            let authorization = try XCTUnwrap({ () -> AnyObject? in
                if case let .approved(a) = ui.tokenDecision { return a } else { return nil }
            }())
            let ga = CBOR.map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash)])
            let (signed, body) = await call(0x02, withToken(ga, key: 6, token: try XCTUnwrap(token), proto: proto))
            XCTAssertEqual(signed, 0)
            XCTAssertNotNil(body?[3])
            XCTAssertEqual(ui.signIns.last?.verified, true)
            XCTAssertTrue(keys.lastAuthorization === authorization, "the token's Touch ID signs")
            (status, _) = await call(0x02, withToken(ga, key: 6, token: try XCTUnwrap(token), proto: proto))
            XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue, "used up")
        }
    }

    func testTokenMisuse() async throws {
        _ = try await register(rk: true)
        let ga = CBOR.map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash)])
        var (_, token) = try await getToken(permissions: 0x02, rpId: "other.example")
        var (status, _) = await call(0x02, withToken(ga, key: 6, token: try XCTUnwrap(token)))
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue, "another site")

        (_, token) = try await getToken(permissions: 0x01)
        (status, _) = await call(0x02, withToken(ga, key: 6, token: try XCTUnwrap(token)))
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue, "mc token cannot sign in")

        (_, token) = try await getToken(permissions: 0x02)
        (status, _) = await call(0x02, withToken(ga, key: 6, token: Data(repeating: 7, count: 32)))
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue, "wrong token")
        if case var .map(pairs) = withToken(ga, key: 6, token: try XCTUnwrap(token)) {
            pairs.removeAll { $0.key == .int(7) }
            (status, _) = await call(0x02, .map(pairs))
            XCTAssertEqual(status, CTAPStatus.missingParameter.rawValue, "protocol missing")
        }
        clock += 31
        (status, _) = await call(0x02, withToken(ga, key: 6, token: try XCTUnwrap(token)))
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue, "unused for 30 s: expired")
        XCTAssertTrue(ui.signIns.isEmpty)
    }

    func testDeclinedOperationUsesUpToken() async throws {
        _ = try await register(rk: true)
        _ = try await register(rk: true, user: "second")
        let ga = CBOR.map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash)])
        let (_, token) = try await getToken(permissions: 0x02)
        ui.decision = .denied // two accounts: the card asks which, and the user declines
        var (status, _) = await call(0x02, withToken(ga, key: 6, token: try XCTUnwrap(token)))
        XCTAssertEqual(status, CTAPStatus.operationDenied.rawValue)
        ui.decision = .approved
        (status, _) = await call(0x02, withToken(ga, key: 6, token: try XCTUnwrap(token)))
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue, "the Touch ID served one attempt")
    }

    func testTokenBoundToItsProtocol() async throws {
        _ = try await register(rk: true)
        let ga = CBOR.map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash)])
        let (_, token) = try await getToken(.two, permissions: 0x02)
        var (status, _) = await call(0x02, withToken(ga, key: 6, token: try XCTUnwrap(token), proto: .one))
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue, "issued over protocol 2")
        (status, _) = await call(0x02, withToken(ga, key: 6, token: try XCTUnwrap(token), proto: .two))
        XCTAssertEqual(status, 0)
    }

    func testTokenTouchIDIsInvalidated() async throws {
        _ = try await register(rk: true)
        func fresh() -> ScriptedUI.Authorization {
            let touchID = ScriptedUI.Authorization()
            ui.tokenDecision = .approved(authorization: touchID)
            return touchID
        }
        // A registration signs nothing, yet the Touch ID goes with it.
        var touchID = fresh()
        var (_, token) = try await getToken(permissions: 0x01)
        XCTAssertFalse(touchID.invalidated)
        _ = await call(0x01, withToken(makeCredentialParams(rk: true, user: "x"), key: 8, token: try XCTUnwrap(token)))
        XCTAssertTrue(touchID.invalidated, "after its one operation")

        touchID = fresh()
        _ = try await getToken(permissions: 0x02)
        let next = fresh()
        (_, token) = try await getToken(permissions: 0x02)
        XCTAssertTrue(touchID.invalidated, "replaced by a new token")
        XCTAssertFalse(next.invalidated)

        clock += 31
        let ga = CBOR.map([.int(1): .text("github.com"), .int(2): .bytes(clientDataHash)])
        let (status, _) = await call(0x02, withToken(ga, key: 6, token: try XCTUnwrap(token)))
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue)
        XCTAssertTrue(next.invalidated, "expired unused")

        touchID = fresh()
        _ = try await getToken(permissions: 0x04, rpId: nil)
        XCTAssertTrue(touchID.invalidated, "a cm token keeps none")

        touchID = fresh()
        _ = try await getToken(permissions: 0x02)
        session.end()
        XCTAssertTrue(touchID.invalidated, "the connection ended")
    }

    func testAuthenticatorSelectionCommand() async {
        var (status, body) = await call(0x0B, nil)
        XCTAssertEqual(status, 0)
        XCTAssertNil(body)
        ui.decision = .denied
        (status, _) = await call(0x0B, nil)
        XCTAssertEqual(status, CTAPStatus.operationDenied.rawValue)
    }

    // MARK: Credential management

    private func credMgmt(_ subCommand: Int, _ params: CBOR? = nil, token: Data?,
                          proto: PinUvAuthProtocol = .two) async -> (UInt8, CBOR?) {
        var pairs: [CBOR.Pair] = [.init(.int(1), .int(subCommand))]
        if let params { pairs.append(.init(.int(2), params)) }
        if let token {
            let message = Data([UInt8(subCommand)]) + (params?.encoded ?? Data())
            pairs.append(.init(.int(3), .int(proto.rawValue)))
            pairs.append(.init(.int(4), .bytes(proto.authenticate(key: token, message))))
        }
        return await call(0x0A, .map(pairs))
    }

    private func registerAt(_ rpId: String, user: String, rk: Bool = true) async {
        let params = CBOR.map([
            .int(1): .bytes(clientDataHash),
            .int(2): .map([.text("id"): .text(rpId), .text("name"): .text(rpId.uppercased())]),
            .int(3): .map([.text("id"): .bytes(Data(user.utf8)), .text("name"): .text(user),
                           .text("displayName"): .text(user.capitalized)]),
            .int(4): .array([.map([.text("alg"): .int(-7), .text("type"): .text("public-key")])]),
            .int(7): .map([.text("rk"): .bool(rk)]),
        ])
        let (status, _) = await call(0x01, params)
        XCTAssertEqual(status, 0)
    }

    func testCredentialManagement() async throws {
        await registerAt("github.com", user: "work")
        await registerAt("github.com", user: "home")
        await registerAt("example.com", user: "me")
        await registerAt("example.com", user: "ssh", rk: false)
        let (_, token) = try await getToken(permissions: 0x04, rpId: nil)
        XCTAssertEqual(ui.tokenPrompts.last?.signs, false, "a cm token keeps no Touch ID")

        var (status, body) = await credMgmt(0x01, token: token)
        XCTAssertEqual(status, 0)
        XCTAssertEqual(body?[1]?.int, 3, "discoverable only")
        XCTAssertEqual(body?[2]?.int, 100)

        (status, body) = await credMgmt(0x02, token: token)
        XCTAssertEqual(body?[3]?["id"]?.text, "example.com")
        XCTAssertEqual(body?[3]?["name"]?.text, "EXAMPLE.COM")
        XCTAssertEqual(body?[4]?.bytes, Data(SHA256.hash(data: Data("example.com".utf8))))
        XCTAssertEqual(body?[5]?.int, 2)
        (status, body) = await credMgmt(0x03, token: nil)
        XCTAssertEqual(body?[3]?["id"]?.text, "github.com")
        (status, _) = await credMgmt(0x03, token: nil)
        XCTAssertEqual(status, CTAPStatus.notAllowed.rawValue, "past the end")

        let github = CBOR.map([.int(1): .bytes(Data(SHA256.hash(data: Data("github.com".utf8))))])
        (status, body) = await credMgmt(0x04, github, token: token)
        XCTAssertEqual(status, 0)
        XCTAssertEqual(body?[9]?.int, 2)
        XCTAssertEqual(body?[6]?["name"]?.text, "work")
        let firstId = try XCTUnwrap(body?[7]?["id"]?.bytes)
        let cose = try XCTUnwrap(body?[8])
        let x963 = Data([0x04]) + (try XCTUnwrap(cose[-2]?.bytes)) + (try XCTUnwrap(cose[-3]?.bytes))
        XCTAssertEqual(x963, keys.keys[firstId]?.publicKey.x963Representation)
        (status, _) = await call(0x04, nil) // any other command ends the enumeration
        (status, _) = await credMgmt(0x05, token: nil)
        XCTAssertEqual(status, CTAPStatus.notAllowed.rawValue)

        // updateUserInformation replaces the site's names; user.id must match.
        let descriptor = CBOR.map([.text("id"): .bytes(firstId), .text("type"): .text("public-key")])
        (status, _) = await credMgmt(0x07, .map([.int(2): descriptor,
                                                 .int(3): .map([.text("id"): .bytes(Data("work".utf8)),
                                                                .text("name"): .text("work@corp")])]),
                                     token: token)
        XCTAssertEqual(status, 0)
        XCTAssertEqual(store.credential(id: firstId)?.userName, "work@corp")
        XCTAssertNil(store.credential(id: firstId)?.userDisplayName)
        (status, _) = await credMgmt(0x07, .map([.int(2): descriptor,
                                                 .int(3): .map([.text("id"): .bytes(Data("x".utf8))])]),
                                     token: token)
        XCTAssertEqual(status, CTAPStatus.invalidParameter.rawValue)

        // deleteCredential asks on the phone.
        ui.decision = .denied
        (status, _) = await credMgmt(0x06, .map([.int(2): descriptor]), token: token)
        XCTAssertEqual(status, CTAPStatus.operationDenied.rawValue)
        XCTAssertNotNil(store.credential(id: firstId))
        ui.decision = .approved
        (status, _) = await credMgmt(0x06, .map([.int(2): descriptor]), token: token)
        XCTAssertEqual(status, 0)
        XCTAssertNil(store.credential(id: firstId))
        XCTAssertNil(keys.keys[firstId])
        XCTAssertEqual(ui.deletions.count, 2)
        (status, _) = await credMgmt(0x06, .map([.int(2): descriptor]), token: token)
        XCTAssertEqual(status, CTAPStatus.noCredentials.rawValue)
    }

    func testCredentialManagementMACOverRawParams() async throws {
        await registerAt("github.com", user: "work")
        let (_, token) = try await getToken(permissions: 0x04, rpId: nil)
        // {1: rpIDHash} with the key in a valid but non-minimal encoding
        // (0x18 0x01): decoding and re-encoding would change the MACed bytes.
        let params = Data([0xA1, 0x18, 0x01, 0x58, 0x20]) + Data(SHA256.hash(data: Data("github.com".utf8)))
        XCTAssertEqual(try CBOR.rawValue(forKey: .int(2), inMap: Data([0xA1, 0x02]) + params), params)
        let mac = PinUvAuthProtocol.two.authenticate(key: try XCTUnwrap(token), Data([0x04]) + params)
        let request = Data([0x0A, 0xA4, 0x01, 0x04, 0x02]) + params + Data([0x03, 0x02, 0x04, 0x58, 0x20]) + mac
        let response = await authenticator.handle(request, session: session)
        XCTAssertEqual(response.first, 0, "enumerateCredentialsBegin verified over the bytes as sent")
    }

    func testCredentialManagementAuthorization() async throws {
        await registerAt("github.com", user: "work")
        var (status, _) = await credMgmt(0x01, token: nil)
        XCTAssertEqual(status, CTAPStatus.puatRequired.rawValue)

        var (_, token) = try await getToken(permissions: 0x02)
        (status, _) = await credMgmt(0x01, token: token)
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue, "no cm permission")

        (_, token) = try await getToken(permissions: 0x04, rpId: "github.com")
        (status, _) = await credMgmt(0x01, token: token)
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue, "metadata needs a token without RP ID")
        let other = CBOR.map([.int(1): .bytes(Data(SHA256.hash(data: Data("example.com".utf8))))])
        (status, _) = await credMgmt(0x04, other, token: token)
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue, "a scoped token reaches its site only")
        let github = CBOR.map([.int(1): .bytes(Data(SHA256.hash(data: Data("github.com".utf8))))])
        (status, _) = await credMgmt(0x04, github, token: token)
        XCTAssertEqual(status, 0)

        // A used cm token stays valid up to 600 s.
        clock += 500
        (status, _) = await credMgmt(0x04, github, token: token)
        XCTAssertEqual(status, 0)
        clock += 101
        (status, _) = await credMgmt(0x04, github, token: token)
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue)

        // Unknown IDs: the token is checked first, so a host without one
        // cannot probe which IDs exist.
        let unknown = CBOR.map([.int(2): .map([.text("id"): .bytes(Data(repeating: 9, count: 32)),
                                               .text("type"): .text("public-key")])])
        (_, token) = try await getToken(permissions: 0x04, rpId: nil)
        (status, _) = await credMgmt(0x06, unknown, token: Data(repeating: 1, count: 32))
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue)
        (status, _) = await credMgmt(0x06, unknown, token: token)
        XCTAssertEqual(status, CTAPStatus.noCredentials.rawValue)
        // A cm token is not bound to the site of a delete: listing still works.
        let work = try XCTUnwrap(store.allCredentials().first)
        let descriptor = CBOR.map([.text("id"): .bytes(work.id), .text("type"): .text("public-key")])
        (status, _) = await credMgmt(0x07, .map([.int(2): descriptor,
                                                 .int(3): .map([.text("id"): .bytes(work.userId)])]),
                                     token: token)
        XCTAssertEqual(status, 0)
        (status, _) = await credMgmt(0x01, token: token)
        XCTAssertEqual(status, 0)

        (status, _) = await credMgmt(0x09, token: token)
        XCTAssertEqual(status, CTAPStatus.invalidSubcommand.rawValue)
        (status, _) = await call(0x41, .map([.int(1): .int(1)]))
        XCTAssertEqual(status, CTAPStatus.invalidCommand.rawValue, "no pre-release credMgmt")
    }
}

private extension Data {
    func ends(with suffix: Data) -> Bool {
        count >= suffix.count && self.suffix(suffix.count) == suffix
    }
}
