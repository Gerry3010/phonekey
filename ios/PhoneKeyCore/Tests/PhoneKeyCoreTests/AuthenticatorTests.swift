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
}

final class SoftwareKeys: CredentialKeys {
    var keys: [Data: P256.Signing.PrivateKey] = [:]
    var denySigning = false

    func createKey(id: Data) throws -> Data {
        let key = P256.Signing.PrivateKey()
        keys[id] = key
        return key.publicKey.x963Representation
    }

    func sign(id: Data, data: Data, reason: String) async throws -> Data {
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

    func decrypt(id: Data, ciphertext: Data, reason: String) async throws -> Data {
        decryptCalls += 1
        if denyDecrypt { throw CTAPStatus.operationDenied }
        guard keys[id] != nil, let plain = sealed[ciphertext] else { throw CTAPStatus.noCredentials }
        return plain
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
        authenticator = Authenticator(store: store, keys: keys, ui: ui)
        session = CTAPSession()
    }

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
        XCTAssertEqual(info?[1], .array([.text("FIDO_2_0")]))
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

    func testGetInfoPhase3a() async {
        let (_, info) = await call(0x04, nil)
        XCTAssertEqual(info?[1], .array([.text("FIDO_2_0")]), "FIDO_2_1 comes with 3b")
        XCTAssertEqual(info?[6], .array([.int(2), .int(1)]))
        XCTAssertNil(info?[4]?["clientPin"])
        XCTAssertNil(info?[4]?["pinUvAuthToken"])
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
        for subCommand in [0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09] {
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
}

private extension Data {
    func ends(with suffix: Data) -> Bool {
        count >= suffix.count && self.suffix(suffix.count) == suffix
    }
}
