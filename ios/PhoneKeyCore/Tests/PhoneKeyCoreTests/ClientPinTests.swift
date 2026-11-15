import CryptoKit
import XCTest
@testable import PhoneKeyCore

/// Step 3c: the PIN that only works together with Touch ID (§10, "PIN (3c)").
final class ClientPinTests: XCTestCase {
    private var store: MemoryStore!
    private var keys: SoftwareKeys!
    private var ui: ScriptedUI!
    private var pins: MemoryPinStorage!
    private var authenticator: Authenticator!
    private var session: CTAPSession!
    private var clock = Date(timeIntervalSince1970: 1_000_000)
    private let clientDataHash = Data(SHA256.hash(data: Data("client data".utf8)))

    override func setUp() {
        store = MemoryStore()
        keys = SoftwareKeys()
        ui = ScriptedUI()
        pins = MemoryPinStorage()
        authenticator = Authenticator(store: store, keys: keys, ui: ui, pins: pins,
                                      now: { [unowned self] in self.clock })
        session = CTAPSession()
    }

    // MARK: The platform's side

    private func call(_ command: UInt8, _ params: CBOR?) async -> (UInt8, CBOR?) {
        let response = await authenticator.handle(Data([command]) + (params?.encoded ?? Data()), session: session)
        let body = response.count > 1 ? try? CBOR.decode(Data(response.dropFirst())) : nil
        return (response[0], body)
    }

    private struct Platform {
        let proto: PinUvAuthProtocol
        let shared: Data
        let keyAgreement: CBOR
    }

    /// getKeyAgreement, then ECDH with a fresh platform key.
    private func platform(_ proto: PinUvAuthProtocol = .two) async throws -> Platform {
        let (_, ka) = await call(0x06, .map([.int(1): .int(proto.rawValue), .int(2): .int(2)]))
        let cose = try XCTUnwrap(ka?[1])
        let x963 = Data([0x04]) + (try XCTUnwrap(cose[-2]?.bytes)) + (try XCTUnwrap(cose[-3]?.bytes))
        let own = P256.KeyAgreement.PrivateKey()
        let shared = try proto.sharedSecret(own, with: try P256.KeyAgreement.PublicKey(x963Representation: x963))
        let raw = [UInt8](own.publicKey.x963Representation)
        let key = CBOR.map([.int(1): .int(2), .int(3): .int(-25), .int(-1): .int(1),
                            .int(-2): .bytes(Data(raw[1...32])), .int(-3): .bytes(Data(raw[33...64]))])
        return Platform(proto: proto, shared: shared, keyAgreement: key)
    }

    private func padded(_ pin: Data) -> Data {
        pin + Data(count: max(0, 64 - pin.count))
    }

    private func pinHashEnc(_ pin: String, _ platform: Platform) throws -> Data {
        try platform.proto.encrypt(key: platform.shared, Data(SHA256.hash(data: Data(pin.utf8)).prefix(16)))
    }

    private func setPin(_ pin: String, proto: PinUvAuthProtocol = .two, raw: Data? = nil,
                        tamper: Bool = false) async throws -> UInt8 {
        let platform = try await platform(proto)
        let newPinEnc = try proto.encrypt(key: platform.shared, padded(raw ?? Data(pin.utf8)))
        var param = proto.authenticate(key: platform.shared, newPinEnc)
        if tamper { param[param.startIndex] ^= 1 }
        let (status, _) = await call(0x06, .map([.int(1): .int(proto.rawValue), .int(2): .int(3),
                                                 .int(3): platform.keyAgreement, .int(4): .bytes(param),
                                                 .int(5): .bytes(newPinEnc)]))
        return status
    }

    private func changePin(from old: String, to new: String) async throws -> UInt8 {
        let platform = try await platform()
        let newPinEnc = try platform.proto.encrypt(key: platform.shared, padded(Data(new.utf8)))
        let hashEnc = try pinHashEnc(old, platform)
        let param = platform.proto.authenticate(key: platform.shared, newPinEnc + hashEnc)
        let (status, _) = await call(0x06, .map([.int(1): .int(2), .int(2): .int(4),
                                                 .int(3): platform.keyAgreement, .int(4): .bytes(param),
                                                 .int(5): .bytes(newPinEnc), .int(6): .bytes(hashEnc)]))
        return status
    }

    /// getPinUvAuthTokenUsingPinWithPermissions (0x09), or getPinToken (0x05)
    /// with `permissions` nil.
    private func pinToken(_ pin: String, permissions: Int? = 0x02, rpId: String? = "github.com",
                          proto: PinUvAuthProtocol = .two) async throws -> (UInt8, Data?) {
        let platform = try await platform(proto)
        var params: [CBOR.Pair] = [
            .init(.int(1), .int(proto.rawValue)), .init(.int(2), .int(permissions == nil ? 5 : 9)),
            .init(.int(3), platform.keyAgreement), .init(.int(6), .bytes(try pinHashEnc(pin, platform))),
        ]
        if let permissions { params.append(.init(.int(9), .int(permissions))) }
        if let rpId, permissions != nil { params.append(.init(.int(10), .text(rpId))) }
        let (status, body) = await call(0x06, .map(params))
        guard status == 0 else { return (status, nil) }
        return (status, try proto.decrypt(key: platform.shared, try XCTUnwrap(body?[2]?.bytes)))
    }

    /// A token via Touch ID only (0x06).
    private func uvToken(permissions: Int = 0x02, rpId: String = "github.com") async throws -> Data {
        let platform = try await platform()
        let (status, body) = await call(0x06, .map([.int(1): .int(2), .int(2): .int(6),
                                                    .int(3): platform.keyAgreement, .int(9): .int(permissions),
                                                    .int(10): .text(rpId)]))
        XCTAssertEqual(status, 0)
        return try platform.proto.decrypt(key: platform.shared, try XCTUnwrap(body?[2]?.bytes))
    }

    private func retries() async -> (UInt8, CBOR?) {
        await call(0x06, .map([.int(1): .int(2), .int(2): .int(1)]))
    }

    private func makeCredential(user: String = "gerry", token: Data? = nil) -> CBOR {
        var pairs: [CBOR.Pair] = [
            .init(.int(1), .bytes(clientDataHash)),
            .init(.int(2), .map([.text("id"): .text("github.com")])),
            .init(.int(3), .map([.text("id"): .bytes(Data(user.utf8)), .text("name"): .text(user)])),
            .init(.int(4), .array([.map([.text("alg"): .int(-7), .text("type"): .text("public-key")])])),
            .init(.int(7), .map([.text("rk"): .bool(true)])),
        ]
        if let token {
            pairs.append(.init(.int(8), .bytes(PinUvAuthProtocol.two.authenticate(key: token, clientDataHash))))
            pairs.append(.init(.int(9), .int(2)))
        }
        return .map(pairs)
    }

    private func getAssertion(token: Data?, silent: Bool = false) -> CBOR {
        var pairs: [CBOR.Pair] = [.init(.int(1), .text("github.com")), .init(.int(2), .bytes(clientDataHash))]
        if silent { pairs.append(.init(.int(5), .map([.text("up"): .bool(false)]))) }
        if let token {
            pairs.append(.init(.int(6), .bytes(PinUvAuthProtocol.two.authenticate(key: token, clientDataHash))))
            pairs.append(.init(.int(7), .int(2)))
        }
        return .map(pairs)
    }

    private func clientPinOption() async -> CBOR? {
        await call(0x04, nil).1?[4]?["clientPin"]
    }

    private func assertClientPin(_ expected: CBOR, _ message: String = "", line: UInt = #line) async {
        let option = await clientPinOption()
        XCTAssertEqual(option, expected, message, line: line)
    }

    private func setPinOK(_ pin: String, line: UInt = #line) async throws {
        let status = try await setPin(pin)
        XCTAssertEqual(status, 0, line: line)
    }

    // MARK: setPIN

    func testSetPin() async throws {
        await assertClientPin(.bool(false))
        let status = try await setPin("1234")
        XCTAssertEqual(status, 0)
        XCTAssertEqual(ui.pinPrompts, [.set])
        XCTAssertTrue(ui.pinAuthorizations[0].invalidated, "storing needs no key operation")
        let record = try XCTUnwrap(pins.record)
        XCTAssertEqual(record.retries, 8)
        XCTAssertNotNil(keys.keys[Authenticator.pinKeyId], "the PIN's own key")
        XCTAssertEqual(keys.sealed[record.sealedHash], Data(SHA256.hash(data: Data("1234".utf8)).prefix(16)),
                       "only LEFT(SHA-256(PIN), 16), encrypted to it")
        await assertClientPin(.bool(true))
        let (_, body) = await retries()
        XCTAssertEqual(body, .map([.int(3): .int(8)]))

        let again = try await setPin("5678")
        XCTAssertEqual(again, CTAPStatus.pinAuthInvalid.rawValue, "already set: CTAP 2.1 §6.5.5.5")
    }

    func testSetPinChecks() async throws {
        for (pin, why) in [("123", "3 code points"), ("äöü", "3 code points in 6 bytes")] {
            let status = try await setPin(pin)
            XCTAssertEqual(status, CTAPStatus.pinPolicyViolation.rawValue, why)
        }
        var status = try await setPin("", raw: Data(repeating: 0x61, count: 64))
        XCTAssertEqual(status, CTAPStatus.pinPolicyViolation.rawValue, "64 bytes: over 63")
        status = try await setPin("", raw: Data([0xFF, 0xFE, 0xFD, 0xFC]))
        XCTAssertEqual(status, CTAPStatus.pinPolicyViolation.rawValue, "not UTF-8")
        status = try await setPin("1234", tamper: true)
        XCTAssertEqual(status, CTAPStatus.pinAuthInvalid.rawValue)
        XCTAssertTrue(ui.pinPrompts.isEmpty, "nothing shown for these")

        ui.touchIDLocked = true
        status = try await setPin("1234")
        XCTAssertEqual(status, CTAPStatus.uvBlocked.rawValue)
        ui.touchIDLocked = false
        ui.pinDecision = .denied
        status = try await setPin("1234")
        XCTAssertEqual(status, CTAPStatus.operationDenied.rawValue)
        XCTAssertNil(pins.record)

        ui.pinDecision = nil
        status = try await setPin("äöüß", proto: .one)
        XCTAssertEqual(status, 0, "4 code points, protocol 1")
        let (tokenStatus, _) = try await pinToken("äöüß", proto: .one)
        XCTAssertEqual(tokenStatus, 0)
    }

    // MARK: Tokens against the PIN

    func testPinTokenSignsWithItsTouchID() async throws {
        _ = await call(0x01, makeCredential())
        try await setPinOK("1234")
        let decrypts = keys.decryptCalls
        let (status, token) = try await pinToken("1234")
        XCTAssertEqual(status, 0)
        XCTAssertEqual(ui.pinPrompts.last, .token(TokenPrompt(permissions: 0x02, rpId: "github.com")))
        XCTAssertEqual(keys.decryptCalls, decrypts + 1, "the PIN check decrypts under that Touch ID")
        let touchID = try XCTUnwrap(ui.pinAuthorizations.last)
        XCTAssertFalse(touchID.invalidated)

        let (signed, _) = await call(0x02, getAssertion(token: try XCTUnwrap(token)))
        XCTAssertEqual(signed, 0)
        XCTAssertTrue(keys.lastAuthorization === touchID, "one Touch ID: PIN check and signature")
        XCTAssertEqual(ui.signIns.last?.verified, true)
        XCTAssertEqual(ui.signIns.last?.confirmByTap, false)
        XCTAssertTrue(touchID.invalidated, "used up")

        // A cm token keeps no Touch ID.
        let (_, cm) = try await pinToken("1234", permissions: 0x04, rpId: nil)
        XCTAssertTrue(try XCTUnwrap(ui.pinAuthorizations.last).invalidated)
        let metadata = CBOR.map([.int(1): .int(1), .int(3): .int(2),
                                 .int(4): .bytes(PinUvAuthProtocol.two.authenticate(key: try XCTUnwrap(cm),
                                                                                    Data([0x01])))])
        let (listed, body) = await call(0x0A, metadata)
        XCTAssertEqual(listed, 0)
        XCTAssertEqual(body?[1]?.int, 1)
    }

    func testPinTokenChecks() async throws {
        var (status, _) = try await pinToken("1234")
        XCTAssertEqual(status, CTAPStatus.pinNotSet.rawValue)
        try await setPinOK("1234")
        (status, _) = try await pinToken("1234", permissions: 0)
        XCTAssertEqual(status, CTAPStatus.invalidParameter.rawValue)
        (status, _) = try await pinToken("1234", permissions: 0x08)
        XCTAssertEqual(status, CTAPStatus.unauthorizedPermission.rawValue)
        (status, _) = try await pinToken("1234", permissions: 0x01, rpId: nil)
        XCTAssertEqual(status, CTAPStatus.missingParameter.rawValue)
        ui.touchIDLocked = true
        (status, _) = try await pinToken("1234")
        XCTAssertEqual(status, CTAPStatus.uvBlocked.rawValue)
        XCTAssertEqual(ui.pinPrompts, [.set], "nothing shown for these")
        ui.touchIDLocked = false
        ui.pinDecision = .timedOut
        (status, _) = try await pinToken("1234")
        XCTAssertEqual(status, CTAPStatus.userActionTimeout.rawValue)
        XCTAssertEqual(pins.record?.retries, 8, "no Touch ID, no try used")
    }

    func testWrongPins() async throws {
        try await setPinOK("1234")
        let (_, before) = await call(0x06, .map([.int(1): .int(2), .int(2): .int(2)]))
        var (status, _) = try await pinToken("0000")
        XCTAssertEqual(status, CTAPStatus.pinInvalid.rawValue)
        XCTAssertEqual(pins.record?.retries, 7)
        XCTAssertTrue(try XCTUnwrap(ui.pinAuthorizations.last).invalidated)
        let (_, after) = await call(0x06, .map([.int(1): .int(2), .int(2): .int(2)]))
        XCTAssertNotEqual(before, after, "a wrong PIN replaces the key agreement key")

        (status, _) = try await pinToken("0000")
        XCTAssertEqual(status, CTAPStatus.pinInvalid.rawValue)
        (status, _) = try await pinToken("0000")
        XCTAssertEqual(status, CTAPStatus.pinAuthBlocked.rawValue, "three in a row")
        (status, _) = try await pinToken("1234")
        XCTAssertEqual(status, CTAPStatus.pinAuthBlocked.rawValue, "until the host reconnects")
        let (_, body) = await retries()
        XCTAssertEqual(body, .map([.int(3): .int(5), .int(4): .bool(true)]))

        session.end()
        session = CTAPSession()
        (status, _) = try await pinToken("1234")
        XCTAssertEqual(status, 0)
        XCTAssertEqual(pins.record?.retries, 8, "a right PIN resets the retries")
    }

    func testPinBlocked() async throws {
        try await setPinOK("1234")
        pins.record?.retries = 1
        var (status, _) = try await pinToken("0000")
        XCTAssertEqual(status, CTAPStatus.pinBlocked.rawValue)
        (status, _) = try await pinToken("1234")
        XCTAssertEqual(status, CTAPStatus.pinBlocked.rawValue, "even the right PIN")
        let (_, body) = await retries()
        XCTAssertEqual(body?[3]?.int, 0)
        // Forgotten or blocked: removed in the app with Touch ID; the keys stay.
        try authenticator.removePin()
        XCTAssertEqual(try authenticator.pinState(), .notSet)
        XCTAssertNil(keys.keys[Authenticator.pinKeyId])
    }

    // MARK: changePIN

    func testChangePin() async throws {
        try await setPinOK("1234")
        let uv = try await uvToken()
        let other = session!
        session = CTAPSession()
        let otherSessionToken = try await uvToken()
        session = other

        var status = try await changePin(from: "0000", to: "5678")
        XCTAssertEqual(status, CTAPStatus.pinInvalid.rawValue)
        XCTAssertEqual(pins.record?.retries, 7)
        let prompts = ui.pinPrompts.count
        status = try await changePin(from: "1234", to: "56")
        XCTAssertEqual(status, CTAPStatus.pinPolicyViolation.rawValue)
        XCTAssertEqual(ui.pinPrompts.count, prompts, "refused before anything is shown")
        status = try await changePin(from: "1234", to: "5678")
        XCTAssertEqual(status, 0)
        XCTAssertEqual(ui.pinPrompts.last, .change)
        XCTAssertEqual(pins.record?.retries, 8)

        var (tokenStatus, _) = try await pinToken("1234")
        XCTAssertEqual(tokenStatus, CTAPStatus.pinInvalid.rawValue)
        (tokenStatus, _) = try await pinToken("5678")
        XCTAssertEqual(tokenStatus, 0)

        // Every token of every session from before the change is gone.
        _ = await call(0x01, makeCredential())
        var (signed, _) = await call(0x02, getAssertion(token: uv))
        XCTAssertEqual(signed, CTAPStatus.pinAuthInvalid.rawValue)
        session = CTAPSession()
        (signed, _) = await call(0x02, getAssertion(token: otherSessionToken))
        XCTAssertEqual(signed, CTAPStatus.pinAuthInvalid.rawValue)
    }

    // MARK: getPinToken (CTAP 2.0)

    func testGetPinTokenShowsTheSiteFirst() async throws {
        try await setPinOK("1234")
        var (status, token) = try await pinToken("1234", permissions: nil)
        XCTAssertEqual(status, 0)
        XCTAssertEqual(ui.pinPrompts.last, .legacyToken)
        (status, _) = await call(0x01, makeCredential(token: try XCTUnwrap(token)))
        XCTAssertEqual(status, 0)
        XCTAssertEqual(ui.registrations.last?.verified, true)
        XCTAssertEqual(ui.registrations.last?.confirmByTap, true, "its prompt could not name the site")

        (_, token) = try await pinToken("1234", permissions: nil)
        (status, _) = await call(0x02, getAssertion(token: try XCTUnwrap(token), silent: true))
        XCTAssertEqual(status, CTAPStatus.unsupportedOption.rawValue, "no silent signature for an unseen site")
        (status, _) = await call(0x02, getAssertion(token: try XCTUnwrap(token)))
        XCTAssertEqual(status, 0)
        XCTAssertEqual(ui.signIns.last?.confirmByTap, true)
    }

    // MARK: Elsewhere

    func testZeroLengthPinUvAuthParamWithPin() async throws {
        try await setPinOK("1234")
        let params: CBOR
        if case var .map(pairs) = makeCredential() {
            pairs.append(.init(.int(8), .bytes(Data())))
            pairs.append(.init(.int(9), .int(2)))
            params = .map(pairs)
        } else {
            return XCTFail()
        }
        let (status, _) = await call(0x01, params)
        XCTAssertEqual(status, CTAPStatus.pinInvalid.rawValue, "authenticator selection with a PIN set")
    }

    func testPinInTheApp() async throws {
        XCTAssertThrowsError(try authenticator.setPinOnPhone("12"))
        try authenticator.setPinOnPhone("2468")
        XCTAssertEqual(try authenticator.pinState(), .set(retries: 8))
        let (status, token) = try await pinToken("2468")
        XCTAssertEqual(status, 0)
        try authenticator.removePin()
        await assertClientPin(.bool(false))
        _ = await call(0x01, makeCredential())
        let (signed, _) = await call(0x02, getAssertion(token: try XCTUnwrap(token)))
        XCTAssertEqual(signed, CTAPStatus.pinAuthInvalid.rawValue, "tokens end with the PIN")
    }

    func testUnreadablePinStorage() async throws {
        pins.failRead = true
        await assertClientPin(.bool(true), "unknown counts as set")
        let status = try await setPin("1234")
        XCTAssertEqual(status, CTAPStatus.other.rawValue)
    }
}
