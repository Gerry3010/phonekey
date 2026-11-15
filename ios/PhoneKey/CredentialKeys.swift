import Foundation
@preconcurrency import LocalAuthentication
import PhoneKeyCore
import Security

/// A token's Touch ID is the `LAContext` that was evaluated for it.
extension LAContext: @retroactive TouchIDAuthorization {}

/// FIDO credential keys: P-256 in the Secure Enclave, usable only after
/// Touch ID with any enrolled finger (re-enrolling fingers keeps them).
/// The Simulator has no Secure Enclave; there the key is a normal keychain key
/// with the same Touch ID rule.
final class SecureEnclaveKeys: CredentialKeys {
    private static let tagPrefix = "net.geraldhofbauer.phonekey.credential."

    /// The Touch ID from the sign-in card, if the user just gave one.
    private let handoff: TouchIDHandoff?

    init(handoff: TouchIDHandoff? = nil) {
        self.handoff = handoff
    }

    private static func tag(_ id: Data) -> Data {
        Data((tagPrefix + id.base64URLEncodedString).utf8)
    }

    /// The rule every credential key carries: usable only after Touch ID.
    static func accessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        #if targetEnvironment(simulator)
        let flags: SecAccessControlCreateFlags = [.biometryAny]
        #else
        let flags: SecAccessControlCreateFlags = [.privateKeyUsage, .biometryAny]
        #endif
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
        else { throw error!.takeRetainedValue() as Error }
        return access
    }

    func createKey(id: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        let access = try Self.accessControl()

        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Self.tag(id),
                kSecAttrAccessControl as String: access,
                kSecAttrLabel as String: "PhoneKey credential",
            ] as [String: Any],
        ]
        #if !targetEnvironment(simulator)
        attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        #endif
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        guard let publicKey = SecKeyCopyPublicKey(key),
              let x963 = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?
        else { throw error!.takeRetainedValue() as Error }
        return x963
    }

    func sign(id: Data, data: Data, reason: String, authorization: TouchIDAuthorization?) async throws -> Data {
        // A token's Touch ID, or the card's that has just been given; only
        // without either does the signature ask on its own. Used up after.
        let context = (authorization as? LAContext) ?? handoff?.take() ?? LAContext()
        context.localizedReason = reason
        context.localizedCancelTitle = "Cancel"
        context.localizedFallbackTitle = ""
        defer { context.invalidate() }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                // SecKeyCreateSignature blocks while Touch ID is shown.
                DispatchQueue.global(qos: .userInitiated).async {
                    let query: [String: Any] = [
                        kSecClass as String: kSecClassKey,
                        kSecAttrApplicationTag as String: Self.tag(id),
                        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                        kSecReturnRef as String: true,
                        kSecUseAuthenticationContext as String: context,
                    ]
                    var item: CFTypeRef?
                    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item else {
                        return continuation.resume(throwing: CTAPStatus.noCredentials)
                    }
                    let key = item as! SecKey
                    var error: Unmanaged<CFError>?
                    if let signature = SecKeyCreateSignature(
                        key, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) as Data? {
                        continuation.resume(returning: signature)
                    } else {
                        // User cancelled, Touch ID failed, or we invalidated the context.
                        continuation.resume(throwing: CTAPStatus.operationDenied)
                    }
                }
            }
        } onCancel: {
            context.invalidate()
        }
    }

    /// ECIES as the Secure Enclave does it (X9.63 SHA-256, AES-GCM).
    private static let ecies = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    func encrypt(toPublicKey x963: Data, plaintext: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
        ]
        guard let publicKey = SecKeyCreateWithData(x963 as CFData, attributes as CFDictionary, &error),
              let sealed = SecKeyCreateEncryptedData(publicKey, Self.ecies, plaintext as CFData, &error) as Data?
        else { throw error!.takeRetainedValue() as Error }
        return sealed
    }

    /// Normally the sign-in card has just done Touch ID: the decryption uses
    /// that context and leaves it for the signature. Without one it asks itself
    /// and hands its own context on, so a sign-in still needs one Touch ID.
    func decrypt(id: Data, ciphertext: Data, reason: String, authorization: TouchIDAuthorization?) async throws -> Data {
        let handed = (authorization as? LAContext) ?? handoff?.peek()
        let context = handed ?? LAContext()
        if handed == nil {
            context.localizedReason = reason
            context.localizedCancelTitle = "Cancel"
            context.localizedFallbackTitle = ""
        }
        let plain: Data = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                DispatchQueue.global(qos: .userInitiated).async {
                    let query: [String: Any] = [
                        kSecClass as String: kSecClassKey,
                        kSecAttrApplicationTag as String: Self.tag(id),
                        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                        kSecReturnRef as String: true,
                        kSecUseAuthenticationContext as String: context,
                    ]
                    var item: CFTypeRef?
                    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item else {
                        return continuation.resume(throwing: CTAPStatus.noCredentials)
                    }
                    var error: Unmanaged<CFError>?
                    if let plain = SecKeyCreateDecryptedData(item as! SecKey, Self.ecies,
                                                             ciphertext as CFData, &error) as Data? {
                        continuation.resume(returning: plain)
                    } else {
                        continuation.resume(throwing: CTAPStatus.operationDenied)
                    }
                }
            }
        } onCancel: {
            context.invalidate()
        }
        if handed == nil { handoff?.put(context) }
        return plain
    }

    /// Credential management lists public keys: no Touch ID may come up.
    func publicKey(id: Data) throws -> Data {
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.tag(id),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var item: CFTypeRef?
        var error: Unmanaged<CFError>?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item,
              let publicKey = SecKeyCopyPublicKey(item as! SecKey),
              let x963 = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?
        else { throw CTAPStatus.noCredentials }
        return x963
    }

    func deleteKey(id: Data) {
        SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.tag(id),
        ] as CFDictionary)
    }
}

/// Credential metadata in the keychain (this device only), one JSON list.
/// Sessions call it from background tasks; the UI reads the published copy.
final class KeychainCredentialStore: ObservableObject, CredentialStore, @unchecked Sendable {
    @Published private(set) var all: [StoredCredential] = []
    /// The user's own names for sites (RP ID → name), only on this phone.
    @Published private(set) var siteNames: [String: String] = [:]

    private let lock = NSLock()
    private var items: [StoredCredential] = []
    private let keys: CredentialKeys

    init(keys: CredentialKeys) {
        self.keys = keys
        if let data = try? Keychain.read("credentials"),
           let decoded = try? JSONDecoder().decode([StoredCredential].self, from: data) {
            items = decoded
        }
        all = items
        if let data = try? Keychain.read("siteNames"),
           let decoded = try? JSONDecoder().decode([String: String].self, from: data) {
            siteNames = decoded
        }
    }

    func credentials(rpId: String) -> [StoredCredential] {
        locked { items.filter { $0.rpId == rpId } }
    }

    func credential(id: Data) -> StoredCredential? {
        locked { items.first { $0.id == id } }
    }

    func save(_ credential: StoredCredential, replacing: [Data]) throws {
        try mutate { items in
            items.removeAll { replacing.contains($0.id) }
            items.append(credential)
        }
    }

    func incrementCounter(id: Data) throws -> UInt32 {
        var counter: UInt32 = 0
        try mutate { items in
            guard let i = items.firstIndex(where: { $0.id == id }) else { throw CTAPStatus.noCredentials }
            items[i].signCount &+= 1
            items[i].lastUsed = Date()
            counter = items[i].signCount
        }
        return counter
    }

    func allCredentials() -> [StoredCredential] {
        locked { items }
    }

    func update(_ credential: StoredCredential) throws {
        try mutate { items in
            guard let i = items.firstIndex(where: { $0.id == credential.id }) else { throw CTAPStatus.noCredentials }
            items[i] = credential
        }
    }

    /// Metadata only; the authenticator deletes the key right after.
    func delete(id: Data) throws {
        try mutate { $0.removeAll { $0.id == id } }
    }

    /// Marks an account as suggested first on its site, or not.
    func setSuggested(id: Data, _ suggested: Bool) {
        try? mutate { items in
            guard let i = items.firstIndex(where: { $0.id == id }) else { return }
            items[i].suggested = suggested ? true : nil
        }
    }

    /// Deletes keys and their metadata. Cannot be undone. The metadata goes
    /// first, so a failure leaves an unused key, never an entry without one.
    func delete(_ credentials: [StoredCredential]) {
        let ids = Set(credentials.map(\.id))
        guard (try? mutate({ $0.removeAll { ids.contains($0.id) } })) != nil else { return }
        for id in ids { keys.deleteKey(id: id) }
    }

    /// The user's own name for a key; nil or blank goes back to the site's name.
    func rename(id: Data, to name: String?) {
        let trimmed = name?.trimmingCharacters(in: .whitespacesAndNewlines)
        try? mutate { items in
            guard let i = items.firstIndex(where: { $0.id == id }) else { return }
            items[i].localName = trimmed?.isEmpty == false ? trimmed : nil
        }
    }

    /// The user's own name for a site; nil or blank removes it. Main thread.
    func renameSite(_ rpId: String, to name: String?) {
        let trimmed = name?.trimmingCharacters(in: .whitespacesAndNewlines)
        var names = siteNames
        names[rpId] = trimmed?.isEmpty == false ? trimmed : nil
        guard let data = try? JSONEncoder().encode(names), (try? Keychain.write(data, "siteNames")) != nil else { return }
        siteNames = names
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    private func mutate(_ change: (inout [StoredCredential]) throws -> Void) throws {
        let snapshot: [StoredCredential] = try locked {
            var copy = items
            try change(&copy)
            try Keychain.write(try JSONEncoder().encode(copy), "credentials")
            items = copy
            return copy
        }
        DispatchQueue.main.async { self.all = snapshot }
    }
}
