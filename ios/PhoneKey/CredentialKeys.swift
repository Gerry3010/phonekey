import Foundation
@preconcurrency import LocalAuthentication
import PhoneKeyCore
import Security

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

    func createKey(id: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        #if targetEnvironment(simulator)
        let flags: SecAccessControlCreateFlags = [.biometryAny]
        #else
        let flags: SecAccessControlCreateFlags = [.privateKeyUsage, .biometryAny]
        #endif
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
        else { throw error!.takeRetainedValue() as Error }

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

    func sign(id: Data, data: Data, reason: String) async throws -> Data {
        // Normally the card has just done Touch ID; only without it does the
        // signature ask on its own.
        let context = handoff?.take() ?? LAContext()
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
    }

    func credentials(rpId: String) -> [StoredCredential] {
        locked { items.filter { $0.rpId == rpId } }
    }

    func credential(id: Data) -> StoredCredential? {
        locked { items.first { $0.id == id } }
    }

    func save(_ credential: StoredCredential) throws {
        try mutate { $0.append(credential) }
    }

    func incrementCounter(id: Data) throws -> UInt32 {
        var counter: UInt32 = 0
        try mutate { items in
            guard let i = items.firstIndex(where: { $0.id == id }) else { throw CTAPStatus.noCredentials }
            items[i].signCount &+= 1
            counter = items[i].signCount
        }
        return counter
    }

    /// Deletes the key and the metadata. Cannot be undone.
    func delete(_ credential: StoredCredential) {
        keys.deleteKey(id: credential.id)
        try? mutate { $0.removeAll { $0.id == credential.id } }
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
