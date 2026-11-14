import CryptoKit
import Foundation
import Security

/// Generic-password items, this device only, never synced.
enum Keychain {
    struct Failure: Error {
        let status: OSStatus
    }

    private static let service = "net.geraldhofbauer.phonekey"

    /// Returns nil only if the item does not exist; other failures throw, so
    /// a locked keychain is never mistaken for "no key yet".
    static func read(_ account: String) throws -> Data? {
        var query = base(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = out as? Data else { throw Failure(status: status) }
        return data
    }

    static func write(_ data: Data, _ account: String) throws {
        let status = SecItemUpdate(base(account) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var add = base(account)
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let added = SecItemAdd(add as CFDictionary, nil)
            guard added == errSecSuccess else { throw Failure(status: added) }
        } else if status != errSecSuccess {
            throw Failure(status: status)
        }
    }

    private static func base(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

/// The phone's static Noise key (X25519). Not the FIDO key: that one will
/// live in the Secure Enclave.
enum Identity {
    static func load() throws -> Curve25519.KeyAgreement.PrivateKey {
        if let raw = try Keychain.read("identity") {
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw)
        }
        let key = Curve25519.KeyAgreement.PrivateKey()
        try Keychain.write(key.rawRepresentation, "identity")
        return key
    }
}
