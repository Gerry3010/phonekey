import Foundation
import PhoneKeyCore

/// The PIN record (sealed hash and retries) in the Keychain, this device
/// only, never synced (§10, "Storage" and "Retries").
final class KeychainPinStorage: PinStorage {
    private static let account = "fido.pin"

    func loadPin() throws -> PinRecord? {
        guard let data = try Keychain.read(Self.account) else { return nil }
        return try JSONDecoder().decode(PinRecord.self, from: data)
    }

    func savePin(_ record: PinRecord?) throws {
        if let record {
            try Keychain.write(try JSONEncoder().encode(record), Self.account)
        } else {
            try Keychain.delete(Self.account)
        }
    }
}
