import Foundation

/// The content of a pairing URL:
/// `phonekey://pair?v=1&k=<host key>&s=<psk>&n=<host name>`.
public struct PairingInvite: Equatable {
    public enum ParseError: Error, Equatable {
        case notAPairingURL
        case unsupportedVersion
        case badHostKey
        case badSecret
    }

    public static let maxNameBytes = 64

    public let hostKey: Data
    public let psk: Data
    public let hostName: String

    public init(hostKey: Data, psk: Data, hostName: String) {
        self.hostKey = hostKey
        self.psk = psk
        self.hostName = hostName
    }

    public init(url: URL) throws {
        guard url.scheme == "phonekey", url.host == "pair",
              let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems
        else { throw ParseError.notAPairingURL }
        func value(_ name: String) -> String? { items.first { $0.name == name }?.value }
        guard value("v") == "1" else { throw ParseError.unsupportedVersion }
        guard let key = value("k").flatMap(Data.init(base64URL:)), key.count == 32 else {
            throw ParseError.badHostKey
        }
        guard let psk = value("s").flatMap(Data.init(base64URL:)), psk.count == 32 else {
            throw ParseError.badSecret
        }
        var name = value("n") ?? ""
        while name.utf8.count > Self.maxNameBytes { name.removeLast() }
        self.init(hostKey: key, psk: psk, hostName: name.isEmpty ? "Unnamed host" : name)
    }
}

extension Data {
    /// Decodes base64url without padding.
    public init?(base64URL string: String) {
        var s = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        self.init(base64Encoded: s)
    }

    public var base64URLEncodedString: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
