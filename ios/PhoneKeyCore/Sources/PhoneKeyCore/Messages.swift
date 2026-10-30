import Foundation

// JSON messages of protocol v1. Field names follow docs/protocol.md.

public struct HelloMessage: Codable, Equatable {
    public struct Device: Codable, Equatable {
        public var model: String
        public var system: String
        public var name: String

        public init(model: String, system: String, name: String) {
            self.model = model
            self.system = system
            self.name = name
        }
    }

    public struct Host: Codable, Equatable {
        public var name: String
        public var os: String
    }

    public var t = "hello"
    public var role: String
    public var `protocol`: Int
    public var appVersion: String
    public var device: Device?
    public var host: Host?
    public var features: [String]?

    enum CodingKeys: String, CodingKey {
        case t, role, `protocol`, device, host, features
        case appVersion = "app_version"
    }

    public static func phone(appVersion: String, device: Device, features: [String]) -> HelloMessage {
        HelloMessage(role: "phone", protocol: Int(Wire.version), appVersion: appVersion,
                     device: device, host: nil, features: features)
    }
}

/// A request from the host. Only the fields of its type are set.
public struct Request: Decodable, Equatable {
    public var t: String
    public var id: UInt64?
    public var camera: String?
    public var maxDimension: Int?
    public var quality: Double?

    enum CodingKeys: String, CodingKey {
        case t, id, camera, quality
        case maxDimension = "max_dimension"
    }
}

public struct PongMessage: Encodable {
    public var t = "pong"
    public var id: UInt64?
}

public struct StatusMessage: Encodable, Equatable {
    public struct Battery: Encodable, Equatable {
        public var level: Double?
        public var state: String

        public init(level: Double?, state: String) {
            self.level = level
            self.state = state
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(level, forKey: .level) // null when unknown
            try c.encode(state, forKey: .state)
        }

        enum CodingKeys: String, CodingKey { case level, state }
    }

    public struct Camera: Encodable, Equatable {
        public var enabled: Bool
        public var available: Bool

        public init(enabled: Bool, available: Bool) {
            self.enabled = enabled
            self.available = available
        }
    }

    public var t = "status"
    public var id: UInt64?
    public var battery: Battery
    public var thermal: String
    public var deskMode: Bool
    public var guidedAccess: Bool
    public var camera: Camera

    enum CodingKeys: String, CodingKey {
        case t, id, battery, thermal, camera
        case deskMode = "desk_mode"
        case guidedAccess = "guided_access"
    }

    public init(id: UInt64?, battery: Battery, thermal: String, deskMode: Bool, guidedAccess: Bool, camera: Camera) {
        self.id = id
        self.battery = battery
        self.thermal = thermal
        self.deskMode = deskMode
        self.guidedAccess = guidedAccess
        self.camera = camera
    }
}

public struct PhotoBeginMessage: Encodable {
    public var t = "photo.begin"
    public var id: UInt64?
    public var stream: UInt32
    public var size: Int
    public var mime = "image/jpeg"
    public var width: Int
    public var height: Int

    public init(id: UInt64?, stream: UInt32, size: Int, width: Int, height: Int) {
        self.id = id
        self.stream = stream
        self.size = size
        self.width = width
        self.height = height
    }
}

public struct PhotoEndMessage: Encodable {
    public var t = "photo.end"
    public var id: UInt64?
    public var stream: UInt32
    public var sha256: String

    public init(id: UInt64?, stream: UInt32, sha256: String) {
        self.id = id
        self.stream = stream
        self.sha256 = sha256
    }
}

/// Error codes of docs/protocol.md §5.
public enum ErrorCode: String, Encodable {
    case notPaired = "not_paired"
    case badRequest = "bad_request"
    case unknownType = "unknown_type"
    case cameraDisabled = "camera_disabled"
    case cameraUnavailable = "camera_unavailable"
    case busy
    case captureFailed = "capture_failed"
    case `internal`
}

public struct ErrorMessage: Encodable, Error {
    public var t = "error"
    public var id: UInt64?
    public var code: ErrorCode
    public var message: String?

    public init(id: UInt64?, code: ErrorCode, message: String? = nil) {
        self.id = id
        self.code = code
        self.message = message
    }
}
