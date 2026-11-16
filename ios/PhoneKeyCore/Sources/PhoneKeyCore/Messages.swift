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
    /// photo.capture: JPEG quality 0.1…1.0.
    public var quality: Double?
    /// camera.start: "720p" or "1080p", under the same key as the photo's
    /// quality (docs/protocol.md §5 "camera").
    public var videoQuality: String?
    /// camera.start: frames per second.
    public var fps: Int?
    /// camera.keyframe and camera.stop: the stream.
    public var stream: UInt32?
    /// ctap.request: CTAPHID command and payload (base64 in JSON).
    public var cmd: Int?
    public var data: Data?

    enum CodingKeys: String, CodingKey {
        case t, id, camera, quality, fps, stream, cmd, data
        case maxDimension = "max_dimension"
    }
}

extension Request {
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        t = try c.decode(String.self, forKey: .t)
        id = try c.decodeIfPresent(UInt64.self, forKey: .id)
        camera = try c.decodeIfPresent(String.self, forKey: .camera)
        maxDimension = try c.decodeIfPresent(Int.self, forKey: .maxDimension)
        // A number for photos, a name for the webcam.
        if let number = try? c.decodeIfPresent(Double.self, forKey: .quality) {
            quality = number
        } else {
            videoQuality = try c.decodeIfPresent(String.self, forKey: .quality)
        }
        fps = try c.decodeIfPresent(Int.self, forKey: .fps)
        stream = try c.decodeIfPresent(UInt32.self, forKey: .stream)
        cmd = try c.decodeIfPresent(Int.self, forKey: .cmd)
        data = try c.decodeIfPresent(Data.self, forKey: .data)
    }
}

public struct CTAPResponseMessage: Encodable {
    public var t = "ctap.response"
    public var id: UInt64?
    public var data: Data

    public init(id: UInt64?, data: Data) {
        self.id = id
        self.data = data
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
        /// The webcam's own switch (Phase 4).
        public var streamEnabled: Bool
        /// A webcam stream is running.
        public var streaming: Bool

        enum CodingKeys: String, CodingKey {
            case enabled, available
            case streamEnabled = "stream_enabled"
            case streaming
        }

        public init(enabled: Bool, available: Bool, streamEnabled: Bool = false, streaming: Bool = false) {
            self.enabled = enabled
            self.available = available
            self.streamEnabled = streamEnabled
            self.streaming = streaming
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
    case cameraStreamDisabled = "camera_stream_disabled"
    case unsupported
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

// MARK: Webcam (Phase 4, docs/protocol.md §5 "camera")

public struct CameraStartedMessage: Encodable, Equatable {
    public var t = "camera.started"
    public var id: UInt64?
    public var stream: UInt32
    public var codec = "h264"
    public var width: Int
    public var height: Int
    public var fps: Int
    public var camera: String

    public init(id: UInt64?, stream: UInt32, width: Int, height: Int, fps: Int, camera: String) {
        self.id = id
        self.stream = stream
        self.width = width
        self.height = height
        self.fps = fps
        self.camera = camera
    }
}

/// The frame rate changed (heat); width and height never do.
public struct CameraChangedMessage: Encodable, Equatable {
    public var t = "camera.changed"
    public var stream: UInt32
    public var fps: Int

    public init(stream: UInt32, fps: Int) {
        self.stream = stream
        self.fps = fps
    }
}

/// Acknowledges camera.keyframe.
public struct CameraKeyframeMessage: Encodable, Equatable {
    public var t = "camera.keyframe"
    public var id: UInt64?
    public var stream: UInt32

    public init(id: UInt64?, stream: UInt32) {
        self.id = id
        self.stream = stream
    }
}

public struct CameraStoppedMessage: Encodable, Equatable {
    public enum Reason: String, Encodable {
        case requested
        case stoppedOnPhone = "stopped_on_phone"
        case switchedOff = "switched_off"
        case interrupted
        case thermal
        case failed
    }

    public var t = "camera.stopped"
    /// Set when it answers camera.stop; nil when the phone stopped on its own.
    public var id: UInt64?
    public var stream: UInt32
    public var reason: Reason

    public init(id: UInt64?, stream: UInt32, reason: Reason) {
        self.id = id
        self.stream = stream
        self.reason = reason
    }
}
