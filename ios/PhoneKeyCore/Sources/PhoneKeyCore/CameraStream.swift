import Foundation

// The webcam stream of docs/protocol.md §5 "camera" (Phase 4a), as far as it
// does not need a camera: checking camera.start, the size ladder, the frame
// format, Annex B, the send queue and the frame rate under heat.

/// A picture size of the stream.
public struct VideoSize: Equatable, Comparable, Sendable, CustomStringConvertible {
    public let width: Int
    public let height: Int

    public init(width: Int, height: Int) {
        self.width = width
        self.height = height
    }

    public static let p1080 = VideoSize(width: 1920, height: 1080)
    public static let p720 = VideoSize(width: 1280, height: 720)
    public static let p540 = VideoSize(width: 960, height: 540)

    /// The fallback ladder, largest first: the phone keeps the frame rate and
    /// steps the size down, never up.
    public static let ladder = [p1080, p720, p540]

    /// The largest size of the ladder that is at most `max` and at most
    /// `availableWidth` wide (no upscaling), or nil.
    public static func best(upTo max: VideoSize, availableWidth: Int) -> VideoSize? {
        ladder.first { $0 <= max && $0.width <= availableWidth }
    }

    public static func < (a: VideoSize, b: VideoSize) -> Bool { a.width * a.height < b.width * b.height }

    public var description: String { "\(width)×\(height)" }
}

/// A checked camera.start.
public struct CameraStreamRequest: Equatable, Sendable {
    public enum Camera: String, Sendable {
        case front, back
    }

    public let camera: Camera
    /// The requested quality, a maximum.
    public let maxSize: VideoSize
    public let fps: Int

    public static let fpsRange = 15...30

    /// Unknown values answer `unsupported`.
    public init(_ request: Request) throws {
        let id = request.id
        guard let camera = Camera(rawValue: request.camera ?? "front") else {
            throw ErrorMessage(id: id, code: .unsupported, message: "camera must be front or back.")
        }
        switch (request.quality, request.videoQuality ?? "720p") {
        case (nil, "720p"): maxSize = .p720
        case (nil, "1080p"): maxSize = .p1080
        default: throw ErrorMessage(id: id, code: .unsupported, message: "quality must be 720p or 1080p.")
        }
        let fps = request.fps ?? 30
        guard Self.fpsRange.contains(fps) else {
            throw ErrorMessage(id: id, code: .unsupported, message: "fps must be 15 to 30.")
        }
        self.camera = camera
        self.fps = fps
    }

    public init(camera: Camera, maxSize: VideoSize, fps: Int) {
        self.camera = camera
        self.maxSize = maxSize
        self.fps = fps
    }

    /// The target bitrate: about 4 and 8 Mbit/s at 720p and 1080p, 2.5 and 5
    /// at 15 fps (§5); 960×540 gets a little more than half of 720p.
    public static func bitrate(for size: VideoSize, fps: Int) -> Int {
        let full: Double
        switch size {
        case .p1080: full = 8_000_000
        case .p720: full = 4_000_000
        default: full = 2_500_000
        }
        // Linear between 15 fps (×0.625) and 30 fps (×1).
        let factor = 0.625 + 0.375 * Double(min(max(fps, 15), 30) - 15) / 15
        return Int(full * factor)
    }
}

/// One frame on the chunk stream: flags, capture time, length, Annex B.
public struct VideoFrame: Equatable, Sendable {
    public var keyframe: Bool
    /// Capture time in microseconds, monotonic on the phone.
    public var time: UInt64
    /// One H.264 access unit in Annex B format.
    public var data: Data

    public static let headerSize = 13

    public init(keyframe: Bool, time: UInt64, data: Data) {
        self.keyframe = keyframe
        self.time = time
        self.data = data
    }

    /// The frame as the stream carries it.
    public var encoded: Data {
        var out = Data(capacity: Self.headerSize + data.count)
        out.append(keyframe ? 0x01 : 0x00)
        withUnsafeBytes(of: time.bigEndian) { out.append(contentsOf: $0) }
        withUnsafeBytes(of: UInt32(data.count).bigEndian) { out.append(contentsOf: $0) }
        out.append(data)
        return out
    }
}

/// VideoToolbox writes NAL units with a length in front (AVCC); the stream
/// wants start codes (Annex B), with SPS and PPS in front of every keyframe.
public enum AnnexB {
    public static let startCode = Data([0x00, 0x00, 0x00, 0x01])

    public struct Malformed: Error {}

    /// `parameterSets`: SPS and PPS, put in front (keyframes).
    public static func fromAVCC(_ avcc: Data, lengthSize: Int = 4, parameterSets: [Data] = []) throws -> Data {
        guard (1...4).contains(lengthSize) else { throw Malformed() }
        var out = Data(capacity: avcc.count + parameterSets.reduce(0) { $0 + $1.count + 4 } + 16)
        for set in parameterSets {
            out.append(startCode)
            out.append(set)
        }
        let bytes = [UInt8](avcc)
        var i = 0
        while i < bytes.count {
            guard bytes.count - i >= lengthSize else { throw Malformed() }
            var length = 0
            for k in 0..<lengthSize { length = length << 8 | Int(bytes[i + k]) }
            i += lengthSize
            guard length > 0, bytes.count - i >= length else { throw Malformed() }
            out.append(startCode)
            out.append(contentsOf: bytes[i..<(i + length)])
            i += length
        }
        return out
    }
}

/// The frames waiting to be sent. Never more than `maxAge` of video: when
/// sending falls behind, everything queued goes and frames are dropped up to
/// the next keyframe, which the encoder is asked for (§5, "Falling behind").
public final class FrameQueue: @unchecked Sendable {
    public let maxAge: UInt64
    private let lock = NSLock()
    private var frames: [VideoFrame] = []
    private var waiter: CheckedContinuation<VideoFrame?, Never>?
    private var closed = false
    private var waitingForKeyframe = false
    private var droppedCount = 0

    /// `maxAge` in microseconds (0.5 s).
    public init(maxAge: UInt64 = 500_000) {
        self.maxAge = maxAge
    }

    /// Frames dropped so far.
    public var dropped: Int {
        lock.lock()
        defer { lock.unlock() }
        return droppedCount
    }

    /// Queues a freshly encoded frame. Returns true when the encoder should
    /// make the next frame a keyframe.
    @discardableResult
    public func push(_ frame: VideoFrame) -> Bool {
        lock.lock()
        if closed {
            lock.unlock()
            return false
        }
        if waitingForKeyframe, !frame.keyframe {
            droppedCount += 1
            lock.unlock()
            return true
        }
        waitingForKeyframe = false
        if let waiter {
            // The sender is idle: hand the frame over at once.
            self.waiter = nil
            lock.unlock()
            waiter.resume(returning: frame)
            return false
        }
        frames.append(frame)
        var wantKeyframe = false
        if let oldest = frames.first, frame.time > oldest.time + maxAge {
            droppedCount += frames.count - (frame.keyframe ? 1 : 0)
            frames = frame.keyframe ? [frame] : []
            if !frame.keyframe {
                waitingForKeyframe = true
                wantKeyframe = true
            }
        }
        lock.unlock()
        return wantKeyframe
    }

    /// The next frame to send; nil once closed.
    public func next() async -> VideoFrame? {
        await withCheckedContinuation { continuation in
            lock.lock()
            if !frames.isEmpty {
                let frame = frames.removeFirst()
                lock.unlock()
                continuation.resume(returning: frame)
            } else if closed {
                lock.unlock()
                continuation.resume(returning: nil)
            } else {
                waiter = continuation
                lock.unlock()
            }
        }
    }

    public func close() {
        lock.lock()
        closed = true
        frames = []
        let waiting = waiter
        waiter = nil
        lock.unlock()
        waiting?.resume(returning: nil)
    }
}

/// The worse of the device's thermal state and the camera's system pressure.
public enum HeatLevel: Int, Comparable, Sendable {
    case nominal, fair, serious, critical

    public static func < (a: HeatLevel, b: HeatLevel) -> Bool { a.rawValue < b.rawValue }
}

/// The frame rate under heat (§5, "Heat"): 15 fps at `serious`, back to the
/// requested rate once it has been `fair` or better for 60 s, stop at
/// `critical`.
public struct FrameRateGovernor: Sendable {
    public enum Action: Equatable, Sendable {
        case none
        case change(fps: Int)
        case stop
    }

    public static let reducedFps = 15
    public static let calmPeriod: TimeInterval = 60

    public let requested: Int
    public private(set) var fps: Int
    private var calmSince: Date?

    /// Already `serious` at the start: start at 15.
    public init(requested: Int, level: HeatLevel, now: Date) {
        self.requested = requested
        fps = level >= .serious ? min(requested, Self.reducedFps) : requested
        calmSince = level <= .fair ? now : nil
    }

    /// Call on every change and now and then (the calm period needs a clock).
    public mutating func update(level: HeatLevel, now: Date) -> Action {
        switch level {
        case .critical:
            return .stop
        case .serious:
            calmSince = nil
            guard fps > Self.reducedFps else { return .none }
            fps = Self.reducedFps
            return .change(fps: fps)
        case .nominal, .fair:
            guard fps < requested else {
                calmSince = nil
                return .none
            }
            let since = calmSince ?? now
            calmSince = since
            guard now.timeIntervalSince(since) >= Self.calmPeriod else { return .none }
            fps = requested
            calmSince = nil
            return .change(fps: fps)
        }
    }
}
