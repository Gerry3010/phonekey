import AVFoundation
import CryptoKit
@preconcurrency import LocalAuthentication
import os
import PhoneKeyCore
import SwiftUI

/// Wires the server, the paired hosts, the camera and desk mode together and
/// answers host requests.
@MainActor
final class AppModel: ObservableObject {
    let hosts = HostStore()
    private(set) var server: PhoneServer?
    let startupError: String?
    private let camera = CameraService()
    private let log = Logger(subsystem: "net.geraldhofbauer.phonekey", category: "app")

    // FIDO security key
    let credentials: KeychainCredentialStore
    let fidoPrompts = FIDOPrompts()
    private let authenticator: Authenticator
    /// The one CTAP request being worked on, across all connections.
    private var ctapJob: (session: ObjectIdentifier, id: UInt64?, task: Task<Void, Never>)?
    /// CTAP state per host connection ("power cycle", §10), dropped with it.
    private var ctapSessions: [ObjectIdentifier: CTAPSession] = [:]

    @Published var photosAllowed: Bool {
        didSet { UserDefaults.standard.set(photosAllowed, forKey: "photosAllowed") }
    }

    /// The webcam's own switch, off by default (§5 "camera"). Turning it off
    /// ends a running stream.
    @Published var webcamAllowed: Bool {
        didSet {
            UserDefaults.standard.set(webcamAllowed, forKey: "webcamAllowed")
            if !webcamAllowed { stopWebcam(.switchedOff) }
            if webcamAllowed, AVCaptureDevice.authorizationStatus(for: .video) == .notDetermined {
                AVCaptureDevice.requestAccess(for: .video) { _ in }
            }
        }
    }

    /// The running webcam stream, for the notice on screen.
    struct WebcamStream: Equatable {
        let hostName: String?
        let camera: CameraStreamRequest.Camera
        let size: VideoSize
        var fps: Int
    }

    @Published private(set) var webcam: WebcamStream?

    @Published var deskMode: Bool {
        didSet {
            UserDefaults.standard.set(deskMode, forKey: "deskMode")
            applyDeskMode()
        }
    }

    @Published private(set) var capturing = false
    @Published private(set) var battery = BatteryInfo.current
    /// A pairing URL opened from outside (QR code in the Camera app, simctl).
    @Published var proposedInvite: PairingInvite?
    @Published var showPairing = false
    /// Set briefly when a host sends CTAPHID WINK.
    @Published private(set) var winking = false
    var scannerActive = false

    private var savedBrightness: CGFloat?
    private var nextStream: UInt32 = 1
    /// The one webcam stream, across all connections (§5: one at a time).
    private var webcamJob: WebcamJob?
    /// Set while a camera.start is setting up, so a second one gets busy.
    private var webcamStarting = false
    private var orientationObserver: NSObjectProtocol?

    private struct WebcamJob {
        let session: PhoneSession
        let stream: UInt32
        let streamer: CameraStreamer
        let sender: Task<Void, Never>
    }

    init() {
        photosAllowed = UserDefaults.standard.bool(forKey: "photosAllowed")
        webcamAllowed = UserDefaults.standard.bool(forKey: "webcamAllowed")
        deskMode = UserDefaults.standard.bool(forKey: "deskMode")
        UIDevice.current.isBatteryMonitoringEnabled = true
        // The property initializer ran before monitoring was on and saw "unknown".
        battery = BatteryInfo.current

        let handoff = TouchIDHandoff()
        fidoPrompts.handoff = handoff
        let keys = SecureEnclaveKeys(handoff: handoff)
        credentials = KeychainCredentialStore(keys: keys)
        fidoPrompts.credentials = credentials
        authenticator = Authenticator(store: credentials, keys: keys, ui: fidoPrompts, pins: KeychainPinStorage())

        do {
            let identity = try Identity.load()
            let hello = HelloMessage.phone(appVersion: AppInfo.current.version,
                                           device: DeviceInfo.helloDevice,
                                           features: ["status", "photo", "fido", "camera"])
            startupError = nil
            server = PhoneServer(identity: identity, registry: hosts, hello: hello, handler: { [weak self] request, session in
                guard let self else { throw ErrorMessage(id: request.id, code: .internal) }
                try await self.handle(request, session)
            }, onSessionEnd: { [weak self] session in
                Task { @MainActor in self?.sessionEnded(ObjectIdentifier(session)) }
            })
        } catch {
            startupError = "The phone key could not be loaded from the keychain (\(error))."
        }

        for name in [UIDevice.batteryLevelDidChangeNotification, UIDevice.batteryStateDidChangeNotification] {
            NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.battery = BatteryInfo.current }
            }
        }

        // A prompt in desk mode lights the screen up until it is answered.
        fidoPrompts.onActiveChange = { [weak self] active in
            guard let self, self.deskMode else { return }
            UIScreen.main.brightness = active ? 0.6 : 0
        }
    }

    // MARK: Lifecycle

    func scenePhaseChanged(_ phase: ScenePhase) {
        switch phase {
        case .active:
            server?.start()
            applyDeskMode()
        case .background:
            server?.stop()
            restoreBrightness()
        default:
            break
        }
    }

    func open(_ url: URL) {
        do {
            proposedInvite = try PairingInvite(url: url)
            showPairing = true
        } catch {
            log.error("Ignoring URL that is not a pairing URL")
        }
    }

    // MARK: Desk mode

    private func applyDeskMode() {
        UIApplication.shared.isIdleTimerDisabled = deskMode
        if deskMode {
            if savedBrightness == nil { savedBrightness = UIScreen.main.brightness }
            UIScreen.main.brightness = 0
        } else {
            restoreBrightness()
        }
    }

    private func restoreBrightness() {
        if let saved = savedBrightness {
            UIScreen.main.brightness = saved
            savedBrightness = nil
        }
    }

    // MARK: Requests

    nonisolated func handle(_ request: Request, _ session: PhoneSession) async throws {
        switch request.t {
        case "status.get":
            try await session.send(await status(id: request.id))
        case "photo.capture":
            try await photo(request, session)
        case "ctap.request":
            try await startCTAP(request, session)
        case "ctap.cancel":
            await cancelCTAP(request.id, session: ObjectIdentifier(session))
        case "camera.start":
            try await startWebcam(request, session)
        case "camera.stop":
            try await stopWebcam(request, session)
        case "camera.keyframe":
            try await webcamKeyframe(request, session)
        default:
            throw ErrorMessage(id: request.id, code: .unknownType, message: "Unknown request \(request.t).")
        }
    }

    // MARK: FIDO

    nonisolated private func startCTAP(_ request: Request, _ session: PhoneSession) async throws {
        let id = request.id
        guard let cmd = request.cmd, let data = request.data else {
            throw ErrorMessage(id: id, code: .badRequest, message: "ctap.request needs cmd and data.")
        }
        switch cmd {
        case 0x08: // WINK
            await wink()
            try await session.send(CTAPResponseMessage(id: id, data: Data()))
        case 0x10: // CBOR
            let started = await MainActor.run { () -> Bool in
                guard ctapJob == nil else { return false }
                fidoPrompts.hostName = session.hostKey.flatMap { hosts.name(for: $0) }
                let key = ObjectIdentifier(session)
                let ctapSession = ctapSessions[key] ?? CTAPSession()
                ctapSessions[key] = ctapSession
                let task = Task { [authenticator] in
                    // Runs on after the handler returns, so the session keeps
                    // reading (ctap.cancel) while the user decides.
                    let response = await authenticator.handle(data, session: ctapSession)
                    let sent = (try? await session.send(CTAPResponseMessage(id: id, data: response))) != nil
                    await MainActor.run {
                        self.ctapJob = nil
                        self.fidoPrompts.requestFinished(succeeded: sent && response.first == CTAPStatus.ok.rawValue)
                    }
                }
                ctapJob = (ObjectIdentifier(session), id, task)
                return true
            }
            if !started {
                try await session.send(CTAPResponseMessage(id: id, data: Data([CTAPStatus.channelBusy.rawValue])))
            }
        default:
            try await session.send(CTAPResponseMessage(id: id, data: Data([CTAPStatus.invalidCommand.rawValue])))
        }
    }

    private func cancelCTAP(_ id: UInt64?, session: ObjectIdentifier) {
        guard let job = ctapJob, job.session == session, job.id == id else { return }
        job.task.cancel()
    }

    // MARK: PIN in the app (§10, "PIN (3c)")

    /// nil when the keychain cannot be read.
    func pinState() -> PinState? {
        try? authenticator.pinState()
    }

    /// Sets or replaces the PIN. The caller has just asked for Touch ID.
    func setPin(_ pin: String) throws {
        try authenticator.setPinOnPhone(pin)
    }

    /// Removes a forgotten or blocked PIN; the keys stay.
    func removePin() throws {
        try authenticator.removePin()
    }

    /// Touch ID for a change made in the app.
    func confirmWithTouchID(_ reason: String) async -> Bool {
        let context = LAContext()
        context.localizedFallbackTitle = ""
        defer { context.invalidate() }
        return (try? await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                                   localizedReason: reason)) == true
    }

    /// A connection ended: whatever it asked for is no longer wanted.
    private func sessionEnded(_ session: ObjectIdentifier) {
        ctapSessions.removeValue(forKey: session)?.end()
        if let job = ctapJob, job.session == session {
            job.task.cancel()
        }
        // The stream ends with its session; there is nobody left to tell.
        if let job = webcamJob, ObjectIdentifier(job.session) == session {
            endWebcam(job)
        }
    }

    // MARK: Webcam (Phase 4a, §5 "camera")

    nonisolated private func startWebcam(_ request: Request, _ session: PhoneSession) async throws {
        let id = request.id
        let wanted = try CameraStreamRequest(request)
        let (stream, orientation, hostName) = try await MainActor.run {
            () -> (UInt32, AVCaptureVideoOrientation, String?) in
            guard webcamAllowed else {
                throw ErrorMessage(id: id, code: .cameraStreamDisabled, message: "The webcam is switched off in PhoneKey.")
            }
            guard CameraService.isAvailable else {
                throw ErrorMessage(id: id, code: .cameraUnavailable, message: "No camera or no camera permission.")
            }
            guard webcamJob == nil, !webcamStarting, !capturing, !scannerActive else {
                throw ErrorMessage(id: id, code: .busy, message: "The camera is in use.")
            }
            webcamStarting = true
            defer { nextStream &+= 1 }
            return (nextStream, currentVideoOrientation(), session.hostKey.flatMap { hosts.name(for: $0) })
        }

        let streamer = CameraStreamer(request: wanted, orientation: orientation)
        streamer.onStop = { [weak self] reason in
            Task { @MainActor in self?.webcamStoppedOnItsOwn(stream: stream, reason: reason) }
        }
        streamer.onFpsChange = { [weak self] fps in
            Task { @MainActor in
                guard let self, let job = self.webcamJob, job.stream == stream else { return }
                self.webcam?.fps = fps
                Task { try? await job.session.send(CameraChangedMessage(stream: stream, fps: fps)) }
            }
        }
        do {
            try await Task.detached(priority: .userInitiated) { try streamer.start() }.value
        } catch {
            await MainActor.run { webcamStarting = false }
            log.error("Webcam did not start: \(String(describing: error), privacy: .public)")
            if case CameraStreamer.StartError.noFormat = error {
                throw ErrorMessage(id: id, code: .unsupported, message: "The camera cannot deliver this.")
            }
            throw ErrorMessage(id: id, code: .cameraUnavailable, message: "The camera did not start.")
        }

        let fps = streamer.fps
        do {
            // The answer goes out before the first chunk (the host sets the stream up on it).
            try await session.send(CameraStartedMessage(id: id, stream: stream, width: streamer.size.width,
                                                        height: streamer.size.height, fps: fps,
                                                        camera: wanted.camera.rawValue))
        } catch {
            streamer.stop()
            await MainActor.run { webcamStarting = false }
            throw error
        }

        await MainActor.run {
            webcamStarting = false
            let sender = Task.detached(priority: .userInitiated) {
                await Self.send(streamer.frames, stream: stream, over: session)
            }
            let job = WebcamJob(session: session, stream: stream, streamer: streamer, sender: sender)
            webcamJob = job
            webcam = WebcamStream(hostName: hostName, camera: wanted.camera, size: streamer.size, fps: fps)
            watchOrientation()
            // It may have ended while the answer went out.
            if let reason = streamer.endedReason {
                webcamStoppedOnItsOwn(stream: stream, reason: reason)
            }
        }
    }

    /// Drains the queue onto the session, chunk by chunk. Each chunk waits for
    /// the connection, so JSON messages (FIDO, ping) go out between chunks (§5,
    /// "Order on the wire").
    nonisolated private static func send(_ frames: FrameQueue, stream: UInt32, over session: PhoneSession) async {
        while let frame = await frames.next() {
            let bytes = frame.encoded
            var offset = 0
            while offset < bytes.count {
                let end = min(offset + Wire.maxChunkData, bytes.count)
                guard (try? await session.sendChunk(stream: stream, data: bytes[offset..<end])) != nil else {
                    frames.close()
                    return
                }
                offset = end
            }
        }
    }

    nonisolated private func stopWebcam(_ request: Request, _ session: PhoneSession) async throws {
        let id = request.id
        let stream = try await MainActor.run { () -> UInt32 in
            guard let job = webcamJob, job.session === session, job.stream == request.stream else {
                throw ErrorMessage(id: id, code: .badRequest, message: "No such webcam stream.")
            }
            endWebcam(job)
            return job.stream
        }
        try await session.send(CameraStoppedMessage(id: id, stream: stream, reason: .requested))
    }

    nonisolated private func webcamKeyframe(_ request: Request, _ session: PhoneSession) async throws {
        let id = request.id
        let stream = try await MainActor.run { () -> UInt32 in
            guard let job = webcamJob, job.session === session, job.stream == request.stream else {
                throw ErrorMessage(id: id, code: .badRequest, message: "No such webcam stream.")
            }
            job.streamer.requestKeyframe()
            return job.stream
        }
        try await session.send(CameraKeyframeMessage(id: id, stream: stream))
    }

    /// Stop on the phone (the notice's Stop button) or the switch turned off.
    func stopWebcam(_ reason: CameraStoppedMessage.Reason) {
        guard let job = webcamJob else { return }
        endWebcam(job)
        Task { try? await job.session.send(CameraStoppedMessage(id: nil, stream: job.stream, reason: reason)) }
    }

    /// The streamer ended by itself (interruption, heat, failure).
    private func webcamStoppedOnItsOwn(stream: UInt32, reason: CameraStoppedMessage.Reason) {
        guard let job = webcamJob, job.stream == stream else { return }
        log.notice("Webcam stopped: \(reason.rawValue, privacy: .public)")
        endWebcam(job)
        Task { try? await job.session.send(CameraStoppedMessage(id: nil, stream: job.stream, reason: reason)) }
    }

    private func endWebcam(_ job: WebcamJob) {
        webcamJob = nil
        webcam = nil
        job.streamer.onStop = nil
        job.streamer.onFpsChange = nil
        let streamer = job.streamer
        DispatchQueue.global(qos: .userInitiated).async { streamer.stop() }
        job.sender.cancel()
        if let observer = orientationObserver {
            NotificationCenter.default.removeObserver(observer)
            orientationObserver = nil
            UIDevice.current.endGeneratingDeviceOrientationNotifications()
        }
    }

    /// The way the phone stands: the device's orientation, else the UI's (the
    /// UI turns only between the two portraits). Lying flat keeps the last.
    private func currentVideoOrientation() -> AVCaptureVideoOrientation {
        switch UIDevice.current.orientation {
        case .portrait: return .portrait
        case .portraitUpsideDown: return .portraitUpsideDown
        case .landscapeLeft: return .landscapeRight // device and video name the sides oppositely
        case .landscapeRight: return .landscapeLeft
        default:
            let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene
            return scene?.interfaceOrientation == .portraitUpsideDown ? .portraitUpsideDown : .portrait
        }
    }

    private func watchOrientation() {
        guard orientationObserver == nil else { return }
        UIDevice.current.beginGeneratingDeviceOrientationNotifications()
        orientationObserver = NotificationCenter.default.addObserver(
            forName: UIDevice.orientationDidChangeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self, let job = self.webcamJob else { return }
                switch UIDevice.current.orientation {
                case .faceUp, .faceDown, .unknown: return // lying flat keeps the last
                default: job.streamer.setOrientation(self.currentVideoOrientation())
                }
            }
        }
    }

    private func wink() {
        winking = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { self.winking = false }
    }

    private func status(id: UInt64?) -> StatusMessage {
        battery = BatteryInfo.current
        return StatusMessage(
            id: id,
            battery: .init(level: battery.level, state: battery.state),
            thermal: DeviceInfo.thermalState,
            deskMode: deskMode,
            guidedAccess: UIAccessibility.isGuidedAccessEnabled,
            camera: .init(enabled: photosAllowed, available: CameraService.isAvailable,
                          streamEnabled: webcamAllowed, streaming: webcamJob != nil))
    }

    nonisolated private func photo(_ request: Request, _ session: PhoneSession) async throws {
        let id = request.id
        let position: AVCaptureDevice.Position
        switch request.camera ?? "back" {
        case "back": position = .back
        case "front": position = .front
        default: throw ErrorMessage(id: id, code: .badRequest, message: "camera must be back or front.")
        }
        let maxDimension = request.maxDimension ?? 1568
        guard (0...20000).contains(maxDimension) else {
            throw ErrorMessage(id: id, code: .badRequest, message: "max_dimension out of range.")
        }
        let quality = min(max(request.quality ?? 0.8, 0.1), 1.0)

        let (stream, upsideDown): (UInt32, Bool) = try await MainActor.run {
            guard photosAllowed else {
                throw ErrorMessage(id: id, code: .cameraDisabled, message: "Photos are switched off in PhoneKey.")
            }
            guard CameraService.isAvailable else {
                throw ErrorMessage(id: id, code: .cameraUnavailable, message: "No camera or no camera permission.")
            }
            guard !capturing, !scannerActive, webcamJob == nil, !webcamStarting else {
                throw ErrorMessage(id: id, code: .busy, message: "The camera is in use.")
            }
            capturing = true
            defer { nextStream &+= 1 }
            // The photo comes out the way up the phone stands.
            let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene
            return (nextStream, scene?.interfaceOrientation == .portraitUpsideDown)
        }
        let result: CameraService.Photo
        do {
            result = try await camera.capture(position: position, upsideDown: upsideDown,
                                              maxDimension: maxDimension, quality: quality)
            await MainActor.run { capturing = false }
        } catch {
            await MainActor.run { capturing = false }
            if case CameraService.CaptureError.busy = error {
                throw ErrorMessage(id: id, code: .busy, message: "The camera is in use.")
            }
            throw ErrorMessage(id: id, code: .captureFailed, message: "Taking the photo failed.")
        }

        try await session.send(PhotoBeginMessage(id: id, stream: stream, size: result.jpeg.count,
                                                 width: result.width, height: result.height))
        var offset = 0
        while offset < result.jpeg.count {
            let end = min(offset + Wire.maxChunkData, result.jpeg.count)
            try await session.sendChunk(stream: stream, data: result.jpeg[offset..<end])
            offset = end
        }
        let digest = SHA256.hash(data: result.jpeg).map { String(format: "%02x", $0) }.joined()
        try await session.send(PhotoEndMessage(id: id, stream: stream, sha256: digest))
    }
}

struct BatteryInfo: Equatable {
    var level: Double?
    var state: String

    @MainActor static var current: BatteryInfo {
        let device = UIDevice.current
        let level: Double? = device.batteryLevel < 0 ? nil : Double(device.batteryLevel)
        let state: String
        switch device.batteryState {
        case .unplugged: state = "unplugged"
        case .charging: state = "charging"
        case .full: state = "full"
        default: state = "unknown"
        }
        return BatteryInfo(level: level, state: state)
    }

    var text: String {
        let percent = level.map { "\(Int(($0 * 100).rounded()))%" } ?? "battery unknown"
        return state == "unknown" ? percent : "\(percent), \(state)"
    }
}

enum DeviceInfo {
    @MainActor static var helloDevice: HelloMessage.Device {
        HelloMessage.Device(model: modelIdentifier,
                            system: "\(UIDevice.current.systemName) \(UIDevice.current.systemVersion)",
                            name: UIDevice.current.name)
    }

    static var modelIdentifier: String {
        #if targetEnvironment(simulator)
        return ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] ?? "Simulator"
        #else
        var info = utsname()
        uname(&info)
        return withUnsafeBytes(of: &info.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        #endif
    }

    static var thermalState: String {
        switch ProcessInfo.processInfo.thermalState {
        case .nominal: return "nominal"
        case .fair: return "fair"
        case .serious: return "serious"
        case .critical: return "critical"
        @unknown default: return "nominal"
        }
    }
}
