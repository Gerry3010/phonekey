import AVFoundation
import CryptoKit
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

    @Published var photosAllowed: Bool {
        didSet { UserDefaults.standard.set(photosAllowed, forKey: "photosAllowed") }
    }

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
    var scannerActive = false

    private var savedBrightness: CGFloat?
    private var nextStream: UInt32 = 1

    init() {
        photosAllowed = UserDefaults.standard.bool(forKey: "photosAllowed")
        deskMode = UserDefaults.standard.bool(forKey: "deskMode")
        UIDevice.current.isBatteryMonitoringEnabled = true

        do {
            let identity = try Identity.load()
            let hello = HelloMessage.phone(appVersion: AppInfo.current.version,
                                           device: DeviceInfo.helloDevice,
                                           features: ["status", "photo"])
            startupError = nil
            server = PhoneServer(identity: identity, registry: hosts, hello: hello) { [weak self] request, session in
                guard let self else { throw ErrorMessage(id: request.id, code: .internal) }
                try await self.handle(request, session)
            }
        } catch {
            startupError = "The phone key could not be loaded from the keychain (\(error))."
        }

        for name in [UIDevice.batteryLevelDidChangeNotification, UIDevice.batteryStateDidChangeNotification] {
            NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.battery = BatteryInfo.current }
            }
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
        default:
            throw ErrorMessage(id: request.id, code: .unknownType, message: "Unknown request \(request.t).")
        }
    }

    private func status(id: UInt64?) -> StatusMessage {
        StatusMessage(
            id: id,
            battery: .init(level: battery.level, state: battery.state),
            thermal: DeviceInfo.thermalState,
            deskMode: deskMode,
            guidedAccess: UIAccessibility.isGuidedAccessEnabled,
            camera: .init(enabled: photosAllowed, available: CameraService.isAvailable))
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

        let stream: UInt32 = try await MainActor.run {
            guard photosAllowed else {
                throw ErrorMessage(id: id, code: .cameraDisabled, message: "Photos are switched off in PhoneKey.")
            }
            guard CameraService.isAvailable else {
                throw ErrorMessage(id: id, code: .cameraUnavailable, message: "No camera or no camera permission.")
            }
            guard !capturing, !scannerActive else {
                throw ErrorMessage(id: id, code: .busy, message: "The camera is in use.")
            }
            capturing = true
            defer { nextStream &+= 1 }
            return nextStream
        }
        let result: CameraService.Photo
        do {
            result = try await camera.capture(position: position, maxDimension: maxDimension, quality: quality)
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
