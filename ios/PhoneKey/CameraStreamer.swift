import AVFoundation
import CoreImage
import os
import PhoneKeyCore
import UIKit
import VideoToolbox

/// The webcam (docs/protocol.md §5 "camera"): the camera's picture, turned
/// upright by AVFoundation, cut to 16:9 and scaled in one Core Image pass,
/// then H.264 from the hardware encoder. Encoded frames go into `frames`,
/// which the sender drains. The Simulator has no camera; it encodes a moving
/// test pattern instead.
///
/// All mutable state lives on `work`; the encoder's output handler only
/// touches `frames` and the keyframe flag.
final class CameraStreamer: NSObject, @unchecked Sendable {
    enum StartError: Error {
        case unavailable
        case noFormat
        case encoder(OSStatus)
    }

    let request: CameraStreamRequest
    /// Chosen at the start; never changes while the stream runs.
    private(set) var size = VideoSize.p720
    /// The current frame rate (lower under heat).
    var fps: Int { work.sync { governor.fps } }
    let frames = FrameQueue()

    /// The stream must end on its own (on any queue).
    var onStop: ((CameraStoppedMessage.Reason) -> Void)?
    /// The frame rate changed under heat (on any queue).
    var onFpsChange: ((Int) -> Void)?

    private let work = DispatchQueue(label: "net.geraldhofbauer.phonekey.webcam", qos: .userInitiated)
    private let log = Logger(subsystem: "net.geraldhofbauer.phonekey", category: "webcam")
    private let ciContext = CIContext(options: [.workingColorSpace: NSNull(), .cacheIntermediates: false])
    private var session: AVCaptureSession?
    private var device: AVCaptureDevice?
    private var connection: AVCaptureConnection?
    private var compression: VTCompressionSession?
    private var governor: FrameRateGovernor
    private var heatTimer: DispatchSourceTimer?
    private var patternTimer: DispatchSourceTimer?
    private var pressureObservation: NSKeyValueObservation?
    private var observers: [NSObjectProtocol] = []
    private var orientation: AVCaptureVideoOrientation
    private var stopped = false
    private let keyframeFlag = Flag(true) // the first frame is a keyframe
    private let endLock = NSLock()
    private var ended: CameraStoppedMessage.Reason?

    /// Why the stream ended on its own, if it has (any thread).
    var endedReason: CameraStoppedMessage.Reason? {
        endLock.lock()
        defer { endLock.unlock() }
        return ended
    }

    init(request: CameraStreamRequest, orientation: AVCaptureVideoOrientation) {
        self.request = request
        self.orientation = orientation
        governor = FrameRateGovernor(requested: request.fps, level: Self.heatLevel(pressure: nil), now: Date())
        super.init()
    }

    // MARK: Control

    /// Sets up camera and encoder and starts capturing. Blocks; call off the
    /// main thread.
    func start() throws {
        try work.sync {
            #if targetEnvironment(simulator)
            size = VideoSize.best(upTo: request.maxSize, availableWidth: request.maxSize.width) ?? .p540
            try makeEncoder()
            startPattern()
            #else
            try startCapture()
            #endif
            startHeatWatch()
            log.notice("webcam started: \(self.size.description, privacy: .public) at \(self.governor.fps) fps")
        }
    }

    /// Ends capturing and encoding; `frames` is closed. Idempotent.
    func stop() {
        work.sync { tearDown() }
        frames.close()
    }

    /// camera.keyframe: the next frame is a keyframe.
    func requestKeyframe() {
        keyframeFlag.set(true)
    }

    /// The phone was turned: the picture stays upright, the size stays.
    func setOrientation(_ orientation: AVCaptureVideoOrientation) {
        work.async {
            guard !self.stopped, self.orientation != orientation else { return }
            self.orientation = orientation
            if let connection = self.connection, connection.isVideoOrientationSupported {
                connection.videoOrientation = orientation
            }
        }
    }

    // MARK: Capture

    private func startCapture() throws {
        let position: AVCaptureDevice.Position = request.camera == .front ? .front : .back
        guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: position),
              let input = try? AVCaptureDeviceInput(device: device)
        else { throw StartError.unavailable }
        guard let (format, size) = Self.chooseFormat(device.formats, request: request) else {
            throw StartError.noFormat
        }
        self.size = size
        let d = CMVideoFormatDescriptionGetDimensions(format.formatDescription)
        let maxRate = format.videoSupportedFrameRateRanges.map(\.maxFrameRate).max() ?? 0
        log.notice("webcam format \(d.width)×\(d.height) up to \(maxRate) fps for \(size.description, privacy: .public)")
        self.device = device

        let session = AVCaptureSession()
        session.beginConfiguration()
        // The active format decides the size; the preset would override it.
        session.sessionPreset = .inputPriority
        guard session.canAddInput(input) else {
            session.commitConfiguration()
            throw StartError.unavailable
        }
        session.addInput(input)
        let output = AVCaptureVideoDataOutput()
        output.videoSettings = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange]
        output.alwaysDiscardsLateVideoFrames = true
        output.setSampleBufferDelegate(self, queue: work)
        guard session.canAddOutput(output) else {
            session.commitConfiguration()
            throw StartError.unavailable
        }
        session.addOutput(output)
        do {
            try device.lockForConfiguration()
            device.activeFormat = format
            Self.setFrameRate(governor.fps, on: device)
            device.unlockForConfiguration()
        } catch {
            session.commitConfiguration()
            throw StartError.unavailable
        }
        if let connection = output.connection(with: .video) {
            // Upright from AVFoundation; the front camera stays unmirrored (§5).
            if connection.isVideoOrientationSupported { connection.videoOrientation = orientation }
            if connection.isVideoMirroringSupported {
                connection.automaticallyAdjustsVideoMirroring = false
                connection.isVideoMirrored = false
            }
            self.connection = connection
        }
        session.commitConfiguration()

        try makeEncoder()
        observe(session)
        session.startRunning()
        guard session.isRunning else {
            tearDown()
            throw StartError.unavailable
        }
        self.session = session
    }

    /// The smallest format whose short side covers the width (in portrait the
    /// picture's width comes from the sensor's short side, §5 "Picture") at the
    /// frame rate, for the largest size of the ladder that works.
    static func chooseFormat(_ formats: [AVCaptureDevice.Format],
                             request: CameraStreamRequest) -> (AVCaptureDevice.Format, VideoSize)? {
        for size in VideoSize.ladder where size <= request.maxSize {
            let fitting = formats.filter { format in
                let subtype = CMFormatDescriptionGetMediaSubType(format.formatDescription)
                guard subtype == kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
                    || subtype == kCVPixelFormatType_420YpCbCr8BiPlanarFullRange
                else { return false }
                let d = CMVideoFormatDescriptionGetDimensions(format.formatDescription)
                return Int(min(d.width, d.height)) >= size.width
                    && format.videoSupportedFrameRateRanges.contains { $0.maxFrameRate >= Double(request.fps) }
            }
            let smallest = fitting.min { a, b in
                let da = CMVideoFormatDescriptionGetDimensions(a.formatDescription)
                let db = CMVideoFormatDescriptionGetDimensions(b.formatDescription)
                return Int(da.width) * Int(da.height) < Int(db.width) * Int(db.height)
            }
            if let smallest { return (smallest, size) }
        }
        return nil
    }

    private static func setFrameRate(_ fps: Int, on device: AVCaptureDevice) {
        let duration = CMTime(value: 1, timescale: CMTimeScale(fps))
        device.activeVideoMinFrameDuration = duration
        device.activeVideoMaxFrameDuration = duration
    }

    /// Cuts the upright picture to a centred 16:9 and scales it to the size.
    private func render(_ image: CIImage, into buffer: CVPixelBuffer) {
        let extent = image.extent
        var crop = extent
        if extent.width * 9 > extent.height * 16 {
            crop.size.width = (extent.height * 16 / 9).rounded(.down)
            crop.origin.x += ((extent.width - crop.width) / 2).rounded(.down)
        } else {
            crop.size.height = (extent.width * 9 / 16).rounded(.down)
            crop.origin.y += ((extent.height - crop.height) / 2).rounded(.down)
        }
        let scale = CGFloat(size.width) / crop.width
        let output = image.cropped(to: crop)
            .transformed(by: CGAffineTransform(translationX: -crop.origin.x, y: -crop.origin.y))
            .transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        ciContext.render(output, to: buffer, bounds: CGRect(x: 0, y: 0, width: size.width, height: size.height),
                         colorSpace: nil)
    }

    // MARK: Encoder

    private func makeEncoder() throws {
        var session: VTCompressionSession?
        let attributes: [String: Any] = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
            kCVPixelBufferWidthKey as String: size.width,
            kCVPixelBufferHeightKey as String: size.height,
            kCVPixelBufferIOSurfacePropertiesKey as String: [String: Any](),
        ]
        let status = VTCompressionSessionCreate(
            allocator: nil, width: Int32(size.width), height: Int32(size.height), codecType: kCMVideoCodecType_H264,
            encoderSpecification: nil, imageBufferAttributes: attributes as CFDictionary,
            compressedDataAllocator: nil, outputCallback: nil, refcon: nil, compressionSessionOut: &session)
        guard status == noErr, let session else { throw StartError.encoder(status) }
        // Real time, no B-frames, so frames arrive in display order (§5).
        VTSessionSetProperty(session, key: kVTCompressionPropertyKey_RealTime, value: kCFBooleanTrue)
        VTSessionSetProperty(session, key: kVTCompressionPropertyKey_AllowFrameReordering, value: kCFBooleanFalse)
        VTSessionSetProperty(session, key: kVTCompressionPropertyKey_ProfileLevel,
                             value: kVTProfileLevel_H264_Main_AutoLevel)
        VTSessionSetProperty(session, key: kVTCompressionPropertyKey_H264EntropyMode, value: kVTH264EntropyMode_CABAC)
        compression = session
        applyRate()
        VTCompressionSessionPrepareToEncodeFrames(session)
    }

    /// Frame rate, keyframe interval (at least one every 2 s) and bitrate.
    private func applyRate() {
        guard let session = compression else { return }
        let fps = governor.fps
        let bitrate = CameraStreamRequest.bitrate(for: size, fps: fps)
        VTSessionSetProperty(session, key: kVTCompressionPropertyKey_ExpectedFrameRate, value: fps as CFNumber)
        VTSessionSetProperty(session, key: kVTCompressionPropertyKey_MaxKeyFrameInterval, value: (fps * 2) as CFNumber)
        VTSessionSetProperty(session, key: kVTCompressionPropertyKey_MaxKeyFrameIntervalDuration, value: 2 as CFNumber)
        VTSessionSetProperty(session, key: kVTCompressionPropertyKey_AverageBitRate, value: bitrate as CFNumber)
        // Caps keyframe bursts at 1.5× the average over one second.
        let limits = [bitrate * 3 / 16, 1] as CFArray // bytes per second, seconds
        VTSessionSetProperty(session, key: kVTCompressionPropertyKey_DataRateLimits, value: limits)
    }

    /// Scales `image` into a buffer of the encoder's pool and encodes it.
    private func encode(_ image: CIImage, time: CMTime) {
        guard !stopped, let session = compression, let pool = VTCompressionSessionGetPixelBufferPool(session) else { return }
        var buffer: CVPixelBuffer?
        guard CVPixelBufferPoolCreatePixelBuffer(nil, pool, &buffer) == kCVReturnSuccess, let buffer else { return }
        render(image, into: buffer)
        let properties: CFDictionary? = keyframeFlag.take()
            ? [kVTEncodeFrameOptionKey_ForceKeyFrame: kCFBooleanTrue] as CFDictionary : nil
        let duration = CMTime(value: 1, timescale: CMTimeScale(governor.fps))
        let status = VTCompressionSessionEncodeFrame(
            session, imageBuffer: buffer, presentationTimeStamp: time, duration: duration,
            frameProperties: properties, infoFlagsOut: nil
        ) { [weak self] status, _, sample in
            self?.encoded(status: status, sample: sample)
        }
        if status != noErr {
            log.error("encoding failed: \(status)")
            fail(.failed)
        }
    }

    /// The encoder's output handler: AVCC to Annex B with SPS/PPS in front of
    /// every keyframe, then into the send queue.
    private func encoded(status: OSStatus, sample: CMSampleBuffer?) {
        guard status == noErr else {
            log.error("encoder output failed: \(status)")
            fail(.failed)
            return
        }
        guard let sample, CMSampleBufferDataIsReady(sample), let block = CMSampleBufferGetDataBuffer(sample) else { return }
        let attachments = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: false) as? [[CFString: Any]]
        let keyframe = !((attachments?.first?[kCMSampleAttachmentKey_NotSync] as? Bool) ?? false)

        var avcc = Data(count: CMBlockBufferGetDataLength(block))
        let copied = avcc.withUnsafeMutableBytes { raw in
            CMBlockBufferCopyDataBytes(block, atOffset: 0, dataLength: raw.count, destination: raw.baseAddress!)
        }
        guard copied == kCMBlockBufferNoErr else { return }

        var parameterSets: [Data] = []
        var lengthSize: Int32 = 4
        if let description = CMSampleBufferGetFormatDescription(sample) {
            var count = 0
            CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                description, parameterSetIndex: 0, parameterSetPointerOut: nil, parameterSetSizeOut: nil,
                parameterSetCountOut: &count, nalUnitHeaderLengthOut: &lengthSize)
            if keyframe {
                for index in 0..<count {
                    var pointer: UnsafePointer<UInt8>?
                    var length = 0
                    if CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                        description, parameterSetIndex: index, parameterSetPointerOut: &pointer,
                        parameterSetSizeOut: &length, parameterSetCountOut: nil, nalUnitHeaderLengthOut: nil) == noErr,
                        let pointer {
                        parameterSets.append(Data(bytes: pointer, count: length))
                    }
                }
            }
        }
        guard let annexB = try? AnnexB.fromAVCC(avcc, lengthSize: Int(lengthSize), parameterSets: parameterSets) else {
            return
        }
        let seconds = CMTimeGetSeconds(CMSampleBufferGetPresentationTimeStamp(sample))
        let time = UInt64(max(0, seconds) * 1_000_000)
        if frames.push(VideoFrame(keyframe: keyframe, time: time, data: annexB)) {
            keyframeFlag.set(true) // fell behind: the next frame is a keyframe
        }
    }

    // MARK: Heat (§5 "Heat")

    private static func heatLevel(pressure: AVCaptureDevice.SystemPressureState.Level?) -> HeatLevel {
        let thermal: HeatLevel
        switch ProcessInfo.processInfo.thermalState {
        case .nominal: thermal = .nominal
        case .fair: thermal = .fair
        case .serious: thermal = .serious
        default: thermal = .critical
        }
        let camera: HeatLevel
        switch pressure {
        case nil, .some(.nominal): camera = .nominal
        case .some(.fair): camera = .fair
        case .some(.serious): camera = .serious
        default: camera = .critical // critical and shutdown
        }
        return max(thermal, camera)
    }

    private func startHeatWatch() {
        if let device {
            pressureObservation = device.observe(\.systemPressureState, options: [.new]) { [weak self] _, _ in
                self?.work.async { self?.checkHeat() }
            }
        }
        observers.append(NotificationCenter.default.addObserver(
            forName: ProcessInfo.thermalStateDidChangeNotification, object: nil, queue: nil
        ) { [weak self] _ in
            self?.work.async { self?.checkHeat() }
        })
        // The 60 s calm period needs a clock.
        let timer = DispatchSource.makeTimerSource(queue: work)
        timer.schedule(deadline: .now() + 5, repeating: 5)
        timer.setEventHandler { [weak self] in self?.checkHeat() }
        timer.resume()
        heatTimer = timer
    }

    private func checkHeat() {
        guard !stopped else { return }
        switch governor.update(level: Self.heatLevel(pressure: device?.systemPressureState.level), now: Date()) {
        case .none:
            break
        case let .change(fps):
            log.notice("webcam now at \(fps) fps")
            if let device, (try? device.lockForConfiguration()) != nil {
                Self.setFrameRate(fps, on: device)
                device.unlockForConfiguration()
            }
            applyRate()
            restartPattern()
            onFpsChange?(fps)
        case .stop:
            fail(.thermal)
        }
    }

    // MARK: Interruptions

    private func observe(_ session: AVCaptureSession) {
        observers.append(NotificationCenter.default.addObserver(
            forName: .AVCaptureSessionWasInterrupted, object: session, queue: nil
        ) { [weak self] note in
            let raw = note.userInfo?[AVCaptureSessionInterruptionReasonKey] as? Int
            let reason = raw.flatMap(AVCaptureSession.InterruptionReason.init(rawValue:))
            self?.fail(reason == .videoDeviceNotAvailableDueToSystemPressure ? .thermal : .interrupted)
        })
        observers.append(NotificationCenter.default.addObserver(
            forName: .AVCaptureSessionRuntimeError, object: session, queue: nil
        ) { [weak self] _ in
            self?.fail(.failed)
        })
    }

    /// Ends the stream on the phone's side and says why, once.
    private func fail(_ reason: CameraStoppedMessage.Reason) {
        work.async {
            guard !self.stopped else { return }
            self.endLock.lock()
            self.ended = reason
            self.endLock.unlock()
            self.tearDown()
            self.frames.close()
            self.onStop?(reason)
        }
    }

    /// `work` only.
    private func tearDown() {
        guard !stopped else { return }
        stopped = true
        heatTimer?.cancel()
        heatTimer = nil
        patternTimer?.cancel()
        patternTimer = nil
        pressureObservation = nil
        observers.forEach(NotificationCenter.default.removeObserver)
        observers = []
        session?.stopRunning()
        session = nil
        connection = nil
        device = nil
        if let compression {
            VTCompressionSessionInvalidate(compression)
        }
        compression = nil
    }

    // MARK: Simulator test pattern

    /// A moving checkerboard with a sweeping bar, so the stream visibly moves.
    private func startPattern() {
        #if targetEnvironment(simulator)
        let timer = DispatchSource.makeTimerSource(queue: work)
        timer.schedule(deadline: .now(), repeating: 1.0 / Double(governor.fps))
        let start = CACurrentMediaTime()
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            let t = CACurrentMediaTime() - start
            self.encode(self.pattern(at: t), time: CMClockGetTime(CMClockGetHostTimeClock()))
        }
        timer.resume()
        patternTimer = timer
        #endif
    }

    private func restartPattern() {
        #if targetEnvironment(simulator)
        patternTimer?.cancel()
        patternTimer = nil
        startPattern()
        #endif
    }

    private func pattern(at t: Double) -> CIImage {
        let w = CGFloat(size.width), h = CGFloat(size.height)
        let checker = CIFilter(name: "CICheckerboardGenerator", parameters: [
            "inputCenter": CIVector(x: CGFloat(t * 120).truncatingRemainder(dividingBy: 160), y: 0),
            "inputColor0": CIColor(red: 0.15, green: 0.35, blue: 0.75),
            "inputColor1": CIColor(red: 0.9, green: 0.9, blue: 0.9),
            "inputWidth": 80,
        ])!.outputImage!
        let barX = CGFloat((t * 0.25).truncatingRemainder(dividingBy: 1)) * w
        let bar = CIImage(color: CIColor(red: 1, green: 0.4, blue: 0)).cropped(to: CGRect(x: barX, y: 0, width: w / 20, height: h))
        return bar.composited(over: checker).cropped(to: CGRect(x: 0, y: 0, width: w, height: h))
    }
}

extension CameraStreamer: AVCaptureVideoDataOutputSampleBufferDelegate {
    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection) {
        guard let buffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        encode(CIImage(cvPixelBuffer: buffer), time: CMSampleBufferGetPresentationTimeStamp(sampleBuffer))
    }
}

/// A flag for the encoder's output handler and the work queue.
private final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Bool

    init(_ value: Bool) {
        self.value = value
    }

    func set(_ new: Bool) {
        lock.lock()
        value = new
        lock.unlock()
    }

    /// Returns the value and clears it.
    func take() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let was = value
        value = false
        return was
    }
}
