import AVFoundation
import ImageIO
import UIKit
import UniformTypeIdentifiers

/// Takes one photo at a time. The capture session only runs during a capture,
/// so the camera (and its green indicator) is off otherwise.
/// Sendable because all mutable state is confined to `queue`.
final class CameraService: @unchecked Sendable {
    enum CaptureError: Error {
        case busy
        case unavailable
        case failed(String)
    }

    struct Photo {
        let jpeg: Data
        let width: Int
        let height: Int
    }

    private let queue = DispatchQueue(label: "net.geraldhofbauer.phonekey.camera")
    private var inFlight: CaptureDelegate? // `queue` only

    static var isAvailable: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return AVCaptureDevice.authorizationStatus(for: .video) == .authorized
            && AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back) != nil
        #endif
    }

    func capture(position: AVCaptureDevice.Position, maxDimension: Int, quality: Double) async throws -> Photo {
        #if targetEnvironment(simulator)
        return try Self.process(Self.simulatorImage(position: position), maxDimension: maxDimension, quality: quality)
        #else
        let jpeg: Data = try await withCheckedThrowingContinuation { continuation in
            queue.async {
                guard self.inFlight == nil else { return continuation.resume(throwing: CaptureError.busy) }
                do {
                    let delegate = try CaptureDelegate(position: position) { result in
                        // AVFoundation calls back on its own queue.
                        self.queue.async {
                            self.inFlight = nil
                            continuation.resume(with: result)
                        }
                    }
                    self.inFlight = delegate
                    delegate.start(on: self.queue)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
        return try Self.process(jpeg, maxDimension: maxDimension, quality: quality)
        #endif
    }

    /// Scales so the longest side is at most `maxDimension` (0 = full size),
    /// bakes in the orientation and re-encodes, which also drops all metadata.
    static func process(_ data: Data, maxDimension: Int, quality: Double) throws -> Photo {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              let props = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
              let width = props[kCGImagePropertyPixelWidth] as? Int,
              let height = props[kCGImagePropertyPixelHeight] as? Int
        else { throw CaptureError.failed("unreadable image") }
        let longest = max(width, height)
        let target = maxDimension > 0 ? min(maxDimension, longest) : longest
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceThumbnailMaxPixelSize: target,
        ]
        guard let image = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary) else {
            throw CaptureError.failed("scaling failed")
        }
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, UTType.jpeg.identifier as CFString, 1, nil) else {
            throw CaptureError.failed("encoding failed")
        }
        CGImageDestinationAddImage(dest, image, [kCGImageDestinationLossyCompressionQuality: quality] as CFDictionary)
        guard CGImageDestinationFinalize(dest) else { throw CaptureError.failed("encoding failed") }
        return Photo(jpeg: out as Data, width: image.width, height: image.height)
    }

    #if targetEnvironment(simulator)
    /// A test picture, so the whole photo path can be exercised without a camera.
    private static func simulatorImage(position: AVCaptureDevice.Position) -> Data {
        let size = CGSize(width: 1200, height: 1600)
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        let image = UIGraphicsImageRenderer(size: size, format: format).image { ctx in
            let colors = [UIColor.systemTeal.cgColor, UIColor.systemIndigo.cgColor] as CFArray
            let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: colors, locations: nil)!
            ctx.cgContext.drawLinearGradient(gradient, start: .zero, end: CGPoint(x: size.width, y: size.height), options: [])
            let text = "PhoneKey Simulator\n\(position == .front ? "front" : "back") camera\n\(Date())"
            let style = NSMutableParagraphStyle()
            style.alignment = .center
            (text as NSString).draw(in: CGRect(x: 60, y: 650, width: size.width - 120, height: 400), withAttributes: [
                .font: UIFont.boldSystemFont(ofSize: 64), .foregroundColor: UIColor.white, .paragraphStyle: style,
            ])
        }
        return image.jpegData(compressionQuality: 1)!
    }
    #endif
}

/// One capture: session up, short settle for exposure, photo, session down.
private final class CaptureDelegate: NSObject, AVCapturePhotoCaptureDelegate {
    private let session = AVCaptureSession()
    private let output = AVCapturePhotoOutput()
    private let completion: (Result<Data, Error>) -> Void

    init(position: AVCaptureDevice.Position, completion: @escaping (Result<Data, Error>) -> Void) throws {
        self.completion = completion
        super.init()
        guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: position),
              let input = try? AVCaptureDeviceInput(device: device)
        else { throw CameraService.CaptureError.unavailable }
        session.beginConfiguration()
        session.sessionPreset = .photo
        guard session.canAddInput(input), session.canAddOutput(output) else {
            session.commitConfiguration()
            throw CameraService.CaptureError.unavailable
        }
        session.addInput(input)
        session.addOutput(output)
        session.commitConfiguration()
        output.connection(with: .video)?.videoOrientation = .portrait
    }

    func start(on queue: DispatchQueue) {
        session.startRunning()
        guard session.isRunning else {
            return finish(.failure(CameraService.CaptureError.failed("camera did not start")))
        }
        queue.asyncAfter(deadline: .now() + 0.7) {
            let settings = AVCapturePhotoSettings(format: [AVVideoCodecKey: AVVideoCodecType.jpeg])
            self.output.capturePhoto(with: settings, delegate: self)
        }
    }

    func photoOutput(_ output: AVCapturePhotoOutput, didFinishProcessingPhoto photo: AVCapturePhoto, error: Error?) {
        if let error {
            finish(.failure(CameraService.CaptureError.failed(error.localizedDescription)))
        } else if let data = photo.fileDataRepresentation() {
            finish(.success(data))
        } else {
            finish(.failure(CameraService.CaptureError.failed("no image data")))
        }
    }

    private func finish(_ result: Result<Data, Error>) {
        session.stopRunning()
        completion(result)
    }
}
