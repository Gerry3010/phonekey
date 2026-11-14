import AVFoundation
import PhoneKeyCore
import SwiftUI

/// Scan the host's QR code, confirm, then wait until the host connects.
struct PairingView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var hosts: HostStore
    @Environment(\.dismiss) private var dismiss
    @State private var candidate: PairingInvite?
    @State private var confirmedKey: Data?
    @State private var scanError: String?

    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                if let paired = hosts.lastPaired, paired.key == confirmedKey {
                    Spacer()
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 64))
                        .foregroundColor(.green)
                    Text("Paired with \(paired.name)")
                        .font(.title3.bold())
                    Spacer()
                } else if let pending = hosts.pending {
                    Spacer()
                    ProgressView()
                    Text("Waiting for \(pending.invite.hostName)…")
                        .font(.title3.bold())
                    Text("Keep `phonekey pair` running on the computer and the phone connected by USB.")
                        .multilineTextAlignment(.center)
                        .foregroundColor(.secondary)
                    Button("Cancel", role: .cancel) { hosts.cancelPending() }
                    Spacer()
                } else {
                    QRScannerView { handleScan($0) }
                        .frame(maxWidth: .infinity)
                        .frame(height: 340)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                        .onAppear { model.scannerActive = true }
                        .onDisappear { model.scannerActive = false }
                    Text("Scan the code shown by `phonekey pair` on the computer.")
                        .multilineTextAlignment(.center)
                        .foregroundColor(.secondary)
                    if let scanError {
                        Text(scanError).foregroundColor(.red)
                    }
                    Spacer()
                }
            }
            .padding()
            .navigationTitle("Pair computer")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .alert("Pair with \(candidate?.hostName ?? "")?", isPresented: Binding(
                get: { candidate != nil }, set: { if !$0 { candidate = nil } }
            ), presenting: candidate) { invite in
                Button("Pair") {
                    confirmedKey = invite.hostKey
                    hosts.confirm(invite)
                }
                Button("Cancel", role: .cancel) {}
            } message: { _ in
                Text("Only pair computers you control. A paired computer can ask PhoneKey for its status "
                    + "and, if you allow it, take photos.")
            }
        }
        .onAppear {
            if let invite = model.proposedInvite {
                candidate = invite
                model.proposedInvite = nil
            }
        }
    }

    private func handleScan(_ text: String) {
        guard candidate == nil, hosts.pending == nil else { return }
        guard let url = URL(string: text), let invite = try? PairingInvite(url: url) else {
            scanError = "That is not a PhoneKey pairing code."
            return
        }
        scanError = nil
        candidate = invite
    }
}

/// Camera preview that reports QR codes.
struct QRScannerView: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let controller = ScannerController()
        controller.onCode = onCode
        return controller
    }

    func updateUIViewController(_ controller: ScannerController, context: Context) {
        controller.onCode = onCode
    }

    final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
        var onCode: ((String) -> Void)?
        private let session = AVCaptureSession()
        private let queue = DispatchQueue(label: "net.geraldhofbauer.phonekey.scanner")
        private var preview: AVCaptureVideoPreviewLayer?
        private var lastCode: (String, Date)?

        override func viewDidLoad() {
            super.viewDidLoad()
            view.backgroundColor = .black
            #if targetEnvironment(simulator)
            showMessage("No camera in the Simulator.\nOpen the pairing URL with\nxcrun simctl openurl booted '<url>'")
            #else
            switch AVCaptureDevice.authorizationStatus(for: .video) {
            case .authorized:
                configure()
            case .notDetermined:
                AVCaptureDevice.requestAccess(for: .video) { granted in
                    DispatchQueue.main.async {
                        granted ? self.configure() : self.showMessage("Camera access is needed to scan the code.")
                    }
                }
            default:
                showMessage("Allow camera access for PhoneKey in Settings to scan the code.")
            }
            #endif
        }

        override func viewDidLayoutSubviews() {
            super.viewDidLayoutSubviews()
            preview?.frame = view.bounds
        }

        override func viewWillDisappear(_ animated: Bool) {
            super.viewWillDisappear(animated)
            queue.async { self.session.stopRunning() }
        }

        private func configure() {
            guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back),
                  let input = try? AVCaptureDeviceInput(device: device), session.canAddInput(input)
            else { return showMessage("The camera is not available.") }
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { return showMessage("The camera is not available.") }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
            let layer = AVCaptureVideoPreviewLayer(session: session)
            layer.videoGravity = .resizeAspectFill
            view.layer.addSublayer(layer)
            preview = layer
            queue.async { self.session.startRunning() }
        }

        private func showMessage(_ text: String) {
            let label = UILabel()
            label.text = text
            label.textColor = .white
            label.numberOfLines = 0
            label.textAlignment = .center
            label.translatesAutoresizingMaskIntoConstraints = false
            view.addSubview(label)
            NSLayoutConstraint.activate([
                label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
                label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
                label.leadingAnchor.constraint(greaterThanOrEqualTo: view.leadingAnchor, constant: 16),
            ])
        }

        func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject],
                            from connection: AVCaptureConnection) {
            guard let code = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
            // The same code is reported many times a second; report it once.
            if let (last, at) = lastCode, last == code, Date().timeIntervalSince(at) < 3 { return }
            lastCode = (code, Date())
            onCode?(code)
        }
    }
}
