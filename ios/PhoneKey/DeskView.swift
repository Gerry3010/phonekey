import SwiftUI

/// Black, minimal screen for the desk station. A tap shows the way out.
struct DeskView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var hosts: HostStore
    let server: PhoneServer?
    @State private var showControls = false

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            VStack(spacing: 16) {
                Image(systemName: "key.fill")
                    .font(.system(size: 40))
                    .foregroundColor(Color(white: 0.25))
                if let server {
                    DeskStatusLine(server: server, hosts: hosts)
                }
                Text(model.battery.text)
                    .font(.footnote)
                    .foregroundColor(Color(white: 0.3))
                if showControls {
                    Button("Leave desk mode") { model.deskMode = false }
                        .buttonStyle(.bordered)
                        .tint(.gray)
                        .padding(.top, 24)
                }
            }
            if model.capturing {
                VStack {
                    Label("Taking a photo", systemImage: "camera.fill")
                        .font(.headline)
                        .foregroundColor(.white)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)
                        .background(Capsule().fill(Color.red))
                    Spacer()
                }
                .padding(.top, 40)
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { reveal() }
        .statusBar(hidden: true)
        .preferredColorScheme(.dark)
    }

    private func reveal() {
        showControls = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { showControls = false }
    }
}

private struct DeskStatusLine: View {
    @ObservedObject var server: PhoneServer
    @ObservedObject var hosts: HostStore

    var body: some View {
        Text(text)
            .font(.callout)
            .foregroundColor(Color(white: 0.4))
            .multilineTextAlignment(.center)
    }

    private var text: String {
        switch server.state {
        case .stopped: return "Not listening"
        case .failed: return "Listener failed"
        case .listening:
            let names = Array(Set(server.connectedHosts)).compactMap { hosts.name(for: $0) }.sorted()
            return names.isEmpty ? "Waiting for a computer" : "Connected to \(names.joined(separator: ", "))"
        }
    }
}
