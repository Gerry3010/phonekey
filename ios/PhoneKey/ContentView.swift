import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Group {
            if model.deskMode {
                DeskView(hosts: model.hosts, server: model.server)
            } else {
                MainView(hosts: model.hosts, server: model.server)
            }
        }
        .sheet(isPresented: $model.showPairing, onDismiss: { model.proposedInvite = nil }) {
            PairingView(hosts: model.hosts)
                .environmentObject(model)
        }
    }
}

private struct MainView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var hosts: HostStore
    let server: PhoneServer?

    var body: some View {
        NavigationView {
            List {
                if let error = model.startupError {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .foregroundColor(.red)
                    }
                }
                if let server {
                    Section {
                        ServerStatusRow(server: server, hosts: hosts)
                    }
                }

                Section {
                    ForEach(hosts.hosts) { host in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(host.name)
                            Text("Paired \(host.pairedAt.formatted(date: .abbreviated, time: .shortened))")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    .onDelete { offsets in
                        offsets.map { hosts.hosts[$0] }.forEach(hosts.remove)
                    }
                    Button {
                        model.showPairing = true
                    } label: {
                        Label("Pair new computer", systemImage: "qrcode.viewfinder")
                    }
                } header: {
                    Text("Paired computers")
                } footer: {
                    if hosts.hosts.isEmpty {
                        Text("Run `phonekey pair` on the computer and scan the code it shows.")
                    }
                }

                Section {
                    Toggle("Allow photos", isOn: $model.photosAllowed)
                } footer: {
                    Text("Paired computers may take photos with the back or front camera. "
                        + "You hear the shutter and see a notice on screen each time.")
                }

                Section {
                    Button {
                        model.deskMode = true
                    } label: {
                        Label("Start desk mode", systemImage: "moon")
                    }
                } footer: {
                    Text("Keeps the screen on at the lowest brightness so PhoneKey stays reachable. "
                        + "Turn on Guided Access (triple-click the Home button) so it stays in front. "
                        + (UIAccessibility.isGuidedAccessEnabled ? "Guided Access is on." : "Guided Access is off."))
                }

                Section {
                } footer: {
                    Text("PhoneKey \(AppInfo.current.versionDescription) · iOS \(UIDevice.current.systemVersion)")
                        .frame(maxWidth: .infinity)
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("PhoneKey")
        }
        .navigationViewStyle(.stack)
    }
}

struct ServerStatusRow: View {
    @ObservedObject var server: PhoneServer
    @ObservedObject var hosts: HostStore

    var body: some View {
        switch server.state {
        case .stopped:
            Label("Not listening", systemImage: "pause.circle")
                .foregroundColor(.secondary)
        case let .failed(message):
            Label("Listener failed: \(message)", systemImage: "exclamationmark.triangle")
                .foregroundColor(.red)
        case .listening:
            if server.connectedHosts.isEmpty {
                Label("Ready, waiting for a computer", systemImage: "cable.connector")
                    .foregroundColor(.secondary)
            } else {
                Label("Connected: \(connectedNames)", systemImage: "checkmark.circle.fill")
                    .foregroundColor(.green)
            }
        }
    }

    private var connectedNames: String {
        Array(Set(server.connectedHosts)).map { hosts.name(for: $0) ?? "unknown" }.sorted().joined(separator: ", ")
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
            .environmentObject(AppModel())
    }
}
