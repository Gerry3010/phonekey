import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack {
            Group {
                if model.deskMode {
                    DeskView(hosts: model.hosts, server: model.server)
                } else {
                    MainView(hosts: model.hosts, server: model.server)
                }
            }
            if model.winking {
                Color.white.opacity(0.9).ignoresSafeArea().transition(.opacity)
            }
            FIDOPromptOverlay(prompts: model.fidoPrompts)
        }
        .animation(.easeInOut(duration: 0.25), value: model.winking)
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
                    NavigationLink {
                        CredentialsView(store: model.credentials)
                    } label: {
                        Label("Passkeys & security keys", systemImage: "key")
                    }
                } footer: {
                    Text("Keys live in the Secure Enclave of this iPhone and are not synced or backed up. "
                        + "Keep a second way to sign in for every account.")
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
                VStack(alignment: .leading, spacing: 4) {
                    Label("Ready, waiting for a computer", systemImage: "cable.connector")
                        .foregroundColor(.secondary)
                    if let contact = server.lastContact {
                        LastContactText(contact: contact, hosts: hosts)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
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

/// "Last contact: MacBook, 5 sec ago", counting up live.
struct LastContactText: View {
    let contact: PhoneServer.Contact
    @ObservedObject var hosts: HostStore

    var body: some View {
        Text("Last contact: \(hosts.name(for: contact.hostKey) ?? "unknown"), ")
            + Text(contact.date, style: .relative)
            + Text(" ago")
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
            .environmentObject(AppModel())
    }
}
