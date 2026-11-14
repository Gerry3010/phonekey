import PhoneKeyCore
import SwiftUI

/// Full-screen card for the current FIDO prompt, above everything else.
struct FIDOPromptOverlay: View {
    @ObservedObject var prompts: FIDOPrompts

    var body: some View {
        if let active = prompts.active {
            ZStack {
                Color.black.opacity(0.88).ignoresSafeArea()
                VStack(spacing: 18) {
                    header(active)
                    content(active)
                    if let note = prompts.note {
                        Text(note).font(.footnote).foregroundColor(.orange)
                    }
                    Text(active.deadline, style: .timer)
                        .font(.caption.monospacedDigit())
                        .foregroundColor(.secondary)
                }
                .padding(24)
                .frame(maxWidth: 360)
                .background(RoundedRectangle(cornerRadius: 20).fill(Color(.secondarySystemBackground)))
                .padding(20)
            }
            .preferredColorScheme(.dark)
            .transition(.opacity)
        }
    }

    @ViewBuilder
    private func header(_ active: FIDOPrompts.Active) -> some View {
        VStack(spacing: 6) {
            Image(systemName: "key.fill").font(.system(size: 34)).foregroundColor(.accentColor)
            if let host = active.hostName {
                Text("Request from \(host)").font(.footnote).foregroundColor(.secondary)
            }
        }
    }

    @ViewBuilder
    private func content(_ active: FIDOPrompts.Active) -> some View {
        switch active.kind {
        case let .registration(p):
            Text(p.passkey ? "Create a passkey" : "Register security key").font(.title3.bold())
            site(p.rpId, name: p.rpName)
            if let account = p.userName ?? p.userDisplayName {
                Label(account, systemImage: "person.crop.circle").foregroundColor(.secondary)
            }
            buttons(primary: "Continue with Touch ID", action: prompts.approveRegistration)

        case let .signIn(p):
            Text("Sign in").font(.title3.bold())
            site(p.rpId, name: nil)
            VStack(spacing: 8) {
                ForEach(p.candidates) { credential in
                    Button {
                        prompts.choose(credential)
                    } label: {
                        Label(credential.accountLabel, systemImage: "person.crop.circle")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                }
            }
            Button("Cancel", role: .cancel, action: prompts.decline)

        case let .excluded(rpId):
            Text("Already registered").font(.title3.bold())
            Text("This key is already registered with \(rpId).")
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
            buttons(primary: "OK", action: prompts.acknowledge, showCancel: false)

        case .selection:
            Text("Use this key?").font(.title3.bold())
            Text("A browser on the computer wants to pick a security key.")
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
            buttons(primary: "Use PhoneKey", action: prompts.acknowledge)
        }
    }

    private func site(_ rpId: String, name: String?) -> some View {
        VStack(spacing: 2) {
            Text(rpId).font(.title2.weight(.semibold)).lineLimit(2).minimumScaleFactor(0.6)
            if let name, name != rpId {
                Text(name).font(.footnote).foregroundColor(.secondary)
            }
        }
    }

    private func buttons(primary: String, action: @escaping () -> Void, showCancel: Bool = true) -> some View {
        VStack(spacing: 8) {
            Button(action: action) {
                Text(primary).frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            if showCancel {
                Button("Cancel", role: .cancel, action: prompts.decline)
            }
        }
    }
}

/// Stored passkeys and security key registrations, grouped by site.
struct CredentialsView: View {
    @ObservedObject var store: KeychainCredentialStore
    @State private var pendingDelete: StoredCredential?

    private var sites: [(String, [StoredCredential])] {
        Dictionary(grouping: store.all, by: \.rpId).sorted { $0.key < $1.key }
    }

    var body: some View {
        List {
            if store.all.isEmpty {
                Text("No keys yet. Register PhoneKey as a security key or passkey on a website.")
                    .foregroundColor(.secondary)
            }
            ForEach(sites, id: \.0) { site, credentials in
                Section(site) {
                    ForEach(credentials) { credential in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(credential.accountLabel)
                            Text("\(credential.discoverable ? "Passkey" : "Security key") · "
                                + "created \(credential.created.formatted(date: .abbreviated, time: .omitted)) · "
                                + "used \(credential.signCount)×")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .swipeActions {
                            Button("Delete", role: .destructive) { pendingDelete = credential }
                        }
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Keys")
        .alert("Delete this key?", isPresented: Binding(
            get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }
        ), presenting: pendingDelete) { credential in
            Button("Delete", role: .destructive) { store.delete(credential) }
            Button("Cancel", role: .cancel) {}
        } message: { credential in
            Text("PhoneKey can no longer sign in to \(credential.rpId) as \(credential.accountLabel). "
                + "This cannot be undone. Make sure you have another way to sign in.")
        }
    }
}
