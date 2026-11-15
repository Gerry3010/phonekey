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
                        Text(note).font(.footnote).foregroundColor(.orange).multilineTextAlignment(.center)
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
        } else if let confirmation = prompts.confirmation {
            // The request is done: says so for a moment, then goes away.
            ZStack {
                Color.black.opacity(0.88).ignoresSafeArea()
                VStack(spacing: 12) {
                    Image(systemName: "checkmark.circle.fill").font(.system(size: 44)).foregroundColor(.green)
                    Text(confirmation).font(.headline).multilineTextAlignment(.center)
                }
                .padding(28)
                .frame(maxWidth: 360)
                .background(RoundedRectangle(cornerRadius: 20).fill(Color(.secondarySystemBackground)))
                .padding(20)
            }
            .preferredColorScheme(.dark)
            .transition(.opacity)
            .allowsHitTesting(false)
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
            touchIDButtons()

        case let .signIn(p):
            Text("Sign in to").font(.title3.bold())
            site(p.rpId, name: nil)
            if prompts.pickingAccount {
                accountList(p.candidates)
                declineButton()
            } else if let chosen = prompts.chosen {
                VStack(spacing: 2) {
                    Label("as \(chosen.accountLabel)", systemImage: "person.crop.circle")
                        .foregroundColor(.secondary)
                    if p.candidates.count > 1 {
                        Text("\(p.candidates.count) accounts for this site").font(.caption).foregroundColor(.secondary)
                    }
                }
                touchIDButtons()
                if p.candidates.count > 1 {
                    Button("Other account", action: prompts.chooseAnotherAccount)
                        .disabled(prompts.authenticating)
                }
            }

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

    /// "Which account?": one row per stored account, newest first. Long
    /// lists scroll so the card keeps Decline and the timer on screen.
    private func accountList(_ candidates: [StoredCredential]) -> some View {
        let sorted = candidates.sorted { $0.created > $1.created }
        return VStack(alignment: .leading, spacing: 8) {
            Text("Which account?").font(.headline)
            Group {
                if sorted.count > 4 {
                    ScrollView { accountRows(sorted) }.frame(height: 260)
                } else {
                    accountRows(sorted)
                }
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color(.tertiarySystemBackground)))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }

    private func accountRows(_ sorted: [StoredCredential]) -> some View {
        VStack(spacing: 0) {
            ForEach(sorted) { credential in
                Button {
                    prompts.choose(credential)
                } label: {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(credential.accountLabel).foregroundColor(.primary)
                            Text("created \(credential.created.formatted(date: .abbreviated, time: .shortened))"
                                + " · used \(credential.signCount)×")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Image(systemName: "chevron.right").font(.caption).foregroundColor(.secondary)
                    }
                    .padding(.vertical, 10)
                    .padding(.horizontal, 12)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                if credential.id != sorted.last?.id {
                    Divider().padding(.leading, 12)
                }
            }
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

    /// Touch ID again (after it was cancelled) and the explicit Decline.
    private func touchIDButtons() -> some View {
        VStack(spacing: 8) {
            Button(action: prompts.authenticate) {
                Label("Touch ID", systemImage: "touchid").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(prompts.authenticating)
            declineButton()
        }
    }

    private func declineButton() -> some View {
        Button("Decline", role: .destructive, action: prompts.decline)
            .disabled(prompts.authenticating)
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
