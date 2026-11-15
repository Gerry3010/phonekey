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
            // The request is done: says so for a moment, then goes away. After
            // signing in with another account than the suggested one it also
            // asks whether to suggest that one from now on.
            ZStack {
                Color.black.opacity(0.88).ignoresSafeArea()
                VStack(spacing: 12) {
                    Image(systemName: "checkmark.circle.fill").font(.system(size: 44)).foregroundColor(.green)
                    Text(confirmation).font(.headline).multilineTextAlignment(.center)
                    if let question = prompts.question {
                        suggestionQuestion(question)
                    }
                }
                .padding(28)
                .frame(maxWidth: 360)
                .background(RoundedRectangle(cornerRadius: 20).fill(Color(.secondarySystemBackground)))
                .padding(20)
            }
            .preferredColorScheme(.dark)
            .transition(.opacity)
            .allowsHitTesting(prompts.question != nil)
        }
    }

    private func suggestionQuestion(_ question: SuggestionQuestion) -> some View {
        VStack(spacing: 10) {
            Divider()
            Text("Suggest \(question.account.accountLabel) for \(question.rpId) from now on?")
                .multilineTextAlignment(.center)
            if question.current.isEmpty {
                Button(action: prompts.suggestAlso) {
                    Text("Suggest").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
            } else {
                Button(action: prompts.suggestAlso) {
                    Text("As well").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                ForEach(question.current.prefix(2)) { other in
                    Button {
                        prompts.suggestInstead(of: other)
                    } label: {
                        Text("Instead of \(other.accountLabel)").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                }
            }
            Button("No", action: prompts.dontSuggest)
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
            site(p.rpId, name: ownSiteName(p.rpId) ?? p.rpName)
            if let account = p.userName ?? p.userDisplayName {
                Label(account, systemImage: "person.crop.circle").foregroundColor(.secondary)
            }
            touchIDButtons()

        case let .signIn(p):
            Text("Sign in to").font(.title3.bold())
            site(p.rpId, name: ownSiteName(p.rpId))
            if prompts.pickingAccount {
                accountList(p.candidates)
                declineButton()
            } else if let chosen = prompts.chosen {
                VStack(spacing: 2) {
                    Label("as \(chosen.accountLabel)", systemImage: chosen.suggested == true ? "star.fill" : "person.crop.circle")
                        .foregroundColor(.secondary)
                    if p.candidates.count > 1 {
                        Text("\(chosen.suggestionReason) · \(p.candidates.count) accounts for this site")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }
                }
                if p.verified {
                    // The token's Touch ID is done: only which account.
                    VStack(spacing: 8) {
                        Button(action: prompts.signInVerified) {
                            Text("Sign in").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        declineButton()
                    }
                } else {
                    touchIDButtons()
                }
                if p.candidates.count > 1 {
                    Button("Other account", action: prompts.chooseAnotherAccount)
                        .disabled(prompts.authenticating)
                }
            }

        case let .token(p):
            Text(p.signs ? FIDOPrompts.tokenPurpose(p) : "Manage passkeys").font(.title3.bold())
            if let rpId = p.rpId {
                site(rpId, name: ownSiteName(rpId))
            }
            if !p.signs {
                Text("The computer wants to list passkeys on this iPhone and may ask to delete some. "
                    + "Each deletion asks you again.")
                    .font(.callout)
                    .multilineTextAlignment(.center)
                    .foregroundColor(.secondary)
            }
            touchIDButtons()

        case let .deletion(credential):
            Text("Delete this passkey?").font(.title3.bold())
            site(credential.rpId, name: ownSiteName(credential.rpId))
            Label(credential.accountLabel, systemImage: "person.crop.circle").foregroundColor(.secondary)
            Text("Deleting is final: keys are not backed up. Make sure you have another way to sign in.")
                .font(.callout)
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
            VStack(spacing: 8) {
                Button(role: .destructive, action: prompts.confirmDeletionTap) {
                    Text("Delete").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .controlSize(.large)
                Button("Cancel", role: .cancel, action: prompts.decline)
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

    /// "Which account?": the suggested accounts first, then the others, each
    /// group in suggestion order. Long lists scroll so the card keeps Decline
    /// and the timer on screen.
    private func accountList(_ candidates: [StoredCredential]) -> some View {
        let ordered = candidates.orderedForSuggestion()
        let suggested = ordered.filter { $0.suggested == true }
        let others = ordered.filter { $0.suggested != true }
        return VStack(alignment: .leading, spacing: 8) {
            Text("Which account?").font(.headline)
            Group {
                if ordered.count > 4 {
                    ScrollView { accountGroups(suggested: suggested, others: others) }.frame(height: 260)
                } else {
                    accountGroups(suggested: suggested, others: others)
                }
            }
        }
    }

    private func accountGroups(suggested: [StoredCredential], others: [StoredCredential]) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if !suggested.isEmpty {
                accountGroup("Suggested", suggested)
            }
            if !others.isEmpty {
                accountGroup(suggested.isEmpty ? nil : "Other accounts", others)
            }
        }
    }

    private func accountGroup(_ title: String?, _ accounts: [StoredCredential]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            if let title {
                Text(title.uppercased()).font(.caption2).foregroundColor(.secondary).padding(.leading, 4)
            }
            VStack(spacing: 0) {
                ForEach(accounts) { credential in
                    Button {
                        prompts.choose(credential)
                    } label: {
                        HStack {
                            if credential.suggested == true {
                                Image(systemName: "star.fill").font(.caption).foregroundColor(.yellow)
                            }
                            VStack(alignment: .leading, spacing: 2) {
                                Text(credential.accountLabel).foregroundColor(.primary)
                                Text(credential.usageLine).font(.caption).foregroundColor(.secondary)
                            }
                            Spacer()
                            Image(systemName: "chevron.right").font(.caption).foregroundColor(.secondary)
                        }
                        .padding(.vertical, 10)
                        .padding(.horizontal, 12)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    if credential.id != accounts.last?.id {
                        Divider().padding(.leading, 12)
                    }
                }
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color(.tertiarySystemBackground)))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }

    /// The user's own name for the site. Shown under the real address, never
    /// instead of it: the address is what the request is really for.
    private func ownSiteName(_ rpId: String) -> String? {
        prompts.credentials?.siteNames[rpId]
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

