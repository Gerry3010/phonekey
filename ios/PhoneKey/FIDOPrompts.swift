@preconcurrency import LocalAuthentication
import PhoneKeyCore
import SwiftUI

/// The authenticator's screen: one prompt at a time, answered by a tap (and
/// Touch ID for registrations), timing out after 60 s.
@MainActor
final class FIDOPrompts: ObservableObject {
    enum Kind {
        case registration(RegistrationPrompt)
        case signIn(SignInPrompt)
        case excluded(rpId: String)
        case selection
    }

    struct Active: Identifiable {
        let id: Int
        let kind: Kind
        let hostName: String?
        let deadline: Date
    }

    static let timeout: TimeInterval = 60

    @Published private(set) var active: Active?
    /// Shown on the card while Touch ID runs or after it failed.
    @Published private(set) var note: String?
    /// The computer the current CTAP request came from.
    var hostName: String?
    /// Told when a prompt appears (true) or goes away (false).
    var onActiveChange: ((Bool) -> Void)?

    private var nextId = 0
    private var continuation: CheckedContinuation<(UserDecision, StoredCredential?), Never>?
    private var cancelledBeforeShown: Set<Int> = []
    private var timeoutTask: Task<Void, Never>?
    private var authContext: LAContext?

    // MARK: User actions

    func approveRegistration() {
        guard case let .registration(prompt) = active?.kind else { return }
        let context = LAContext()
        authContext = context
        note = nil
        let what = prompt.passkey ? "create a passkey for" : "register this key with"
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                               localizedReason: "Touch ID to \(what) \(prompt.rpId)") { ok, error in
            Task { @MainActor in
                guard self.authContext === context else { return }
                if ok {
                    self.finish(.approved, nil)
                } else {
                    self.note = (error as? LAError)?.code == .biometryNotEnrolled
                        ? "Set up Touch ID in Settings first."
                        : "Touch ID did not succeed."
                }
            }
        }
    }

    func choose(_ credential: StoredCredential) {
        finish(.approved, credential)
    }

    func acknowledge() {
        finish(.approved, nil)
    }

    func decline() {
        finish(.denied, nil)
    }

    // MARK: Presenting (called from the authenticator's task)

    nonisolated func present(_ kind: Kind) async -> (UserDecision, StoredCredential?) {
        let id = await MainActor.run { () -> Int in
            nextId += 1
            return nextId
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                Task { @MainActor in self.show(id: id, kind: kind, continuation: continuation) }
            }
        } onCancel: {
            Task { @MainActor in
                if self.active?.id == id {
                    self.finish(.denied, nil)
                } else {
                    self.cancelledBeforeShown.insert(id)
                }
            }
        }
    }

    private func show(id: Int, kind: Kind,
                      continuation: CheckedContinuation<(UserDecision, StoredCredential?), Never>) {
        if cancelledBeforeShown.remove(id) != nil || self.continuation != nil {
            continuation.resume(returning: (.denied, nil))
            return
        }
        self.continuation = continuation
        note = nil
        active = Active(id: id, kind: kind, hostName: hostName, deadline: Date().addingTimeInterval(Self.timeout))
        onActiveChange?(true)
        UINotificationFeedbackGenerator().notificationOccurred(.warning)
        timeoutTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(Self.timeout * 1_000_000_000))
            guard !Task.isCancelled, self?.active?.id == id else { return }
            self?.finish(.timedOut, nil)
        }
    }

    private func finish(_ decision: UserDecision, _ credential: StoredCredential?) {
        timeoutTask?.cancel()
        timeoutTask = nil
        authContext?.invalidate()
        authContext = nil
        note = nil
        active = nil
        onActiveChange?(false)
        continuation?.resume(returning: (decision, credential))
        continuation = nil
    }
}

extension FIDOPrompts: AuthenticatorUI {
    nonisolated func confirmRegistration(_ prompt: RegistrationPrompt) async -> UserDecision {
        await present(.registration(prompt)).0
    }

    nonisolated func chooseCredential(_ prompt: SignInPrompt) async -> (UserDecision, StoredCredential?) {
        await present(.signIn(prompt))
    }

    nonisolated func acknowledgeExcluded(rpId: String) async -> UserDecision {
        await present(.excluded(rpId: rpId)).0
    }

    nonisolated func confirmSelection() async -> UserDecision {
        await present(.selection).0
    }
}
