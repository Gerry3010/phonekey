@preconcurrency import LocalAuthentication
import PhoneKeyCore
import SwiftUI

/// The authenticator's screen: one prompt at a time, timing out after 60 s.
///
/// Registrations and sign-ins open Touch ID right away. Cancelling Touch ID
/// does not decline: the card stays with the details and offers Touch ID again.
/// Only the Decline button declines. With several accounts the user picks one
/// first, then Touch ID opens.
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
    /// Shown on the card after Touch ID was cancelled or failed.
    @Published private(set) var note: String?
    /// The Touch ID sheet is up.
    @Published private(set) var authenticating = false
    /// The sign-in account Touch ID is for: picked by the user, or the only one.
    @Published private(set) var chosen: StoredCredential?
    /// The computer the current CTAP request came from.
    var hostName: String?
    /// Told when a prompt appears (true) or goes away (false).
    var onActiveChange: ((Bool) -> Void)?
    /// Carries the Touch ID of an approved sign-in to the signature.
    var handoff: TouchIDHandoff?

    private var nextId = 0
    private var continuation: CheckedContinuation<(UserDecision, StoredCredential?), Never>?
    private var cancelledBeforeShown: Set<Int> = []
    private var timeoutTask: Task<Void, Never>?
    private var authContext: LAContext?

    // MARK: User actions

    /// Opens Touch ID for the current registration or chosen sign-in account.
    func authenticate() {
        guard let active, !authenticating else { return }
        let reason: String
        switch active.kind {
        case let .registration(prompt):
            reason = prompt.passkey ? "Create a passkey for \(prompt.rpId)" : "Register this key with \(prompt.rpId)"
        case let .signIn(prompt):
            guard let chosen else { return }
            reason = "Sign in to \(prompt.rpId) as \(chosen.accountLabel)"
        case .excluded, .selection:
            return
        }

        let context = LAContext()
        context.localizedCancelTitle = "Details"
        context.localizedFallbackTitle = "" // no passcode fallback: the keys need Touch ID
        authContext = context
        authenticating = true
        note = nil
        let promptId = active.id
        let reply: @Sendable (Bool, Error?) -> Void = { ok, error in
            Task { @MainActor in
                guard self.authContext === context, self.active?.id == promptId else { return }
                self.authenticating = false
                if ok {
                    self.approve(with: context)
                } else {
                    self.authContext = nil
                    self.touchIDDidNotSucceed(error as? LAError)
                }
            }
        }
        if case .signIn = active.kind, let access = try? SecureEnclaveKeys.accessControl() {
            // The Secure Enclave only takes a context that was evaluated for
            // signing with a key under this rule; a plain policy check makes
            // the signature ask again.
            context.evaluateAccessControl(access, operation: .useKeySign, localizedReason: reason, reply: reply)
        } else {
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason, reply: reply)
        }
    }

    /// Sign-in with several accounts: picks one and opens Touch ID.
    func choose(_ credential: StoredCredential) {
        guard case .signIn = active?.kind, !authenticating else { return }
        chosen = credential
        authenticate()
    }

    /// Sign-in with several accounts: back to the list.
    func chooseAnotherAccount() {
        guard case let .signIn(prompt) = active?.kind, prompt.candidates.count > 1, !authenticating else { return }
        chosen = nil
        note = nil
    }

    func acknowledge() {
        finish(.approved, nil)
    }

    func decline() {
        finish(.denied, nil)
    }

    private func approve(with context: LAContext) {
        guard let active else { return }
        switch active.kind {
        case .registration:
            finish(.approved, nil)
        case .signIn:
            // The signature reuses this Touch ID instead of asking again.
            authContext = nil
            handoff?.put(context)
            finish(.approved, chosen)
        case .excluded, .selection:
            finish(.approved, nil)
        }
    }

    private func touchIDDidNotSucceed(_ error: LAError?) {
        switch error?.code {
        case .biometryNotEnrolled, .biometryNotAvailable:
            note = "Set up Touch ID in Settings first."
        case .biometryLockout:
            note = "Touch ID is locked. Unlock the iPhone with its passcode, then try again."
        case .authenticationFailed:
            note = "Touch ID did not recognise the finger."
        default:
            // Cancelled (or interrupted by the system): the request stays open.
            note = nil
        }
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
        // A Touch ID from an earlier prompt must never sign for this one.
        handoff?.clear()
        self.continuation = continuation
        note = nil
        authenticating = false
        chosen = nil
        if case let .signIn(prompt) = kind, prompt.candidates.count == 1 {
            chosen = prompt.candidates.first
        }
        active = Active(id: id, kind: kind, hostName: hostName, deadline: Date().addingTimeInterval(Self.timeout))
        onActiveChange?(true)
        UINotificationFeedbackGenerator().notificationOccurred(.warning)
        timeoutTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(Self.timeout * 1_000_000_000))
            guard !Task.isCancelled, self?.active?.id == id else { return }
            self?.finish(.timedOut, nil)
        }
        switch kind {
        case .registration:
            authenticate()
        case .signIn where chosen != nil:
            authenticate()
        default:
            break
        }
    }

    private func finish(_ decision: UserDecision, _ credential: StoredCredential?) {
        timeoutTask?.cancel()
        timeoutTask = nil
        authContext?.invalidate()
        authContext = nil
        authenticating = false
        note = nil
        chosen = nil
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

/// Hands the Touch ID that approved a sign-in on the card to the signature that
/// follows, so the user sees Touch ID once. Each prompt clears it first, and it
/// expires after a few seconds, so it can never sign for another request.
final class TouchIDHandoff: @unchecked Sendable {
    private static let lifetime: TimeInterval = 10

    private let lock = NSLock()
    private var context: LAContext?
    private var since = Date.distantPast

    func put(_ context: LAContext) {
        lock.lock()
        defer { lock.unlock() }
        self.context?.invalidate()
        self.context = context
        since = Date()
    }

    func clear() {
        lock.lock()
        defer { lock.unlock() }
        context?.invalidate()
        context = nil
    }

    /// The approved context, once; nil if there is none or it is too old.
    func take() -> LAContext? {
        lock.lock()
        defer { lock.unlock() }
        let taken = context
        context = nil
        guard let taken else { return nil }
        guard Date().timeIntervalSince(since) < Self.lifetime else {
            taken.invalidate()
            return nil
        }
        return taken
    }
}
