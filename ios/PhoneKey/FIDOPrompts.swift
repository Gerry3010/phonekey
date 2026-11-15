@preconcurrency import LocalAuthentication
import os
import PhoneKeyCore
import SwiftUI

/// The authenticator's screen: one prompt at a time, timing out after 60 s.
///
/// Registrations and sign-ins open Touch ID right away; with several accounts
/// for the suggested one (marked as suggested, else last used, else newest),
/// and "Other account" lists the rest. Cancelling Touch ID does not decline:
/// the card stays with the details and offers Touch ID again. Only the Decline
/// button declines. After the computer got its answer, a short confirmation
/// shows that the request is done; if another account than the suggested one
/// was used, it asks whether to suggest that one from now on.
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
    /// The sign-in account Touch ID is for: the newest one, or the one picked.
    @Published private(set) var chosen: StoredCredential?
    /// The sign-in card lists all accounts ("Other account").
    @Published private(set) var pickingAccount = false
    /// "Signed in as …" for a moment after a request succeeded.
    @Published private(set) var confirmation: String?
    /// Asked with the confirmation: suggest the account just used from now on?
    @Published private(set) var question: SuggestionQuestion?
    /// The computer the current CTAP request came from.
    var hostName: String?
    /// Told when a prompt appears (true) or goes away (false).
    var onActiveChange: ((Bool) -> Void)?
    /// Carries the Touch ID of an approved sign-in to the signature.
    var handoff: TouchIDHandoff?
    /// Where the answer to a suggestion question is stored.
    var credentials: KeychainCredentialStore?

    private var nextId = 0
    private var continuation: CheckedContinuation<(UserDecision, StoredCredential?), Never>?
    private var cancelledBeforeShown: Set<Int> = []
    private var timeoutTask: Task<Void, Never>?
    private var authContext: LAContext?
    private let log = Logger(subsystem: "net.geraldhofbauer.phonekey", category: "fido")
    /// What the user approved, shown as the confirmation once the request
    /// really succeeded.
    private var approvedSummary: String?
    /// The account the sign-in card preselected, and the question to ask if
    /// the user signed in with another one.
    private var preselectedId: Data?
    private var pendingQuestion: SuggestionQuestion?
    private var confirmationTask: Task<Void, Never>?
    private var confirmationShown = Date.distantPast
    /// The confirmation stays at least this long before the next prompt
    /// replaces it, so one request is visibly done before the next begins.
    private static let confirmationMinimum: TimeInterval = 1.5

    // MARK: User actions

    /// Opens Touch ID for the current registration or chosen sign-in account.
    func authenticate() {
        authenticate(forSigning: true)
    }

    /// `forSigning`: for a sign-in, evaluate the credential keys' access
    /// control for signing, which the Secure Enclave then takes for the
    /// signature itself (one Touch ID). A plain policy check would make the
    /// signature ask again. The Simulator has no Secure Enclave and its plain
    /// keychain keys take the policy check.
    private func authenticate(forSigning: Bool) {
        guard let active, !authenticating else { return }
        let reason: String
        var isSignIn = false
        switch active.kind {
        case let .registration(prompt):
            reason = prompt.passkey ? "Create a passkey for \(prompt.rpId)" : "Register this key with \(prompt.rpId)"
        case let .signIn(prompt):
            guard let chosen else { return }
            reason = "Sign in to \(prompt.rpId) as \(chosen.accountLabel)"
            isSignIn = true
        case .excluded, .selection:
            return
        }
        #if targetEnvironment(simulator)
        let access: SecAccessControl? = nil
        #else
        let access = forSigning && isSignIn ? try? SecureEnclaveKeys.accessControl() : nil
        #endif

        let context = LAContext()
        context.localizedCancelTitle = "Details"
        context.localizedFallbackTitle = "" // no passcode fallback: the keys need Touch ID
        authContext = context
        authenticating = true
        note = nil
        let promptId = active.id
        let usedAccessControl = access != nil
        let reply: @Sendable (Bool, Error?) -> Void = { ok, error in
            Task { @MainActor in
                guard self.authContext === context, self.active?.id == promptId else { return }
                self.authenticating = false
                if ok {
                    self.approve(with: context)
                    return
                }
                self.authContext = nil
                let laError = error as? LAError
                self.log.notice("Touch ID ended without success, code \(laError?.code.rawValue ?? -1, privacy: .public)")
                if usedAccessControl, !Self.isUserOutcome(laError) {
                    // The key rule could not be evaluated: fall back to the plain
                    // check. The signature then asks once more, as before.
                    self.authenticate(forSigning: false)
                } else {
                    self.touchIDDidNotSucceed(laError)
                }
            }
        }
        if let access {
            context.evaluateAccessControl(access, operation: .useKeySign, localizedReason: reason, reply: reply)
        } else {
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason, reply: reply)
        }
    }

    /// Outcomes the user caused or must deal with, as opposed to Touch ID not
    /// being able to evaluate the request at all.
    private static func isUserOutcome(_ error: LAError?) -> Bool {
        switch error?.code {
        case .userCancel, .systemCancel, .appCancel, .userFallback, .authenticationFailed,
             .biometryLockout, .biometryNotEnrolled, .biometryNotAvailable:
            return true
        default:
            return false
        }
    }

    /// Sign-in with several accounts: picks one from the list and opens Touch ID.
    func choose(_ credential: StoredCredential) {
        guard case .signIn = active?.kind, !authenticating else { return }
        chosen = credential
        pickingAccount = false
        authenticate()
    }

    /// Sign-in with several accounts: shows the list.
    func chooseAnotherAccount() {
        guard case let .signIn(prompt) = active?.kind, prompt.candidates.count > 1, !authenticating else { return }
        pickingAccount = true
        note = nil
    }

    /// Called once the computer has the answer to the current request.
    func requestFinished(succeeded: Bool) {
        defer {
            approvedSummary = nil
            pendingQuestion = nil
        }
        guard succeeded, active == nil, let summary = approvedSummary else { return }
        confirmation = summary
        question = pendingQuestion
        confirmationShown = Date()
        // A question waits a while for an answer; a plain confirmation goes soon.
        let seconds: UInt64 = question == nil ? 2 : 20
        confirmationTask?.cancel()
        confirmationTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
            guard !Task.isCancelled else { return }
            self?.endConfirmation()
        }
    }

    // MARK: Suggestion question

    /// Suggest the account as well as the current ones.
    func suggestAlso() {
        guard let question else { return }
        credentials?.setSuggested(id: question.account.id, true)
        endConfirmation()
    }

    /// Suggest the account instead of `other`.
    func suggestInstead(of other: StoredCredential) {
        guard let question else { return }
        credentials?.setSuggested(id: other.id, false)
        credentials?.setSuggested(id: question.account.id, true)
        endConfirmation()
    }

    func dontSuggest() {
        endConfirmation()
    }

    private func endConfirmation() {
        confirmationTask?.cancel()
        confirmationTask = nil
        confirmation = nil
        question = nil
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
        case let .registration(prompt):
            approvedSummary = prompt.passkey ? "Passkey created for \(prompt.rpId)" : "Key registered with \(prompt.rpId)"
            finish(.approved, nil)
        case let .signIn(prompt):
            approvedSummary = "Signed in to \(prompt.rpId) as \(chosen?.accountLabel ?? "")"
            if let chosen {
                pendingQuestion = SuggestionQuestion.after(signingInWith: chosen, preselectedId: preselectedId,
                                                           candidates: prompt.candidates, rpId: prompt.rpId)
            }
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
        let (id, wait) = await MainActor.run { () -> (Int, TimeInterval) in
            nextId += 1
            let wait = confirmation == nil ? 0 : Self.confirmationMinimum - Date().timeIntervalSince(confirmationShown)
            return (nextId, wait)
        }
        if wait > 0 {
            // Cancelled meanwhile: the handler below sees it and declines.
            try? await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000))
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
        pickingAccount = false
        approvedSummary = nil
        pendingQuestion = nil
        endConfirmation() // an open question counts as "no"
        chosen = nil
        preselectedId = nil
        if case let .signIn(prompt) = kind {
            chosen = prompt.candidates.orderedForSuggestion().first
            preselectedId = chosen?.id
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
        pickingAccount = false
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

    /// The approved context without handing it out for good: the hmac-secret
    /// decryption looks first, the signature then takes it (§10).
    func peek() -> LAContext? {
        lock.lock()
        defer { lock.unlock() }
        guard let context, Date().timeIntervalSince(since) < Self.lifetime else { return nil }
        return context
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
