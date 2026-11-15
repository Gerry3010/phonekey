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
        /// getPinUvAuthTokenUsingUvWithPermissions (3b): Touch ID for a token.
        case token(TokenPrompt)
        /// Credential management deletes a passkey: a tap.
        case deletion(StoredCredential)
        /// A PIN request (3c): set, change, or a token against the PIN.
        case pin(PinPrompt)
    }

    /// How a prompt ended. `authorization` is a token's Touch ID that may
    /// sign once; `blocked` means iOS locked Touch ID during a token prompt.
    struct Outcome {
        var decision: UserDecision
        var credential: StoredCredential?
        var authorization: LAContext?
        var blocked = false
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
    private var continuation: CheckedContinuation<Outcome, Never>?
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
        var signs = false
        switch active.kind {
        case let .registration(prompt):
            // A token already carried the Touch ID: the card only confirms the site.
            guard !prompt.verified else { return }
            reason = prompt.passkey ? "Create a passkey for \(prompt.rpId)" : "Register this key with \(prompt.rpId)"
        case let .signIn(prompt):
            // A token already carried the Touch ID: the card only picks the account.
            guard let chosen, !prompt.verified else { return }
            reason = "Sign in to \(prompt.rpId) as \(chosen.accountLabel)"
            signs = true
        case let .token(prompt):
            reason = Self.tokenPurpose(prompt)
            signs = prompt.signs
        case let .pin(prompt):
            reason = Self.pinPurpose(prompt)
            // The stored PIN hash is encrypted to a Secure Enclave key with the
            // keys' Touch ID rule: this Touch ID must decrypt it (and, for a
            // token that signs, sign once). Setting a PIN only confirms.
            signs = prompt != .set
        case .excluded, .selection, .deletion:
            return
        }
        #if targetEnvironment(simulator)
        let access: SecAccessControl? = nil
        #else
        let access = forSigning && signs ? try? SecureEnclaveKeys.accessControl() : nil
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

    /// What a token is for, in the card and the Touch ID sheet.
    static func tokenPurpose(_ prompt: TokenPrompt) -> String {
        let site = prompt.rpId ?? "a site"
        switch prompt.permissions & (TokenPrompt.makeCredential | TokenPrompt.getAssertion) {
        case TokenPrompt.makeCredential: return "Register at \(site)"
        case TokenPrompt.getAssertion: return "Sign in to \(site)"
        case 0: return "List and delete passkeys on this iPhone"
        default: return "Register or sign in at \(site)"
        }
    }

    /// What a PIN request is for, in the card and the Touch ID sheet.
    static func pinPurpose(_ prompt: PinPrompt) -> String {
        switch prompt {
        case .set: return "Set a PIN for this security key"
        case .change: return "Change the security key PIN"
        case let .token(token): return token.signs ? tokenPurpose(token) + " with your PIN" : "Manage passkeys with your PIN"
        case .legacyToken: return "Register or sign in with your PIN"
        }
    }

    /// A registration after a getPinToken token: the tap that confirms the site.
    func confirmVerifiedRegistration() {
        guard case let .registration(prompt) = active?.kind, prompt.verified else { return }
        approve(with: nil)
    }

    /// Sign-in with several accounts: picks one from the list and opens Touch ID
    /// (or, when a token already verified, signs in with it right away).
    func choose(_ credential: StoredCredential) {
        guard case let .signIn(prompt) = active?.kind, !authenticating else { return }
        chosen = credential
        pickingAccount = false
        if prompt.verified {
            approve(with: nil)
        } else {
            authenticate()
        }
    }

    /// Sign-in after a token's Touch ID: the tap on "Sign in".
    func signInVerified() {
        guard case let .signIn(prompt) = active?.kind, prompt.verified, chosen != nil else { return }
        approve(with: nil)
    }

    /// Credential management: the tap on "Delete".
    func confirmDeletionTap() {
        guard case .deletion = active?.kind else { return }
        approve(with: nil)
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

    /// `context` is the Touch ID just given, nil for a tap.
    private func approve(with context: LAContext?) {
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
            if let context {
                // The signature reuses this Touch ID instead of asking again.
                authContext = nil
                handoff?.put(context)
            }
            finish(.approved, chosen)
        case let .token(prompt):
            // A token that signs keeps this Touch ID for its one operation;
            // a cm-only token keeps none.
            authContext = nil
            if prompt.signs {
                finish(.approved, nil, authorization: context)
            } else {
                context?.invalidate()
                finish(.approved, nil)
            }
        case let .deletion(credential):
            approvedSummary = "Deleted \(credential.accountLabel) from \(credential.rpId)"
            finish(.approved, nil)
        case let .pin(prompt):
            // The authenticator decides what the Touch ID is still needed for.
            authContext = nil
            switch prompt {
            case .set: approvedSummary = "PIN set"
            case .change: approvedSummary = "PIN changed"
            case .token, .legacyToken: break
            }
            finish(.approved, nil, authorization: context)
        case .excluded, .selection:
            finish(.approved, nil)
        }
    }

    /// A token's Touch ID covered a registration or a single sign-in: nothing
    /// to show now, only the confirmation once the answer has gone out.
    private func noteVerified(_ summary: String) {
        approvedSummary = summary
        pendingQuestion = nil
    }

    private func touchIDDidNotSucceed(_ error: LAError?) {
        switch error?.code {
        case .biometryNotEnrolled, .biometryNotAvailable:
            note = "Set up Touch ID in Settings first."
        case .biometryLockout:
            switch active?.kind {
            case .token, .pin:
                // A token or PIN request answers UV_BLOCKED right away (§10).
                finish(.denied, nil, blocked: true)
                return
            default:
                break
            }
            note = "Touch ID is locked. Unlock the iPhone with its passcode, then try again."
        case .authenticationFailed:
            note = "Touch ID did not recognise the finger."
        default:
            // Cancelled (or interrupted by the system): the request stays open.
            note = nil
        }
    }

    // MARK: Presenting (called from the authenticator's task)

    nonisolated func present(_ kind: Kind) async -> Outcome {
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

    private func show(id: Int, kind: Kind, continuation: CheckedContinuation<Outcome, Never>) {
        if cancelledBeforeShown.remove(id) != nil || self.continuation != nil {
            continuation.resume(returning: Outcome(decision: .denied))
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
        case let .registration(prompt) where !prompt.verified:
            authenticate()
        case .token, .pin:
            authenticate()
        case let .signIn(prompt) where chosen != nil && !prompt.verified:
            authenticate()
        default:
            break
        }
    }

    private func finish(_ decision: UserDecision, _ credential: StoredCredential?,
                        authorization: LAContext? = nil, blocked: Bool = false) {
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
        continuation?.resume(returning: Outcome(decision: decision, credential: credential,
                                                authorization: authorization, blocked: blocked))
        continuation = nil
    }
}

extension FIDOPrompts: AuthenticatorUI {
    nonisolated func confirmRegistration(_ prompt: RegistrationPrompt) async -> UserDecision {
        if prompt.verified, !prompt.confirmByTap {
            await MainActor.run {
                noteVerified(prompt.passkey ? "Passkey created for \(prompt.rpId)" : "Key registered with \(prompt.rpId)")
            }
            return .approved
        }
        return await present(.registration(prompt)).decision
    }

    nonisolated func chooseCredential(_ prompt: SignInPrompt) async -> (UserDecision, StoredCredential?) {
        if prompt.verified, !prompt.confirmByTap, prompt.candidates.count == 1, let only = prompt.candidates.first {
            await MainActor.run { noteVerified("Signed in to \(prompt.rpId) as \(only.accountLabel)") }
            return (.approved, only)
        }
        let outcome = await present(.signIn(prompt))
        return (outcome.decision, outcome.credential)
    }

    nonisolated func acknowledgeExcluded(rpId: String) async -> UserDecision {
        await present(.excluded(rpId: rpId)).decision
    }

    nonisolated func confirmSelection() async -> UserDecision {
        await present(.selection).decision
    }

    nonisolated func authorizeToken(_ prompt: TokenPrompt) async -> TokenDecision {
        let outcome = await present(.token(prompt))
        switch outcome.decision {
        case .approved: return .approved(authorization: outcome.authorization)
        case .denied: return outcome.blocked ? .blocked : .denied
        case .timedOut: return .timedOut
        }
    }

    nonisolated func authorizePin(_ prompt: PinPrompt) async -> TokenDecision {
        let outcome = await present(.pin(prompt))
        switch outcome.decision {
        case .approved: return .approved(authorization: outcome.authorization)
        case .denied: return outcome.blocked ? .blocked : .denied
        case .timedOut: return .timedOut
        }
    }

    nonisolated func confirmDeletion(_ credential: StoredCredential) async -> UserDecision {
        await present(.deletion(credential)).decision
    }

    /// iOS locks Touch ID after too many failed attempts until the passcode
    /// is entered.
    nonisolated var touchIDLocked: Bool {
        var error: NSError?
        let ok = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        return !ok && error.map { LAError.Code(rawValue: $0.code) == .biometryLockout } == true
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
