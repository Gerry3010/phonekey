import PhoneKeyCore
import SwiftUI

/// The security key PIN (§10, "PIN (3c)"): set, change or remove it here,
/// always with Touch ID. Removing it is also the way out of a forgotten or
/// blocked PIN; the passkeys stay.
struct PinSettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var state: PinState?
    @State private var editing = false
    @State private var confirmingRemoval = false
    @State private var failure: String?

    private var isSet: Bool {
        if case .set = state { return true }
        return false
    }

    var body: some View {
        List {
            Section {
                HStack {
                    Text("PIN")
                    Spacer()
                    Text(statusText).foregroundColor(isBlocked ? .red : .secondary)
                }
            } footer: {
                Text("ssh-keygen -K, ssh-add -K and Chrome's security key settings need a PIN. "
                    + "It never replaces Touch ID: every use still needs Touch ID on this iPhone, "
                    + "and browsers keep signing in with Touch ID alone.")
            }

            Section {
                Button(isSet ? "Change PIN…" : "Set PIN…") { editing = true }
                if isSet {
                    Button("Remove PIN", role: .destructive) { confirmingRemoval = true }
                }
            } footer: {
                if isSet {
                    Text("Forgot the PIN, or entered it wrong too often? Remove it here and set a new one. "
                        + "Your passkeys stay.")
                }
            }

            if let failure {
                Section {
                    Label(failure, systemImage: "exclamationmark.triangle").foregroundColor(.red)
                }
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Security key PIN")
        .onAppear(perform: reload)
        .sheet(isPresented: $editing) {
            PinEntrySheet(title: isSet ? "Change PIN" : "Set PIN") { pin in
                save(pin)
            }
        }
        .alert("Remove the PIN?", isPresented: $confirmingRemoval) {
            Button("Remove", role: .destructive, action: remove)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Programs that need a PIN stop working until you set a new one. Your passkeys stay.")
        }
    }

    private var isBlocked: Bool {
        if case .set(retries: 0) = state { return true }
        return false
    }

    private var statusText: String {
        switch state {
        case .none: return "Unknown"
        case .notSet: return "Not set"
        case .set(retries: 0): return "Blocked"
        case let .set(retries): return retries == Authenticator.maxPinRetries ? "Set" : "Set, \(retries) tries left"
        }
    }

    private func reload() {
        state = model.pinState()
    }

    private func save(_ pin: String) {
        let reason = isSet ? "Change the security key PIN" : "Set a security key PIN"
        Task {
            guard await model.confirmWithTouchID(reason) else { return }
            do {
                try model.setPin(pin)
                failure = nil
                editing = false
            } catch {
                failure = "The PIN could not be saved (\(error))."
            }
            reload()
        }
    }

    private func remove() {
        Task {
            guard await model.confirmWithTouchID("Remove the security key PIN") else { return }
            do {
                try model.removePin()
                failure = nil
            } catch {
                failure = "The PIN could not be removed (\(error))."
            }
            reload()
        }
    }
}

/// New PIN, twice. The rules are CTAP's: at least 4 characters, at most 63
/// bytes of UTF-8.
private struct PinEntrySheet: View {
    let title: String
    let onSave: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var pin = ""
    @State private var repeated = ""
    @FocusState private var focused: Bool

    private var problem: String? {
        if pin.unicodeScalars.count < Authenticator.minPinLength { return "At least 4 characters." }
        if pin.utf8.count > 63 { return "Too long." }
        if pin != repeated { return "The two entries differ." }
        return nil
    }

    var body: some View {
        NavigationView {
            Form {
                Section {
                    SecureField("New PIN", text: $pin)
                        .focused($focused)
                    SecureField("Repeat", text: $repeated)
                        .onSubmit { if problem == nil { onSave(pin) } }
                } footer: {
                    Text(pin.isEmpty ? "Any characters; digits are easiest to type on the computer." : problem ?? " ")
                }
            }
            .disableAutocorrection(true)
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { onSave(pin) }.disabled(problem != nil)
                }
            }
            .onAppear {
                // A sheet's first field focuses only after it is on screen.
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { focused = true }
            }
        }
    }
}
