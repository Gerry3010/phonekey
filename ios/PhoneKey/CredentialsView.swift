import PhoneKeyCore
import SwiftUI

/// Stored passkeys and security key registrations, grouped by site. Keys and
/// sites can get their own names (only on this phone); "Select" picks several
/// keys or whole sites to delete at once.
struct CredentialsView: View {
    @ObservedObject var store: KeychainCredentialStore
    @State private var editMode: EditMode = .inactive
    @State private var selection = Set<Data>()
    @State private var pendingDelete: [StoredCredential] = []
    @State private var renaming: RenameTarget?

    private var editing: Bool { editMode == .active }

    /// Sites sorted by what the list shows for them.
    private var sites: [(rpId: String, credentials: [StoredCredential])] {
        Dictionary(grouping: store.all, by: \.rpId)
            .map { (rpId: $0.key, credentials: $0.value.orderedForSuggestion()) }
            .sorted { siteTitle($0.rpId).localizedCaseInsensitiveCompare(siteTitle($1.rpId)) == .orderedAscending }
    }

    var body: some View {
        List(selection: $selection) {
            if store.all.isEmpty {
                Text("No keys yet. Register PhoneKey as a security key or passkey on a website.")
                    .foregroundColor(.secondary)
            }
            ForEach(sites, id: \.rpId) { site in
                Section {
                    ForEach(site.credentials) { credential in
                        row(credential)
                    }
                } header: {
                    header(site.rpId, site.credentials)
                }
            }
        }
        .listStyle(.insetGrouped)
        .environment(\.editMode, $editMode)
        .navigationTitle("Keys")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button(editing ? "Done" : "Select") {
                    withAnimation {
                        editMode = editing ? .inactive : .active
                        selection = []
                    }
                }
                .disabled(store.all.isEmpty)
            }
            ToolbarItemGroup(placement: .bottomBar) {
                if editing {
                    Button(selection.count == store.all.count ? "Deselect all" : "Select all") {
                        selection = selection.count == store.all.count ? [] : Set(store.all.map(\.id))
                    }
                    Spacer()
                    Button(role: .destructive) {
                        pendingDelete = store.all.filter { selection.contains($0.id) }
                    } label: {
                        Text(selection.isEmpty ? "Delete" : "Delete (\(selection.count))")
                    }
                    .disabled(selection.isEmpty)
                }
            }
        }
        // The keys go into the alert as its presented value: on iOS 15 the
        // binding is reset to "not presented" (clearing pendingDelete) before
        // the button's action runs, so the action must not read the state.
        .alert(Self.deleteTitle(pendingDelete), isPresented: Binding(
            get: { !pendingDelete.isEmpty }, set: { if !$0 { pendingDelete = [] } }
        ), presenting: pendingDelete.isEmpty ? nil : pendingDelete) { keys in
            Button("Delete", role: .destructive) {
                let ids = Set(keys.map(\.id))
                let deletesAll = Set(store.all.map(\.id)).isSubset(of: ids)
                store.delete(keys)
                selection.subtract(ids)
                if deletesAll { editMode = .inactive }
            }
            Button("Cancel", role: .cancel) {}
        } message: { keys in
            Text(Self.deleteMessage(keys))
        }
        .sheet(item: $renaming) { target in
            RenameSheet(target: target, store: store)
        }
    }

    // MARK: Rows and headers

    private func row(_ credential: StoredCredential) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text(credential.accountLabel)
                if credential.suggested == true {
                    Image(systemName: "star.fill").font(.caption).foregroundColor(.yellow)
                }
            }
            if credential.localName != nil, let original = credential.userName ?? credential.userDisplayName {
                Text("On the site: \(original)").font(.caption).foregroundColor(.secondary)
            }
            Text("\(credential.discoverable ? "Passkey" : "Security key") · \(credential.usageLine)")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .swipeActions {
            Button("Delete", role: .destructive) { pendingDelete = [credential] }
            Button("Rename") { renaming = .key(credential) }.tint(.blue)
        }
        .swipeActions(edge: .leading) {
            suggestButton(credential)
        }
        .contextMenu {
            Button { renaming = .key(credential) } label: { Label("Rename…", systemImage: "pencil") }
            suggestButton(credential)
            Button(role: .destructive) { pendingDelete = [credential] } label: { Label("Delete…", systemImage: "trash") }
        }
    }

    @ViewBuilder
    private func suggestButton(_ credential: StoredCredential) -> some View {
        if credential.suggested == true {
            Button { store.setSuggested(id: credential.id, false) } label: {
                Label("Don't suggest", systemImage: "star.slash")
            }
            .tint(.gray)
        } else {
            Button { store.setSuggested(id: credential.id, true) } label: {
                Label("Suggest", systemImage: "star")
            }
            .tint(.yellow)
        }
    }

    private func header(_ rpId: String, _ credentials: [StoredCredential]) -> some View {
        let ids = Set(credentials.map(\.id))
        let allSelected = ids.isSubset(of: selection)
        return HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 1) {
                Text(siteTitle(rpId))
                if store.siteNames[rpId] != nil {
                    Text(rpId).font(.caption2).foregroundColor(.secondary)
                }
            }
            Spacer()
            if editing {
                Button(allSelected ? "Deselect" : "Select all") {
                    if allSelected { selection.subtract(ids) } else { selection.formUnion(ids) }
                }
                .font(.footnote)
            } else {
                Menu {
                    Button { renaming = .site(rpId) } label: { Label("Rename site…", systemImage: "pencil") }
                    Button {
                        withAnimation { editMode = .active }
                        selection = ids
                    } label: {
                        Label("Select all keys", systemImage: "checkmark.circle")
                    }
                    Button(role: .destructive) { pendingDelete = credentials } label: {
                        Label("Delete all keys…", systemImage: "trash")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle").font(.body)
                }
            }
        }
        .textCase(nil)
    }

    private func siteTitle(_ rpId: String) -> String {
        store.siteNames[rpId] ?? rpId
    }

    // MARK: Deleting

    private static func deleteTitle(_ keys: [StoredCredential]) -> String {
        keys.count == 1 ? "Delete this key?" : "Delete \(keys.count) keys?"
    }

    private static func deleteMessage(_ keys: [StoredCredential]) -> String {
        let sites = Set(keys.map(\.rpId)).sorted()
        let where_ = sites.count <= 3 ? sites.joined(separator: ", ") : "\(sites.count) sites"
        if keys.count == 1, let credential = keys.first {
            return "PhoneKey can no longer sign in to \(credential.rpId) as \(credential.accountLabel). "
                + "This cannot be undone. Make sure you have another way to sign in."
        }
        return "PhoneKey can no longer sign in with them (\(where_)). "
            + "This cannot be undone. Make sure you have another way to sign in."
    }
}

/// What is being renamed.
enum RenameTarget: Identifiable {
    case key(StoredCredential)
    case site(String)

    var id: String {
        switch self {
        case let .key(credential): return "key:" + credential.id.base64EncodedString()
        case let .site(rpId): return "site:" + rpId
        }
    }
}

/// Sets or clears the user's own name for a key or a site.
struct RenameSheet: View {
    let target: RenameTarget
    @ObservedObject var store: KeychainCredentialStore
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @FocusState private var focused: Bool

    var body: some View {
        NavigationView {
            Form {
                Section {
                    TextField(placeholder, text: $name)
                        .textInputAutocapitalization(.words)
                        .disableAutocorrection(true)
                        .focused($focused)
                        .submitLabel(.done)
                        .onSubmit { save(name) }
                } footer: {
                    Text(footer)
                }
                if hasOwnName {
                    Section {
                        Button("Use the site's name", role: .destructive) {
                            save(nil)
                        }
                    }
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save(name) }
                }
            }
        }
        .onAppear {
            name = currentName ?? ""
            // The sheet must be on screen before the keyboard can come up.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { focused = true }
        }
    }

    private var title: String {
        if case .site = target { return "Rename site" }
        return "Rename key"
    }

    /// What the site itself calls it.
    private var placeholder: String {
        switch target {
        case let .key(credential): return credential.userName ?? credential.userDisplayName ?? "Name"
        case let .site(rpId): return rpId
        }
    }

    private var currentName: String? {
        switch target {
        case let .key(credential): return store.all.first { $0.id == credential.id }?.localName
        case let .site(rpId): return store.siteNames[rpId]
        }
    }

    private var hasOwnName: Bool { currentName != nil }

    private var footer: String {
        switch target {
        case let .key(credential):
            return "Only on this iPhone. \(credential.rpId) keeps its own name for the account."
        case let .site(rpId):
            return "Only on this iPhone, for your overview. Requests still show the real address, \(rpId)."
        }
    }

    private func save(_ value: String?) {
        switch target {
        case let .key(credential): store.rename(id: credential.id, to: value)
        case let .site(rpId): store.renameSite(rpId, to: value)
        }
        dismiss()
    }
}
