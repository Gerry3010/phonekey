import Foundation
import PhoneKeyCore

extension Array where Element == StoredCredential {
    /// Accounts in the order the sign-in card suggests them: the ones marked
    /// as suggested first, then by last use, then the newest. The first one is
    /// preselected.
    func orderedForSuggestion() -> [StoredCredential] {
        sorted { a, b in
            let aSuggested = a.suggested == true, bSuggested = b.suggested == true
            if aSuggested != bSuggested { return aSuggested }
            let aUsed = a.lastUsed ?? .distantPast, bUsed = b.lastUsed ?? .distantPast
            if aUsed != bUsed { return aUsed > bUsed }
            return a.created > b.created
        }
    }
}

extension StoredCredential {
    /// Why this account is the one suggested, for the sign-in card.
    var suggestionReason: String {
        if suggested == true { return "Suggested for this site" }
        if let lastUsed { return "Last used \(lastUsed.formatted(.relative(presentation: .named)))" }
        return "Newest account"
    }

    /// One line for account lists.
    var usageLine: String {
        if let lastUsed {
            return "last used \(lastUsed.formatted(date: .abbreviated, time: .shortened))"
        }
        let createdText = "created \(created.formatted(date: .abbreviated, time: .shortened))"
        // Older data has a counter but no date of last use.
        return signCount > 0 ? "\(createdText) · used \(signCount)×" : "\(createdText), not used yet"
    }
}

/// After signing in with an account other than the suggested one: should the
/// phone suggest it from now on, as well as or instead of the current ones?
struct SuggestionQuestion {
    let rpId: String
    let account: StoredCredential
    /// The accounts suggested for the site so far.
    let current: [StoredCredential]
}
