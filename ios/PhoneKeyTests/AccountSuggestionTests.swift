import PhoneKeyCore
import XCTest
@testable import PhoneKey

final class AccountSuggestionTests: XCTestCase {
    private func account(_ name: String, created: TimeInterval, lastUsed: TimeInterval? = nil,
                         suggested: Bool? = nil) -> StoredCredential {
        StoredCredential(id: Data(name.utf8), rpId: "example.com", rpName: nil, userId: Data(name.utf8),
                         userName: name, userDisplayName: nil, discoverable: true,
                         created: Date(timeIntervalSince1970: created), signCount: 0,
                         lastUsed: lastUsed.map { Date(timeIntervalSince1970: $0) }, suggested: suggested)
    }

    func testNewestFirstWhenNothingIsKnown() {
        let order = [account("old", created: 1), account("new", created: 3), account("mid", created: 2)]
            .orderedForSuggestion()
        XCTAssertEqual(order.map(\.userName), ["new", "mid", "old"])
    }

    func testLastUsedBeatsNewest() {
        let order = [account("new", created: 3), account("used", created: 1, lastUsed: 10)]
            .orderedForSuggestion()
        XCTAssertEqual(order.first?.userName, "used")
    }

    func testSuggestedBeatsLastUsed() {
        let order = [
            account("used", created: 1, lastUsed: 20),
            account("work", created: 2, lastUsed: 5, suggested: true),
            account("private", created: 3, suggested: true),
        ].orderedForSuggestion()
        // Suggested ones first (the one used more recently first), then the rest.
        XCTAssertEqual(order.map(\.userName), ["work", "private", "used"])
    }
    func testNoQuestionForThePreselectedAccount() {
        let accounts = [account("a", created: 1), account("b", created: 2)]
        XCTAssertNil(SuggestionQuestion.after(signingInWith: accounts[1], preselectedId: accounts[1].id,
                                              candidates: accounts, rpId: "example.com"))
    }

    /// Gerry's bug: two suggested accounts, the other one used last and so
    /// preselected; picking this one must not ask again.
    func testNoQuestionForAnAlreadySuggestedAccount() {
        let work = account("work", created: 1, lastUsed: 20, suggested: true)
        let home = account("home", created: 2, lastUsed: 5, suggested: true)
        let accounts = [work, home]
        XCTAssertEqual(accounts.orderedForSuggestion().first?.userName, "work")
        XCTAssertNil(SuggestionQuestion.after(signingInWith: home, preselectedId: work.id,
                                              candidates: accounts, rpId: "example.com"))
    }

    func testQuestionOffersOnlyOtherSuggestedAccounts() {
        let work = account("work", created: 1, suggested: true)
        let other = account("other", created: 2)
        let question = SuggestionQuestion.after(signingInWith: other, preselectedId: work.id,
                                                candidates: [work, other], rpId: "example.com")
        XCTAssertEqual(question?.account.userName, "other")
        XCTAssertEqual(question?.current.map(\.userName), ["work"])
    }

    func testNoQuestionWithASingleAccount() {
        let only = account("only", created: 1)
        XCTAssertNil(SuggestionQuestion.after(signingInWith: only, preselectedId: nil,
                                              candidates: [only], rpId: "example.com"))
    }
}
