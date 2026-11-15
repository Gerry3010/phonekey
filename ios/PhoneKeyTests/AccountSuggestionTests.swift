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
}
