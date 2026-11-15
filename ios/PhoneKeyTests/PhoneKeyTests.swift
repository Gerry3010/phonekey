import XCTest
@testable import PhoneKey

final class PhoneKeyTests: XCTestCase {
    func testHostAppBundleIdentifier() {
        XCTAssertEqual(Bundle.main.bundleIdentifier, "net.geraldhofbauer.phonekey")
    }

    func testAppInfoReadsHostBundle() {
        let info = AppInfo.current
        XCTAssertNotEqual(info.version, "?")
        XCTAssertNotEqual(info.build, "?")
        XCTAssertEqual(info.versionDescription, "v\(info.version) (\(info.build))")
    }
}
