import XCTest
@testable import PhoneKeyCore

final class CBORTests: XCTestCase {
    /// RFC 8949 Appendix A.
    func testRFCExamples() throws {
        let cases: [(CBOR, String)] = [
            (.int(0), "00"), (.int(23), "17"), (.int(24), "1818"), (.int(100), "1864"),
            (.int(1000), "1903e8"), (.int(1_000_000), "1a000f4240"),
            (.unsigned(1_000_000_000_000), "1b000000e8d4a51000"),
            (.int(-1), "20"), (.int(-10), "29"), (.int(-100), "3863"), (.int(-1000), "3903e7"),
            (.bytes(Data()), "40"), (.bytes(Data([1, 2, 3, 4])), "4401020304"),
            (.text(""), "60"), (.text("a"), "6161"), (.text("IETF"), "6449455446"),
            (.text("\u{00fc}"), "62c3bc"),
            (.array([]), "80"), (.array([.int(1), .int(2), .int(3)]), "83010203"),
            (.map([]), "a0"), (.map([.int(1): .int(2), .int(3): .int(4)]), "a201020304"),
            (.map([.text("a"): .int(1), .text("b"): .array([.int(2), .int(3)])]), "a26161016162820203"),
            (.bool(false), "f4"), (.bool(true), "f5"), (.null, "f6"),
        ]
        for (value, hexString) in cases {
            XCTAssertEqual(value.encoded, hex(hexString), "encode \(value)")
            XCTAssertEqual(try CBOR.decode(hex(hexString)), value, "decode \(hexString)")
        }
    }

    func testCanonicalMapOrder() {
        let map = CBOR.map([.text("b"): .int(1), .text("a"): .int(2), .int(10): .int(3), .int(-1): .int(4),
                            .text("aa"): .int(5)])
        // 10 (0x0a), -1 (0x20), "a", "b", then the longer "aa".
        XCTAssertEqual(map.encoded, hex("a50a0320046161026162016261610" + "5"))
    }

    func testAccessors() throws {
        let m = try CBOR.decode(hex("a201020304"))
        XCTAssertEqual(m[1]?.int, 2)
        XCTAssertNil(m[2])
        XCTAssertEqual(CBOR.int(-7).int, -7)
    }

    func testRejects() {
        let bad: [(String, CBOR.DecodeError)] = [
            ("9f01ff", .unsupported(31)),        // indefinite array
            ("1903", .truncated),
            ("0000", .trailingBytes),
            ("44010203", .truncated),
            ("c11a514b67b0", .unsupported(0xC1)), // tag
            ("f93c00", .unsupported(0xF9)),       // half float
            ("7aFFFFFFFF", .truncated),           // huge length
            ("62c328", .invalidText),
        ]
        for (h, want) in bad {
            XCTAssertThrowsError(try CBOR.decode(hex(h)), h) { XCTAssertEqual($0 as? CBOR.DecodeError, want, h) }
        }
        let deep = Data(repeating: 0x81, count: 40) + Data([0x00])
        XCTAssertThrowsError(try CBOR.decode(deep)) { XCTAssertEqual($0 as? CBOR.DecodeError, .tooDeep) }
    }
}
