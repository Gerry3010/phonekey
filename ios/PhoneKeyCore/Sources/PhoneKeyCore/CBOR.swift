import Foundation

/// The CBOR subset CTAP2 uses (RFC 8949): integers, byte and text strings,
/// arrays, maps, booleans and null. Definite lengths only; maps are encoded in
/// CTAP2 canonical order (shorter key encoding first, then bytewise).
public indirect enum CBOR: Equatable {
    case unsigned(UInt64)
    /// The value is `-1 - n`.
    case negative(UInt64)
    case bytes(Data)
    case text(String)
    case array([CBOR])
    case map([Pair])
    case bool(Bool)
    case null
    case undefined

    public struct Pair: Equatable {
        public let key: CBOR
        public let value: CBOR

        public init(_ key: CBOR, _ value: CBOR) {
            self.key = key
            self.value = value
        }
    }

    public enum DecodeError: Error, Equatable {
        case truncated
        case trailingBytes
        case unsupported(UInt8)
        case tooDeep
        case invalidText
    }

    // MARK: Convenience

    public static func int(_ v: Int) -> CBOR {
        v >= 0 ? .unsigned(UInt64(v)) : .negative(UInt64(-1 - v))
    }

    public static func map(_ entries: KeyValuePairs<CBOR, CBOR>) -> CBOR {
        .map(entries.map { Pair($0.key, $0.value) })
    }

    public var int: Int? {
        switch self {
        case let .unsigned(v): return v <= UInt64(Int.max) ? Int(v) : nil
        case let .negative(n): return n < UInt64(Int.max) ? -1 - Int(n) : nil
        default: return nil
        }
    }

    public var bytes: Data? {
        if case let .bytes(d) = self { return d }
        return nil
    }

    public var text: String? {
        if case let .text(s) = self { return s }
        return nil
    }

    public var array: [CBOR]? {
        if case let .array(a) = self { return a }
        return nil
    }

    public var bool: Bool? {
        if case let .bool(b) = self { return b }
        return nil
    }

    public var isMap: Bool {
        if case .map = self { return true }
        return false
    }

    public subscript(key: CBOR) -> CBOR? {
        guard case let .map(pairs) = self else { return nil }
        return pairs.first { $0.key == key }?.value
    }

    public subscript(key: Int) -> CBOR? { self[.int(key)] }
    public subscript(key: String) -> CBOR? { self[.text(key)] }

    // MARK: Encoding

    public var encoded: Data {
        var out = Data()
        encode(into: &out)
        return out
    }

    private func encode(into out: inout Data) {
        switch self {
        case let .unsigned(v): Self.head(0, v, &out)
        case let .negative(n): Self.head(1, n, &out)
        case let .bytes(d):
            Self.head(2, UInt64(d.count), &out)
            out += d
        case let .text(s):
            let utf8 = Data(s.utf8)
            Self.head(3, UInt64(utf8.count), &out)
            out += utf8
        case let .array(items):
            Self.head(4, UInt64(items.count), &out)
            items.forEach { $0.encode(into: &out) }
        case let .map(pairs):
            Self.head(5, UInt64(pairs.count), &out)
            let sorted = pairs.map { ($0.key.encoded, $0.value) }.sorted { a, b in
                a.0.count != b.0.count ? a.0.count < b.0.count : a.0.lexicographicallyPrecedes(b.0)
            }
            for (key, value) in sorted {
                out += key
                value.encode(into: &out)
            }
        case let .bool(b): out.append(b ? 0xF5 : 0xF4)
        case .null: out.append(0xF6)
        case .undefined: out.append(0xF7)
        }
    }

    private static func head(_ major: UInt8, _ value: UInt64, _ out: inout Data) {
        let m = major << 5
        switch value {
        case 0..<24:
            out.append(m | UInt8(value))
        case 24..<0x100:
            out += [m | 24, UInt8(value)]
        case 0x100..<0x10000:
            out += [m | 25, UInt8(value >> 8), UInt8(value & 0xFF)]
        case 0x10000..<0x1_0000_0000:
            out.append(m | 26)
            withUnsafeBytes(of: UInt32(value).bigEndian) { out.append(contentsOf: $0) }
        default:
            out.append(m | 27)
            withUnsafeBytes(of: value.bigEndian) { out.append(contentsOf: $0) }
        }
    }

    // MARK: Decoding

    /// Decodes exactly one item; trailing bytes are an error.
    public static func decode(_ data: Data) throws -> CBOR {
        var reader = Reader(bytes: [UInt8](data))
        let item = try reader.item(depth: 0)
        guard reader.offset == reader.bytes.count else { throw DecodeError.trailingBytes }
        return item
    }

    /// The encoding of the value under `key` in the map `data`, byte for byte
    /// as it arrived: CTAP MACs some parameters over their encoding, which a
    /// decode and re-encode need not reproduce. nil when the key is absent.
    public static func rawValue(forKey key: CBOR, inMap data: Data) throws -> Data? {
        var reader = Reader(bytes: [UInt8](data))
        let initial = try reader.take(1).first!
        guard initial >> 5 == 5 else { throw DecodeError.unsupported(initial) }
        var found: Data?
        for _ in 0..<(try reader.length(initial & 0x1F)) {
            let entryKey = try reader.item(depth: 1)
            let start = reader.offset
            _ = try reader.item(depth: 1)
            if found == nil, entryKey == key { found = Data(reader.bytes[start..<reader.offset]) }
        }
        guard reader.offset == reader.bytes.count else { throw DecodeError.trailingBytes }
        return found
    }

    private struct Reader {
        let bytes: [UInt8]
        var offset = 0

        static let maxDepth = 16

        mutating func take(_ n: Int) throws -> ArraySlice<UInt8> {
            guard n >= 0, bytes.count - offset >= n else { throw DecodeError.truncated }
            defer { offset += n }
            return bytes[offset..<offset + n]
        }

        mutating func argument(_ info: UInt8) throws -> UInt64 {
            switch info {
            case 0..<24: return UInt64(info)
            case 24: return UInt64(try take(1).first!)
            case 25: return try take(2).reduce(0) { $0 << 8 | UInt64($1) }
            case 26: return try take(4).reduce(0) { $0 << 8 | UInt64($1) }
            case 27: return try take(8).reduce(0) { $0 << 8 | UInt64($1) }
            default: throw DecodeError.unsupported(info) // indefinite lengths, reserved
            }
        }

        mutating func length(_ info: UInt8) throws -> Int {
            let n = try argument(info)
            // A length can never exceed what is left in the input.
            guard n <= UInt64(bytes.count - offset) else { throw DecodeError.truncated }
            return Int(n)
        }

        mutating func item(depth: Int) throws -> CBOR {
            guard depth < Self.maxDepth else { throw DecodeError.tooDeep }
            let initial = try take(1).first!
            let major = initial >> 5, info = initial & 0x1F
            switch major {
            case 0: return .unsigned(try argument(info))
            case 1: return .negative(try argument(info))
            case 2: return .bytes(Data(try take(try length(info))))
            case 3:
                guard let s = String(bytes: try take(try length(info)), encoding: .utf8) else {
                    throw DecodeError.invalidText
                }
                return .text(s)
            case 4:
                let n = try length(info)
                var items: [CBOR] = []
                for _ in 0..<n { items.append(try item(depth: depth + 1)) }
                return .array(items)
            case 5:
                let n = try length(info)
                var pairs: [Pair] = []
                for _ in 0..<n {
                    let key = try item(depth: depth + 1)
                    pairs.append(Pair(key, try item(depth: depth + 1)))
                }
                return .map(pairs)
            case 7:
                switch info {
                case 20: return .bool(false)
                case 21: return .bool(true)
                case 22: return .null
                case 23: return .undefined
                default: throw DecodeError.unsupported(initial) // floats, simple values
                }
            default:
                throw DecodeError.unsupported(initial) // tags
            }
        }
    }
}
