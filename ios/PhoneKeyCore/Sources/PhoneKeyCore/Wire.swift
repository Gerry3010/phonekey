import Foundation

/// Constants and plaintext encodings of docs/protocol.md.
public enum Wire {
    public static let port: UInt16 = 20555
    public static let version: UInt8 = 1
    public static let preambleSize = 8
    public static let maxFrame = 65535
    public static let maxChunkData = 60000

    public enum Mode: UInt8 {
        case session = 0x00
        case pairing = 0x01
    }

    public enum PreambleStatus: UInt8 {
        case ok = 0x00
        case unsupportedVersion = 0x01
        case noPairingPending = 0x02
        case busy = 0x03
        case unknownMode = 0x04
    }

    private static let magic: [UInt8] = Array("PHKY".utf8)

    public static func hostPreamble(mode: Mode) -> Data {
        Data(magic + [version, mode.rawValue, 0, 0])
    }

    public static func phonePreamble(status: PreambleStatus) -> Data {
        Data(magic + [version, status.rawValue, 0, 0])
    }

    /// Returns the version and the mode/status byte, or nil for a wrong magic.
    public static func parsePreamble(_ data: Data) -> (version: UInt8, value: UInt8)? {
        let bytes = [UInt8](data)
        guard bytes.count == preambleSize, Array(bytes[0..<4]) == magic else { return nil }
        return (bytes[4], bytes[5])
    }

    /// Prefixes a Noise message with its 2-byte big-endian length.
    public static func frame(_ message: Data) -> Data {
        precondition(!message.isEmpty && message.count <= maxFrame, "frame size out of range")
        return Data([UInt8(message.count >> 8), UInt8(message.count & 0xff)]) + message
    }
}

/// A decrypted transport message.
public enum TransportMessage: Equatable {
    case json(type: String, id: UInt64?, body: Data)
    case chunk(stream: UInt32, data: Data)
    case unknown(kind: UInt8)

    static let kindJSON: UInt8 = 0x01
    static let kindChunk: UInt8 = 0x02

    public static func decode(_ plaintext: Data) throws -> TransportMessage {
        guard let kind = plaintext.first else { throw NoiseError.malformedMessage }
        let body = Data(plaintext.dropFirst())
        switch kind {
        case kindJSON:
            struct Envelope: Decodable {
                let t: String
                let id: UInt64?
            }
            guard let env = try? JSONDecoder().decode(Envelope.self, from: body) else {
                throw NoiseError.malformedMessage
            }
            return .json(type: env.t, id: env.id, body: body)
        case kindChunk:
            guard body.count >= 4 else { throw NoiseError.malformedMessage }
            let stream = body.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            return .chunk(stream: stream, data: Data(body.dropFirst(4)))
        default:
            return .unknown(kind: kind)
        }
    }

    public static func encodeJSON<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return Data([kindJSON]) + (try encoder.encode(value))
    }

    public static func encodeChunk(stream: UInt32, data: Data) -> Data {
        var out = Data([kindChunk])
        withUnsafeBytes(of: stream.bigEndian) { out.append(contentsOf: $0) }
        return out + data
    }
}
