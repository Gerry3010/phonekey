import XCTest
@testable import PhoneKeyCore

/// Phase 4a: the parts of the webcam stream that need no camera (§5 "camera").
final class CameraStreamTests: XCTestCase {
    private func request(_ json: String) throws -> Request {
        try JSONDecoder().decode(Request.self, from: Data(json.utf8))
    }

    // MARK: camera.start

    func testQualityIsANumberForPhotosAndANameForTheWebcam() throws {
        let photo = try request(#"{"t":"photo.capture","id":3,"camera":"back","quality":0.8}"#)
        XCTAssertEqual(photo.quality, 0.8)
        XCTAssertNil(photo.videoQuality)
        let start = try request(#"{"t":"camera.start","id":5,"camera":"front","quality":"1080p","fps":25}"#)
        XCTAssertNil(start.quality)
        XCTAssertEqual(start.videoQuality, "1080p")
        XCTAssertEqual(start.fps, 25)
        let stop = try request(#"{"t":"camera.stop","id":7,"stream":2}"#)
        XCTAssertEqual(stop.stream, 2)
    }

    func testCameraStartDefaultsAndChecks() throws {
        let plain = try CameraStreamRequest(try request(#"{"t":"camera.start","id":1}"#))
        XCTAssertEqual(plain, CameraStreamRequest(camera: .front, maxSize: .p720, fps: 30))
        let full = try CameraStreamRequest(try request(#"{"t":"camera.start","id":1,"camera":"back","quality":"1080p","fps":15}"#))
        XCTAssertEqual(full, CameraStreamRequest(camera: .back, maxSize: .p1080, fps: 15))
        for bad in [#""camera":"side""#, #""quality":"4k""#, #""quality":0.5"#, #""fps":14"#, #""fps":31"#] {
            XCTAssertThrowsError(try CameraStreamRequest(try request(#"{"t":"camera.start","id":9,"# + bad + "}"))) { error in
                XCTAssertEqual((error as? ErrorMessage)?.code, .unsupported, bad)
                XCTAssertEqual((error as? ErrorMessage)?.id, 9)
            }
        }
        XCTAssertThrowsError(try request(#"{"t":"camera.start","fps":29.5}"#), "fps is an integer")
    }

    func testSizeLadderNeverScalesUp() {
        XCTAssertEqual(VideoSize.best(upTo: .p1080, availableWidth: 2320), .p1080)
        XCTAssertEqual(VideoSize.best(upTo: .p1080, availableWidth: 1500), .p720, "portrait crop too narrow for 1080p")
        XCTAssertEqual(VideoSize.best(upTo: .p720, availableWidth: 4000), .p720, "the request is a maximum")
        XCTAssertEqual(VideoSize.best(upTo: .p720, availableWidth: 1080), .p540)
        XCTAssertNil(VideoSize.best(upTo: .p720, availableWidth: 900))
    }

    func testBitrates() {
        XCTAssertEqual(CameraStreamRequest.bitrate(for: .p720, fps: 30), 4_000_000)
        XCTAssertEqual(CameraStreamRequest.bitrate(for: .p1080, fps: 30), 8_000_000)
        XCTAssertEqual(CameraStreamRequest.bitrate(for: .p720, fps: 15), 2_500_000)
        XCTAssertEqual(CameraStreamRequest.bitrate(for: .p1080, fps: 15), 5_000_000)
    }

    func testMessages() throws {
        func json<T: Encodable>(_ value: T) throws -> [String: AnyHashable] {
            try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(value)) as? [String: AnyHashable])
        }
        XCTAssertEqual(try json(CameraStartedMessage(id: 5, stream: 2, width: 1280, height: 720, fps: 30, camera: "front")),
                       ["t": "camera.started", "id": 5, "stream": 2, "codec": "h264", "width": 1280,
                        "height": 720, "fps": 30, "camera": "front"])
        XCTAssertEqual(try json(CameraChangedMessage(stream: 2, fps: 15)), ["t": "camera.changed", "stream": 2, "fps": 15])
        XCTAssertEqual(try json(CameraStoppedMessage(id: nil, stream: 2, reason: .stoppedOnPhone)),
                       ["t": "camera.stopped", "stream": 2, "reason": "stopped_on_phone"])
        let camera = try json(StatusMessage.Camera(enabled: false, available: true, streamEnabled: true, streaming: false))
        XCTAssertEqual(camera, ["enabled": false, "available": true, "stream_enabled": true, "streaming": false])
    }

    // MARK: Frames

    func testFrameFormat() {
        let frame = VideoFrame(keyframe: true, time: 0x0102_0304_0506_0708, data: Data([0xAA, 0xBB]))
        XCTAssertEqual(frame.encoded, Data([0x01, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 2, 0xAA, 0xBB]))
        XCTAssertEqual(VideoFrame(keyframe: false, time: 1, data: Data([0x09])).encoded.first, 0x00)
    }

    func testAnnexB() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x1F]), pps = Data([0x68, 0xEE, 0x3C, 0x80])
        let idr = Data([0x65, 0x88, 0x84]), sei = Data([0x06, 0x05])
        let avcc = Data([0, 0, 0, 2]) + sei + Data([0, 0, 0, 3]) + idr
        let annexB = try AnnexB.fromAVCC(avcc, parameterSets: [sps, pps])
        let start = AnnexB.startCode
        XCTAssertEqual(annexB, start + sps + start + pps + start + sei + start + idr)
        XCTAssertEqual(try AnnexB.fromAVCC(Data([0, 2]) + sei, lengthSize: 2), start + sei)
        XCTAssertThrowsError(try AnnexB.fromAVCC(Data([0, 0, 0, 9, 0x65])), "length past the end")
        XCTAssertThrowsError(try AnnexB.fromAVCC(Data([0, 0])), "truncated length")
        XCTAssertThrowsError(try AnnexB.fromAVCC(Data([0, 0, 0, 0])), "empty NAL unit")
    }

    // MARK: Send queue

    private func frame(_ ms: UInt64, key: Bool = false) -> VideoFrame {
        VideoFrame(keyframe: key, time: ms * 1000, data: Data([key ? 0x65 : 0x41]))
    }

    func testQueueHandsOverAndKeepsOrder() async {
        let queue = FrameQueue()
        XCTAssertFalse(queue.push(frame(0, key: true)))
        XCTAssertFalse(queue.push(frame(33)))
        let first = await queue.next()
        let second = await queue.next()
        XCTAssertEqual(first?.time, 0)
        XCTAssertEqual(second?.time, 33_000)
        let waiting = Task { await queue.next() }
        try? await Task.sleep(nanoseconds: 20_000_000)
        queue.push(frame(66))
        let handed = await waiting.value
        XCTAssertEqual(handed?.time, 66_000, "an idle sender gets the frame at once")
        queue.close()
        let closed = await queue.next()
        XCTAssertNil(closed)
    }

    func testQueueDropsToTheNextKeyframeWhenBehind() async {
        let queue = FrameQueue()
        queue.push(frame(0, key: true))
        for ms in stride(from: 33, through: 499, by: 33) {
            XCTAssertFalse(queue.push(frame(UInt64(ms))), "up to 0.5 s is kept")
        }
        XCTAssertTrue(queue.push(frame(533)), "over 0.5 s behind: ask for a keyframe")
        XCTAssertEqual(queue.dropped, 17, "everything queued and the new frame")
        XCTAssertTrue(queue.push(frame(566)), "still no keyframe: keep asking, drop")
        XCTAssertFalse(queue.push(frame(600, key: true)))
        XCTAssertFalse(queue.push(frame(633)))
        let resumed = await queue.next()
        XCTAssertEqual(resumed, frame(600, key: true), "the stream resumes at a keyframe")
        let following = await queue.next()
        XCTAssertEqual(following?.time, 633_000)
        XCTAssertEqual(queue.dropped, 18)
    }

    func testQueueKeepsAKeyframeThatArrivesLate() async {
        let queue = FrameQueue()
        queue.push(frame(0, key: true))
        queue.push(frame(100))
        XCTAssertFalse(queue.push(frame(700, key: true)), "a keyframe already: nothing to ask for")
        let next = await queue.next()
        XCTAssertEqual(next, frame(700, key: true))
    }

    // MARK: Heat

    func testGovernor() {
        let t0 = Date(timeIntervalSince1970: 1_000)
        var governor = FrameRateGovernor(requested: 30, level: .nominal, now: t0)
        XCTAssertEqual(governor.fps, 30)
        XCTAssertEqual(governor.update(level: .fair, now: t0), .none)
        XCTAssertEqual(governor.update(level: .serious, now: t0 + 10), .change(fps: 15))
        XCTAssertEqual(governor.update(level: .serious, now: t0 + 20), .none)
        XCTAssertEqual(governor.update(level: .fair, now: t0 + 30), .none)
        XCTAssertEqual(governor.update(level: .nominal, now: t0 + 89), .none, "59 s calm")
        XCTAssertEqual(governor.update(level: .serious, now: t0 + 89.5), .none, "serious again resets")
        XCTAssertEqual(governor.update(level: .fair, now: t0 + 100), .none)
        XCTAssertEqual(governor.update(level: .fair, now: t0 + 160), .change(fps: 30), "60 s fair or better")
        XCTAssertEqual(governor.fps, 30)
        XCTAssertEqual(governor.update(level: .critical, now: t0 + 170), .stop)

        let hot = FrameRateGovernor(requested: 25, level: .serious, now: t0)
        XCTAssertEqual(hot.fps, 15, "already serious at the start")
        var slow = FrameRateGovernor(requested: 15, level: .nominal, now: t0)
        XCTAssertEqual(slow.update(level: .serious, now: t0 + 1), .none, "15 is already the floor")
    }
}
