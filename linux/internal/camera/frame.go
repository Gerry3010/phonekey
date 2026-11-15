// Package camera handles the webcam stream of docs/protocol.md §5 "camera":
// the frame format on the chunk stream, decoding with ffmpeg and the
// placeholder picture shown while the phone does not stream.
package camera

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame is one video frame of a camera stream.
type Frame struct {
	// Keyframe marks an IDR frame with SPS and PPS in front of it.
	Keyframe bool
	// Time is the capture time in microseconds, monotonic on the phone.
	Time uint64
	// Data is one H.264 access unit in Annex B format.
	Data []byte
}

// HeaderSize is the size of the header in front of each frame: flags (1),
// capture time (8) and length (4).
const HeaderSize = 13

// MaxFrameSize bounds a frame, so a corrupt length cannot exhaust memory. A
// 1080p keyframe at 8 Mbit/s is far below it.
const MaxFrameSize = 8 << 20

const flagKeyframe = 0x01

// ReadFrame reads the next frame. Frames do not line up with chunks, so r is
// the stream as a whole. Unknown flag bits are ignored.
func ReadFrame(r io.Reader) (Frame, error) {
	var h [HeaderSize]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(h[9:])
	if n == 0 || n > MaxFrameSize {
		return Frame{}, fmt.Errorf("camera frame of %d bytes", n)
	}
	f := Frame{Keyframe: h[0]&flagKeyframe != 0, Time: binary.BigEndian.Uint64(h[1:]), Data: make([]byte, n)}
	if _, err := io.ReadFull(r, f.Data); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	return f, nil
}

// AppendFrame appends f in the stream format (the phone's side; tests).
func AppendFrame(dst []byte, f Frame) []byte {
	var flags byte
	if f.Keyframe {
		flags = flagKeyframe
	}
	dst = append(dst, flags)
	dst = binary.BigEndian.AppendUint64(dst, f.Time)
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(f.Data)))
	return append(dst, f.Data...)
}
