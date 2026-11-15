package camera

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"testing"
)

// Frames survive any chunking: a frame may span chunks, and a chunk may end
// inside a frame (docs/protocol.md §5 "camera").
func TestFramesAcrossChunks(t *testing.T) {
	var frames []Frame
	var stream []byte
	for i := range 20 {
		f := Frame{Keyframe: i%10 == 0, Time: uint64(i) * 33_333, Data: bytes.Repeat([]byte{byte(i)}, 1+i*7919)}
		frames = append(frames, f)
		stream = AppendFrame(stream, f)
	}
	r := &chunkReader{data: stream}
	for i, want := range frames {
		got, err := ReadFrame(r)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if got.Keyframe != want.Keyframe || got.Time != want.Time || !bytes.Equal(got.Data, want.Data) {
			t.Fatalf("frame %d differs", i)
		}
	}
	if _, err := ReadFrame(r); err != io.EOF {
		t.Fatalf("after the last frame: %v, want EOF", err)
	}
}

func TestFrameRejects(t *testing.T) {
	huge := AppendFrame(nil, Frame{Data: []byte{1}})
	huge[9], huge[10] = 0x7F, 0xFF // length far above MaxFrameSize
	if _, err := ReadFrame(bytes.NewReader(huge)); err == nil {
		t.Fatal("oversized frame accepted")
	}
	short := AppendFrame(nil, Frame{Data: []byte{1, 2, 3}})
	if _, err := ReadFrame(bytes.NewReader(short[:len(short)-1])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated frame: %v", err)
	}
	unknown := AppendFrame(nil, Frame{Data: []byte{1}})
	unknown[0] = 0x81 // a future flag bit next to the keyframe bit
	if f, err := ReadFrame(bytes.NewReader(unknown)); err != nil || !f.Keyframe {
		t.Fatalf("unknown flag bits: %v %+v", err, f)
	}
}

// chunkReader hands out data in random pieces, like chunks off the wire.
type chunkReader struct{ data []byte }

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), len(c.data), 1+rand.IntN(70_000))
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}
