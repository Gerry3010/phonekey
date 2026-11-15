package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Gerry3010/phonekey/linux/internal/camera"
	"github.com/Gerry3010/phonekey/linux/internal/proto"
	"github.com/Gerry3010/phonekey/linux/internal/testphone"
)

func pairedMux(t *testing.T, f *testphone.Phone) *Mux {
	t.Helper()
	c := newClient(t, f)
	hostKey, _ := c.Store.HostKey()
	psk := make([]byte, 32)
	rand.Read(psk)
	f.SetPending(psk, hostKey.Public)
	s, err := c.Pair(context.Background(), psk)
	if err != nil {
		t.Fatal(err)
	}
	m := s.Mux()
	t.Cleanup(func() { m.Close() })
	return m
}

// A webcam stream: frames arrive in order right from the first one (the
// stream is set up as camera.started arrives), FIDO keeps working beside it,
// and camera.stop ends it.
func TestCameraStream(t *testing.T) {
	f := testphone.New(t)
	var frames []camera.Frame
	for i := range 6 {
		// Larger than a chunk, so frames span several chunks.
		frames = append(frames, camera.Frame{Keyframe: i == 0, Data: bytes.Repeat([]byte{byte(i + 1)}, 70_000+i)})
	}
	f.Camera = &testphone.Camera{Width: 1280, Height: 720, FPS: 30, Frames: frames}
	m := pairedMux(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	msg, s, err := m.StartStream(ctx, func(id uint64) any {
		return proto.CameraStart{T: "camera.start", ID: id, Camera: "back", Quality: "720p", FPS: 30}
	})
	if err != nil {
		t.Fatal(err)
	}
	var started proto.CameraStarted
	json.Unmarshal(msg.JSON, &started)
	if started.Stream != s.ID || started.Width != 1280 || started.Camera != "back" {
		t.Fatalf("camera.started %+v, stream %d", started, s.ID)
	}
	for i := range 8 {
		got, err := camera.ReadFrame(s)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		want := frames[i%len(frames)]
		if got.Keyframe != want.Keyframe || !bytes.Equal(got.Data, want.Data) {
			t.Fatalf("frame %d differs (%d bytes, keyframe %v)", i, len(got.Data), got.Keyframe)
		}
		if i == 3 {
			// CTAP between the video chunks.
			if resp, err := m.CTAP(ctx, []byte{0x04}); err != nil || !bytes.Equal(resp, []byte{0x00, 0xA0}) {
				t.Fatalf("getInfo during the stream: %x %v", resp, err)
			}
		}
	}

	stopped, err := m.Call(ctx, func(id uint64) any {
		return proto.CameraControl{T: "camera.stop", ID: id, Stream: s.ID}
	})
	if err != nil || stopped.Type != "camera.stopped" {
		t.Fatalf("camera.stop: %v %v", stopped.Type, err)
	}
	s.Close()
	// Data already queued may remain, but then the stream must end.
	for {
		if _, err := s.Read(make([]byte, 64<<10)); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("after Close: %v, want EOF", err)
			}
			break
		}
	}
}

func TestCameraStreamRefused(t *testing.T) {
	f := testphone.New(t)
	f.Camera = &testphone.Camera{Disabled: true}
	m := pairedMux(t, f)
	_, _, err := m.StartStream(context.Background(), func(id uint64) any {
		return proto.CameraStart{T: "camera.start", ID: id}
	})
	var re *proto.RemoteError
	if !errors.As(err, &re) || re.Code != "camera_stream_disabled" {
		t.Fatalf("got %v, want camera_stream_disabled", err)
	}
}

// The queue never blocks its writer and gives up when its reader falls too
// far behind.
func TestQueueBacklog(t *testing.T) {
	q := newQueue(10)
	q.push([]byte("12345"))
	q.push([]byte("67890"))
	buf := make([]byte, 3)
	if n, _ := q.read(buf); string(buf[:n]) != "123" {
		t.Fatalf("read %q", buf[:n])
	}
	q.push([]byte("abcdef")) // 7 queued + 6 > 10
	if _, err := q.read(buf); !errors.Is(err, ErrStreamBacklog) {
		t.Fatalf("after overflow: %v", err)
	}
}
