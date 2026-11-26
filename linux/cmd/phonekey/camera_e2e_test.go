//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/Gerry3010/phonekey/linux/internal/camera"
	"github.com/Gerry3010/phonekey/linux/internal/client"
	"github.com/Gerry3010/phonekey/linux/internal/store"
	"github.com/Gerry3010/phonekey/linux/internal/testphone"
)

// The webcam end to end, against a real v4l2loopback device
// (PHONEKEY_TEST_V4L2, e.g. /dev/video10) and a test phone that sends H.264
// like the app: no stream while nobody reads, the phone's pictures while
// ffmpeg reads, and camera.stop once it is done.
func TestWebcamEndToEnd(t *testing.T) {
	path := os.Getenv("PHONEKEY_TEST_V4L2")
	if path == "" {
		t.Skip("set PHONEKEY_TEST_V4L2 to a v4l2loopback device")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	phone, cl := webcamTestPhone(ctx, t)

	const w, h = 1280, 720
	runCtx, stopRun := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- runWebcam(runCtx, webcamConfig{Client: cl, Device: path, Quality: "720p",
			FPS: 30, Width: w, Height: h}, log.New(testLog{t}, "", 0))
	}()
	defer func() {
		stopRun()
		<-done
	}()

	time.Sleep(time.Second)
	if r := phone.Requests(); len(r) != 0 {
		t.Fatalf("requests before any reader: %v", r)
	}

	// An application reads 60 pictures (2 s at 30 fps).
	reader := exec.CommandContext(ctx, "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
		"-f", "v4l2", "-input_format", "yuv420p", "-video_size", "1280x720", "-i", path,
		"-frames:v", "60", "-f", "rawvideo", "-pix_fmt", "yuv420p", "pipe:1")
	reader.Stderr = testLog{t}
	got, err := reader.Output()
	if err != nil {
		t.Fatalf("reading the webcam: %v", err)
	}
	size := camera.PictureSize(w, h)
	placeholder := camera.Placeholder(w, h)
	live := 0
	for off := 0; off+size <= len(got); off += size {
		if !bytes.Equal(got[off:off+size], placeholder) {
			live++
		}
	}
	t.Logf("%d of %d pictures came from the phone", live, len(got)/size)
	if snap := os.Getenv("PHONEKEY_TEST_SNAPSHOT"); snap != "" && len(got) >= 40*size {
		// One raw I420 picture to look at: ffmpeg -f rawvideo -pix_fmt yuv420p -s 1280x720 -i FILE out.png
		os.WriteFile(snap, got[39*size:40*size], 0o644)
	}
	if live < 20 {
		t.Fatalf("only %d pictures from the phone", live)
	}

	deadline := time.Now().Add(5 * time.Second)
	for !slices.Contains(phone.Requests(), "camera.stop") {
		if time.Now().After(deadline) {
			t.Fatalf("no camera.stop after the reader left: %v", phone.Requests())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if r := phone.Requests(); r[0] != "camera.start" {
		t.Fatalf("requests %v", r)
	}
	// Without -camera the phone picks the camera (the one chosen in the app).
	if s := phone.Starts(); len(s) == 0 || s[0].Camera != "" {
		t.Fatalf("camera.start %+v, want no camera", s)
	}
}

// After the webcam switch went off and on again, the picture comes back
// while the application keeps reading.
func TestWebcamSwitchBackOn(t *testing.T) {
	path := os.Getenv("PHONEKEY_TEST_V4L2")
	if path == "" {
		t.Skip("set PHONEKEY_TEST_V4L2 to a v4l2loopback device")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	phone, cl := webcamTestPhone(ctx, t)
	defer func(d time.Duration) { switchPollEvery = d }(switchPollEvery)
	switchPollEvery = 200 * time.Millisecond

	runCtx, stopRun := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- runWebcam(runCtx, webcamConfig{Client: cl, Device: path, Quality: "720p",
			FPS: 30, Width: 1280, Height: 720}, log.New(testLog{t}, "", 0))
	}()
	defer func() {
		stopRun()
		<-done
	}()
	time.Sleep(time.Second)

	reader := exec.CommandContext(ctx, "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
		"-f", "v4l2", "-i", path, "-t", "6", "-f", "null", "-")
	reader.Stderr = testLog{t}
	if err := reader.Start(); err != nil {
		t.Fatal(err)
	}
	starts := func() int {
		n := 0
		for _, r := range phone.Requests() {
			if r == "camera.start" {
				n++
			}
		}
		return n
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatalf("%s: requests %v", what, phone.Requests())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitFor("first camera.start", func() bool { return starts() == 1 })

	phone.SetStreamEnabled(false)
	time.Sleep(time.Second)
	if n := starts(); n != 1 {
		t.Fatalf("%d camera.start while the switch is off", n)
	}
	phone.SetStreamEnabled(true)
	waitFor("camera.start after the switch is on again", func() bool { return starts() == 2 })
	// The same reader read all along; nothing else opened the webcam.
	if err := reader.Wait(); err != nil {
		t.Fatalf("reading the webcam: %v", err)
	}
}

// webcamTestPhone starts a test phone with a camera and pairs a client with it.
func webcamTestPhone(ctx context.Context, t *testing.T) (*testphone.Phone, *client.Client) {
	t.Helper()
	frames := testphone.Video(t, 640, 360, 30, 2)
	lockDevice(t)
	phone := testphone.New(t)
	phone.Camera = &testphone.Camera{Width: 640, Height: 360, FPS: 30, Frames: frames}
	cl := &client.Client{Store: &store.Store{Dir: t.TempDir()}, Transport: client.TCP{Addr: phone.Addr()},
		HostName: "test-host", Version: "test"}
	hostKey, _ := cl.Store.HostKey()
	psk := make([]byte, 32)
	rand.Read(psk)
	phone.SetPending(psk, hostKey.Public)
	s, err := cl.Pair(ctx, psk)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	return phone, cl
}

type testLog struct{ t *testing.T }

func (l testLog) Write(p []byte) (int, error) {
	l.t.Log(string(bytes.TrimRight(p, "\n")))
	return len(p), nil
}

var _ io.Writer = testLog{}

// lockDevice serializes the tests that use the v4l2loopback device: go test
// runs packages in parallel, and two producers on one device disturb each
// other.
func lockDevice(t *testing.T) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(os.TempDir(), "phonekey-v4l2-test.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
}
