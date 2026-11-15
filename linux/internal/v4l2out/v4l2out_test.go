//go:build linux

package v4l2out

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Needs a v4l2loopback device (PHONEKEY_TEST_V4L2, e.g. /dev/video10) and
// v4l2-ctl as a reader; skipped otherwise.
func TestUsageFollowsReaders(t *testing.T) {
	path := os.Getenv("PHONEKEY_TEST_V4L2")
	if path == "" {
		t.Skip("set PHONEKEY_TEST_V4L2 to a v4l2loopback device")
	}
	if _, err := exec.LookPath("v4l2-ctl"); err != nil {
		t.Skip("v4l2-ctl not installed")
	}
	lockDevice(t)
	d, err := Open(path, 320, 180)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	pic := make([]byte, 320*180*3/2)
	// With exclusive_caps=1 the webcam exists for readers only after the
	// first picture.
	if err := d.Write(pic); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go func() {
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				d.Write(pic)
			}
		}
	}()

	next := func() int {
		select {
		case n := <-d.Usage():
			return n
		case <-ctx.Done():
			t.Fatal("no usage event")
			return -1
		}
	}
	if n := next(); n != 0 {
		t.Fatalf("initial usage %d, want 0", n)
	}
	reader := exec.CommandContext(ctx, "v4l2-ctl", "-d", path, "--stream-mmap", "--stream-count=10", "--stream-to=/dev/null")
	if err := reader.Start(); err != nil {
		t.Fatal(err)
	}
	if n := next(); n != 1 {
		t.Fatalf("usage %d while reading, want 1", n)
	}
	if err := reader.Wait(); err != nil {
		t.Fatalf("reader: %v", err)
	}
	if n := next(); n != 0 {
		t.Fatalf("usage %d after reading, want 0", n)
	}
}

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
