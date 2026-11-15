package camera

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Decoder turns the H.264 frames of a stream into raw I420 pictures of a fixed
// size, with ffmpeg in a child process. The size is the webcam's, so a
// smaller stream (the phone may step down) is scaled to it.
type Decoder struct {
	Width, Height int
	cmd           *exec.Cmd
	in            io.WriteCloser
	out           io.ReadCloser
	stderr        *tailBuffer
	waitOnce      sync.Once
	waitErr       error
}

// PictureSize is the size of one I420 picture.
func PictureSize(width, height int) int { return width * height * 3 / 2 }

// NewDecoder starts ffmpeg. It needs the ffmpeg binary on PATH.
func NewDecoder(ctx context.Context, width, height int) (*Decoder, error) {
	// -threads 1: frame threading holds back as many pictures as there are
	// threads before the first one comes out; a webcam wants each at once.
	// -fps_mode passthrough: one picture per frame, never duplicated.
	cmd := exec.CommandContext(ctx, "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
		"-flags", "low_delay", "-probesize", "32", "-analyzeduration", "0",
		"-threads", "1", "-f", "h264", "-i", "pipe:0",
		"-vf", fmt.Sprintf("scale=%d:%d:flags=fast_bilinear", width, height),
		"-fps_mode", "passthrough", "-pix_fmt", "yuv420p", "-f", "rawvideo", "pipe:1")
	d := &Decoder{Width: width, Height: height, cmd: cmd, stderr: &tailBuffer{max: 2048}}
	var err error
	if d.in, err = cmd.StdinPipe(); err != nil {
		return nil, err
	}
	if d.out, err = cmd.StdoutPipe(); err != nil {
		return nil, err
	}
	cmd.Stderr = d.stderr
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting ffmpeg: %w", err)
	}
	return d, nil
}

// Write feeds one access unit (Annex B).
func (d *Decoder) Write(au []byte) error {
	if _, err := d.in.Write(au); err != nil {
		return d.failure(err)
	}
	return nil
}

// ReadPicture reads the next decoded picture into pic, which must hold
// PictureSize(Width, Height) bytes.
func (d *Decoder) ReadPicture(pic []byte) error {
	if len(pic) != PictureSize(d.Width, d.Height) {
		return errors.New("picture buffer of the wrong size")
	}
	if _, err := io.ReadFull(d.out, pic); err != nil {
		return d.failure(err)
	}
	return nil
}

// Close stops ffmpeg; pictures still in it are discarded.
func (d *Decoder) Close() error {
	d.in.Close()
	if d.cmd.Process != nil {
		d.cmd.Process.Kill()
	}
	d.wait()
	return nil
}

func (d *Decoder) wait() error {
	d.waitOnce.Do(func() { d.waitErr = d.cmd.Wait() })
	return d.waitErr
}

// failure adds what ffmpeg said to an I/O error with it.
func (d *Decoder) failure(err error) error {
	if msg := strings.TrimSpace(d.stderr.String()); msg != "" {
		return fmt.Errorf("ffmpeg: %s (%w)", msg, err)
	}
	return fmt.Errorf("ffmpeg: %w", err)
}

// tailBuffer keeps the last bytes written to it (ffmpeg's error output).
type tailBuffer struct {
	mu  sync.Mutex
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.b)
}
