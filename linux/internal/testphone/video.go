package testphone

import (
	"bytes"
	"fmt"
	"os/exec"
	"testing"

	"github.com/Gerry3010/phonekey/linux/internal/camera"
)

// Video encodes ffmpeg's moving test picture as H.264 the way the phone sends
// it (Annex B, no B-frames, SPS and PPS before every keyframe) and splits it
// into frames. The test is skipped without ffmpeg and libx264.
func Video(t testing.TB, width, height, fps int, seconds float64) []camera.Frame {
	t.Helper()
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not installed")
	}
	out, err := exec.Command("ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
		"-f", "lavfi", "-i", fmt.Sprintf("testsrc2=size=%dx%d:rate=%d", width, height, fps),
		"-t", fmt.Sprint(seconds), "-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency",
		"-profile:v", "main", "-bf", "0", "-g", fmt.Sprint(2*fps), "-pix_fmt", "yuv420p",
		"-x264-params", "aud=1:repeat-headers=1", "-f", "h264", "pipe:1").Output()
	if err != nil {
		t.Skipf("ffmpeg with libx264: %v", err)
	}
	frames := SplitAccessUnits(out)
	if len(frames) == 0 || !frames[0].Keyframe {
		t.Fatalf("test video: %d frames, first a keyframe: %v", len(frames), len(frames) > 0 && frames[0].Keyframe)
	}
	return frames
}

// SplitAccessUnits splits an Annex B stream at its access unit delimiters
// (NAL type 9). A frame is a keyframe when it holds an IDR slice (type 5).
func SplitAccessUnits(b []byte) []camera.Frame {
	type nal struct{ start, typ int }
	var nals []nal
	for i := 0; i+3 < len(b); i++ {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 1 {
			start := i
			if i > 0 && b[i-1] == 0 {
				start = i - 1
			}
			nals = append(nals, nal{start, int(b[i+3] & 0x1F)})
			i += 2
		}
	}
	var frames []camera.Frame
	for k := 0; k < len(nals); k++ {
		if nals[k].typ != 9 {
			continue
		}
		end := len(b)
		key := false
		for j := k + 1; j < len(nals); j++ {
			if nals[j].typ == 9 {
				end = nals[j].start
				break
			}
			key = key || nals[j].typ == 5
		}
		frames = append(frames, camera.Frame{Keyframe: key, Data: bytes.Clone(b[nals[k].start:end])})
	}
	return frames
}
