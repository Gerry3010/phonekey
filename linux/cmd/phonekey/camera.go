package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/Gerry3010/phonekey/linux/internal/proto"
)

func cameraCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: phonekey camera run [-device /dev/video10] [-camera front|back] [-quality 720p|1080p] [-fps 15-30]")
	}
	switch args[0] {
	case "run":
		return cameraRun(ctx, args[1:])
	default:
		return fmt.Errorf("unknown camera command %q", args[0])
	}
}

// webcamSize is the webcam's picture size for a quality of camera.start
// (docs/protocol.md §5 "camera"). A smaller stream is scaled up to it.
func webcamSize(quality string) (width, height int, err error) {
	switch quality {
	case "720p":
		return 1280, 720, nil
	case "1080p":
		return 1920, 1080, nil
	}
	return 0, 0, fmt.Errorf("quality %q: use 720p or 1080p", quality)
}

// cameraChange describes a camera.changed for the log. It carries only what
// changed: the frame rate, the camera (switched on the phone) or both
// (docs/protocol.md §5 "camera"). Empty when it names nothing known.
func cameraChange(c proto.CameraChanged) string {
	switch {
	case c.Camera != "" && c.FPS != 0:
		return fmt.Sprintf("the phone switched to the %s camera and now sends %d fps", c.Camera, c.FPS)
	case c.Camera != "":
		return fmt.Sprintf("the phone switched to the %s camera", c.Camera)
	case c.FPS != 0:
		return fmt.Sprintf("the phone now sends %d fps", c.FPS)
	}
	return ""
}
