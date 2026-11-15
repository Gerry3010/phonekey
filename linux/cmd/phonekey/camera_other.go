//go:build !linux

package main

import (
	"context"
	"errors"
)

func cameraRun(ctx context.Context, args []string) error {
	return errors.New("camera run needs Linux (v4l2loopback)")
}
