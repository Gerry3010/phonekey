//go:build !linux

package main

import (
	"context"
	"errors"
)

func fidoRun(ctx context.Context, args []string) error {
	return errors.New("fido run needs Linux (/dev/uhid); on this system use fido info or fido selftest")
}
