//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"time"

	"github.com/Gerry3010/phonekey/linux/internal/client"
	"github.com/Gerry3010/phonekey/linux/internal/ctaphid"
	"github.com/Gerry3010/phonekey/linux/internal/proto"
	"github.com/Gerry3010/phonekey/linux/internal/uhid"
)

// fidoRun keeps a session with the phone and, while it is up, exposes a
// virtual USB security key. When the phone goes away (app in the background,
// cable out) the key disappears, like pulling a real one.
func fidoRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("fido run", flag.ExitOnError)
	var cf connFlags
	cf.register(fs)
	trace := fs.Bool("trace", false, "log each CTAP request and its status (no keys, challenges or IDs)")
	fs.Parse(args)
	cl, err := cf.client()
	if err != nil {
		return err
	}
	logger := log.New(log.Writer(), "phonekey: ", log.LstdFlags)
	backoff, lastErr := time.Second, ""
	for ctx.Err() == nil {
		s, err := cl.Connect(ctx)
		if err != nil {
			if errors.Is(err, client.ErrUnknownPhone) {
				return err
			}
			if msg := err.Error(); msg != lastErr {
				logger.Printf("waiting for the phone: %v", err)
				lastErr = msg
			}
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 10*time.Second)
			continue
		}
		backoff, lastErr = time.Second, ""
		logger.Printf("connected to %s; security key available", s.Phone.Name)
		var tracer *log.Logger
		if *trace {
			tracer = logger
		}
		err = serveKey(ctx, s, tracer)
		logger.Printf("security key removed: %v", err)
	}
	return nil
}

type phoneBackend struct {
	mux   *client.Mux
	trace *log.Logger // nil unless `fido run -trace`
}

func (b phoneBackend) CBOR(ctx context.Context, req []byte) ([]byte, error) {
	if b.trace == nil {
		return b.mux.CTAP(ctx, req)
	}
	b.trace.Printf("-> %s", traceRequest(req))
	start := time.Now()
	resp, err := b.mux.CTAP(ctx, req)
	took := time.Since(start).Round(time.Millisecond)
	if err != nil {
		b.trace.Printf("<- error after %v: %v", took, err)
	} else {
		b.trace.Printf("<- %s after %v", traceResponse(resp), took)
	}
	return resp, err
}

func (b phoneBackend) Wink(ctx context.Context) error {
	cmd := 0x08
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := b.mux.Request(ctx, proto.Request{T: "ctap.request", Cmd: &cmd, Data: []byte{}})
	return err
}

func serveKey(ctx context.Context, s *client.Session, trace *log.Logger) error {
	mux := s.Mux()
	defer mux.Close()
	dev, err := uhid.Create(uhid.Config{
		Name:             "PhoneKey",
		ReportDescriptor: ctaphid.ReportDescriptor,
		// pid.codes test ID; Linux and browsers find FIDO keys by usage page.
		Vendor:  0x1209,
		Product: 0x0001,
	})
	if err != nil {
		return err
	}
	defer dev.Close()
	hid := ctaphid.New(dev.Input, phoneBackend{mux: mux, trace: trace})
	defer hid.Close()

	go func() {
		for {
			r, err := dev.ReadOutput()
			if err != nil {
				return
			}
			hid.HandleReport(r)
		}
	}()

	// A ping now and then notices a half-open connection.
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-mux.Done():
			return mux.Err()
		case <-ticker.C:
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, err := mux.Request(pctx, proto.Request{T: "ping"})
			cancel()
			if err != nil {
				return err
			}
		}
	}
}
