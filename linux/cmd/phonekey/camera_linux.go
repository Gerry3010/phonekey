//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Gerry3010/phonekey/linux/internal/camera"
	"github.com/Gerry3010/phonekey/linux/internal/client"
	"github.com/Gerry3010/phonekey/linux/internal/proto"
	"github.com/Gerry3010/phonekey/linux/internal/v4l2out"
)

// cameraRun makes the phone a webcam: a v4l2loopback device that shows a
// placeholder, and the phone's camera while an application reads it
// (docs/protocol.md §5 "camera", Host side).
func cameraRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("camera run", flag.ExitOnError)
	var cf connFlags
	cf.register(fs)
	device := fs.String("device", "/dev/video10", "v4l2loopback device")
	cam := fs.String("camera", "front", "front or back")
	quality := fs.String("quality", "720p", "720p or 1080p")
	fps := fs.Int("fps", 30, "frame rate, 15 to 30")
	fs.Parse(args)
	width, height, err := webcamSize(*quality)
	if err != nil {
		return err
	}
	if *cam != "front" && *cam != "back" {
		return fmt.Errorf("camera %q: use front or back", *cam)
	}
	if *fps < 15 || *fps > 30 {
		return fmt.Errorf("fps %d: use 15 to 30", *fps)
	}
	cl, err := cf.client()
	if err != nil {
		return err
	}
	logger := log.New(log.Writer(), "phonekey: ", log.LstdFlags)
	return runWebcam(ctx, webcamConfig{Client: cl, Device: *device, Camera: *cam, Quality: *quality,
		FPS: *fps, Width: width, Height: height}, logger)
}

type webcamConfig struct {
	Client         *client.Client
	Device         string
	Camera         string
	Quality        string
	FPS            int
	Width, Height  int
	ReconnectAfter time.Duration // first wait after losing the phone; default 1 s
}

// runWebcam keeps the webcam until ctx ends, across phone connections.
func runWebcam(ctx context.Context, cfg webcamConfig, logger *log.Logger) error {
	dev, err := v4l2out.Open(cfg.Device, cfg.Width, cfg.Height)
	if err != nil {
		return err
	}
	defer dev.Close()
	out := &pictureOut{dev: dev, placeholder: camera.Placeholder(cfg.Width, cfg.Height)}
	if err := out.showPlaceholder(); err != nil {
		return err
	}
	go out.idle(ctx)
	readers := watchReaders(ctx, dev.Usage())
	logger.Printf("webcam %s ready (%dx%d)", cfg.Device, cfg.Width, cfg.Height)

	backoff := cfg.ReconnectAfter
	if backoff == 0 {
		backoff = time.Second
	}
	first, lastErr := backoff, ""
	for ctx.Err() == nil {
		s, err := cfg.Client.Connect(ctx)
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
		backoff, lastErr = first, ""
		logger.Printf("connected to %s; the webcam streams while an application reads it", s.Phone.Name)
		err = serveWebcam(ctx, s.Mux(), cfg, out, readers, logger)
		logger.Printf("phone gone: %v", err)
	}
	return nil
}

// serveWebcam streams while applications read the webcam, for one session.
func serveWebcam(ctx context.Context, mux *client.Mux, cfg webcamConfig, out *pictureOut, readers *readerCount, logger *log.Logger) error {
	defer mux.Close()
	var live *liveStream
	// The phone refused or stopped on its own: no new start until the
	// readers have dropped to 0, so a refusal does not turn into a loop.
	held := false
	stop := func(tell bool) {
		if live != nil {
			live.close(tell)
			live = nil
		}
	}
	defer stop(false)
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		n := readers.current()
		switch {
		case n == 0:
			held = false
			if live != nil {
				logger.Printf("no application reads the webcam; stopping the stream")
				stop(true)
			}
		case live == nil && !held:
			var err error
			live, err = startLive(ctx, mux, cfg, out, logger)
			if err != nil {
				var re *proto.RemoteError
				if !errors.As(err, &re) {
					return err
				}
				logger.Printf("the phone does not stream: %v", err)
				held = true
			}
		}
		var events <-chan proto.Message
		var ended <-chan struct{}
		if live != nil {
			events, ended = live.stream.Events, live.ended
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-mux.Done():
			return mux.Err()
		case <-readers.changed:
		case msg := <-events:
			switch msg.Type {
			case "camera.changed":
				var c proto.CameraChanged
				json.Unmarshal(msg.JSON, &c)
				logger.Printf("the phone now sends %d fps", c.FPS)
			case "camera.stopped":
				var s proto.CameraStopped
				json.Unmarshal(msg.JSON, &s)
				logger.Printf("the phone stopped the webcam: %s", s.Reason)
				stop(false)
				held = true
			}
		case <-ended:
			logger.Printf("webcam stream ended: %v", live.err)
			stop(true)
			held = true
		case <-ping.C:
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, err := mux.Request(pctx, proto.Request{T: "ping"})
			cancel()
			if err != nil {
				return err
			}
		}
	}
}

// liveStream is one running camera stream: frames from the phone into the
// decoder, pictures from the decoder onto the webcam.
type liveStream struct {
	mux    *client.Mux
	stream *client.Stream
	dec    *camera.Decoder
	ended  chan struct{}
	once   sync.Once
	err    error
	wg     sync.WaitGroup
}

func startLive(ctx context.Context, mux *client.Mux, cfg webcamConfig, out *pictureOut, logger *log.Logger) (*liveStream, error) {
	msg, stream, err := mux.StartStream(ctx, func(id uint64) any {
		return proto.CameraStart{T: "camera.start", ID: id, Camera: cfg.Camera, Quality: cfg.Quality, FPS: cfg.FPS}
	})
	if err != nil {
		return nil, err
	}
	var started proto.CameraStarted
	json.Unmarshal(msg.JSON, &started)
	if started.Codec != "h264" {
		stream.Close()
		return nil, fmt.Errorf("the phone sends %q, not h264", started.Codec)
	}
	logger.Printf("streaming the %s camera: %dx%d at %d fps", started.Camera, started.Width, started.Height, started.FPS)
	dec, err := camera.NewDecoder(ctx, cfg.Width, cfg.Height)
	if err != nil {
		stream.Close()
		return nil, err
	}
	l := &liveStream{mux: mux, stream: stream, dec: dec, ended: make(chan struct{})}
	l.wg.Add(2)
	go func() { // phone → decoder
		defer l.wg.Done()
		key := false
		for {
			f, err := camera.ReadFrame(stream)
			if err != nil {
				l.finish(err)
				return
			}
			if !key && !f.Keyframe {
				continue // the first frame is a keyframe; this only skips after a loss
			}
			key = true
			if err := dec.Write(f.Data); err != nil {
				l.finish(err)
				return
			}
		}
	}()
	go func() { // decoder → webcam
		defer l.wg.Done()
		pic := make([]byte, camera.PictureSize(cfg.Width, cfg.Height))
		for {
			if err := dec.ReadPicture(pic); err != nil {
				l.finish(err)
				return
			}
			if err := out.live(pic); err != nil {
				l.finish(err)
				return
			}
		}
	}()
	return l, nil
}

func (l *liveStream) finish(err error) {
	l.once.Do(func() {
		l.err = err
		close(l.ended)
	})
}

// close ends the stream; tell sends camera.stop first.
func (l *liveStream) close(tell bool) {
	if tell {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		l.mux.Call(ctx, func(id uint64) any {
			return proto.CameraControl{T: "camera.stop", ID: id, Stream: l.stream.ID}
		})
		cancel()
	}
	l.finish(errors.New("stopped"))
	l.stream.Close()
	l.dec.Close()
	l.wg.Wait()
}

// pictureOut writes live pictures to the webcam and the placeholder while
// none come.
type pictureOut struct {
	dev         *v4l2out.Device
	placeholder []byte
	mu          sync.Mutex
	lastLive    time.Time
}

func (o *pictureOut) live(pic []byte) error {
	o.mu.Lock()
	o.lastLive = time.Now()
	o.mu.Unlock()
	return o.dev.Write(pic)
}

func (o *pictureOut) showPlaceholder() error { return o.dev.Write(o.placeholder) }

// idle shows the placeholder at 5 fps once no live picture came for 0.5 s.
func (o *pictureOut) idle(ctx context.Context) {
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		o.mu.Lock()
		stale := time.Since(o.lastLive) > 500*time.Millisecond
		o.mu.Unlock()
		if stale {
			o.showPlaceholder()
		}
	}
}

// readerCount keeps the latest number of applications reading the webcam,
// also while no phone is connected.
type readerCount struct {
	mu      sync.Mutex
	n       int
	changed chan struct{}
}

func watchReaders(ctx context.Context, usage <-chan int) *readerCount {
	r := &readerCount{changed: make(chan struct{}, 1)}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case n := <-usage:
				r.mu.Lock()
				r.n = n
				r.mu.Unlock()
				select {
				case r.changed <- struct{}{}:
				default:
				}
			}
		}
	}()
	return r
}

func (r *readerCount) current() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}
