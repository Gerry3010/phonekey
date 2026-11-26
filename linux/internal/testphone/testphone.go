// Package testphone is a minimal phone that follows docs/protocol.md, for
// tests on the host side: handshake and pairing, status, photos, CTAP that
// waits for ctap.cancel, and a webcam stream that loops given frames.
package testphone

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Gerry3010/phonekey/linux/internal/camera"
	"github.com/Gerry3010/phonekey/linux/internal/proto"
	"github.com/Gerry3010/phonekey/linux/internal/store"
)

// Phone listens on a local TCP port until the test ends.
type Phone struct {
	Static proto.Keypair
	// Photo is what photo.capture returns; BadSHA corrupts its checksum.
	Photo  []byte
	BadSHA bool
	// Camera, if set, answers camera.start; nil answers camera_unavailable.
	Camera *Camera

	ln         net.Listener
	mu         sync.Mutex
	paired     map[string]bool
	pendingPSK []byte
	pendingKey []byte
	requests   []string
	starts     []proto.CameraStart
	// switchedOff has one channel per session; SetStreamEnabled(false)
	// signals each so that a running stream stops.
	switchedOff []chan struct{}
}

// Camera is the webcam of the test phone: it loops Frames at FPS.
type Camera struct {
	Width, Height, FPS int
	// Frames start with a keyframe; camera.keyframe restarts from the first.
	Frames []camera.Frame
	// Disabled answers camera.start with camera_stream_disabled; status
	// reports it as camera.stream_enabled. Change it with SetStreamEnabled
	// while the phone runs.
	Disabled bool
}

// New starts a test phone.
func New(t testing.TB) *Phone {
	t.Helper()
	kp, err := proto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &Phone{Static: kp, ln: ln, paired: map[string]bool{}, Photo: make([]byte, 150_000)}
	rand.Read(p.Photo)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

// Addr is the address to dial (client.TCP).
func (p *Phone) Addr() string { return p.ln.Addr().String() }

// SetPending arms a pairing with psk for hostKey, as the QR code would.
func (p *Phone) SetPending(psk, hostKey []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pendingPSK, p.pendingKey = psk, hostKey
}

// Pair marks hostKey as paired without a pairing run.
func (p *Phone) Pair(hostKey []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paired[store.EncodeKey(hostKey)] = true
}

// SetStreamEnabled flips the webcam switch. Turning it off stops a running
// stream with camera.stopped "switched_off", as the app does.
func (p *Phone) SetStreamEnabled(on bool) {
	p.mu.Lock()
	p.Camera.Disabled = !on
	conns := append([]chan struct{}(nil), p.switchedOff...)
	p.mu.Unlock()
	if !on {
		for _, c := range conns {
			select {
			case c <- struct{}{}:
			default:
			}
		}
	}
}

func (p *Phone) streamEnabled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Camera != nil && !p.Camera.Disabled
}

// Requests lists the camera requests received so far ("camera.start", …).
func (p *Phone) Requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.requests...)
}

// Starts lists the camera.start requests received so far, as sent.
func (p *Phone) Starts() []proto.CameraStart {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]proto.CameraStart(nil), p.starts...)
}

func (p *Phone) note(t string) {
	p.mu.Lock()
	p.requests = append(p.requests, t)
	p.mu.Unlock()
}

func (p *Phone) serve(c net.Conn) {
	defer c.Close()
	pre := make([]byte, proto.PreambleSize)
	if _, err := io.ReadFull(c, pre); err != nil {
		return
	}
	_, mode, err := proto.ParsePreamble(pre)
	if err != nil {
		return
	}
	p.mu.Lock()
	psk, wantKey := p.pendingPSK, p.pendingKey
	p.mu.Unlock()
	status := proto.StatusOK
	if mode == proto.ModePairing && psk == nil {
		status = proto.StatusNoPairingPending
	}
	resp := proto.PhonePreamble(status)
	c.Write(resp)
	if status != proto.StatusOK {
		return
	}
	cfg := proto.HandshakeConfig{Static: p.Static, Prologue: append(pre, resp...)}
	if mode == proto.ModePairing {
		cfg.PSK = psk
	}
	ciphers, err := proto.Handshake(c, cfg)
	if err != nil {
		return
	}
	conn := proto.NewConn(c, ciphers)
	host := store.EncodeKey(ciphers.PeerStatic)
	p.mu.Lock()
	if mode == proto.ModePairing {
		if !bytes.Equal(wantKey, ciphers.PeerStatic) {
			p.mu.Unlock()
			return
		}
		p.paired[host] = true
		p.pendingPSK, p.pendingKey = nil, nil
	}
	ok := p.paired[host]
	p.mu.Unlock()
	if !ok {
		conn.WriteJSON(proto.RemoteError{T: "error", Code: "not_paired"})
		return
	}
	conn.WriteJSON(proto.Hello{T: "hello", Role: "phone", Protocol: 1, AppVersion: "test",
		Device: &proto.Device{Model: "iPhone9,3", System: "iOS 15.8", Name: "Test iPhone"}})

	var stream *videoStream
	defer func() {
		if stream != nil {
			stream.stop()
		}
	}()
	// ctap.request waits for the "user" until ctap.cancel arrives, unless it
	// is a getInfo (0x04), which answers at once.
	pending := map[uint64]bool{}
	off := make(chan struct{}, 1)
	p.mu.Lock()
	p.switchedOff = append(p.switchedOff, off)
	p.mu.Unlock()
	done := make(chan struct{})
	defer close(done)
	msgs := make(chan proto.Message)
	go func() {
		defer close(msgs)
		for {
			m, err := conn.Read()
			if err != nil {
				return
			}
			select {
			case msgs <- m:
			case <-done:
				return
			}
		}
	}()
	for {
		var m proto.Message
		select {
		case <-off:
			if stream != nil {
				stream.stop()
				stream = nil
				conn.WriteJSON(proto.CameraStopped{T: "camera.stopped", Stream: videoStreamID, Reason: "switched_off"})
			}
			continue
		case msg, ok := <-msgs:
			if !ok {
				return
			}
			m = msg
		}
		switch m.Type {
		case "hello":
		case "ping":
			conn.WriteJSON(map[string]any{"t": "pong", "id": *m.ID})
		case "status.get":
			lvl := 0.5
			st := proto.StatusReport{T: "status", ID: *m.ID, Thermal: "nominal",
				Battery: proto.Battery{Level: &lvl, State: "charging"}}
			st.Camera.Enabled, st.Camera.Available = true, true
			st.Camera.StreamEnabled, st.Camera.Streaming = p.streamEnabled(), stream != nil
			conn.WriteJSON(st)
		case "ctap.request":
			var req proto.Request
			json.Unmarshal(m.JSON, &req)
			if len(req.Data) > 0 && req.Data[0] == 0x04 {
				conn.WriteJSON(proto.CTAPResponse{T: "ctap.response", ID: req.ID, Data: []byte{0x00, 0xA0}})
			} else {
				pending[req.ID] = true
			}
		case "ctap.cancel":
			if pending[*m.ID] {
				delete(pending, *m.ID)
				conn.WriteJSON(proto.CTAPResponse{T: "ctap.response", ID: *m.ID, Data: []byte{0x2D}})
			}
		case "photo.capture":
			if stream != nil {
				conn.WriteJSON(proto.RemoteError{T: "error", ID: m.ID, Code: "busy"})
				continue
			}
			conn.WriteJSON(proto.PhotoBegin{T: "photo.begin", ID: *m.ID, Stream: 1, Size: len(p.Photo), MIME: "image/jpeg"})
			for off := 0; off < len(p.Photo); off += proto.MaxChunkData {
				conn.WriteChunk(1, p.Photo[off:min(off+proto.MaxChunkData, len(p.Photo))])
			}
			sum := sha256.Sum256(p.Photo)
			if p.BadSHA {
				sum[0] ^= 1
			}
			conn.WriteJSON(proto.PhotoEnd{T: "photo.end", ID: *m.ID, Stream: 1, SHA256: hex.EncodeToString(sum[:])})
		case "camera.start":
			p.note(m.Type)
			switch {
			case p.Camera == nil:
				conn.WriteJSON(proto.RemoteError{T: "error", ID: m.ID, Code: "camera_unavailable"})
			case !p.streamEnabled():
				conn.WriteJSON(proto.RemoteError{T: "error", ID: m.ID, Code: "camera_stream_disabled"})
			case stream != nil:
				conn.WriteJSON(proto.RemoteError{T: "error", ID: m.ID, Code: "busy"})
			default:
				var req proto.CameraStart
				json.Unmarshal(m.JSON, &req)
				p.mu.Lock()
				p.starts = append(p.starts, req)
				p.mu.Unlock()
				if req.Camera == "" {
					req.Camera = "front"
				}
				conn.WriteJSON(proto.CameraStarted{T: "camera.started", ID: *m.ID, Stream: videoStreamID, Codec: "h264",
					Width: p.Camera.Width, Height: p.Camera.Height, FPS: p.Camera.FPS, Camera: req.Camera})
				stream = startVideo(conn, videoStreamID, p.Camera)
			}
		case "camera.keyframe":
			p.note(m.Type)
			if stream != nil {
				stream.keyframe()
			}
			conn.WriteJSON(map[string]any{"t": "camera.keyframe", "id": *m.ID})
		case "camera.stop":
			p.note(m.Type)
			var req proto.CameraControl
			json.Unmarshal(m.JSON, &req)
			if stream != nil {
				stream.stop()
				stream = nil
			}
			id := *m.ID
			conn.WriteJSON(proto.CameraStopped{T: "camera.stopped", ID: &id, Stream: req.Stream, Reason: "requested"})
		default:
			conn.WriteJSON(proto.RemoteError{T: "error", ID: m.ID, Code: "unknown_type"})
		}
	}
}

// videoStreamID is the chunk stream the test phone sends video on.
const videoStreamID = 2

// videoStream loops the camera's frames on a chunk stream.
type videoStream struct {
	done  chan struct{}
	wg    sync.WaitGroup
	reset chan struct{}
}

func startVideo(conn *proto.Conn, id uint32, cam *Camera) *videoStream {
	v := &videoStream{done: make(chan struct{}), reset: make(chan struct{}, 1)}
	v.wg.Add(1)
	go func() {
		defer v.wg.Done()
		tick := time.NewTicker(time.Second / time.Duration(max(cam.FPS, 1)))
		defer tick.Stop()
		start := time.Now()
		for i := 0; ; i++ {
			select {
			case <-v.done:
				return
			case <-v.reset:
				i = 0
			case <-tick.C:
			}
			f := cam.Frames[i%len(cam.Frames)]
			f.Time = uint64(time.Since(start).Microseconds())
			b := camera.AppendFrame(nil, f)
			for off := 0; off < len(b); off += proto.MaxChunkData {
				if conn.WriteChunk(id, b[off:min(off+proto.MaxChunkData, len(b))]) != nil {
					return
				}
			}
		}
	}()
	return v
}

func (v *videoStream) keyframe() {
	select {
	case v.reset <- struct{}{}:
	default:
	}
}

func (v *videoStream) stop() {
	close(v.done)
	v.wg.Wait()
}
