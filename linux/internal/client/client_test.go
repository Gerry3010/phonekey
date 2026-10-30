package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Gerry3010/phonekey/linux/internal/proto"
	"github.com/Gerry3010/phonekey/linux/internal/store"
)

// fakePhone is a minimal responder that follows docs/protocol.md.
type fakePhone struct {
	static     proto.Keypair
	ln         net.Listener
	mu         sync.Mutex
	paired     map[string]bool
	pendingPSK []byte
	pendingKey []byte
	photo      []byte
	badSHA     bool
}

func newFakePhone(t *testing.T) *fakePhone {
	t.Helper()
	kp, _ := proto.GenerateKeypair()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePhone{static: kp, ln: ln, paired: map[string]bool{}}
	f.photo = make([]byte, 150_000)
	rand.Read(f.photo)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakePhone) setPending(psk, hostKey []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pendingPSK, f.pendingKey = psk, hostKey
}

func (f *fakePhone) serve(c net.Conn) {
	defer c.Close()
	pre := make([]byte, proto.PreambleSize)
	if _, err := io.ReadFull(c, pre); err != nil {
		return
	}
	_, mode, err := proto.ParsePreamble(pre)
	if err != nil {
		return
	}
	f.mu.Lock()
	psk, wantKey := f.pendingPSK, f.pendingKey
	f.mu.Unlock()
	status := proto.StatusOK
	if mode == proto.ModePairing && psk == nil {
		status = proto.StatusNoPairingPending
	}
	resp := proto.PhonePreamble(status)
	c.Write(resp)
	if status != proto.StatusOK {
		return
	}
	cfg := proto.HandshakeConfig{Static: f.static, Prologue: append(pre, resp...)}
	if mode == proto.ModePairing {
		cfg.PSK = psk
	}
	ciphers, err := proto.Handshake(c, cfg)
	if err != nil {
		return
	}
	conn := proto.NewConn(c, ciphers)
	host := store.EncodeKey(ciphers.PeerStatic)
	f.mu.Lock()
	if mode == proto.ModePairing {
		if !bytes.Equal(wantKey, ciphers.PeerStatic) {
			f.mu.Unlock()
			return
		}
		f.paired[host] = true
		f.pendingPSK, f.pendingKey = nil, nil
	}
	ok := f.paired[host]
	f.mu.Unlock()
	if !ok {
		conn.WriteJSON(proto.RemoteError{T: "error", Code: "not_paired"})
		return
	}
	conn.WriteJSON(proto.Hello{T: "hello", Role: "phone", Protocol: 1, AppVersion: "test",
		Device: &proto.Device{Model: "iPhone9,3", System: "iOS 15.8", Name: "Test iPhone"}})
	for {
		m, err := conn.Read()
		if err != nil {
			return
		}
		switch m.Type {
		case "hello":
		case "ping":
			conn.WriteJSON(map[string]any{"t": "pong", "id": *m.ID})
		case "status.get":
			lvl := 0.5
			conn.WriteJSON(proto.StatusReport{T: "status", ID: *m.ID, Thermal: "nominal",
				Battery: proto.Battery{Level: &lvl, State: "charging"}})
		case "photo.capture":
			conn.WriteJSON(proto.PhotoBegin{T: "photo.begin", ID: *m.ID, Stream: 1, Size: len(f.photo), MIME: "image/jpeg"})
			for off := 0; off < len(f.photo); off += proto.MaxChunkData {
				conn.WriteChunk(1, f.photo[off:min(off+proto.MaxChunkData, len(f.photo))])
			}
			sum := sha256.Sum256(f.photo)
			if f.badSHA {
				sum[0] ^= 1
			}
			conn.WriteJSON(proto.PhotoEnd{T: "photo.end", ID: *m.ID, Stream: 1, SHA256: hex.EncodeToString(sum[:])})
		default:
			conn.WriteJSON(proto.RemoteError{T: "error", ID: m.ID, Code: "unknown_type"})
		}
	}
}

func newClient(t *testing.T, f *fakePhone) *Client {
	t.Helper()
	return &Client{Store: &store.Store{Dir: t.TempDir()}, Transport: TCP{Addr: f.ln.Addr().String()},
		HostName: "test-host", Version: "test"}
}

func TestPairThenSession(t *testing.T) {
	f := newFakePhone(t)
	c := newClient(t, f)
	hostKey, err := c.Store.HostKey()
	if err != nil {
		t.Fatal(err)
	}
	psk := make([]byte, 32)
	rand.Read(psk)
	// The user scans the code a moment later; Pair must retry until then.
	time.AfterFunc(1500*time.Millisecond, func() { f.setPending(psk, hostKey.Public) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := c.Pair(ctx, psk)
	if err != nil {
		t.Fatal(err)
	}
	if s.Phone.Name != "Test iPhone" || s.Phone.Model != "iPhone9,3" {
		t.Fatalf("stored phone %+v", s.Phone)
	}
	s.Close()

	s, err = c.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := s.Status(ctx)
	if err != nil || st.Battery.State != "charging" || *st.Battery.Level != 0.5 {
		t.Fatalf("status %+v %v", st, err)
	}
	p, err := s.Photo(ctx, PhotoOptions{MaxDimension: 1568})
	if err != nil || !bytes.Equal(p.Data, f.photo) {
		t.Fatalf("photo: %v", err)
	}
	var re *proto.RemoteError
	if _, err := s.send(ctx, proto.Request{T: "nope"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.await(s.nextID); !errors.As(err, &re) || re.Code != "unknown_type" {
		t.Fatalf("unknown type: %v", err)
	}
}

func TestPhoneDoesNotKnowHost(t *testing.T) {
	f := newFakePhone(t)
	c := newClient(t, f)
	c.Store.SavePhone(store.Phone{Name: "x", Key: store.EncodeKey(f.static.Public)})
	_, err := c.Connect(context.Background())
	var re *proto.RemoteError
	if !errors.As(err, &re) || re.Code != "not_paired" {
		t.Fatalf("got %v", err)
	}
}

func TestHostDoesNotKnowPhone(t *testing.T) {
	f := newFakePhone(t)
	c := newClient(t, f)
	if _, err := c.Connect(context.Background()); !errors.Is(err, ErrUnknownPhone) {
		t.Fatalf("got %v", err)
	}
}

func TestPairingWithWrongSecretFails(t *testing.T) {
	f := newFakePhone(t)
	c := newClient(t, f)
	hostKey, _ := c.Store.HostKey()
	right, wrong := make([]byte, 32), make([]byte, 32)
	rand.Read(right)
	rand.Read(wrong)
	f.setPending(right, hostKey.Public)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.Pair(ctx, wrong); err == nil {
		t.Fatal("pairing with the wrong secret succeeded")
	}
	if phones, _ := c.Store.Phones(); len(phones) != 0 {
		t.Fatal("phone stored after failed pairing")
	}
}

func TestCorruptPhotoIsRejected(t *testing.T) {
	f := newFakePhone(t)
	f.badSHA = true
	c := newClient(t, f)
	hostKey, _ := c.Store.HostKey()
	psk := make([]byte, 32)
	rand.Read(psk)
	f.setPending(psk, hostKey.Public)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := c.Pair(ctx, psk)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Photo(ctx, PhotoOptions{}); err == nil {
		t.Fatal("corrupt photo accepted")
	}
}
