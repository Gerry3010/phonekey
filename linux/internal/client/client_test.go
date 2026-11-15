package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/Gerry3010/phonekey/linux/internal/proto"
	"github.com/Gerry3010/phonekey/linux/internal/store"
	"github.com/Gerry3010/phonekey/linux/internal/testphone"
)

func newClient(t *testing.T, f *testphone.Phone) *Client {
	t.Helper()
	return &Client{Store: &store.Store{Dir: t.TempDir()}, Transport: TCP{Addr: f.Addr()},
		HostName: "test-host", Version: "test"}
}

func TestPairThenSession(t *testing.T) {
	f := testphone.New(t)
	c := newClient(t, f)
	hostKey, err := c.Store.HostKey()
	if err != nil {
		t.Fatal(err)
	}
	psk := make([]byte, 32)
	rand.Read(psk)
	// The user scans the code a moment later; Pair must retry until then.
	time.AfterFunc(1500*time.Millisecond, func() { f.SetPending(psk, hostKey.Public) })

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
	if err != nil || !bytes.Equal(p.Data, f.Photo) {
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
	f := testphone.New(t)
	c := newClient(t, f)
	c.Store.SavePhone(store.Phone{Name: "x", Key: store.EncodeKey(f.Static.Public)})
	_, err := c.Connect(context.Background())
	var re *proto.RemoteError
	if !errors.As(err, &re) || re.Code != "not_paired" {
		t.Fatalf("got %v", err)
	}
}

func TestHostDoesNotKnowPhone(t *testing.T) {
	f := testphone.New(t)
	c := newClient(t, f)
	if _, err := c.Connect(context.Background()); !errors.Is(err, ErrUnknownPhone) {
		t.Fatalf("got %v", err)
	}
}

func TestPairingWithWrongSecretFails(t *testing.T) {
	f := testphone.New(t)
	c := newClient(t, f)
	hostKey, _ := c.Store.HostKey()
	right, wrong := make([]byte, 32), make([]byte, 32)
	rand.Read(right)
	rand.Read(wrong)
	f.SetPending(right, hostKey.Public)
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
	f := testphone.New(t)
	f.BadSHA = true
	c := newClient(t, f)
	hostKey, _ := c.Store.HostKey()
	psk := make([]byte, 32)
	rand.Read(psk)
	f.SetPending(psk, hostKey.Public)
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

func TestMuxCTAPAndCancel(t *testing.T) {
	f := testphone.New(t)
	c := newClient(t, f)
	hostKey, _ := c.Store.HostKey()
	psk := make([]byte, 32)
	rand.Read(psk)
	f.SetPending(psk, hostKey.Public)
	s, err := c.Pair(context.Background(), psk)
	if err != nil {
		t.Fatal(err)
	}
	mux := s.Mux()
	defer mux.Close()

	resp, err := mux.CTAP(context.Background(), []byte{0x04})
	if err != nil || !bytes.Equal(resp, []byte{0x00, 0xA0}) {
		t.Fatalf("getInfo: %x %v", resp, err)
	}

	// The browser cancels while the phone waits for the user.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	resp, err = mux.CTAP(ctx, []byte{0x02, 0xA0})
	if err != nil || !bytes.Equal(resp, []byte{0x2D}) {
		t.Fatalf("after cancel: %x %v", resp, err)
	}

	// Ping still works on the same mux afterwards.
	if _, err := mux.Request(context.Background(), proto.Request{T: "ping"}); err != nil {
		t.Fatal(err)
	}
}
