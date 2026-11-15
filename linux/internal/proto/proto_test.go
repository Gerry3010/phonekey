package proto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	for _, n := range []int{1, 300, MaxFrame} {
		msg := bytes.Repeat([]byte{0xab}, n)
		if err := WriteFrame(&buf, msg); err != nil {
			t.Fatal(err)
		}
		got, err := ReadFrame(&buf)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("size %d: got %d bytes, err %v", n, len(got), err)
		}
	}
	if err := WriteFrame(&buf, make([]byte, MaxFrame+1)); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestPreamble(t *testing.T) {
	v, mode, err := ParsePreamble(HostPreamble(ModePairing))
	if err != nil || v != Version || mode != ModePairing {
		t.Fatalf("got %d %d %v", v, mode, err)
	}
	if _, _, err := ParsePreamble([]byte("GET / HT")); err == nil {
		t.Fatal("wrong magic accepted")
	}
}

func handshakePair(t *testing.T, hostPSK, phonePSK []byte) (*Ciphers, *Ciphers, error, error) {
	t.Helper()
	host, _ := GenerateKeypair()
	phone, _ := GenerateKeypair()
	prologue := append(HostPreamble(ModeSession), PhonePreamble(StatusOK)...)
	a, b := net.Pipe()
	type res struct {
		c   *Ciphers
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := Handshake(b, HandshakeConfig{Static: phone, PSK: phonePSK, Prologue: prologue})
		if err != nil {
			b.Close()
		}
		ch <- res{c, err}
	}()
	hc, herr := Handshake(a, HandshakeConfig{Initiator: true, Static: host, PSK: hostPSK, Prologue: prologue})
	if herr != nil {
		a.Close()
	}
	r := <-ch
	if herr == nil && r.err == nil {
		if !bytes.Equal(hc.PeerStatic, phone.Public) || !bytes.Equal(r.c.PeerStatic, host.Public) {
			t.Fatal("peer static keys do not match")
		}
	}
	return hc, r.c, herr, r.err
}

func TestHandshakeSessionAndTransport(t *testing.T) {
	hc, pc, herr, perr := handshakePair(t, nil, nil)
	if herr != nil || perr != nil {
		t.Fatal(herr, perr)
	}
	ct, _ := hc.Send.Encrypt(nil, nil, []byte("hi phone"))
	pt, err := pc.Recv.Decrypt(nil, nil, ct)
	if err != nil || string(pt) != "hi phone" {
		t.Fatalf("decrypt: %q %v", pt, err)
	}
	ct, _ = pc.Send.Encrypt(nil, nil, []byte("hi host"))
	if pt, err := hc.Recv.Decrypt(nil, nil, ct); err != nil || string(pt) != "hi host" {
		t.Fatalf("decrypt: %q %v", pt, err)
	}
}

func TestHandshakePairingPSK(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	if _, _, herr, perr := handshakePair(t, psk, psk); herr != nil || perr != nil {
		t.Fatal(herr, perr)
	}
	wrong := make([]byte, 32)
	rand.Read(wrong)
	if _, _, herr, perr := handshakePair(t, psk, wrong); herr == nil && perr == nil {
		t.Fatal("handshake with mismatched PSK succeeded")
	}
}

func TestDecodeMessages(t *testing.T) {
	b, _ := EncodeJSON(Request{T: "status.get", ID: 7})
	m, err := Decode(b)
	if err != nil || m.Type != "status.get" || m.ID == nil || *m.ID != 7 {
		t.Fatalf("got %+v %v", m, err)
	}
	m, err = Decode(EncodeChunk(9, []byte("data")))
	if err != nil || m.Kind != KindChunk || m.Stream != 9 || string(m.Data) != "data" {
		t.Fatalf("got %+v %v", m, err)
	}
	if _, err := Decode([]byte{KindChunk, 0, 1}); err == nil {
		t.Fatal("short chunk accepted")
	}
	var re *RemoteError
	if !errors.As(error(&RemoteError{Code: "busy"}), &re) {
		t.Fatal("RemoteError is not an error")
	}
}
