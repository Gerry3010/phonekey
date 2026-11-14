package ctaphid

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"
)

type fakeBackend struct {
	delay    time.Duration
	requests chan []byte
}

func (b *fakeBackend) CBOR(ctx context.Context, req []byte) ([]byte, error) {
	if b.requests != nil {
		b.requests <- req
	}
	select {
	case <-time.After(b.delay):
		return append([]byte{0x00}, req...), nil // echo with status OK
	case <-ctx.Done():
		return []byte{0x2D}, nil // what the phone answers on cancel
	}
}

func (b *fakeBackend) Wink(context.Context) error { return nil }

// host is the browser side: it frames requests and reassembles responses.
type host struct {
	t       *testing.T
	dev     *Device
	reports chan []byte
}

func newHost(t *testing.T, b Backend) *host {
	h := &host{t: t, reports: make(chan []byte, 1024)}
	h.dev = New(func(r []byte) error { h.reports <- append([]byte{}, r...); return nil }, b)
	t.Cleanup(h.dev.Close)
	return h
}

func (h *host) send(cid uint32, cmd byte, data []byte) {
	for _, r := range Frame(cid, cmd, data) {
		h.dev.HandleReport(r)
	}
}

// recv returns the next complete message, skipping keepalives if asked.
func (h *host) recv(skipKeepalive bool) (cid uint32, cmd byte, data []byte, keepalives int) {
	h.t.Helper()
	for {
		var r []byte
		select {
		case r = <-h.reports:
		case <-time.After(3 * time.Second):
			h.t.Fatal("no response")
		}
		cid, cmd = binary.BigEndian.Uint32(r), r[4]
		n := int(binary.BigEndian.Uint16(r[5:7]))
		data = append([]byte{}, r[7:]...)
		for len(data) < n {
			c := <-h.reports
			data = append(data, c[5:]...)
		}
		data = data[:n]
		if cmd == CmdKeepalive && skipKeepalive {
			keepalives++
			continue
		}
		return
	}
}

func (h *host) initChannel() uint32 {
	h.t.Helper()
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	h.send(broadcastCID, CmdInit, nonce)
	cid, cmd, data, _ := h.recv(false)
	if cid != broadcastCID || cmd != CmdInit || !bytes.Equal(data[:8], nonce) || len(data) != 17 {
		h.t.Fatalf("init response %x %x %x", cid, cmd, data)
	}
	if data[12] != 2 || data[16] != capWink|capCBOR|capNMsg {
		h.t.Fatalf("protocol/capabilities %x", data[12:])
	}
	return binary.BigEndian.Uint32(data[8:12])
}

func TestInitAndPingAcrossPackets(t *testing.T) {
	h := newHost(t, &fakeBackend{})
	a, b := h.initChannel(), h.initChannel()
	if a == b || a == 0 {
		t.Fatalf("channels %d %d", a, b)
	}
	payload := bytes.Repeat([]byte("phonekey"), 100) // 800 bytes: 1 init + 14 continuation packets
	h.send(a, CmdPing, payload)
	cid, cmd, data, _ := h.recv(false)
	if cid != a || cmd != CmdPing || !bytes.Equal(data, payload) {
		t.Fatalf("ping: cid %d cmd %x len %d", cid, cmd, len(data))
	}
}

func TestCBORWithKeepalives(t *testing.T) {
	KeepaliveInterval = 20 * time.Millisecond
	h := newHost(t, &fakeBackend{delay: 120 * time.Millisecond})
	cid := h.initChannel()
	h.send(cid, CmdCBOR, []byte{0x04})
	got, cmd, data, keepalives := h.recv(true)
	if got != cid || cmd != CmdCBOR || !bytes.Equal(data, []byte{0x00, 0x04}) {
		t.Fatalf("cbor response %x %x", cmd, data)
	}
	if keepalives < 2 {
		t.Fatalf("only %d keepalives", keepalives)
	}
}

func TestCancel(t *testing.T) {
	h := newHost(t, &fakeBackend{delay: time.Hour})
	cid := h.initChannel()
	h.send(cid, CmdCBOR, []byte{0x02, 0xA0})
	time.Sleep(30 * time.Millisecond)
	h.send(cid, CmdCancel, nil)
	_, cmd, data, _ := h.recv(true)
	if cmd != CmdCBOR || !bytes.Equal(data, []byte{0x2D}) {
		t.Fatalf("after cancel: %x %x", cmd, data)
	}
}

func TestBusyAndErrors(t *testing.T) {
	h := newHost(t, &fakeBackend{delay: time.Hour})
	a, b := h.initChannel(), h.initChannel()
	h.send(a, CmdCBOR, []byte{0x02})
	time.Sleep(20 * time.Millisecond)

	h.send(b, CmdCBOR, []byte{0x04})
	if cid, cmd, data, _ := h.recv(true); cid != b || cmd != CmdError || data[0] != ErrChannelBusy {
		t.Fatalf("busy: %d %x %x", cid, cmd, data)
	}
	h.send(0x1234, CmdPing, []byte{1})
	if _, cmd, data, _ := h.recv(true); cmd != CmdError || data[0] != ErrInvalidChannel {
		t.Fatalf("unknown channel: %x %x", cmd, data)
	}
	h.send(broadcastCID, CmdPing, []byte{1})
	if _, cmd, data, _ := h.recv(true); cmd != CmdError || data[0] != ErrInvalidChannel {
		t.Fatalf("ping on broadcast: %x %x", cmd, data)
	}
	h.dev.HandleReport(Frame(a, CmdCancel, nil)[0])
	if _, _, data, _ := h.recv(true); !bytes.Equal(data, []byte{0x2D}) {
		t.Fatalf("cancel answer %x", data)
	}

	h.send(b, CmdMsg, []byte{0, 1, 0, 0})
	if _, cmd, data, _ := h.recv(true); cmd != CmdError || data[0] != ErrInvalidCmd {
		t.Fatalf("U2F MSG: %x %x", cmd, data)
	}

	// A continuation packet out of sequence.
	reports := Frame(b, CmdPing, bytes.Repeat([]byte{7}, 200))
	h.dev.HandleReport(reports[0])
	reports[2][4] = 5
	h.dev.HandleReport(reports[2])
	if _, cmd, data, _ := h.recv(true); cmd != CmdError || data[0] != ErrInvalidSeq {
		t.Fatalf("bad seq: %x %x", cmd, data)
	}
}

func TestInitResyncDropsRequest(t *testing.T) {
	be := &fakeBackend{delay: time.Hour}
	h := newHost(t, be)
	cid := h.initChannel()
	h.send(cid, CmdCBOR, []byte{0x02})
	time.Sleep(20 * time.Millisecond)
	nonce := []byte{9, 9, 9, 9, 9, 9, 9, 9}
	h.send(cid, CmdInit, nonce)
	got, cmd, data, _ := h.recv(true)
	if got != cid || cmd != CmdInit || binary.BigEndian.Uint32(data[8:12]) != cid {
		t.Fatalf("resync: %d %x %x", got, cmd, data)
	}
	// The abandoned request must not answer later; the channel is free again.
	h.send(cid, CmdPing, []byte{42})
	if _, cmd, data, _ := h.recv(true); cmd != CmdPing || data[0] != 42 {
		t.Fatalf("after resync: %x %x", cmd, data)
	}
	select {
	case r := <-h.reports:
		if r[4] != CmdKeepalive {
			t.Fatalf("unexpected report after resync: %x", r[:8])
		}
	case <-time.After(100 * time.Millisecond):
	}
}

func TestFrameSizes(t *testing.T) {
	if n := len(Frame(1, CmdCBOR, make([]byte, 57))); n != 1 {
		t.Fatalf("57 bytes need 1 report, got %d", n)
	}
	if n := len(Frame(1, CmdCBOR, make([]byte, 58))); n != 2 {
		t.Fatalf("58 bytes need 2 reports, got %d", n)
	}
	if n := len(Frame(1, CmdCBOR, make([]byte, maxPayload))); n != 129 {
		t.Fatalf("max payload needs 129 reports, got %d", n)
	}
}
