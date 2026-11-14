// Package ctaphid implements the device side of CTAPHID (CTAP 2.0 §8.1): the
// framing a browser or libfido2 speaks to a USB security key. It is pure Go;
// the Linux daemon feeds it HID reports from /dev/uhid.
package ctaphid

import (
	"context"
	"encoding/binary"
	"sync"
	"time"
)

// ReportSize is the HID report size of a FIDO device.
const ReportSize = 64

// ReportDescriptor describes a FIDO HID device: usage page 0xF1D0, 64-byte
// input and output reports, no report IDs.
var ReportDescriptor = []byte{
	0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
	0x09, 0x01, // Usage (CTAPHID)
	0xA1, 0x01, // Collection (Application)
	0x09, 0x20, //   Usage (Input Report Data)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x81, 0x02, //   Input (Data, Var, Abs)
	0x09, 0x21, //   Usage (Output Report Data)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x91, 0x02, //   Output (Data, Var, Abs)
	0xC0, // End Collection
}

// Commands (with the init-packet bit set).
const (
	CmdPing      = 0x81
	CmdMsg       = 0x83
	CmdLock      = 0x84
	CmdInit      = 0x86
	CmdWink      = 0x88
	CmdCBOR      = 0x90
	CmdCancel    = 0x91
	CmdKeepalive = 0xBB
	CmdError     = 0xBF
)

// Error codes for CmdError.
const (
	ErrInvalidCmd     = 0x01
	ErrInvalidPar     = 0x02
	ErrInvalidLen     = 0x03
	ErrInvalidSeq     = 0x04
	ErrMsgTimeout     = 0x05
	ErrChannelBusy    = 0x06
	ErrInvalidChannel = 0x0B
	ErrOther          = 0x7F
)

const (
	broadcastCID   = 0xFFFFFFFF
	maxPayload     = ReportSize - 7 + 128*(ReportSize-5) // 7609
	statusUPNeeded = 0x02

	capWink = 0x01
	capCBOR = 0x04
	capNMsg = 0x08 // no CTAPHID_MSG (U2F)
)

// KeepaliveInterval is how often KEEPALIVE goes out while the user decides.
var KeepaliveInterval = 100 * time.Millisecond

// MessageTimeout limits how long a fragmented request may take.
var MessageTimeout = 3 * time.Second

// Backend executes requests. CBOR must return when ctx is cancelled
// (CTAPHID_CANCEL); it then returns the authenticator's answer, normally
// status 0x2D (CTAP2_ERR_KEEPALIVE_CANCEL).
type Backend interface {
	CBOR(ctx context.Context, request []byte) ([]byte, error)
	Wink(ctx context.Context) error
}

// Device is one virtual security key.
type Device struct {
	send    func(report []byte) error
	backend Backend

	mu       sync.Mutex
	sendMu   sync.Mutex
	nextCID  uint32
	channels map[uint32]bool
	asm      *assembly // request being received
	busyCID  uint32    // channel with a CBOR request in flight, 0 if none
	cancel   context.CancelFunc
	txn      uint64 // bumped when a request in flight is abandoned (INIT resync)
	closed   bool
}

type assembly struct {
	cid      uint32
	cmd      byte
	total    int
	data     []byte
	seq      byte
	deadline time.Time
}

// New creates a device that writes input reports with send.
func New(send func(report []byte) error, backend Backend) *Device {
	return &Device{send: send, backend: backend, nextCID: 1, channels: map[uint32]bool{}}
}

// Close cancels a request in flight.
func (d *Device) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	if d.cancel != nil {
		d.cancel()
	}
}

// HandleReport processes one output report from the host.
func (d *Device) HandleReport(r []byte) {
	if len(r) != ReportSize {
		return
	}
	cid := binary.BigEndian.Uint32(r)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}

	if r[4]&0x80 == 0 { // continuation packet
		a := d.asm
		if a == nil || a.cid != cid {
			return // stray continuation: ignore, as the spec allows
		}
		if r[4] != a.seq {
			d.asm = nil
			d.errorLocked(cid, ErrInvalidSeq)
			return
		}
		a.seq++
		a.data = append(a.data, r[5:]...)
		d.finishAssembly()
		return
	}

	cmd := r[4]
	n := int(binary.BigEndian.Uint16(r[5:7]))
	if cmd == CmdCancel {
		if cid == d.busyCID && d.cancel != nil {
			d.cancel() // the request answers with KEEPALIVE_CANCEL
		}
		return
	}
	if cid == 0 || (cid != broadcastCID && !d.channels[cid]) {
		d.errorLocked(cid, ErrInvalidChannel)
		return
	}
	if cid == broadcastCID && cmd != CmdInit {
		d.errorLocked(cid, ErrInvalidChannel)
		return
	}
	if cmd != CmdInit {
		if d.busyCID != 0 {
			d.errorLocked(cid, ErrChannelBusy)
			return
		}
		if a := d.asm; a != nil && a.cid != cid && time.Now().Before(a.deadline) {
			d.errorLocked(cid, ErrChannelBusy)
			return
		}
	}
	if n > maxPayload {
		d.errorLocked(cid, ErrInvalidLen)
		return
	}
	d.asm = &assembly{cid: cid, cmd: cmd, total: n, data: append([]byte{}, r[7:]...),
		deadline: time.Now().Add(MessageTimeout)}
	d.finishAssembly()
}

// finishAssembly dispatches the request once all of it has arrived.
func (d *Device) finishAssembly() {
	a := d.asm
	if len(a.data) < a.total {
		return
	}
	d.asm = nil
	data := a.data[:a.total]
	switch a.cmd {
	case CmdInit:
		d.init(a.cid, data)
	case CmdPing:
		d.respond(a.cid, CmdPing, data)
	case CmdLock:
		d.respond(a.cid, CmdLock, nil)
	case CmdWink:
		go func() {
			_ = d.backend.Wink(context.Background())
			d.respond(a.cid, CmdWink, nil)
		}()
	case CmdCBOR:
		if len(data) == 0 {
			d.errorLocked(a.cid, ErrInvalidLen)
			return
		}
		d.startCBOR(a.cid, data)
	default: // CmdMsg (NMSG) and anything unknown
		d.errorLocked(a.cid, ErrInvalidCmd)
	}
}

func (d *Device) init(cid uint32, nonce []byte) {
	if len(nonce) != 8 {
		d.errorLocked(cid, ErrInvalidLen)
		return
	}
	newCID := cid
	if cid == broadcastCID {
		newCID = d.nextCID
		d.nextCID++
		if d.nextCID == broadcastCID {
			d.nextCID = 1
		}
		d.channels[newCID] = true
	} else if cid == d.busyCID && d.cancel != nil {
		// INIT on a busy channel resynchronizes it: drop the request in flight
		// without answering it.
		d.cancel()
		d.txn++
		d.busyCID, d.cancel = 0, nil
	}
	resp := append(append([]byte{}, nonce...), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(resp[8:], newCID)
	resp = append(resp, 2, 0, 1, 0, capWink|capCBOR|capNMsg) // protocol 2, version 0.1.0
	d.respond(cid, CmdInit, resp)
}

func (d *Device) startCBOR(cid uint32, request []byte) {
	ctx, cancel := context.WithCancel(context.Background())
	d.busyCID, d.cancel = cid, cancel
	txn := d.txn
	go func() {
		done := make(chan struct{})
		go func() {
			t := time.NewTicker(KeepaliveInterval)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					d.respond(cid, CmdKeepalive, []byte{statusUPNeeded})
				}
			}
		}()
		resp, err := d.backend.CBOR(ctx, request)
		close(done)
		d.mu.Lock()
		abandoned := d.closed || d.txn != txn
		if !abandoned {
			d.busyCID, d.cancel = 0, nil
		}
		d.mu.Unlock()
		cancel()
		if abandoned {
			return
		}
		if err != nil || len(resp) == 0 {
			d.respond(cid, CmdError, []byte{ErrOther})
			return
		}
		d.respond(cid, CmdCBOR, resp)
	}()
}

func (d *Device) errorLocked(cid uint32, code byte) { d.respond(cid, CmdError, []byte{code}) }

// respond frames data into init and continuation reports. It only takes
// sendMu, so it may be called with or without d.mu held.
func (d *Device) respond(cid uint32, cmd byte, data []byte) {
	d.sendMu.Lock()
	defer d.sendMu.Unlock()
	for _, r := range Frame(cid, cmd, data) {
		if err := d.send(r); err != nil {
			return
		}
	}
}

// Frame splits a message into 64-byte reports (also used by tests and hosts).
func Frame(cid uint32, cmd byte, data []byte) [][]byte {
	var out [][]byte
	r := make([]byte, ReportSize)
	binary.BigEndian.PutUint32(r, cid)
	r[4] = cmd
	binary.BigEndian.PutUint16(r[5:], uint16(len(data)))
	n := copy(r[7:], data)
	out = append(out, r)
	for seq := byte(0); n < len(data); seq++ {
		r = make([]byte, ReportSize)
		binary.BigEndian.PutUint32(r, cid)
		r[4] = seq
		n += copy(r[5:], data[n:])
		out = append(out, r)
	}
	return out
}
