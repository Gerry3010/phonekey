// Package proto implements the phonekey wire protocol (docs/protocol.md):
// preamble, framing, the Noise handshake and transport messages.
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// Port is the TCP port the phone listens on (loopback only).
	Port = 20555
	// Version is the protocol version implemented here.
	Version = 1

	ModeSession byte = 0x00
	ModePairing byte = 0x01

	PreambleSize = 8
)

// Status is the phone's answer in its preamble.
type Status byte

const (
	StatusOK                 Status = 0x00
	StatusUnsupportedVersion Status = 0x01
	StatusNoPairingPending   Status = 0x02
	StatusBusy               Status = 0x03
	StatusUnknownMode        Status = 0x04
)

func (s Status) Error() string {
	switch s {
	case StatusUnsupportedVersion:
		return "phone does not support this protocol version"
	case StatusNoPairingPending:
		return "no pairing pending on the phone"
	case StatusBusy:
		return "phone is busy (connection limit reached)"
	case StatusUnknownMode:
		return "phone does not know this mode"
	default:
		return fmt.Sprintf("phone refused the connection (status 0x%02x)", byte(s))
	}
}

var magic = [4]byte{'P', 'H', 'K', 'Y'}

// HostPreamble returns the 8-byte preamble the host sends first.
func HostPreamble(mode byte) []byte {
	return []byte{magic[0], magic[1], magic[2], magic[3], Version, mode, 0, 0}
}

// PhonePreamble returns the 8-byte preamble the phone answers with.
func PhonePreamble(status Status) []byte {
	return []byte{magic[0], magic[1], magic[2], magic[3], Version, byte(status), 0, 0}
}

// ParsePreamble checks the magic and returns the version and the mode or status byte.
func ParsePreamble(b []byte) (version, value byte, err error) {
	if len(b) != PreambleSize || b[0] != magic[0] || b[1] != magic[1] || b[2] != magic[2] || b[3] != magic[3] {
		return 0, 0, errors.New("not a phonekey preamble")
	}
	return b[4], b[5], nil
}

// MaxFrame is the largest Noise message a frame can carry.
const MaxFrame = 65535

// WriteFrame writes one length-prefixed frame.
func WriteFrame(w io.Writer, msg []byte) error {
	if len(msg) == 0 || len(msg) > MaxFrame {
		return fmt.Errorf("frame size %d out of range", len(msg))
	}
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	copy(buf[2:], msg)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one length-prefixed frame.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 {
		return nil, errors.New("empty frame")
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
