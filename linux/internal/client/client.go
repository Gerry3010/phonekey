// Package client is the host side of a phonekey session: connect, pair, and
// the requests of protocol v1.
package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"time"

	"github.com/Gerry3010/phonekey/linux/internal/proto"
	"github.com/Gerry3010/phonekey/linux/internal/store"
	"github.com/Gerry3010/phonekey/linux/internal/usbmux"
)

// Transport opens a raw connection to the phone.
type Transport interface {
	Dial(ctx context.Context) (net.Conn, error)
}

// USBMux reaches the phone through usbmuxd.
type USBMux struct{ UDID string }

func (u USBMux) Dial(ctx context.Context) (net.Conn, error) {
	devices, err := usbmux.ListDevices()
	if err != nil {
		return nil, err
	}
	d, err := usbmux.Pick(devices, u.UDID)
	if err != nil {
		return nil, err
	}
	return usbmux.Connect(d.DeviceID, proto.Port)
}

// TCP connects directly, e.g. to the app in the iOS Simulator.
type TCP struct{ Addr string }

func (t TCP) Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", t.Addr)
}

// Client holds what every connection needs.
type Client struct {
	Store     *store.Store
	Transport Transport
	HostName  string
	Version   string
}

// Session is an authenticated connection with a paired phone.
type Session struct {
	conn   *proto.Conn
	raw    net.Conn
	Phone  store.Phone
	Hello  proto.Hello
	nextID uint64
}

const handshakeTimeout = 15 * time.Second

func (c *Client) open(ctx context.Context, mode byte, psk []byte) (*proto.Conn, net.Conn, error) {
	hostKey, err := c.Store.HostKey()
	if err != nil {
		return nil, nil, err
	}
	raw, err := c.Transport.Dial(ctx)
	if err != nil {
		return nil, nil, err
	}
	raw.SetDeadline(deadline(ctx, handshakeTimeout))
	pre := proto.HostPreamble(mode)
	if _, err := raw.Write(pre); err != nil {
		raw.Close()
		return nil, nil, err
	}
	resp := make([]byte, proto.PreambleSize)
	if _, err := io.ReadFull(raw, resp); err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("no answer from the phone: %w", err)
	}
	_, status, err := proto.ParsePreamble(resp)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	if proto.Status(status) != proto.StatusOK {
		raw.Close()
		return nil, nil, proto.Status(status)
	}
	ciphers, err := proto.Handshake(raw, proto.HandshakeConfig{
		Initiator: true,
		Static:    hostKey,
		PSK:       psk,
		Prologue:  append(append([]byte(nil), pre...), resp...),
	})
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	return proto.NewConn(raw, ciphers), raw, nil
}

func (c *Client) hello() proto.Hello {
	return proto.Hello{
		T: "hello", Role: "host", Protocol: proto.Version, AppVersion: c.Version,
		Host: &proto.HostInfo{Name: c.HostName, OS: runtime.GOOS},
	}
}

// exchangeHello sends ours and waits for the phone's hello.
func (s *Session) exchangeHello(h proto.Hello) error {
	if err := s.conn.WriteJSON(h); err != nil {
		return err
	}
	for {
		m, err := s.conn.Read()
		if err != nil {
			return fmt.Errorf("phone closed the connection: %w", err)
		}
		switch m.Type {
		case "hello":
			return json.Unmarshal(m.JSON, &s.Hello)
		case "error":
			return remoteError(m)
		}
	}
}

// ErrUnknownPhone means the phone's key is not in phones.json.
var ErrUnknownPhone = errors.New("this phone is not paired with this computer (run: phonekey pair)")

// Connect opens a session with a paired phone.
func (c *Client) Connect(ctx context.Context) (*Session, error) {
	conn, raw, err := c.open(ctx, proto.ModeSession, nil)
	if err != nil {
		return nil, err
	}
	phone, ok, err := c.Store.PhoneByKey(conn.PeerStatic)
	if err != nil || !ok {
		conn.Close()
		if err == nil {
			err = ErrUnknownPhone
		}
		return nil, err
	}
	s := &Session{conn: conn, raw: raw, Phone: phone}
	if err := s.exchangeHello(c.hello()); err != nil {
		conn.Close()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return s, nil
}

// retryablePairing reports errors that mean "not ready yet, try again".
func retryablePairing(err error) bool {
	var st proto.Status
	return errors.Is(err, usbmux.ErrNoDevice) || usbmux.ErrConnectionRefused(err) ||
		(errors.As(err, &st) && st == proto.StatusNoPairingPending) ||
		errors.Is(err, errConnRefused)
}

var errConnRefused = errors.New("connection refused")

// Pair waits until the phone has a pending pairing for psk, pairs, and stores
// the phone. It retries until ctx ends.
func (c *Client) Pair(ctx context.Context, psk []byte) (*Session, error) {
	for {
		conn, raw, err := c.open(ctx, proto.ModePairing, psk)
		if err == nil {
			s := &Session{conn: conn, raw: raw}
			if err := s.exchangeHello(c.hello()); err != nil {
				conn.Close()
				return nil, fmt.Errorf("pairing failed (wrong or expired code?): %w", err)
			}
			raw.SetDeadline(time.Time{})
			s.Phone = store.Phone{Key: store.EncodeKey(conn.PeerStatic), PairedAt: time.Now().UTC()}
			if d := s.Hello.Device; d != nil {
				s.Phone.Name, s.Phone.Model = d.Name, d.Model
			}
			if err := c.Store.SavePhone(s.Phone); err != nil {
				conn.Close()
				return nil, err
			}
			return s, nil
		}
		if isConnRefused(err) {
			err = errConnRefused
		}
		if !retryablePairing(err) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("pairing timed out: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

func isConnRefused(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

func deadline(ctx context.Context, fallback time.Duration) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(fallback)
}

func remoteError(m proto.Message) error {
	var e proto.RemoteError
	if err := json.Unmarshal(m.JSON, &e); err != nil {
		return err
	}
	return &e
}

// Close ends the session.
func (s *Session) Close() error { return s.conn.Close() }

func (s *Session) send(ctx context.Context, req proto.Request) (uint64, error) {
	s.nextID++
	req.ID = s.nextID
	s.raw.SetDeadline(deadline(ctx, 30*time.Second))
	return req.ID, s.conn.WriteJSON(req)
}

// await reads until a JSON message answering id arrives. Errors for id are
// returned as *proto.RemoteError.
func (s *Session) await(id uint64) (proto.Message, error) {
	for {
		m, err := s.conn.Read()
		if err != nil {
			return proto.Message{}, err
		}
		if m.Kind != proto.KindJSON || m.ID == nil || *m.ID != id {
			continue
		}
		if m.Type == "error" {
			return proto.Message{}, remoteError(m)
		}
		return m, nil
	}
}

// Ping measures one round trip.
func (s *Session) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	id, err := s.send(ctx, proto.Request{T: "ping"})
	if err != nil {
		return 0, err
	}
	if _, err := s.await(id); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// Status asks for the phone's status.
func (s *Session) Status(ctx context.Context) (*proto.StatusReport, error) {
	id, err := s.send(ctx, proto.Request{T: "status.get"})
	if err != nil {
		return nil, err
	}
	m, err := s.await(id)
	if err != nil {
		return nil, err
	}
	var st proto.StatusReport
	return &st, json.Unmarshal(m.JSON, &st)
}

// PhotoOptions mirror photo.capture.
type PhotoOptions struct {
	Camera       string
	MaxDimension int
	Quality      float64
}

// Photo is a received picture.
type Photo struct {
	proto.PhotoBegin
	Data []byte
}

// Photo takes a picture and returns the verified JPEG.
func (s *Session) Photo(ctx context.Context, o PhotoOptions) (*Photo, error) {
	req := proto.Request{T: "photo.capture", Camera: o.Camera}
	if o.MaxDimension >= 0 {
		req.MaxDimension = &o.MaxDimension
	}
	if o.Quality > 0 {
		req.Quality = &o.Quality
	}
	id, err := s.send(ctx, req)
	if err != nil {
		return nil, err
	}
	m, err := s.await(id)
	if err != nil {
		return nil, err
	}
	if m.Type != "photo.begin" {
		return nil, fmt.Errorf("unexpected %q", m.Type)
	}
	p := &Photo{}
	if err := json.Unmarshal(m.JSON, &p.PhotoBegin); err != nil {
		return nil, err
	}
	if p.Size < 0 || p.Size > 64<<20 {
		return nil, fmt.Errorf("implausible photo size %d", p.Size)
	}
	p.Data = make([]byte, 0, p.Size)
	for {
		m, err := s.conn.Read()
		if err != nil {
			return nil, err
		}
		switch {
		case m.Kind == proto.KindChunk && m.Stream == p.Stream:
			if len(p.Data)+len(m.Data) > p.Size {
				return nil, errors.New("photo larger than announced")
			}
			p.Data = append(p.Data, m.Data...)
		case m.Kind == proto.KindJSON && m.ID != nil && *m.ID == id && m.Type == "error":
			return nil, remoteError(m)
		case m.Kind == proto.KindJSON && m.ID != nil && *m.ID == id && m.Type == "photo.end":
			var end proto.PhotoEnd
			if err := json.Unmarshal(m.JSON, &end); err != nil {
				return nil, err
			}
			sum := sha256.Sum256(p.Data)
			if len(p.Data) != p.Size || end.SHA256 != hex.EncodeToString(sum[:]) {
				return nil, errors.New("photo corrupted in transfer (size or SHA-256 mismatch)")
			}
			return p, nil
		}
	}
}
