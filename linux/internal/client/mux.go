package client

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Gerry3010/phonekey/linux/internal/proto"
)

// Mux lets several goroutines share one session: requests are matched to
// answers by id, and a reader goroutine owns the receive side. After Mux the
// synchronous Session methods must not be used any more.
type Mux struct {
	conn    *proto.Conn
	nextID  atomic.Uint64
	mu      sync.Mutex
	pending map[uint64]chan proto.Message
	done    chan struct{}
	err     error
}

// Mux starts the reader goroutine. It ends when the connection does.
func (s *Session) Mux() *Mux {
	m := &Mux{conn: s.conn, pending: map[uint64]chan proto.Message{}, done: make(chan struct{})}
	m.nextID.Store(s.nextID)
	go m.read()
	return m
}

func (m *Mux) read() {
	for {
		msg, err := m.conn.Read()
		if err != nil {
			m.mu.Lock()
			m.err = err
			m.mu.Unlock()
			close(m.done)
			return
		}
		if msg.Kind != proto.KindJSON || msg.ID == nil {
			continue
		}
		m.mu.Lock()
		ch := m.pending[*msg.ID]
		m.mu.Unlock()
		if ch != nil {
			select {
			case ch <- msg:
			default: // nobody waiting any more
			}
		}
	}
}

// Done is closed when the connection ends; Err says why.
func (m *Mux) Done() <-chan struct{} { return m.done }

func (m *Mux) Err() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.err
}

// NewID returns a fresh request id.
func (m *Mux) NewID() uint64 { return m.nextID.Add(1) }

// Register returns the channel the answer to id will arrive on.
func (m *Mux) Register(id uint64) <-chan proto.Message {
	ch := make(chan proto.Message, 1)
	m.mu.Lock()
	m.pending[id] = ch
	m.mu.Unlock()
	return ch
}

func (m *Mux) Unregister(id uint64) {
	m.mu.Lock()
	delete(m.pending, id)
	m.mu.Unlock()
}

// Send writes one message; safe from any goroutine.
func (m *Mux) Send(v any) error { return m.conn.WriteJSON(v) }

// Request sends req with a fresh id and waits for the answer.
func (m *Mux) Request(ctx context.Context, req proto.Request) (proto.Message, error) {
	req.ID = m.NewID()
	ch := m.Register(req.ID)
	defer m.Unregister(req.ID)
	if err := m.Send(req); err != nil {
		return proto.Message{}, err
	}
	select {
	case msg := <-ch:
		if msg.Type == "error" {
			return proto.Message{}, remoteError(msg)
		}
		return msg, nil
	case <-m.done:
		return proto.Message{}, m.Err()
	case <-ctx.Done():
		return proto.Message{}, ctx.Err()
	}
}

// Close ends the session.
func (m *Mux) Close() error { return m.conn.Close() }

// CancelGrace is how long CTAP waits for the phone's answer after ctap.cancel.
var CancelGrace = 5 * time.Second

// CTAP forwards one CTAPHID CBOR message. When ctx is cancelled (the browser
// sent CTAPHID_CANCEL) it sends ctap.cancel and returns the phone's answer,
// normally status 0x2D.
func (m *Mux) CTAP(ctx context.Context, request []byte) ([]byte, error) {
	id := m.NewID()
	ch := m.Register(id)
	defer m.Unregister(id)
	cmd := 0x10
	if err := m.Send(proto.Request{T: "ctap.request", ID: id, Cmd: &cmd, Data: request}); err != nil {
		return nil, err
	}
	decode := func(msg proto.Message) ([]byte, error) {
		if msg.Type == "error" {
			return nil, remoteError(msg)
		}
		var r proto.CTAPResponse
		if err := json.Unmarshal(msg.JSON, &r); err != nil {
			return nil, err
		}
		if len(r.Data) == 0 {
			return nil, errors.New("empty ctap.response")
		}
		return r.Data, nil
	}
	select {
	case msg := <-ch:
		return decode(msg)
	case <-m.done:
		return nil, m.Err()
	case <-ctx.Done():
	}
	_ = m.Send(proto.Request{T: "ctap.cancel", ID: id})
	select {
	case msg := <-ch:
		return decode(msg)
	case <-m.done:
	case <-time.After(CancelGrace):
	}
	return []byte{0x2D}, nil
}
