package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
	pending map[uint64]*pendingRequest
	streams map[uint32]*Stream
	// opened holds the stream an answer opened until StartStream picks it up.
	opened map[uint64]*Stream
	done   chan struct{}
	err    error
}

type pendingRequest struct {
	ch chan proto.Message
	// opensStream: the answer names a chunk stream to set up (camera.start).
	opensStream bool
}

// Mux starts the reader goroutine. It ends when the connection does.
func (s *Session) Mux() *Mux {
	m := &Mux{conn: s.conn, pending: map[uint64]*pendingRequest{}, streams: map[uint32]*Stream{},
		opened: map[uint64]*Stream{}, done: make(chan struct{})}
	m.nextID.Store(s.nextID)
	go m.read()
	return m
}

// read never waits for a consumer: chunks go to their stream's queue, and
// answers and events are dropped when nobody listens any more. So a slow
// video decoder cannot hold up FIDO answers (docs/protocol.md §5 "camera").
func (m *Mux) read() {
	for {
		msg, err := m.conn.Read()
		if err != nil {
			m.mu.Lock()
			m.err = err
			for id, s := range m.streams {
				delete(m.streams, id)
				s.close(err)
			}
			m.mu.Unlock()
			close(m.done)
			return
		}
		switch {
		case msg.Kind == proto.KindChunk:
			m.mu.Lock()
			if s := m.streams[msg.Stream]; s != nil {
				s.q.push(msg.Data)
			}
			m.mu.Unlock()
		case msg.Kind != proto.KindJSON:
		case msg.ID == nil:
			// Events without an id belong to a stream (camera.changed, or
			// camera.stopped when the phone stops on its own).
			var env struct {
				Stream *uint32 `json:"stream"`
			}
			if json.Unmarshal(msg.JSON, &env) != nil || env.Stream == nil {
				continue
			}
			m.mu.Lock()
			if s := m.streams[*env.Stream]; s != nil {
				select {
				case s.events <- msg:
				default: // nobody reads events: drop rather than block
				}
			}
			m.mu.Unlock()
		default:
			m.mu.Lock()
			p := m.pending[*msg.ID]
			if p != nil && p.opensStream && msg.Type != "error" {
				// Set up the stream before reading on, so no chunk that
				// follows the answer is lost.
				var env struct {
					Stream *uint32 `json:"stream"`
				}
				if json.Unmarshal(msg.JSON, &env) == nil && env.Stream != nil {
					s := &Stream{ID: *env.Stream, q: newQueue(maxStreamBacklog), events: make(chan proto.Message, 16), m: m}
					s.Events = s.events
					m.streams[s.ID] = s
					m.opened[*msg.ID] = s
				}
			}
			m.mu.Unlock()
			if p != nil {
				select {
				case p.ch <- msg:
				default: // nobody waiting any more
				}
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
	return m.register(id, false)
}

func (m *Mux) register(id uint64, opensStream bool) chan proto.Message {
	ch := make(chan proto.Message, 1)
	m.mu.Lock()
	m.pending[id] = &pendingRequest{ch: ch, opensStream: opensStream}
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
	return m.Call(ctx, func(id uint64) any { req.ID = id; return req })
}

// Call sends the message build makes for a fresh id and waits for the answer.
// An error answer becomes a RemoteError.
func (m *Mux) Call(ctx context.Context, build func(id uint64) any) (proto.Message, error) {
	id := m.NewID()
	ch := m.register(id, false)
	defer m.Unregister(id)
	return m.await(ctx, ch, build(id))
}

func (m *Mux) await(ctx context.Context, ch chan proto.Message, req any) (proto.Message, error) {
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

// StartStream sends a request whose answer opens a chunk stream
// (camera.start) and returns the answer and the stream. The reader sets the
// stream up as the answer arrives, so no chunk that follows it is lost.
func (m *Mux) StartStream(ctx context.Context, build func(id uint64) any) (proto.Message, *Stream, error) {
	id := m.NewID()
	ch := m.register(id, true)
	msg, err := m.await(ctx, ch, build(id))
	m.mu.Lock()
	delete(m.pending, id)
	s := m.opened[id]
	delete(m.opened, id)
	m.mu.Unlock()
	switch {
	case err != nil:
		if s != nil {
			s.Close()
		}
		return proto.Message{}, nil, err
	case s == nil:
		return proto.Message{}, nil, errors.New(msg.Type + " named no stream")
	}
	return msg, s, nil
}

// Close ends the session.
func (m *Mux) Close() error { return m.conn.Close() }

// maxStreamBacklog bounds what a stream holds when its reader falls behind.
// The phone keeps at most 0.5 s of video itself; this is many seconds of it.
const maxStreamBacklog = 32 << 20

// ErrStreamBacklog ends a stream whose reader fell too far behind.
var ErrStreamBacklog = errors.New("stream reader fell behind")

// Stream is one chunk stream of the phone: its data in order (Read) and the
// events the phone sends for it without an id (Events).
type Stream struct {
	ID     uint32
	Events <-chan proto.Message
	events chan proto.Message
	q      *queue
	m      *Mux
}

// Read returns the stream's data; at the end it returns io.EOF, or the error
// that ended the session or the stream.
func (s *Stream) Read(p []byte) (int, error) { return s.q.read(p) }

// Close stops receiving: further chunks for the stream are dropped.
func (s *Stream) Close() {
	s.m.mu.Lock()
	if s.m.streams[s.ID] == s {
		delete(s.m.streams, s.ID)
	}
	s.m.mu.Unlock()
	s.close(io.EOF)
}

func (s *Stream) close(err error) { s.q.close(err) }

// queue is an in-order byte queue that never blocks its writer.
type queue struct {
	mu   sync.Mutex
	cond *sync.Cond
	bufs [][]byte
	size int
	max  int
	err  error
}

func newQueue(max int) *queue {
	q := &queue{max: max}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *queue) push(b []byte) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil || len(b) == 0 {
		return
	}
	if q.size+len(b) > q.max {
		q.bufs, q.size, q.err = nil, 0, ErrStreamBacklog
	} else {
		q.bufs = append(q.bufs, b)
		q.size += len(b)
	}
	q.cond.Broadcast()
}

func (q *queue) read(p []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.bufs) == 0 && q.err == nil {
		q.cond.Wait()
	}
	if len(q.bufs) == 0 {
		return 0, q.err
	}
	n := copy(p, q.bufs[0])
	if n == len(q.bufs[0]) {
		q.bufs[0] = nil
		q.bufs = q.bufs[1:]
	} else {
		q.bufs[0] = q.bufs[0][n:]
	}
	q.size -= n
	return n, nil
}

func (q *queue) close(err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err == nil {
		q.err = err
	}
	q.cond.Broadcast()
}

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
