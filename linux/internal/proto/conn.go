package proto

import (
	"io"
	"sync"
)

// Conn is an established session: framed, encrypted transport messages.
type Conn struct {
	rw         io.ReadWriteCloser
	c          *Ciphers
	writeMu    sync.Mutex
	PeerStatic []byte
}

// NewConn wraps a transport after a finished handshake.
func NewConn(rw io.ReadWriteCloser, c *Ciphers) *Conn {
	return &Conn{rw: rw, c: c, PeerStatic: c.PeerStatic}
}

// WritePlain encrypts and sends one transport message.
func (c *Conn) WritePlain(plain []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	ct, err := c.c.Send.Encrypt(nil, nil, plain)
	if err != nil {
		return err
	}
	return WriteFrame(c.rw, ct)
}

// WriteJSON sends a JSON message.
func (c *Conn) WriteJSON(v any) error {
	b, err := EncodeJSON(v)
	if err != nil {
		return err
	}
	return c.WritePlain(b)
}

// WriteChunk sends a chunk.
func (c *Conn) WriteChunk(stream uint32, data []byte) error {
	return c.WritePlain(EncodeChunk(stream, data))
}

// Read receives and decrypts one transport message.
func (c *Conn) Read() (Message, error) {
	frame, err := ReadFrame(c.rw)
	if err != nil {
		return Message{}, err
	}
	plain, err := c.c.Recv.Decrypt(nil, nil, frame)
	if err != nil {
		return Message{}, err
	}
	return Decode(plain)
}

// Close closes the underlying transport.
func (c *Conn) Close() error { return c.rw.Close() }
