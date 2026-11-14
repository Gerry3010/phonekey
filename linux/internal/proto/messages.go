package proto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// Transport message kinds (first plaintext byte).
const (
	KindJSON  byte = 0x01
	KindChunk byte = 0x02
)

// MaxChunkData is the largest chunk payload senders should use.
const MaxChunkData = 60000

// Message is one decrypted transport message.
type Message struct {
	Kind byte
	// Type is the JSON "t" field; ID the optional "id".
	Type string
	ID   *uint64
	JSON json.RawMessage
	// Stream and Data are set for chunks.
	Stream uint32
	Data   []byte
}

// Decode unpacks one decrypted transport message.
func Decode(plain []byte) (Message, error) {
	if len(plain) == 0 {
		return Message{}, errors.New("empty transport message")
	}
	m := Message{Kind: plain[0]}
	body := plain[1:]
	switch m.Kind {
	case KindJSON:
		var env struct {
			T  string  `json:"t"`
			ID *uint64 `json:"id"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			return Message{}, fmt.Errorf("bad JSON message: %w", err)
		}
		m.Type, m.ID, m.JSON = env.T, env.ID, json.RawMessage(body)
	case KindChunk:
		if len(body) < 4 {
			return Message{}, errors.New("short chunk")
		}
		m.Stream = binary.BigEndian.Uint32(body)
		m.Data = body[4:]
	}
	return m, nil
}

// EncodeJSON packs a JSON message.
func EncodeJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append([]byte{KindJSON}, b...), nil
}

// EncodeChunk packs a chunk.
func EncodeChunk(stream uint32, data []byte) []byte {
	out := make([]byte, 5+len(data))
	out[0] = KindChunk
	binary.BigEndian.PutUint32(out[1:], stream)
	copy(out[5:], data)
	return out
}

// Hello is exchanged by both sides right after the handshake.
type Hello struct {
	T          string    `json:"t"`
	Role       string    `json:"role"`
	Protocol   int       `json:"protocol"`
	AppVersion string    `json:"app_version"`
	Device     *Device   `json:"device,omitempty"`
	Host       *HostInfo `json:"host,omitempty"`
	Features   []string  `json:"features,omitempty"`
}

type Device struct {
	Model  string `json:"model"`
	System string `json:"system"`
	Name   string `json:"name"`
}

type HostInfo struct {
	Name string `json:"name"`
	OS   string `json:"os"`
}

// Request is a host request; only the fields of its type are set.
type Request struct {
	T            string   `json:"t"`
	ID           uint64   `json:"id"`
	Camera       string   `json:"camera,omitempty"`
	MaxDimension *int     `json:"max_dimension,omitempty"`
	Quality      *float64 `json:"quality,omitempty"`
}

type StatusReport struct {
	T            string  `json:"t"`
	ID           uint64  `json:"id"`
	Battery      Battery `json:"battery"`
	Thermal      string  `json:"thermal"`
	DeskMode     bool    `json:"desk_mode"`
	GuidedAccess bool    `json:"guided_access"`
	Camera       struct {
		Enabled   bool `json:"enabled"`
		Available bool `json:"available"`
	} `json:"camera"`
}

type Battery struct {
	Level *float64 `json:"level"`
	State string   `json:"state"`
}

type PhotoBegin struct {
	T      string `json:"t"`
	ID     uint64 `json:"id"`
	Stream uint32 `json:"stream"`
	Size   int    `json:"size"`
	MIME   string `json:"mime"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

type PhotoEnd struct {
	T      string `json:"t"`
	ID     uint64 `json:"id"`
	Stream uint32 `json:"stream"`
	SHA256 string `json:"sha256"`
}

// RemoteError is an "error" message from the phone.
type RemoteError struct {
	T       string  `json:"t"`
	ID      *uint64 `json:"id,omitempty"`
	Code    string  `json:"code"`
	Message string  `json:"message,omitempty"`
}

func (e *RemoteError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("phone: %s (%s)", e.Message, e.Code)
	}
	return "phone: " + e.Code
}
