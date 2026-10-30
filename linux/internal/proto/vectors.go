package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
)

// VectorFile is the layout of docs/protocol-vectors.json.
type VectorFile struct {
	Description string   `json:"description"`
	Vectors     []Vector `json:"vectors"`
}

// Vector is one complete handshake plus a few transport messages.
type Vector struct {
	Name                  string      `json:"name"`
	ProtocolName          string      `json:"protocol_name"`
	Prologue              string      `json:"prologue"`
	HostStaticPrivate     string      `json:"host_static_private"`
	HostStaticPublic      string      `json:"host_static_public"`
	HostEphemeralPrivate  string      `json:"host_ephemeral_private"`
	PhoneStaticPrivate    string      `json:"phone_static_private"`
	PhoneStaticPublic     string      `json:"phone_static_public"`
	PhoneEphemeralPrivate string      `json:"phone_ephemeral_private"`
	PSK                   *string     `json:"psk"`
	HandshakeMessages     []string    `json:"handshake_messages"`
	HandshakeHash         string      `json:"handshake_hash"`
	TransportMessages     []Transport `json:"transport_messages"`
}

// Transport is one encrypted transport message, in send order per direction.
type Transport struct {
	From       string `json:"from"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

// key derives a fixed 32-byte test key from a label.
func key(label string) []byte {
	sum := sha256.Sum256([]byte("phonekey test vector: " + label))
	return sum[:]
}

// recorder captures what one side writes to the pipe.
type recorder struct {
	net.Conn
	frames *[][]byte
}

func (r recorder) Write(p []byte) (int, error) {
	// Each Write is exactly one frame (WriteFrame writes it in one call).
	*r.frames = append(*r.frames, append([]byte(nil), p[2:]...))
	return r.Conn.Write(p)
}

func vector(name string, pairing bool) (Vector, error) {
	hostStatic, _ := KeypairFromPrivate(key("host static"))
	phoneStatic, _ := KeypairFromPrivate(key("phone static"))
	mode := ModeSession
	if pairing {
		mode = ModePairing
	}
	prologue := append(HostPreamble(mode), PhonePreamble(StatusOK)...)
	var psk []byte
	if pairing {
		psk = key("psk")
	}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var frames [][]byte
	type result struct {
		c   *Ciphers
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, err := Handshake(recorder{b, &frames}, HandshakeConfig{
			Static: phoneStatic, PSK: psk, Prologue: prologue, EphemeralPrivate: key("phone ephemeral"),
		})
		done <- result{c, err}
	}()
	host, err := Handshake(recorder{a, &frames}, HandshakeConfig{
		Initiator: true, Static: hostStatic, PSK: psk, Prologue: prologue, EphemeralPrivate: key("host ephemeral"),
	})
	phone := <-done
	if err != nil || phone.err != nil {
		return Vector{}, fmt.Errorf("handshake: %v %v", err, phone.err)
	}

	hx := hex.EncodeToString
	v := Vector{
		Name:                  name,
		ProtocolName:          ProtocolName(pairing),
		Prologue:              hx(prologue),
		HostStaticPrivate:     hx(hostStatic.Private),
		HostStaticPublic:      hx(hostStatic.Public),
		HostEphemeralPrivate:  hx(key("host ephemeral")),
		PhoneStaticPrivate:    hx(phoneStatic.Private),
		PhoneStaticPublic:     hx(phoneStatic.Public),
		PhoneEphemeralPrivate: hx(key("phone ephemeral")),
		HandshakeHash:         hx(host.HandshakeHash),
	}
	if psk != nil {
		s := hx(psk)
		v.PSK = &s
	}
	for _, f := range frames {
		v.HandshakeMessages = append(v.HandshakeMessages, hx(f))
	}

	hostHello, _ := EncodeJSON(Hello{T: "hello", Role: "host", Protocol: Version, AppVersion: "0.1.0",
		Host: &HostInfo{Name: "workstation", OS: "linux"}})
	phoneHello, _ := EncodeJSON(Hello{T: "hello", Role: "phone", Protocol: Version, AppVersion: "0.2.0",
		Device: &Device{Model: "iPhone9,3", System: "iOS 15.8.3", Name: "iPhone"}, Features: []string{"status", "photo"}})
	ping, _ := EncodeJSON(Request{T: "ping", ID: 1})
	msgs := []struct {
		from  string
		plain []byte
	}{
		{"host", hostHello},
		{"phone", phoneHello},
		{"host", ping},
		{"phone", EncodeChunk(1, []byte("\xff\xd8\xff\xe0 jpeg bytes"))},
	}
	for _, m := range msgs {
		cs := host.Send
		if m.from == "phone" {
			cs = phone.c.Send
		}
		ct, err := cs.Encrypt(nil, nil, m.plain)
		if err != nil {
			return Vector{}, err
		}
		v.TransportMessages = append(v.TransportMessages, Transport{From: m.from, Plaintext: hx(m.plain), Ciphertext: hx(ct)})
	}
	return v, nil
}

// GenerateVectors returns the content of docs/protocol-vectors.json.
func GenerateVectors() ([]byte, error) {
	f := VectorFile{Description: "phonekey protocol v1 test vectors. Keys are SHA-256(\"phonekey test vector: \" + label). " +
		"Handshake messages are the Noise messages without the 2-byte frame length. " +
		"Transport ciphertexts use the cipher state of the sending side, in order."}
	for _, c := range []struct {
		name    string
		pairing bool
	}{{"session", false}, {"pairing", true}} {
		v, err := vector(c.name, c.pairing)
		if err != nil {
			return nil, err
		}
		f.Vectors = append(f.Vectors, v)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
