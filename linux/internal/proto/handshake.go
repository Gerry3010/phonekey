package proto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/flynn/noise"
)

// Suite is the Noise cipher suite: 25519, ChaChaPoly, SHA256.
var Suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// Keypair is a static or ephemeral X25519 key pair.
type Keypair = noise.DHKey

// GenerateKeypair creates a new random X25519 key pair.
func GenerateKeypair() (Keypair, error) {
	return noise.DH25519.GenerateKeypair(rand.Reader)
}

// KeypairFromPrivate rebuilds a key pair from its 32-byte private key.
func KeypairFromPrivate(priv []byte) (Keypair, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{Private: append([]byte(nil), priv...), Public: k.PublicKey().Bytes()}, nil
}

// HandshakeConfig describes one side of a handshake.
type HandshakeConfig struct {
	Initiator bool
	Static    Keypair
	// PSK switches to Noise_XXpsk3 (pairing). Nil means Noise_XX (session).
	PSK []byte
	// Prologue is host preamble || phone preamble.
	Prologue []byte
	// EphemeralPrivate fixes the ephemeral private key; only for test vectors.
	EphemeralPrivate []byte
}

// Ciphers holds the transport cipher states after the handshake.
type Ciphers struct {
	Send, Recv    *noise.CipherState
	PeerStatic    []byte
	HandshakeHash []byte
}

// ProtocolName returns the Noise protocol name for a mode.
func ProtocolName(pairing bool) string {
	if pairing {
		return "Noise_XXpsk3_25519_ChaChaPoly_SHA256"
	}
	return "Noise_XX_25519_ChaChaPoly_SHA256"
}

func newHandshakeState(cfg HandshakeConfig) (*noise.HandshakeState, error) {
	nc := noise.Config{
		CipherSuite:   Suite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeXX,
		Initiator:     cfg.Initiator,
		Prologue:      cfg.Prologue,
		StaticKeypair: cfg.Static,
	}
	if cfg.PSK != nil {
		if len(cfg.PSK) != 32 {
			return nil, errors.New("PSK must be 32 bytes")
		}
		nc.PresharedKey = cfg.PSK
		nc.PresharedKeyPlacement = 3
	}
	if cfg.EphemeralPrivate != nil {
		// flynn/noise draws the ephemeral key from Random for the "e" token.
		nc.Random = bytes.NewReader(cfg.EphemeralPrivate)
	}
	return noise.NewHandshakeState(nc)
}

// Handshake runs the three-message XX handshake over rw using frames.
// Handshake payloads are empty (protocol v1).
func Handshake(rw io.ReadWriter, cfg HandshakeConfig) (*Ciphers, error) {
	hs, err := newHandshakeState(cfg)
	if err != nil {
		return nil, err
	}
	var c1, c2 *noise.CipherState
	for i := 0; i < 3; i++ {
		write := (i%2 == 0) == cfg.Initiator
		if write {
			msg, a, b, err := hs.WriteMessage(nil, nil)
			if err != nil {
				return nil, fmt.Errorf("handshake message %d: %w", i+1, err)
			}
			if err := WriteFrame(rw, msg); err != nil {
				return nil, err
			}
			c1, c2 = a, b
		} else {
			msg, err := ReadFrame(rw)
			if err != nil {
				return nil, fmt.Errorf("handshake message %d: %w", i+1, err)
			}
			if _, a, b, err := hs.ReadMessage(nil, msg); err != nil {
				return nil, fmt.Errorf("handshake message %d: %w", i+1, err)
			} else {
				c1, c2 = a, b
			}
		}
	}
	if c1 == nil || c2 == nil {
		return nil, errors.New("handshake did not complete")
	}
	out := &Ciphers{PeerStatic: hs.PeerStatic(), HandshakeHash: hs.ChannelBinding()}
	if cfg.Initiator {
		out.Send, out.Recv = c1, c2
	} else {
		out.Send, out.Recv = c2, c1
	}
	return out, nil
}
