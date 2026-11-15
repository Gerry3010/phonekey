// Package ctap is a small CTAP2 client: request and response structures,
// authenticator data parsing and assertion verification. The daemon itself
// only forwards bytes; this package is for `phonekey fido` diagnostics and tests.
package ctap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// CTAP2 commands.
const (
	CmdMakeCredential   byte = 0x01
	CmdGetAssertion     byte = 0x02
	CmdGetInfo          byte = 0x04
	CmdGetNextAssertion byte = 0x08
)

// Authenticator data flags.
const (
	FlagUP byte = 0x01
	FlagUV byte = 0x04
	FlagAT byte = 0x40
	FlagED byte = 0x80
)

var enc, _ = cbor.CTAP2EncOptions().EncMode()

// Status is a non-zero CTAP status byte.
type Status byte

var statusNames = map[Status]string{
	0x01: "INVALID_COMMAND", 0x02: "INVALID_PARAMETER", 0x03: "INVALID_LENGTH", 0x06: "CHANNEL_BUSY",
	0x11: "CBOR_UNEXPECTED_TYPE", 0x12: "INVALID_CBOR", 0x14: "MISSING_PARAMETER",
	0x19: "CREDENTIAL_EXCLUDED", 0x26: "UNSUPPORTED_ALGORITHM", 0x27: "OPERATION_DENIED",
	0x28: "KEY_STORE_FULL", 0x2B: "UNSUPPORTED_OPTION", 0x2C: "INVALID_OPTION",
	0x2D: "KEEPALIVE_CANCEL", 0x2E: "NO_CREDENTIALS", 0x2F: "USER_ACTION_TIMEOUT",
	0x30: "NOT_ALLOWED", 0x35: "PIN_NOT_SET", 0x36: "PIN_AUTH_INVALID", 0x7F: "OTHER",
}

func (s Status) Error() string {
	if n, ok := statusNames[s]; ok {
		return fmt.Sprintf("CTAP2_ERR_%s (0x%02x)", n, byte(s))
	}
	return fmt.Sprintf("CTAP status 0x%02x", byte(s))
}

// Transport sends one CBOR message (command byte + parameters) and returns
// the answer (status byte + CBOR).
type Transport func(message []byte) ([]byte, error)

// Call encodes req, sends it and decodes the response into resp (may be nil).
func Call(t Transport, command byte, req, resp any) error {
	msg := []byte{command}
	if req != nil {
		b, err := enc.Marshal(req)
		if err != nil {
			return err
		}
		msg = append(msg, b...)
	}
	out, err := t(msg)
	if err != nil {
		return err
	}
	if len(out) == 0 {
		return errors.New("empty CTAP response")
	}
	if out[0] != 0 {
		return Status(out[0])
	}
	if resp == nil {
		return nil
	}
	return cbor.Unmarshal(out[1:], resp)
}

type Info struct {
	Versions   []string        `cbor:"1,keyasint"`
	Extensions []string        `cbor:"2,keyasint,omitempty"`
	AAGUID     []byte          `cbor:"3,keyasint"`
	Options    map[string]bool `cbor:"4,keyasint"`
	MaxMsgSize int             `cbor:"5,keyasint,omitempty"`
	Transports []string        `cbor:"9,keyasint,omitempty"`
	Algorithms []CredParam     `cbor:"10,keyasint,omitempty"`
}

type RP struct {
	ID   string `cbor:"id"`
	Name string `cbor:"name,omitempty"`
}

type User struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name,omitempty"`
	DisplayName string `cbor:"displayName,omitempty"`
}

type CredParam struct {
	Alg  int    `cbor:"alg"`
	Type string `cbor:"type"`
}

type Descriptor struct {
	ID   []byte `cbor:"id"`
	Type string `cbor:"type"`
}

type MakeCredentialRequest struct {
	ClientDataHash []byte          `cbor:"1,keyasint"`
	RP             RP              `cbor:"2,keyasint"`
	User           User            `cbor:"3,keyasint"`
	Params         []CredParam     `cbor:"4,keyasint"`
	Exclude        []Descriptor    `cbor:"5,keyasint,omitempty"`
	Options        map[string]bool `cbor:"7,keyasint,omitempty"`
}

type MakeCredentialResponse struct {
	Fmt      string          `cbor:"1,keyasint"`
	AuthData []byte          `cbor:"2,keyasint"`
	AttStmt  cbor.RawMessage `cbor:"3,keyasint"`
}

type GetAssertionRequest struct {
	RPID           string          `cbor:"1,keyasint"`
	ClientDataHash []byte          `cbor:"2,keyasint"`
	Allow          []Descriptor    `cbor:"3,keyasint,omitempty"`
	Options        map[string]bool `cbor:"5,keyasint,omitempty"`
}

type GetAssertionResponse struct {
	Credential          Descriptor `cbor:"1,keyasint"`
	AuthData            []byte     `cbor:"2,keyasint"`
	Signature           []byte     `cbor:"3,keyasint"`
	User                *User      `cbor:"4,keyasint,omitempty"`
	NumberOfCredentials int        `cbor:"5,keyasint,omitempty"`
}

// AuthData is parsed authenticator data.
type AuthData struct {
	RPIDHash     []byte
	Flags        byte
	Counter      uint32
	AAGUID       []byte           // with FlagAT
	CredentialID []byte           // with FlagAT
	PublicKey    *ecdsa.PublicKey // with FlagAT
	Extensions   map[string]any   // with FlagED
}

// ParseAuthData reads authenticator data, including attested credential data.
func ParseAuthData(b []byte) (*AuthData, error) {
	if len(b) < 37 {
		return nil, errors.New("authenticator data too short")
	}
	a := &AuthData{RPIDHash: b[:32], Flags: b[32], Counter: binary.BigEndian.Uint32(b[33:37])}
	dec, _ := cbor.DecOptions{}.DecMode()
	if a.Flags&FlagAT == 0 {
		// An assertion: with ED (hmac-secret, credProtect) the extensions
		// follow the 37 fixed bytes directly.
		rem := b[37:]
		if a.Flags&FlagED != 0 {
			var err error
			if rem, err = dec.UnmarshalFirst(rem, &a.Extensions); err != nil {
				return nil, fmt.Errorf("extensions: %w", err)
			}
		}
		if len(rem) != 0 {
			return nil, errors.New("unexpected bytes after authenticator data")
		}
		return a, nil
	}
	rest := b[37:]
	if len(rest) < 18 {
		return nil, errors.New("attested credential data too short")
	}
	a.AAGUID = rest[:16]
	n := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if len(rest) < n {
		return nil, errors.New("credential ID truncated")
	}
	a.CredentialID, rest = rest[:n], rest[n:]
	var key struct {
		Kty int    `cbor:"1,keyasint"`
		Alg int    `cbor:"3,keyasint"`
		Crv int    `cbor:"-1,keyasint"`
		X   []byte `cbor:"-2,keyasint"`
		Y   []byte `cbor:"-3,keyasint"`
	}
	rem, err := dec.UnmarshalFirst(rest, &key)
	if err != nil {
		return nil, fmt.Errorf("COSE key: %w", err)
	}
	if a.Flags&FlagED != 0 {
		if rem, err = dec.UnmarshalFirst(rem, &a.Extensions); err != nil {
			return nil, fmt.Errorf("extensions: %w", err)
		}
	}
	if len(rem) != 0 {
		return nil, errors.New("unexpected bytes after authenticator data")
	}
	if key.Kty != 2 || key.Alg != -7 || key.Crv != 1 || len(key.X) != 32 || len(key.Y) != 32 {
		return nil, fmt.Errorf("not an ES256 P-256 key (kty %d alg %d crv %d)", key.Kty, key.Alg, key.Crv)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, key.X...), key.Y...))
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	a.PublicKey = pub
	return a, nil
}

// VerifyAssertion checks rpIdHash, the UP and UV flags and the signature over
// authData || clientDataHash, and returns the parsed authenticator data.
func VerifyAssertion(pub *ecdsa.PublicKey, rpID string, clientDataHash []byte, r *GetAssertionResponse) (*AuthData, error) {
	a, err := ParseAuthData(r.AuthData)
	if err != nil {
		return nil, err
	}
	want := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(a.RPIDHash, want[:]) {
		return nil, errors.New("rpIdHash does not match")
	}
	if a.Flags&(FlagUP|FlagUV) != FlagUP|FlagUV {
		return nil, fmt.Errorf("flags 0x%02x lack UP and UV", a.Flags)
	}
	digest := sha256.Sum256(append(append([]byte{}, r.AuthData...), clientDataHash...))
	if !ecdsa.VerifyASN1(pub, digest[:], r.Signature) {
		return nil, errors.New("signature does not verify")
	}
	return a, nil
}

func dec(b []byte, v any) error { return cbor.Unmarshal(b, v) }
