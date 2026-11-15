package ctap

// PIN/UV auth protocols one and two (CTAP 2.1 §6.5.6 and §6.5.7), as far as a
// platform needs them for hmac-secret (§12.5). Written independently of the
// phone's Swift code, so the self-test checks one against the other.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// CmdClientPIN is authenticatorClientPIN.
const CmdClientPIN byte = 0x06

// PinUvAuthProtocol is protocol one or two.
type PinUvAuthProtocol int

const (
	PinUvAuthProtocolOne PinUvAuthProtocol = 1
	PinUvAuthProtocolTwo PinUvAuthProtocol = 2
)

// COSEKey is a P-256 key agreement key as CTAP sends it.
type COSEKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

type clientPINRequest struct {
	Protocol   PinUvAuthProtocol `cbor:"1,keyasint"`
	SubCommand int               `cbor:"2,keyasint"`
}

type keyAgreementResponse struct {
	KeyAgreement COSEKey `cbor:"1,keyasint"`
}

// KeyAgreement gets the authenticator's key agreement key (getKeyAgreement)
// and returns a fresh platform key and the shared secret with it.
func KeyAgreement(t Transport, p PinUvAuthProtocol) (platform COSEKey, shared []byte, err error) {
	var resp keyAgreementResponse
	if err := Call(t, CmdClientPIN, clientPINRequest{Protocol: p, SubCommand: 2}, &resp); err != nil {
		return COSEKey{}, nil, fmt.Errorf("getKeyAgreement: %w", err)
	}
	k := resp.KeyAgreement
	if k.Kty != 2 || k.Crv != 1 || len(k.X) != 32 || len(k.Y) != 32 {
		return COSEKey{}, nil, fmt.Errorf("key agreement key: kty %d crv %d", k.Kty, k.Crv)
	}
	peer, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, k.X...), k.Y...))
	if err != nil {
		return COSEKey{}, nil, fmt.Errorf("key agreement key: %w", err)
	}
	own, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return COSEKey{}, nil, err
	}
	z, err := own.ECDH(peer)
	if err != nil {
		return COSEKey{}, nil, err
	}
	raw := own.PublicKey().Bytes()
	return COSEKey{Kty: 2, Alg: -25, Crv: 1, X: raw[1:33], Y: raw[33:65]}, p.kdf(z), nil
}

// kdf turns the ECDH x coordinate into the shared secret: SHA-256 (one, 32
// bytes) or HKDF-SHA-256 into an HMAC key and an AES key (two, 64 bytes).
func (p PinUvAuthProtocol) kdf(z []byte) []byte {
	if p == PinUvAuthProtocolOne {
		sum := sha256.Sum256(z)
		return sum[:]
	}
	derive := func(info string) []byte {
		// Cannot fail: 32 bytes are far below HKDF-SHA-256's limit.
		out, _ := hkdf.Key(sha256.New, z, make([]byte, 32), info, 32)
		return out
	}
	return append(derive("CTAP2 HMAC key"), derive("CTAP2 AES key")...)
}

func (p PinUvAuthProtocol) aesKey(key []byte) []byte {
	if p == PinUvAuthProtocolTwo && len(key) == 64 {
		return key[32:]
	}
	return key
}

func (p PinUvAuthProtocol) hmacKey(key []byte) []byte {
	if p == PinUvAuthProtocolTwo && len(key) > 32 {
		return key[:32]
	}
	return key
}

// Encrypt is AES-256-CBC without padding: a zero IV (one), or a random IV sent
// in front of the ciphertext (two).
func (p PinUvAuthProtocol) Encrypt(key, plain []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if p == PinUvAuthProtocolTwo {
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}
	}
	return p.encrypt(key, plain, iv)
}

func (p PinUvAuthProtocol) encrypt(key, plain, iv []byte) ([]byte, error) {
	if len(plain)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the AES block size")
	}
	block, err := aes.NewCipher(p.aesKey(key))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	if p == PinUvAuthProtocolTwo {
		return append(append([]byte{}, iv...), out...), nil
	}
	return out, nil
}

// Decrypt reverses Encrypt.
func (p PinUvAuthProtocol) Decrypt(key, data []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if p == PinUvAuthProtocolTwo {
		if len(data) < aes.BlockSize {
			return nil, errors.New("ciphertext too short")
		}
		iv, data = data[:aes.BlockSize], data[aes.BlockSize:]
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the AES block size")
	}
	block, err := aes.NewCipher(p.aesKey(key))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return out, nil
}

// Authenticate is HMAC-SHA-256, the first 16 bytes (one) or all 32 (two).
func (p PinUvAuthProtocol) Authenticate(key, message []byte) []byte {
	m := hmac.New(sha256.New, p.hmacKey(key))
	m.Write(message)
	sum := m.Sum(nil)
	if p == PinUvAuthProtocolOne {
		return sum[:16]
	}
	return sum
}

// HmacSecretInput is the getAssertion extension input "hmac-secret".
type HmacSecretInput struct {
	KeyAgreement COSEKey           `cbor:"1,keyasint"`
	SaltEnc      []byte            `cbor:"2,keyasint"`
	SaltAuth     []byte            `cbor:"3,keyasint"`
	Protocol     PinUvAuthProtocol `cbor:"4,keyasint,omitempty"`
}

// NewHmacSecretInput encrypts and authenticates one or two 32-byte salts.
func NewHmacSecretInput(p PinUvAuthProtocol, platform COSEKey, shared []byte, salts ...[]byte) (HmacSecretInput, error) {
	if len(salts) < 1 || len(salts) > 2 {
		return HmacSecretInput{}, errors.New("one or two salts")
	}
	var plain []byte
	for _, s := range salts {
		if len(s) != 32 {
			return HmacSecretInput{}, errors.New("salts are 32 bytes")
		}
		plain = append(plain, s...)
	}
	saltEnc, err := p.Encrypt(shared, plain)
	if err != nil {
		return HmacSecretInput{}, err
	}
	in := HmacSecretInput{KeyAgreement: platform, SaltEnc: saltEnc, SaltAuth: p.Authenticate(shared, saltEnc)}
	if p != PinUvAuthProtocolOne {
		in.Protocol = p // absent means one
	}
	return in, nil
}
