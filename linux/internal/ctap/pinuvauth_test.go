package ctap

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// AES-256 of a zero block under a zero key; with a zero IV it is also the
// first CBC block.
const aesZeroBlock = "dc95c078a2408989ad48a21492842087"

func TestEncryptKnownAnswer(t *testing.T) {
	got, err := PinUvAuthProtocolOne.Encrypt(make([]byte, 32), make([]byte, 16))
	if err != nil || !bytes.Equal(got, mustHex(t, aesZeroBlock)) {
		t.Fatalf("protocol one: %x %v", got, err)
	}
	// Protocol two: the AES key is the second half, the IV goes in front.
	got, err = PinUvAuthProtocolTwo.encrypt(make([]byte, 64), make([]byte, 16), make([]byte, 16))
	want := append(make([]byte, 16), mustHex(t, aesZeroBlock)...)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("protocol two: %x %v", got, err)
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	for _, p := range []PinUvAuthProtocol{PinUvAuthProtocolOne, PinUvAuthProtocolTwo} {
		key := make([]byte, 32*int(p))
		rand.Read(key)
		plain := make([]byte, 64)
		rand.Read(plain)
		sealed, err := p.Encrypt(key, plain)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := p.Decrypt(key, sealed); err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("protocol %d: round trip failed: %v", p, err)
		}
		if _, err := p.Decrypt(key, sealed[:len(sealed)-1]); err == nil {
			t.Fatalf("protocol %d: a broken length must fail", p)
		}
	}
}

// RFC 4231 test case 2.
func TestAuthenticateKnownAnswer(t *testing.T) {
	key, msg := []byte("Jefe"), []byte("what do ya want for nothing?")
	mac := mustHex(t, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
	if got := PinUvAuthProtocolOne.Authenticate(key, msg); !bytes.Equal(got, mac[:16]) {
		t.Fatalf("protocol one: %x", got)
	}
	if got := PinUvAuthProtocolTwo.Authenticate(key, msg); !bytes.Equal(got, mac) {
		t.Fatalf("protocol two: %x", got)
	}
}

func TestKdfLengths(t *testing.T) {
	a, _ := ecdh.P256().GenerateKey(rand.Reader)
	b, _ := ecdh.P256().GenerateKey(rand.Reader)
	z1, _ := a.ECDH(b.PublicKey())
	z2, _ := b.ECDH(a.PublicKey())
	for _, p := range []PinUvAuthProtocol{PinUvAuthProtocolOne, PinUvAuthProtocolTwo} {
		if !bytes.Equal(p.kdf(z1), p.kdf(z2)) || len(p.kdf(z1)) != 32*int(p) {
			t.Fatalf("protocol %d: kdf", p)
		}
	}
}

func TestNewHmacSecretInput(t *testing.T) {
	shared := make([]byte, 64)
	rand.Read(shared)
	in, err := NewHmacSecretInput(PinUvAuthProtocolTwo, COSEKey{}, shared, make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if len(in.SaltEnc) != 16+64 || len(in.SaltAuth) != 32 || in.Protocol != 2 {
		t.Fatalf("protocol two input: %d %d %d", len(in.SaltEnc), len(in.SaltAuth), in.Protocol)
	}
	if !bytes.Equal(in.SaltAuth, PinUvAuthProtocolTwo.Authenticate(shared, in.SaltEnc)) {
		t.Fatal("saltAuth must authenticate saltEnc")
	}
	in, _ = NewHmacSecretInput(PinUvAuthProtocolOne, COSEKey{}, shared[:32], make([]byte, 32))
	if in.Protocol != 0 || len(in.SaltEnc) != 32 || len(in.SaltAuth) != 16 {
		t.Fatal("protocol one input: key 4 absent, no IV, 16-byte MAC")
	}
	if _, err := NewHmacSecretInput(PinUvAuthProtocolOne, COSEKey{}, shared[:32], make([]byte, 16)); err == nil {
		t.Fatal("a short salt must fail")
	}
}
