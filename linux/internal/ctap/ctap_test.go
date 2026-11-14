package ctap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

// fakeAuthenticator answers like docs/protocol.md §10 with a software key.
func fakeAuthenticator(t *testing.T) (Transport, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := make([]byte, 32)
	rand.Read(credID)
	var counter uint32
	return func(msg []byte) ([]byte, error) {
		switch msg[0] {
		case CmdMakeCredential:
			var req MakeCredentialRequest
			if err := dec(msg[1:], &req); err != nil {
				return []byte{0x12}, nil
			}
			h := sha256.Sum256([]byte(req.RP.ID))
			ad := append(h[:], FlagUP|FlagUV|FlagAT, 0, 0, 0, 0)
			ad = append(ad, make([]byte, 16)...)
			ad = binary.BigEndian.AppendUint16(ad, uint16(len(credID)))
			ad = append(ad, credID...)
			pub, _ := key.PublicKey.Bytes()
			cose, _ := enc.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: pub[1:33], -3: pub[33:]})
			ad = append(ad, cose...)
			b, _ := enc.Marshal(MakeCredentialResponse{Fmt: "none", AuthData: ad, AttStmt: []byte{0xa0}})
			return append([]byte{0}, b...), nil
		case CmdGetAssertion:
			var req GetAssertionRequest
			if err := dec(msg[1:], &req); err != nil {
				return []byte{0x12}, nil
			}
			if req.RPID != "example.org" {
				return []byte{0x2E}, nil
			}
			counter++
			h := sha256.Sum256([]byte(req.RPID))
			ad := binary.BigEndian.AppendUint32(append(h[:], FlagUP|FlagUV), counter)
			digest := sha256.Sum256(append(append([]byte{}, ad...), req.ClientDataHash...))
			sig, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
			b, _ := enc.Marshal(GetAssertionResponse{Credential: Descriptor{ID: credID, Type: "public-key"}, AuthData: ad, Signature: sig})
			return append([]byte{0}, b...), nil
		}
		return []byte{0x01}, nil
	}, key
}

func TestRegisterAndVerify(t *testing.T) {
	tr, key := fakeAuthenticator(t)
	var mc MakeCredentialResponse
	err := Call(tr, CmdMakeCredential, MakeCredentialRequest{
		ClientDataHash: make([]byte, 32), RP: RP{ID: "example.org"}, User: User{ID: []byte{1}},
		Params: []CredParam{{Alg: -7, Type: "public-key"}}, Options: map[string]bool{"rk": true},
	}, &mc)
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseAuthData(mc.AuthData)
	if err != nil {
		t.Fatal(err)
	}
	if !a.PublicKey.Equal(&key.PublicKey) || len(a.CredentialID) != 32 || a.Flags != 0x45 {
		t.Fatalf("parsed %+v", a)
	}

	cdh := sha256.Sum256([]byte("client data"))
	var ga GetAssertionResponse
	if err := Call(tr, CmdGetAssertion, GetAssertionRequest{RPID: "example.org", ClientDataHash: cdh[:]}, &ga); err != nil {
		t.Fatal(err)
	}
	got, err := VerifyAssertion(a.PublicKey, "example.org", cdh[:], &ga)
	if err != nil || got.Counter != 1 {
		t.Fatalf("verify: %v %+v", err, got)
	}
	if _, err := VerifyAssertion(a.PublicKey, "example.org", make([]byte, 32), &ga); err == nil {
		t.Fatal("signature verified for a different clientDataHash")
	}
	if _, err := VerifyAssertion(a.PublicKey, "evil.example", cdh[:], &ga); err == nil {
		t.Fatal("rpIdHash check passed for the wrong rpId")
	}

	err = Call(tr, CmdGetAssertion, GetAssertionRequest{RPID: "evil.example", ClientDataHash: cdh[:]}, &ga)
	var st Status
	if !errors.As(err, &st) || st != 0x2E || st.Error() != "CTAP2_ERR_NO_CREDENTIALS (0x2e)" {
		t.Fatalf("status: %v", err)
	}
}

func TestParseAuthDataRejects(t *testing.T) {
	if _, err := ParseAuthData(make([]byte, 36)); err == nil {
		t.Fatal("short authData accepted")
	}
	ad := append(make([]byte, 32), FlagAT, 0, 0, 0, 0)
	ad = append(ad, make([]byte, 16)...)
	ad = append(ad, 0, 40, 1, 2) // claims a 40-byte credential ID
	if _, err := ParseAuthData(ad); err == nil {
		t.Fatal("truncated credential ID accepted")
	}
}
