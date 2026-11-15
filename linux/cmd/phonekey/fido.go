package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Gerry3010/phonekey/linux/internal/client"
	"github.com/Gerry3010/phonekey/linux/internal/ctap"
)

func fido(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: phonekey fido info|selftest|run")
	}
	switch args[0] {
	case "info":
		return fidoInfo(ctx, args[1:])
	case "selftest":
		return fidoSelftest(ctx, args[1:])
	case "run":
		return fidoRun(ctx, args[1:])
	default:
		return fmt.Errorf("unknown fido command %q", args[0])
	}
}

// transport sends CBOR messages over the session, waiting up to 90 s each
// (the phone gives the user 60 s).
func transport(ctx context.Context, s *client.Session) ctap.Transport {
	return func(msg []byte) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		return s.CTAP(ctx, 0x10, msg)
	}
}

func fidoInfo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("fido info", flag.ExitOnError)
	var cf connFlags
	cf.register(fs)
	fs.Parse(args)
	s, err := cf.session(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	var info ctap.Info
	if err := ctap.Call(transport(ctx, s), ctap.CmdGetInfo, nil, &info); err != nil {
		return err
	}
	fmt.Printf("Versions:    %v\nAAGUID:      %x\nOptions:     %v\nMax message: %d\nAlgorithms:  %v\n",
		info.Versions, info.AAGUID, info.Options, info.MaxMsgSize, info.Algorithms)
	return nil
}

// fidoSelftest registers a passkey for a test site, signs in with it twice
// and verifies everything on the host side, independently of the phone's code.
func fidoSelftest(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("fido selftest", flag.ExitOnError)
	var cf connFlags
	cf.register(fs)
	rpID := fs.String("rp", "phonekey.test", "relying party ID used for the test")
	fs.Parse(args)
	s, err := cf.session(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	call := transport(ctx, s)
	random := func(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
	check := func(ok bool, what string) error {
		if !ok {
			return errors.New("FAIL: " + what)
		}
		fmt.Println("  ok:", what)
		return nil
	}

	var info ctap.Info
	if err := ctap.Call(call, ctap.CmdGetInfo, nil, &info); err != nil {
		return err
	}
	fmt.Printf("getInfo: %v, AAGUID %x\n", info.Versions, info.AAGUID)
	// hmac-secret (Phase 3a) adds two sign-ins; older apps skip them.
	hmacSecret := slices.Contains(info.Extensions, "hmac-secret")
	steps := 3
	var extensions map[string]any
	if hmacSecret {
		steps = 5
		extensions = map[string]any{"hmac-secret": true}
	}

	userID, label, detail := selftestAccount(time.Now())
	fmt.Printf("\n1/%d Register a passkey for %s: confirm on the phone, then Touch ID.\n", steps, *rpID)
	var mc ctap.MakeCredentialResponse
	err = ctap.Call(call, ctap.CmdMakeCredential, ctap.MakeCredentialRequest{
		ClientDataHash: random(32),
		RP:             ctap.RP{ID: *rpID, Name: "PhoneKey self-test"},
		User:           ctap.User{ID: userID, Name: label, DisplayName: detail},
		Params:         []ctap.CredParam{{Alg: -7, Type: "public-key"}},
		Extensions:     extensions,
		Options:        map[string]bool{"rk": true},
	}, &mc)
	if err != nil {
		return err
	}
	reg, err := ctap.ParseAuthData(mc.AuthData)
	if err != nil {
		return err
	}
	rpHash := sha256.Sum256([]byte(*rpID))
	for _, c := range []struct {
		ok   bool
		what string
	}{
		{mc.Fmt == "none", "attestation format none"},
		{bytes.Equal(reg.RPIDHash, rpHash[:]), "rpIdHash"},
		{reg.Flags&0x45 == 0x45, "flags UP, UV, AT"},
		{reg.Counter == 0, "counter starts at 0"},
		{bytes.Equal(reg.AAGUID, info.AAGUID), "AAGUID matches getInfo"},
		{len(reg.CredentialID) == 32 && reg.PublicKey != nil, "credential ID and P-256 public key"},
		{!hmacSecret || reg.Extensions["hmac-secret"] == true, "hmac-secret confirmed"},
	} {
		if err := check(c.ok, c.what); err != nil {
			return err
		}
	}

	// Other computers' self-tests leave their own phonekey.test accounts, and
	// the phone preselects the one used last.
	fmt.Printf("\n2/%d Sign in with the passkey (no allow list): pick %q (under \"Other account\" if another one is preselected), then Touch ID.\n", steps, label)
	cdh := random(32)
	var ga ctap.GetAssertionResponse
	if err := ctap.Call(call, ctap.CmdGetAssertion, ctap.GetAssertionRequest{RPID: *rpID, ClientDataHash: cdh}, &ga); err != nil {
		return err
	}
	// Compare the credential first: a passkey from an earlier run would fail
	// the signature check against this run's key, which reads like a bug.
	if !bytes.Equal(ga.Credential.ID, reg.CredentialID) {
		return fmt.Errorf("FAIL: the phone signed with another %s passkey, not %q. Run the self-test again and pick %q under \"Other account\", or delete the other test passkeys in PhoneKey → Passkeys & security keys", *rpID, label, label)
	}
	fmt.Println("  ok: same credential")
	a1, err := ctap.VerifyAssertion(reg.PublicKey, *rpID, cdh, &ga)
	if err != nil {
		return errors.New("FAIL: " + err.Error())
	}
	if err := check(true, "signature, rpIdHash, UP and UV"); err != nil {
		return err
	}
	if err := check(ga.User != nil && bytes.Equal(ga.User.ID, userID), "user handle returned"); err != nil {
		return err
	}

	fmt.Printf("\n3/%d Sign in with an allow list: confirm, then Touch ID.\n", steps)
	cdh = random(32)
	allow := []ctap.Descriptor{{ID: reg.CredentialID, Type: "public-key"}}
	if err := ctap.Call(call, ctap.CmdGetAssertion, ctap.GetAssertionRequest{RPID: *rpID, ClientDataHash: cdh, Allow: allow}, &ga); err != nil {
		return err
	}
	a2, err := ctap.VerifyAssertion(reg.PublicKey, *rpID, cdh, &ga)
	if err != nil {
		return errors.New("FAIL: " + err.Error())
	}
	if err := check(a2.Counter > a1.Counter, fmt.Sprintf("counter increases (%d → %d)", a1.Counter, a2.Counter)); err != nil {
		return err
	}

	var st ctap.Status
	err = ctap.Call(call, ctap.CmdGetAssertion, ctap.GetAssertionRequest{RPID: "other." + *rpID, ClientDataHash: cdh, Allow: allow}, nil)
	if err := check(errors.As(err, &st) && st == 0x2E, "credential is bound to its site (NO_CREDENTIALS elsewhere)"); err != nil {
		return err
	}

	if hmacSecret {
		// The same salt must give the same secret (that is what unlocks LUKS),
		// whichever PIN/UV auth protocol carries it; another salt another one.
		salt1, salt2 := random(32), random(32)
		fmt.Printf("\n4/%d hmac-secret, protocol 2, one salt: confirm, then Touch ID.\n", steps)
		out2, err := selftestHmacSecret(call, *rpID, reg, allow, ctap.PinUvAuthProtocolTwo, salt1)
		if err != nil {
			return err
		}
		fmt.Printf("\n5/%d hmac-secret, protocol 1, two salts: confirm, then Touch ID.\n", steps)
		out1, err := selftestHmacSecret(call, *rpID, reg, allow, ctap.PinUvAuthProtocolOne, salt1, salt2)
		if err != nil {
			return err
		}
		if err := check(bytes.Equal(out1[:32], out2), "same salt, same secret (protocols 1 and 2)"); err != nil {
			return err
		}
		if err := check(!bytes.Equal(out1[32:], out2), "another salt, another secret"); err != nil {
			return err
		}
	} else {
		fmt.Println("\n(hmac-secret skipped: this PhoneKey does not offer it yet)")
	}

	fmt.Printf("\nPASS. The test passkey %q stays on the phone. The next self-test from this computer replaces it; to remove it, use PhoneKey → Passkeys & security keys.\n", label)
	return nil
}

// selftestHmacSecret signs in with the hmac-secret extension and returns the
// decrypted output: 32 bytes per salt.
func selftestHmacSecret(call ctap.Transport, rpID string, reg *ctap.AuthData, allow []ctap.Descriptor,
	p ctap.PinUvAuthProtocol, salts ...[]byte) ([]byte, error) {
	platform, shared, err := ctap.KeyAgreement(call, p)
	if err != nil {
		return nil, err
	}
	in, err := ctap.NewHmacSecretInput(p, platform, shared, salts...)
	if err != nil {
		return nil, err
	}
	cdh := make([]byte, 32)
	rand.Read(cdh)
	var ga ctap.GetAssertionResponse
	err = ctap.Call(call, ctap.CmdGetAssertion, ctap.GetAssertionRequest{
		RPID: rpID, ClientDataHash: cdh, Allow: allow,
		Extensions: map[string]any{"hmac-secret": in},
	}, &ga)
	if err != nil {
		return nil, err
	}
	a, err := ctap.VerifyAssertion(reg.PublicKey, rpID, cdh, &ga)
	if err != nil {
		return nil, errors.New("FAIL: " + err.Error())
	}
	sealed, ok := a.Extensions["hmac-secret"].([]byte)
	if !ok {
		return nil, errors.New("FAIL: no hmac-secret output in the assertion")
	}
	out, err := p.Decrypt(shared, sealed)
	if err != nil || len(out) != 32*len(salts) {
		return nil, fmt.Errorf("FAIL: hmac-secret output (%d bytes, %v)", len(out), err)
	}
	fmt.Printf("  ok: signature over the extension, %d-byte secret\n", len(out))
	return out, nil
}

// selftestAccount names the test account after this computer, the same name
// the phone shows as "Request from …". The user ID depends only on that name,
// so each run from the same computer registers the same account again, and the
// phone replaces the old passkey instead of collecting one per run.
func selftestAccount(now time.Time) (userID []byte, name, displayName string) {
	host, _ := os.Hostname()
	if short, _, _ := strings.Cut(host, "."); short != "" {
		host = short
	} else {
		host = "this computer"
	}
	sum := sha256.Sum256([]byte("phonekey self-test\x00" + host))
	name = "Self-test from " + host
	return sum[:16], name, name + ", " + now.Format("2 Jan 2006 15:04")
}
