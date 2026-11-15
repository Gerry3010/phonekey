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

	userID, label, detail := selftestAccount(time.Now())
	fmt.Printf("\n1/3 Register a passkey for %s: confirm on the phone, then Touch ID.\n", *rpID)
	var mc ctap.MakeCredentialResponse
	err = ctap.Call(call, ctap.CmdMakeCredential, ctap.MakeCredentialRequest{
		ClientDataHash: random(32),
		RP:             ctap.RP{ID: *rpID, Name: "PhoneKey self-test"},
		User:           ctap.User{ID: userID, Name: label, DisplayName: detail},
		Params:         []ctap.CredParam{{Alg: -7, Type: "public-key"}},
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
	} {
		if err := check(c.ok, c.what); err != nil {
			return err
		}
	}

	fmt.Printf("\n2/3 Sign in with the passkey (no allow list): pick %q, then Touch ID.\n", label)
	cdh := random(32)
	var ga ctap.GetAssertionResponse
	if err := ctap.Call(call, ctap.CmdGetAssertion, ctap.GetAssertionRequest{RPID: *rpID, ClientDataHash: cdh}, &ga); err != nil {
		return err
	}
	// Compare the credential first: a passkey from an earlier run would fail
	// the signature check against this run's key, which reads like a bug.
	if !bytes.Equal(ga.Credential.ID, reg.CredentialID) {
		return fmt.Errorf("FAIL: the phone signed with an older %s passkey. Delete the old test passkeys in PhoneKey → Passkeys & security keys and run the self-test again", *rpID)
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

	fmt.Println("\n3/3 Sign in with an allow list: confirm, then Touch ID.")
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

	fmt.Printf("\nPASS. The test passkey %q stays on the phone. The next self-test from this computer replaces it; to remove it, use PhoneKey → Passkeys & security keys.\n", label)
	return nil
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
