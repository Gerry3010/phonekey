package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestTraceRequest(t *testing.T) {
	secretID := bytes.Repeat([]byte{0xAB}, 32)
	challenge := bytes.Repeat([]byte{0xCD}, 32)
	params, _ := cbor.Marshal(map[int]any{
		1: "example.org",
		2: challenge,
		3: []map[string]any{{"id": secretID, "type": "public-key"}},
		5: map[string]bool{"up": false},
		6: make([]byte, 32),
		7: 2,
	})
	got := traceRequest(append([]byte{0x02}, params...))
	want := "getAssertion: rp example.org; allowList 1; options up=false; pinUvAuthParam 32 bytes, protocol 2"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	// No secrets in the trace: neither the credential ID nor the challenge.
	for _, b := range [][]byte{secretID, challenge} {
		if strings.Contains(got, string(b)) || strings.Contains(got, "abab") || strings.Contains(got, "cdcd") {
			t.Fatal("trace leaks request bytes")
		}
	}

	params, _ = cbor.Marshal(map[int]any{1: 2, 2: 6, 3: map[int]any{1: 2}, 9: 2, 10: "example.org"})
	if got := traceRequest(append([]byte{0x06}, params...)); got != "clientPIN: protocol 2, subCommand 0x06; permissions 0x02; rp example.org" {
		t.Fatalf("clientPIN: %q", got)
	}
	if got := traceRequest([]byte{0x04}); got != "getInfo" {
		t.Fatalf("getInfo: %q", got)
	}
}

func TestTraceResponse(t *testing.T) {
	if got := traceResponse([]byte{0x00, 1, 2}); got != "OK (2 bytes)" {
		t.Fatal(got)
	}
	if got := traceResponse([]byte{0x33}); got != "CTAP2_ERR_PIN_AUTH_INVALID (0x33)" {
		t.Fatal(got)
	}
}
