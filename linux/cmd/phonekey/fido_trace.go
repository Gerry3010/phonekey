package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Gerry3010/phonekey/linux/internal/ctap"
	"github.com/fxamacker/cbor/v2"
)

// traceRequest describes a CTAP CBOR request for `fido run -trace`: the
// command, the RP ID, options, list lengths, extension names and whether a
// pinUvAuthParam came along. Never keys, challenges, credential or user IDs.
func traceRequest(req []byte) string {
	if len(req) == 0 {
		return "empty request"
	}
	names := map[byte]string{
		0x01: "makeCredential", 0x02: "getAssertion", 0x04: "getInfo", 0x06: "clientPIN",
		0x07: "reset", 0x08: "getNextAssertion", 0x0A: "credentialManagement", 0x0B: "selection",
	}
	name, ok := names[req[0]]
	if !ok {
		name = fmt.Sprintf("command 0x%02x", req[0])
	}
	var p map[int]cbor.RawMessage
	if len(req) > 1 {
		if err := cbor.Unmarshal(req[1:], &p); err != nil {
			return name + " (parameters not readable)"
		}
	}
	var parts []string
	add := func(format string, a ...any) { parts = append(parts, fmt.Sprintf(format, a...)) }
	text := func(key int) (s string) { cbor.Unmarshal(p[key], &s); return }
	count := func(key int) int { var l []cbor.RawMessage; cbor.Unmarshal(p[key], &l); return len(l) }
	keys := func(key int) string {
		var m map[string]cbor.RawMessage
		cbor.Unmarshal(p[key], &m)
		var k []string
		for n := range m {
			k = append(k, n)
		}
		slices.Sort(k)
		return strings.Join(k, ",")
	}
	options := func(key int) string {
		var m map[string]bool
		cbor.Unmarshal(p[key], &m)
		var k []string
		for n, v := range m {
			k = append(k, fmt.Sprintf("%s=%t", n, v))
		}
		slices.Sort(k)
		return strings.Join(k, ",")
	}
	puap := func(paramKey, protoKey int) {
		var b []byte
		if p[paramKey] == nil {
			return
		}
		cbor.Unmarshal(p[paramKey], &b)
		var proto int
		cbor.Unmarshal(p[protoKey], &proto)
		add("pinUvAuthParam %d bytes, protocol %d", len(b), proto)
	}
	switch req[0] {
	case 0x01:
		var rp struct {
			ID string `cbor:"id"`
		}
		cbor.Unmarshal(p[2], &rp)
		add("rp %s", rp.ID)
		if n := count(5); n > 0 {
			add("excludeList %d", n)
		}
		if e := keys(6); e != "" {
			add("extensions %s", e)
		}
		if o := options(7); o != "" {
			add("options %s", o)
		}
		puap(8, 9)
	case 0x02:
		add("rp %s", text(1))
		add("allowList %d", count(3))
		if e := keys(4); e != "" {
			add("extensions %s", e)
		}
		if o := options(5); o != "" {
			add("options %s", o)
		}
		puap(6, 7)
	case 0x06:
		var proto, sub, perms int
		cbor.Unmarshal(p[1], &proto)
		cbor.Unmarshal(p[2], &sub)
		add("protocol %d, subCommand 0x%02x", proto, sub)
		if cbor.Unmarshal(p[9], &perms) == nil && p[9] != nil {
			add("permissions 0x%02x", perms)
		}
		if rp := text(10); rp != "" {
			add("rp %s", rp)
		}
	case 0x0A:
		var sub int
		cbor.Unmarshal(p[1], &sub)
		add("subCommand 0x%02x", sub)
		if p[4] != nil {
			add("with pinUvAuthParam")
		}
	}
	if len(parts) == 0 {
		return name
	}
	return name + ": " + strings.Join(parts, "; ")
}

// traceResponse names the status of a response.
func traceResponse(resp []byte) string {
	switch {
	case len(resp) == 0:
		return "empty response"
	case resp[0] == 0:
		return fmt.Sprintf("OK (%d bytes)", len(resp)-1)
	default:
		return ctap.Status(resp[0]).Error()
	}
}
