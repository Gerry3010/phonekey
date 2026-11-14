package pairing

import (
	"bytes"
	"strings"
	"testing"
)

func TestURLRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xfe}, 32)
	psk := bytes.Repeat([]byte{0x01}, 32)
	for _, name := range []string{"workstation", "Geralds Rechner & Co+1", strings.Repeat("ä", 40)} {
		u := URL(key, psk, name)
		p, err := Parse(u)
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		if !bytes.Equal(p.HostKey, key) || !bytes.Equal(p.PSK, psk) {
			t.Fatal("keys differ")
		}
		if want := truncate(name, MaxNameBytes); p.Name != want {
			t.Fatalf("name %q, want %q", p.Name, want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, u := range []string{
		"https://pair?v=1",
		"phonekey://pair?v=2&k=AA&s=AA",
		"phonekey://pair?v=1&k=AA&s=AA",
	} {
		if _, err := Parse(u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

func TestRenderQR(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderQR(&buf, URL(make([]byte, 32), make([]byte, 32), "host")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "█") {
		t.Fatal("no modules rendered")
	}
}
