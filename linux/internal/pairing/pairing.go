// Package pairing builds and parses pairing URLs and prints them as QR codes.
package pairing

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"

	"rsc.io/qr"
)

// MaxNameBytes is the longest host name a pairing URL carries.
const MaxNameBytes = 64

// URL builds phonekey://pair?v=1&k=…&s=…&n=…
func URL(hostPub, psk []byte, name string) string {
	return fmt.Sprintf("phonekey://pair?v=1&k=%s&s=%s&n=%s",
		base64.RawURLEncoding.EncodeToString(hostPub),
		base64.RawURLEncoding.EncodeToString(psk),
		percentEncode(truncate(name, MaxNameBytes)))
}

// Pairing is the content of a parsed pairing URL.
type Pairing struct {
	HostKey []byte
	PSK     []byte
	Name    string
}

// Parse reads a pairing URL.
func Parse(s string) (Pairing, error) {
	u, err := url.Parse(s)
	if err != nil {
		return Pairing{}, err
	}
	if u.Scheme != "phonekey" || u.Host != "pair" {
		return Pairing{}, errors.New("not a phonekey pairing URL")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Pairing{}, err
	}
	if q.Get("v") != "1" {
		return Pairing{}, fmt.Errorf("unsupported pairing version %q", q.Get("v"))
	}
	k, err := base64.RawURLEncoding.DecodeString(q.Get("k"))
	if err != nil || len(k) != 32 {
		return Pairing{}, errors.New("bad host key")
	}
	psk, err := base64.RawURLEncoding.DecodeString(q.Get("s"))
	if err != nil || len(psk) != 32 {
		return Pairing{}, errors.New("bad secret")
	}
	return Pairing{HostKey: k, PSK: psk, Name: q.Get("n")}, nil
}

// percentEncode escapes everything except RFC 3986 unreserved characters, so
// both URL parsers and query parsers read it the same way ('+' stays '%2B').
func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-._~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// RenderQR prints text as a QR code using half-block characters, black on
// white so it scans on dark terminals too.
func RenderQR(w io.Writer, text string) error {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return err
	}
	const quiet = 2
	black := func(x, y int) bool {
		if x < 0 || y < 0 || x >= code.Size || y >= code.Size {
			return false
		}
		return code.Black(x, y)
	}
	for y := -quiet; y < code.Size+quiet; y += 2 {
		var line strings.Builder
		line.WriteString("\x1b[30;107m")
		for x := -quiet; x < code.Size+quiet; x++ {
			top, bottom := black(x, y), black(x, y+1)
			switch {
			case top && bottom:
				line.WriteString("█")
			case top:
				line.WriteString("▀")
			case bottom:
				line.WriteString("▄")
			default:
				line.WriteString(" ")
			}
		}
		line.WriteString("\x1b[0m\n")
		if _, err := io.WriteString(w, line.String()); err != nil {
			return err
		}
	}
	return nil
}
