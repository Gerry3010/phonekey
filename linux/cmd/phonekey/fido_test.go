package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestSelftestAccount(t *testing.T) {
	first := time.Date(2026, 11, 15, 1, 12, 0, 0, time.UTC)
	id1, name1, display1 := selftestAccount(first)
	id2, name2, display2 := selftestAccount(first.Add(26 * time.Hour))

	// The phone replaces a passkey with the same site and user ID, so every
	// run from one computer must reuse both.
	if !bytes.Equal(id1, id2) || name1 != name2 {
		t.Fatalf("account changes between runs: %x %q, %x %q", id1, name1, id2, name2)
	}
	if len(id1) != 16 {
		t.Errorf("user ID is %d bytes, want 16", len(id1))
	}
	if !strings.HasPrefix(name1, "Self-test from ") || strings.Contains(name1, ".") {
		t.Errorf("name %q: want a short host name after %q", name1, "Self-test from ")
	}
	if display1 != name1+", 15 Nov 2026 01:12" || display2 != name2+", 16 Nov 2026 03:12" {
		t.Errorf("display names %q, %q: want the name plus the time of the run", display1, display2)
	}
}
