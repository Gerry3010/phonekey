package proto

import (
	"bytes"
	"os"
	"testing"
)

// TestVectorsUpToDate keeps docs/protocol-vectors.json in sync with the code.
// Regenerate with: go run ./cmd/gen-vectors ../docs/protocol-vectors.json
func TestVectorsUpToDate(t *testing.T) {
	want, err := GenerateVectors()
	if err != nil {
		t.Fatal(err)
	}
	again, _ := GenerateVectors()
	if !bytes.Equal(want, again) {
		t.Fatal("vectors are not deterministic")
	}
	got, err := os.ReadFile("../../../docs/protocol-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("docs/protocol-vectors.json is out of date; regenerate it")
	}
}
