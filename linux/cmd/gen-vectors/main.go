// Command gen-vectors writes docs/protocol-vectors.json.
//
//	go run ./cmd/gen-vectors ../docs/protocol-vectors.json
package main

import (
	"log"
	"os"

	"github.com/Gerry3010/phonekey/linux/internal/proto"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: gen-vectors <output.json>")
	}
	b, err := proto.GenerateVectors()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(os.Args[1], b, 0o644); err != nil {
		log.Fatal(err)
	}
}
