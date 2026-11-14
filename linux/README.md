# linux/: the host side

`phonekey` is the host side of [docs/protocol.md](../docs/protocol.md). It targets
Linux and also runs on macOS, where it uses the Mac's built-in usbmuxd. That is
how the iOS app is tested against a real iPhone.

## Build

Go 1.21 or later. `go` fetches the toolchain named in `go.mod` by itself.

```bash
go build ./cmd/phonekey
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/phonekey   # static Linux binary
go test ./...
```

## Linux setup

- `usbmuxd` must be running (package `usbmuxd`; it starts when an iPhone is plugged in).
- The iPhone must trust the computer: unlock it, plug it in, tap "Trust", or run
  `idevicepair pair` (package `libimobiledevice-utils`).

## Use

```bash
phonekey devices          # is the iPhone visible?
phonekey pair             # shows a QR code; scan it in PhoneKey
phonekey status
phonekey photo -o desk.jpg
```

The PhoneKey app must be open on the phone; iOS stops it in the background.
`-connect tcp:127.0.0.1:20555` talks to the app in the iOS Simulator instead.

Keys live in `~/.config/phonekey` (macOS: `~/Library/Application Support/phonekey`):
`host.key` (mode 0600) and `phones.json`.

## Layout

```
cmd/phonekey        CLI
cmd/gen-vectors     writes docs/protocol-vectors.json
internal/proto      preamble, framing, Noise handshake (flynn/noise), messages
internal/client     connect, pair, requests
internal/usbmux     usbmuxd client
internal/store      host key and paired phones
internal/pairing    pairing URL and terminal QR code
```

After a protocol change: `go run ./cmd/gen-vectors ../docs/protocol-vectors.json`.
A test fails if the file is out of date.
