# linux/: the host side

`phonekey` is the host side of [docs/protocol.md](../docs/protocol.md). It targets
Linux and also runs on macOS, where it uses the Mac's built-in usbmuxd. That is
how the iOS app is tested against a real iPhone. The security key itself
(`phonekey fido run`) needs Linux.

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

## Security key (FIDO2) and passkeys

`phonekey fido run` creates a virtual USB security key while the phone is
connected and the app is open. Browsers, `ssh` and anything else built on
libfido2 see an ordinary FIDO2 key. Every registration and sign-in shows the
site on the phone and needs Touch ID.

One-time setup (needs root once):

```bash
sudo install -m 0755 phonekey /usr/local/bin/phonekey
sudo install -m 0644 contrib/90-phonekey-uhid.rules /etc/udev/rules.d/
echo uhid | sudo tee /etc/modules-load.d/uhid.conf
sudo modprobe uhid
sudo groupadd -f -r uhid && sudo usermod -aG uhid "$USER"
sudo udevadm control --reload && sudo udevadm trigger
# log out and in again for the group, then:
phonekey pair
mkdir -p ~/.config/systemd/user && cp contrib/phonekey-fido.service ~/.config/systemd/user/
systemctl --user enable --now phonekey-fido
```

The key's `/dev/hidraw*` node is opened up to the logged-in user by systemd's
own rule (`60-fido-id.rules`), as for any FIDO key. Check with `fido2-token -L`
(package `fido2-tools`).

Then:

- **Websites:** choose "security key" or "passkey on another device / USB key"
  in Chrome or Firefox.
- **SSH:** `ssh-keygen -t ecdsa-sk` (optionally `-O resident -O verify-required`).
  For `verify-required` keys OpenSSH asks for a PIN: just press Enter, Touch ID
  is the verification.
- **Diagnostics without Linux:** `phonekey fido info` and `phonekey fido selftest`
  work on macOS too and check the phone's authenticator from the host side.

Not supported yet: listing resident keys (`ssh-keygen -K`, browser key
management), `hmac-secret` (LUKS via `systemd-cryptenroll`), U2F-only sites, PINs.
Keys are bound to this iPhone and not backed up: keep a second way to sign in
everywhere.

## Layout

```
cmd/phonekey        CLI (fido_linux.go: the security key daemon)
cmd/gen-vectors     writes docs/protocol-vectors.json
contrib/            udev rule, systemd user unit
internal/proto      preamble, framing, Noise handshake (flynn/noise), messages
internal/client     connect, pair, requests, Mux for concurrent requests
internal/ctap       CTAP2 client for diagnostics (fxamacker/cbor)
internal/ctaphid    device side of CTAPHID (pure Go)
internal/uhid       /dev/uhid (Linux only)
internal/usbmux     usbmuxd client
internal/store      host key and paired phones
internal/pairing    pairing URL and terminal QR code
```

After a protocol change: `go run ./cmd/gen-vectors ../docs/protocol-vectors.json`.
A test fails if the file is out of date.
