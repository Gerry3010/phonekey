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
sudo install -m 0644 contrib/70-phonekey-uhid.rules /etc/udev/rules.d/
echo uhid | sudo tee /etc/modules-load.d/uhid.conf
sudo udevadm control --reload
sudo modprobe uhid
sudo udevadm trigger --action=add --subsystem-match=misc --sysname-match=uhid
getfacl -p /dev/uhid      # should list your user with rw-
phonekey pair             # needs the phone; enable the service only after this
mkdir -p ~/.config/systemd/user && cp contrib/phonekey-fido.service ~/.config/systemd/user/
systemctl --user enable --now phonekey-fido
```

The udev rule tags `/dev/uhid` with `uaccess`, so systemd-logind gives the user
logged in at the machine access to it, the way it handles `/dev/uinput` for game
controllers. There is no group to join and no need to log out. The access ends
with the local session, so a login over SSH alone cannot start the key. Like
any `/dev/uhid` access, it lets your user create other virtual HID devices too,
keyboards included.

On a machine you only reach over SSH, such as a test VM (`limactl shell`), there
is no local session and `uaccess` grants nothing. Use a group there instead:

```bash
sudo groupadd -f -r uhid && sudo usermod -aG uhid "$USER"
echo 'KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="uhid", MODE="0660"' \
  | sudo tee /etc/udev/rules.d/70-phonekey-uhid.rules
sudo udevadm control --reload && sudo modprobe uhid
sudo udevadm trigger --action=add --subsystem-match=misc --sysname-match=uhid
# log in again for the group
```

Before this, the setup used that group with `90-phonekey-uhid.rules` on every
machine. On a desktop, remove `/etc/udev/rules.d/90-phonekey-uhid.rules` when you
switch to the `uaccess` rule.

Enable the service only after `phonekey pair`: if an unpaired phone is connected,
`phonekey fido run` exits with an error and systemd would restart it every five
seconds.

The key's `/dev/hidraw*` node is opened up to the logged-in user by systemd's
own rule (`60-fido-id.rules`), as for any FIDO key. Check with `fido2-token -L`
(package `fido2-tools`).

Then:

- **Websites:** choose "security key" or "passkey on another device / USB key"
  in Chrome or Firefox. Both first ask the phone for a token ("Sign in to …",
  Touch ID) and then sign in with it, without a second Touch ID.
- **SSH:** `ssh-keygen -t ecdsa-sk` (optionally `-O resident -O verify-required`).
  For `verify-required` keys without a PIN set, OpenSSH still asks for one: just
  press Enter, Touch ID is the verification. `ssh-keygen -K` and `ssh-add -K`
  load resident keys from the phone and need a PIN (see below).
- **Managing passkeys:** `fido2-token -L -r` lists the sites, `-L -k <site>`
  their passkeys, and `-D -i <id>` deletes one after a tap on the phone. Each
  call asks for Touch ID. Chrome's list under `chrome://settings/securityKeys`
  needs a PIN.
- **PIN:** only for programs that insist on one (`ssh-keygen -K`, `ssh-add -K`,
  Chrome's key management). Set it with `fido2-token -S` or in PhoneKey →
  Security key PIN, change it with `fido2-token -C`. Every use still needs
  Touch ID on the phone. There are 8 tries, and three wrong PINs in a row block
  PIN use until the phone reconnects. A forgotten PIN is removed in the app;
  the passkeys stay.
- **Diagnostics without Linux:** `phonekey fido info` and `phonekey fido selftest`
  work on macOS too and check the phone's authenticator from the host side. If
  the phone offers `hmac-secret`, the self-test also checks it with both PIN/UV
  auth protocols: the same salt must give the same secret (what unlocks LUKS).
- **When an application fails:** stop the service and run
  `phonekey fido run -trace`. It logs each CTAP request with its command, RP ID,
  options, list lengths and extension names, and the phone's status code. It
  never logs keys, challenges, credential IDs or user IDs.
  ```bash
  systemctl --user stop phonekey-fido
  phonekey fido run -trace
  systemctl --user start phonekey-fido   # afterwards
  ```

Not supported: sites that only speak U2F (CTAP1). Keys are bound to this iPhone
and not backed up: keep a second way to sign in everywhere.

### Disk encryption (LUKS)

The phone supports `hmac-secret` (Phase 3a), so `systemd-cryptenroll` can add it
to a LUKS2 volume as a FIDO2 key. Opening the volume then needs the phone with
the app open, and one Touch ID.

```bash
sudo systemd-cryptenroll --fido2-device=auto \
  --fido2-with-client-pin=no --fido2-with-user-verification=yes /dev/sdXN
sudo systemd-cryptsetup attach data /dev/sdXN - fido2-device=auto
```

- Enrolling asks for Touch ID twice: systemd creates a key on the phone, then
  reads the secret once. Every open asks once.
- This works for volumes you open after logging in, while `phonekey fido run`
  is running, such as data partitions and external disks. The root volume at
  boot would need the daemon and usbmuxd in the initramfs and is not covered.
- `--fido2-with-client-pin=no` keeps Touch ID as the only check once the phone
  has a PIN (Phase 3c). Without it, systemd would ask for that PIN.
- Keep the passphrase key slot: the secret behind the FIDO2 slot exists only on
  this phone. `sudo systemd-cryptenroll --wipe-slot=fido2 /dev/sdXN` removes the
  FIDO2 slot again.
- The key appears in PhoneKey under `io.systemd.cryptsetup`. Deleting it there
  makes the FIDO2 slot useless; the passphrase still opens the volume.

Tested with a LUKS2 file on the iPhone 7: `systemd-cryptenroll` as above,
`cryptsetup open --token-only --test-passphrase` and `systemd-cryptsetup attach`.

## Webcam (Phase 4a)

`phonekey camera run` turns the phone's camera into a webcam: a v4l2loopback
device that browsers, video call apps and OBS can open. While no application
reads it, it shows a still placeholder and the phone does not film. When an
application starts reading, the host asks the phone for a stream, and when it
stops, the stream stops too. The phone needs the PhoneKey app with Phase 4a and
the webcam switched on in the app.

One-time setup (needs root once):

```bash
# the headers for your kernel (Manjaro: e.g. linux72-headers), then the module
sudo pacman -S linux72-headers v4l2loopback-dkms     # Debian/Ubuntu: v4l2loopback-dkms
echo v4l2loopback | sudo tee /etc/modules-load.d/v4l2loopback.conf
echo 'options v4l2loopback devices=1 video_nr=10 card_label="PhoneKey" exclusive_caps=1' \
  | sudo tee /etc/modprobe.d/v4l2loopback.conf
sudo modprobe v4l2loopback
cp contrib/phonekey-camera.service ~/.config/systemd/user/
systemctl --user enable --now phonekey-camera
```

- Options: `-camera front|back` (default front), `-quality 720p|1080p` (default
  720p), `-fps 15` to `30`, `-device` (default `/dev/video10`).
- The webcam always has the size of `-quality`. If the phone delivers less
  (it may in portrait), the host scales up.
- With `exclusive_caps=1`, applications see the webcam only while
  `phonekey camera run` is running.
- One application at a time can stream from the webcam; a second one gets
  "Device or resource busy".
- Decoding uses `ffmpeg` and adds about 67 ms, two frames at 30 fps.
- The tests that need the real device run with
  `PHONEKEY_TEST_V4L2=/dev/video10 go test ./...`.

## Layout

```
cmd/phonekey        CLI (fido_linux.go: the security key daemon, camera_linux.go: the webcam)
cmd/gen-vectors     writes docs/protocol-vectors.json
contrib/            udev rule, systemd user units (fido, camera)
internal/proto      preamble, framing, Noise handshake (flynn/noise), messages
internal/client     connect, pair, requests, Mux for concurrent requests
internal/ctap       CTAP2 client for diagnostics (fxamacker/cbor)
internal/ctaphid    device side of CTAPHID (pure Go)
internal/uhid       /dev/uhid (Linux only)
internal/v4l2out    v4l2loopback producer and reader events (Linux only)
internal/camera     webcam frames, ffmpeg decoder, placeholder picture
internal/testphone  a phone for tests: handshake, pairing, CTAP, webcam
internal/usbmux     usbmuxd client
internal/store      host key and paired phones
internal/pairing    pairing URL and terminal QR code
```

After a protocol change: `go run ./cmd/gen-vectors ../docs/protocol-vectors.json`.
A test fails if the file is out of date.
