# phonekey

Turn an old iPhone into a desk peripheral for a Linux machine: a Touch-ID-gated
FIDO2 security key and passkey store, a camera and a microphone.

> **Experimental.** Do not use phonekey as your only security key. Always keep a
> second key or a recovery method for every account you protect with it.

## Idea

An iPhone 7 (iOS 15) sits on the desk, permanently connected to the Linux machine
over USB, with the app always in the foreground. A daemon on Linux turns what the
phone offers into ordinary Linux devices:

| Phone | Linux |
|---|---|
| FIDO2 authenticator, keys in the Secure Enclave, Touch ID per signature | virtual USB security key via `/dev/uhid` (browsers, `ssh`, `pam-u2f`) |
| Camera | webcam via `v4l2loopback`, or single photos on request |
| Microphone | PipeWire source, or recordings on request |

More in [docs/architecture.md](docs/architecture.md). The contract between phone
and daemon is [docs/protocol.md](docs/protocol.md). A walkthrough in German with
diagrams of every flow is in [docs/how-it-works.de.html](docs/how-it-works.de.html)
(download it and open it in a browser; GitHub shows HTML only as source).

## Status

- **Phase 1:** encrypted USB session, QR pairing, status, photos, desk mode.
  Verified on an iPhone 7 with iOS 15.8.2 over USB.
- **Phase 2:** FIDO2 security key and passkeys. The phone is the authenticator
  (Secure Enclave, Touch ID per use); `phonekey fido run` exposes it on Linux as
  a USB security key. Verified in an Ubuntu VM with libfido2 and OpenSSH
  (`ssh-keygen -t ecdsa-sk`, resident and `verify-required`), and on the iPhone 7
  with real Touch ID through `phonekey fido selftest`. Chrome and Firefox on real
  Linux work.
- **Phase 3a:** `hmac-secret` with PIN/UV auth protocols 1 and 2, for LUKS
  through `systemd-cryptenroll`. Verified in an Ubuntu VM (enroll and unlock a
  LUKS2 file) and on the iPhone 7 with real Linux (`systemd-cryptenroll`,
  `systemd-cryptsetup attach`, one Touch ID per unlock).
- **Phase 3b:** CTAP 2.1 (`FIDO_2_1`) with a `pinUvAuthToken` via Touch ID,
  credential management and `authenticatorSelection`. `fido2-token -L` and `-D`
  list and delete passkeys with Touch ID alone, no PIN. Verified in an Ubuntu
  VM with libfido2 and python-fido2 against the Simulator, and on the iPhone 7
  with real Linux: `fido2-token -L` and `-D`, and Chrome and Firefox signing in
  through the token with one Touch ID.
- **Phase 3c:** a PIN for `ssh-keygen -K`, `ssh-add -K` and Chrome's key
  management, which insist on one. It only works together with Touch ID: every
  token issued against the PIN also needs Touch ID on the phone. Set it from the
  computer (`fido2-token -S`) or in the app. Verified in an Ubuntu VM against the
  Simulator (OpenSSH resident and `verify-required` keys with PIN, `-K`, LUKS
  without PIN), and on the iPhone 7 with real Linux: `fido2-token -S` and `-C`,
  `ssh-keygen -K`, Chrome's key management, LUKS without PIN, and three wrong
  PINs in a row blocking until the phone reconnects.

The roadmap is in [docs/architecture.md](docs/architecture.md#roadmap).

```bash
cd linux && go build ./cmd/phonekey
./phonekey pair            # scan the QR code with PhoneKey → Pair new computer
./phonekey status
./phonekey fido run        # Linux: USB security key while the phone is connected
```

Setup for the security key: [linux/README.md](linux/README.md#security-key-fido2-and-passkeys).

## Layout

```
ios/            iOS app (Swift, SwiftUI, iOS 15+)
ios/PhoneKeyCore  protocol, Noise and session logic as a Swift package
linux/          host CLI in Go (Linux, also runs on macOS)
docs/           architecture, wire protocol, test vectors
```

## Security notes

- Private keys are created in the Secure Enclave and never leave it. Every
  signature needs Touch ID.
- The `hmac-secret` behind a LUKS unlock is different: the Secure Enclave cannot
  compute HMAC, so for that moment the 32-byte secret exists in plain text in
  the app's memory. At rest it is encrypted to the credential's Secure Enclave
  key, and decrypting it needs the same Touch ID as the signature. Keep your
  LUKS passphrase: if the phone or the key is lost, the secret is gone.
- The PIN (Phase 3c) is there because some programs insist on one; it never
  replaces Touch ID. The phone keeps only a hash of it, encrypted to a Secure
  Enclave key, so every PIN check needs Touch ID: the computer cannot guess the
  PIN without your finger, and the PIN alone unlocks nothing.
- There is no vendor attestation, so services that only accept certified keys
  will reject phonekey.
- The iPhone 7 (A10) has the unpatchable checkm8 bootrom flaw. A stolen phone
  gives an attacker more to work with than a stolen hardware key. Fine for a key
  that stays on your desk, not for your only factor.
- Do not register phonekey as an Apple ID security key.

## Building the iOS app

Xcode 26 or later. Open `ios/PhoneKey.xcodeproj`, or from the command line:

```bash
xcodebuild -project ios/PhoneKey.xcodeproj -scheme PhoneKey -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
(cd ios/PhoneKeyCore && swift test)
```

The host CLI is described in [linux/README.md](linux/README.md).

Current Xcode has no iOS 15 simulator, so iOS 15 behaviour can only be checked
on a real device.

## License

[MIT](LICENSE)
