# phonekey

Turn an old iPhone into a desk peripheral for a Linux machine: a Touch-ID-gated
FIDO2 security key, a camera, a microphone and an approval button for AI coding
agents.

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
| Touch ID approval | signed yes/no for risky actions of a coding agent |

More in [docs/architecture.md](docs/architecture.md). The contract between phone
and daemon is [docs/protocol.md](docs/protocol.md).

## Status

**Phase 1:** encrypted USB session, QR pairing, status, photos and desk mode.
It works end to end between the `phonekey` CLI and the app in the iOS Simulator,
but it has **not been tried on a real iPhone 7 yet**. No security key yet. The
roadmap is in [docs/architecture.md](docs/architecture.md#roadmap).

```bash
cd linux && go build ./cmd/phonekey
./phonekey pair            # scan the QR code with PhoneKey → Pair new computer
./phonekey status
./phonekey photo -o desk.jpg   # after "Allow photos" in the app
```

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
