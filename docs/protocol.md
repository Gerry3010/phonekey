# phonekey wire protocol

**Status: draft (skeleton).** The content is written in Phase 1. Protocol version: 0, unstable.

This is the contract between the iOS app (`ios/`) and the Linux daemon (`linux/`).
Both sides implement this document. Changes go through a pull request that edits
this file, and the other side is told about them.

## 1. Transport

TCP to a port on the phone, reached through `usbmuxd` over USB. Port number: *TBD*.
Wi-Fi fallback via Bonjour: *later*.

## 2. Session security

Mutually authenticated, end-to-end encrypted channel; each side pins the other's
static key after pairing. Proposed: a Noise handshake. *TBD in Phase 1.*

## 3. Pairing

The daemon shows a QR code, the phone scans it with its camera, both sides store
the other's public key. *TBD in Phase 1.*

## 4. Framing

*TBD in Phase 1* (length-prefixed frames with a channel id).

## 5. Channels

| Channel | Phase | Purpose |
|---|---|---|
| `control` | 1 | hello, version, ping, status |
| `photo` | 1 | take a still image on request |
| `approval` | 2 | signed yes/no for an action |
| `ctap` | 3 | CTAPHID messages, tunneled to the authenticator |
| `video` | 4 | camera stream |
| `audio` | 4 | microphone stream |

## 6. Versioning

*TBD in Phase 1.*
