# Architecture

## Goal

Reuse an iPhone 7 as a peripheral for a Linux machine:

- a FIDO2 security key and passkey store whose keys live in the Secure Enclave and sign only after Touch ID,
- a camera (webcam stream or single photos),
- a microphone (audio stream or recordings).

## Desk station

iOS suspends apps in the background: the camera stops, sockets are torn down and
Touch ID prompts only appear while the app is in front. phonekey therefore
assumes a dedicated phone:

- permanently connected to the Linux machine with a Lightning cable (data and power),
- app always in the foreground (Guided Access), idle timer disabled,
- screen dimmed as far as possible.

An old battery on permanent charge can swell. Check it now and then.

## Transport

```
iPhone 7 (iOS 15, app)                       Linux (daemon)
 FIDO2 authenticator (Secure Enclave) ┐      ┌ /dev/uhid    → virtual security key
 camera                               │      ├ v4l2loopback → webcam
 microphone                           ├ USB ─┤ PipeWire     → microphone
 status, photos                       │usbmux├ phonekey CLI → status, photos
 desk mode                            ┘      └ (Wi-Fi fallback via Bonjour, later)
```

- **USB first.** The app listens on a TCP port; the daemon reaches it through
  `usbmuxd` (libimobiledevice), the same channel Xcode and iTunes use. No network needed.
- **Authenticated and encrypted anyway.** Any local process with `usbmuxd` access
  could otherwise talk to the phone. The channel is end-to-end encrypted and both
  sides pin each other's keys after pairing.
- **Pairing** by QR code: the daemon shows it, the phone camera scans it.

The exact format is in [protocol.md](protocol.md).

## Components

| Area | iOS app | Linux daemon |
|---|---|---|
| Session | TCP listener, handshake, pairing UI | usbmuxd client, handshake, QR display |
| Security key | CTAP2 authenticator (no U2F), ES256 keys in the Secure Enclave, Touch ID per signature, shows the site before signing | CTAPHID over `/dev/uhid`, so browsers, `ssh-keygen -t ecdsa-sk` and `pam-u2f` see a normal key |
| Camera | `AVCaptureSession`, H.264 (VideoToolbox) or JPEG | `v4l2loopback` device, photo tool |
| Microphone | `AVAudioEngine` | PipeWire source, recording tool |

## Limits

- **iOS 15.8 is the end of the line** for the iPhone 7. No passkey or credential provider APIs (iOS 16/17).
- **No Bluetooth "use a phone" (hybrid/caBLE).** It needs BLE advertisement data that iOS does not let third-party apps send. The USB bridge over `/dev/uhid` replaces it.
- **ES256 only.** The Secure Enclave does P-256. That covers WebAuthn and OpenSSH `-sk` keys.
- **No vendor attestation.** Services that accept only certified keys will reject phonekey.
- **checkm8.** The A10 bootrom flaw cannot be patched. A stolen phone is weaker than a stolen hardware key.
- **No iOS 15 simulator** on current macOS. iOS 15 behaviour is verified on the device.

## Out of scope

- **Apple ID security key.** Apple requires at least two FIDO-certified keys, and a lockout would hit the owner's main Apple ID. Use hardware keys for that.

## Roadmap

0. **Project init.** Repo, Xcode project, docs. *(done)*
1. **Transport and desk mode.** usbmuxd TCP channel, encrypted session, QR pairing, desk mode, photo tool as the first end-to-end feature. Protocol spec for the daemon. *(done; verified on an iPhone 7 with iOS 15.8.2)*
2. **FIDO2 security key and passkeys.** The phone is a full CTAP2 authenticator: discoverable credentials, user verification via Touch ID (any enrolled finger), ES256 keys in the Secure Enclave, attestation "none", `credProtect`. The host tunnels CTAPHID through a virtual `/dev/uhid` device that exists only while the phone is connected. *(done; verified with libfido2 and OpenSSH in a VM and on the iPhone 7; browser test on real Linux open)*
3. **More FIDO**, in three steps (protocol §10): 3a `hmac-secret` (LUKS via `systemd-cryptenroll`), 3b `pinUvAuthToken` via Touch ID and credential management (`FIDO_2_1`), 3c a PIN that only works together with Touch ID, because `ssh-keygen -K` and Chrome's key management insist on one.
   - U2F/CTAP1: only if a service needs it.
4. **Streaming and voice.** Webcam and microphone streams.
5. **macOS host (optional).** Needs a DriverKit virtual HID device and an entitlement from Apple.

An approval button for coding agents was considered and dropped: Touch ID is only used for the security key.
