# phonekey wire protocol

**Protocol version 1** (session, pairing, status, photo; FIDO from Phase 2,
extended in Phase 3).

This is the contract between the iOS app (`ios/`, the **phone**) and the daemon
(`linux/`, the **host**). Both sides implement this document. Changes go through
a pull request that edits this file. [protocol-vectors.json](protocol-vectors.json)
holds test vectors that every implementation must reproduce.

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Transport

- The phone listens on **TCP `127.0.0.1:20555`** ("PK"). It MUST NOT listen on
  other interfaces in v1.
- The host reaches that port through **usbmuxd** over USB: `Connect` with the
  phone's `DeviceID` and port 20555 (see [§9](#9-usbmuxd-notes)). The phone must
  trust the computer (tap "Trust"; on Linux `idevicepair pair`).
- For tests the host MAY connect directly over TCP, e.g. to the app running in
  the iOS Simulator, which shares the Mac's loopback interface.
- The host is always the connecting side and the Noise **initiator**. The phone
  is the **responder**.
- The phone only listens while the app is in the foreground. When it goes to the
  background it closes the listener and all connections. Hosts SHOULD reconnect
  with backoff (1 s, doubling, capped at 10 s).
- The phone accepts at most 4 concurrent connections.

## 2. Preamble

Before the handshake each side sends one 8-byte plaintext preamble.

Host → phone:

| Offset | Size | Value |
|---|---|---|
| 0 | 4 | ASCII `PHKY` |
| 4 | 1 | protocol version, `0x01` |
| 5 | 1 | mode: `0x00` session, `0x01` pairing |
| 6 | 2 | reserved, `0x0000` |

Phone → host, sent after reading the host preamble:

| Offset | Size | Value |
|---|---|---|
| 0 | 4 | ASCII `PHKY` |
| 4 | 1 | highest protocol version the phone supports, `0x01` |
| 5 | 1 | status (below) |
| 6 | 2 | reserved, `0x0000` |

| Status | Meaning |
|---|---|
| `0x00` | ok, the handshake follows |
| `0x01` | unsupported protocol version |
| `0x02` | pairing requested but no pairing is pending on the phone |
| `0x03` | busy (connection limit reached) |
| `0x04` | unknown mode |

A wrong magic closes the connection without an answer. For any status other
than `0x00` the phone closes the connection after sending its preamble. A host
that receives `0x02` while pairing SHOULD retry every second until the pairing
times out (see [§6](#6-pairing)).

The Noise **prologue** is `host preamble || phone preamble` (16 bytes). That
authenticates the negotiation.

## 3. Handshake

| Mode | Noise protocol name |
|---|---|
| session | `Noise_XX_25519_ChaChaPoly_SHA256` |
| pairing | `Noise_XXpsk3_25519_ChaChaPoly_SHA256` |

```
XX:      -> e
         <- e, ee, s, es
         -> s, se
XXpsk3:  -> e
         <- e, ee, s, es
         -> s, se, psk
```

- The PSK is the 32-byte secret from the pairing URL.
- Each handshake message is sent as a frame ([§4](#4-framing)). Handshake
  payloads are empty in v1; receivers MUST ignore any payload.
- Implementations MUST follow the Noise specification (revision 34), including
  `MixKey(e.public_key)` for the `e` token in PSK handshakes.

After the third message each side checks the other's static public key:

| Mode | Phone checks the host key | Host checks the phone key |
|---|---|---|
| session | it is in the phone's list of paired hosts | it is in the host's list of paired phones |
| pairing | it equals the key in the pending pairing | none; the host stores the key |

If the phone rejects the host key it sends one transport message
`{"t":"error","code":"not_paired"}` ([§5](#5-messages)) and closes the
connection. If the host rejects the phone key it closes the connection.

The phone MUST close a connection whose handshake has not finished within 10 s.

`Split()` yields two cipher states. The host encrypts with the first and
decrypts with the second, the phone does the opposite. There is no rekeying in
v1.

## 4. Framing

Every handshake message and every transport message is one frame:

| Size | Value |
|---|---|
| 2 | length `L` of what follows, unsigned big-endian, 1…65535 |
| `L` | Noise message |

A transport message decrypts to:

| Size | Value |
|---|---|
| 1 | kind: `0x01` JSON, `0x02` chunk |
| rest | body |

- **JSON** (`0x01`): the body is one UTF-8 JSON object.
- **Chunk** (`0x02`): the body is a 4-byte big-endian stream id followed by raw
  data. With the 16-byte tag the data in one chunk is at most 65514 bytes.
  Senders SHOULD use at most 60000 bytes.

Unknown kinds MUST be ignored.

## 5. Messages

Every JSON message has a string field `t` (type). Requests carry a numeric `id`
chosen by the host; the phone copies it into the response. Unknown fields MUST be
ignored. An unknown `t` in a request is answered with the error `unknown_type`.

After the handshake both sides send `hello` first, without waiting for each
other.

### hello

Phone:

```json
{"t":"hello","role":"phone","protocol":1,"app_version":"0.2.0",
 "device":{"model":"iPhone9,3","system":"iOS 15.8.3","name":"iPhone"},
 "features":["status","photo"]}
```

Host:

```json
{"t":"hello","role":"host","protocol":1,"app_version":"0.1.0",
 "host":{"name":"workstation","os":"linux"}}
```

### ping

```json
{"t":"ping","id":1}
{"t":"pong","id":1}
```

### status

```json
{"t":"status.get","id":2}
{"t":"status","id":2,
 "battery":{"level":0.83,"state":"charging"},
 "thermal":"nominal",
 "desk_mode":true,
 "guided_access":false,
 "camera":{"enabled":false,"available":true,"stream_enabled":false,"streaming":false}}
```

- `battery.level`: 0…1, or `null` if unknown. `battery.state`: `unknown`,
  `unplugged`, `charging`, `full`.
- `thermal`: `nominal`, `fair`, `serious`, `critical`.
- `camera.enabled`: the user allows hosts to take photos (a switch in the app,
  off by default). `camera.available`: the device has a usable camera and the
  app has camera permission. `camera.stream_enabled`: the user allows the
  webcam (its own switch, off by default; Phase 4). `camera.streaming`: a
  webcam stream is running.

### photo

```json
{"t":"photo.capture","id":3,"camera":"back","max_dimension":1568,"quality":0.8}
```

- `camera`: `back` (default) or `front`.
- `max_dimension`: longest side in pixels, default 1568; `0` means full resolution.
- `quality`: JPEG quality 0.1…1.0, default 0.8.

On success the phone sends `photo.begin`, the data as chunks with the given
stream id, then `photo.end`:

```json
{"t":"photo.begin","id":3,"stream":1,"size":245113,"mime":"image/jpeg","width":1568,"height":1176}
{"t":"photo.end","id":3,"stream":1,"sha256":"<64 hex digits>"}
```

The host MUST check `size` and `sha256`. While a photo is taken the phone shows
it on screen and iOS plays the shutter sound.

### camera (Phase 4)

A webcam stream. A phone that offers it lists the feature `camera` in `hello`.

```json
{"t":"camera.start","id":5,"camera":"front","quality":"720p","fps":30}
```

- `camera`: `front` or `back`. Without it the phone uses the camera picked in
  the app (front unless the user changed it), so hosts send it only when the
  user asked for one.
- `quality`: `720p` (1280×720, default) or `1080p` (1920×1080).
- `fps`: an integer from 15 to 30, default 30.

The phone answers with what it actually delivers. The host uses these values,
not the ones it asked for:

```json
{"t":"camera.started","id":5,"stream":2,"codec":"h264","width":1280,"height":720,"fps":30,"camera":"front"}
```

The requested quality is a maximum. If the camera cannot deliver it at the
requested frame rate in the current orientation (see Picture), the phone keeps
the frame rate and steps the size down: 1920×1080, 1280×720, 960×540. It never
scales up and never adds black bars.

**Video.** The chunks of `stream` carry a sequence of frames. Frames do not line
up with chunks: a frame can span several chunks, and a chunk can end inside a
frame. Each frame is:

| Size | Value |
|---|---|
| 1 | flags: bit 0 set for a keyframe, the other bits 0 |
| 8 | capture time in microseconds, unsigned big-endian, monotonic on the phone |
| 4 | length `N`, unsigned big-endian |
| `N` | one H.264 access unit in Annex B format (with start codes) |

- H.264 Main or High profile without B-frames, so frames arrive in display order.
- A keyframe is an IDR frame with SPS and PPS in front of it. The first frame
  is one, and then at least one every 2 s.
- About 4 Mbit/s at 720p and 8 Mbit/s at 1080p, about 2.5 and 5 Mbit/s at
  15 fps.

**Picture.** Always upright and landscape (16:9), however the phone stands:
portrait with the cable at the bottom or at the top, or landscape. The phone
rotates and crops. In portrait the picture is cut from the short side of the
sensor, so it shows a narrower field of view than in landscape. Turning the
phone during a stream can change the field of view, never width and height;
lying flat keeps the last orientation. The front camera is not mirrored; video
apps mirror their own preview.

**Order on the wire.** Video shares the session with everything else. The
phone sends JSON messages ahead of queued video chunks (between chunks, never
inside one), so FIDO requests and pings are not held up by video. The host
reads the session without waiting on its decoder.

**Falling behind.** The phone never holds more than 0.5 s of video. When sending
falls behind, it drops whole frames up to the next keyframe and has the encoder
make one. The host can ask for a keyframe too, for example after restarting its
decoder:

```json
{"t":"camera.keyframe","id":6,"stream":2}
```

**Heat.** The phone acts on the worse of `thermal` and the camera's own system
pressure. At `serious` it lowers the frame rate to 15 and says so. Once both
have been `fair` or better for 60 s, it returns to the requested rate. If it is
already `serious` at `camera.start`, it starts at 15. Width and height never
change while a stream runs.

```json
{"t":"camera.changed","stream":2,"fps":15}
{"t":"camera.changed","stream":2,"fps":30}
```

**Switching cameras.** The user can switch between front and back on the phone
while a stream runs (see Preview). Width, height and frame rate stay; the phone
offers the switch only when the other camera delivers them. The first frame from
the other camera is a keyframe, and capture times keep rising. The phone says
so:

```json
{"t":"camera.changed","stream":2,"camera":"back"}
```

A `camera.changed` carries only what changed: `fps`, `camera`, or both. Hosts
ignore fields they do not know.

**Preview.** The app shows a live preview of what is sent, with the front/back
switch, while a stream runs, and can show one without a stream to aim the
camera and pick the default camera. The preview never sends anything. When a
`camera.start` arrives while the preview runs without a stream, the stream takes
the camera over and the preview shows the stream.

**Stopping.**

```json
{"t":"camera.stop","id":7,"stream":2}
{"t":"camera.stopped","id":7,"stream":2,"reason":"requested"}
```

The phone also stops on its own and then sends `camera.stopped` without `id`:

| `reason` | Meaning |
|---|---|
| `requested` | the host asked |
| `stopped_on_phone` | the user tapped Stop on the phone |
| `switched_off` | the user turned the webcam off in the app |
| `interrupted` | iOS took the camera away, for example for a phone call |
| `thermal` | `thermal` reached `critical`, or iOS stopped the camera for system pressure |
| `failed` | capturing or encoding failed |

When the session ends, the stream ends with it.

**Rules.**
- One stream at a time. Another `camera.start`, or `photo.capture` while a
  stream or the preview runs, gets `busy`.
- The webcam has its own switch in the app, off by default and separate from
  photos (`camera.stream_enabled` in `status`). While it is off, `camera.start`
  gets `camera_stream_disabled`.
- While a stream runs, the phone shows which computer receives it, with a Stop
  button, and iOS shows its green camera dot. The screen may stay dimmed in desk
  mode. FIDO prompts appear above the notice as usual.

**Host side.** `phonekey camera run` keeps a v4l2loopback device named
"PhoneKey" open as its producer. While no application reads it, the host shows a
still placeholder picture and the phone does not stream. When an application
opens the webcam (v4l2loopback's client usage event), the host sends
`camera.start`, decodes the frames with ffmpeg and writes them to the device.
When the last application closes it, the host sends `camera.stop`.

When the phone refuses or stops on its own, the host shows the placeholder and
sends no new `camera.start` until the applications have closed the webcam, so a
refusal does not turn into a loop. The webcam switch is the exception: after
`camera_stream_disabled` or `switched_off`, the host asks for `status` every
2 s while applications still read, and starts again once
`camera.stream_enabled` is true. When the session ends (the app went to the
background), the host reconnects and starts again while applications read.

### error

```json
{"t":"error","id":3,"code":"camera_disabled","message":"Photos are switched off in the app."}
```

`id` is the request id, or absent if the error is not tied to a request.
`message` is for humans and may change.

| Code | Meaning |
|---|---|
| `not_paired` | the host key is not paired (sent right after the handshake) |
| `bad_request` | the request is malformed |
| `unknown_type` | the request type is unknown |
| `camera_disabled` | photos are switched off in the app |
| `camera_unavailable` | no camera, or no camera permission |
| `camera_stream_disabled` | the webcam is switched off in the app |
| `unsupported` | a requested value is not supported (`camera`, `quality`, `fps`) |
| `busy` | the phone is already handling a conflicting request |
| `capture_failed` | taking the photo failed |
| `internal` | anything else |

### fido

Feature `fido` in the phone's `hello`. The phone is a complete CTAP2
authenticator; the host only carries CTAPHID payloads between a virtual USB
security key and the phone ([§10](#10-fido-security-key)).

```json
{"t":"ctap.request","id":4,"cmd":16,"data":"BKA…"}
{"t":"ctap.response","id":4,"data":"AKk…"}
{"t":"ctap.cancel","id":4}
```

- `cmd` is the CTAPHID command: `16` (`0x10`, CBOR) or `8` (`0x08`, WINK).
- `data` is standard base64 with padding (the JSON encoding of a byte array in
  Go and Swift). For CBOR the request is the CTAP command byte followed by the
  CBOR parameters; the response is the CTAP status byte followed by the CBOR
  response. For WINK both are empty.
- The phone answers every `ctap.request` with exactly one `ctap.response`, also
  for errors (a CTAP status byte other than `0x00`). Protocol errors such as a
  missing `data` field use the `error` message with code `bad_request`.
- `ctap.cancel` has no answer of its own. If request `id` is still waiting for
  the user, the phone stops waiting and answers it with status `0x2D`
  (`CTAP2_ERR_KEEPALIVE_CANCEL`).
- The phone handles one CTAP request at a time across all connections. A second
  one is answered with `0x06` (`CTAP1_ERR_CHANNEL_BUSY`). While a request waits
  for the user, the phone keeps reading and answering other messages
  (`ping`, `status.get`, `ctap.cancel`).

## 6. Pairing

1. The host creates its static key on first use and a fresh 32-byte random PSK.
2. The host shows the **pairing URL** as a QR code and as text:

   ```
   phonekey://pair?v=1&k=<host static public key>&s=<psk>&n=<host name>
   ```

   `k` and `s` are 32 bytes each, base64url without padding. `n` is
   percent-encoded UTF-8, at most 64 bytes.
3. The user scans the code with the app (or opens the URL on the phone). The app
   shows the host name and asks for confirmation. Once confirmed, the pairing is
   **pending** for 5 minutes.
4. The host connects in pairing mode and retries while it gets status `0x02`.
5. After a successful `XXpsk3` handshake the phone stores the host key and name,
   the host stores the phone key, and the pending pairing ends. The session then
   continues normally (`hello` and so on).

A PSK is used for one pairing only. The host SHOULD give up after 5 minutes.

## 7. Key storage

| Side | Secret | Where |
|---|---|---|
| phone | static X25519 key, paired hosts | Keychain, `…ThisDeviceOnly`, never synced |
| host | static X25519 key | file, mode 0600, in the user config directory |
| host | paired phones (public keys, names) | file in the user config directory |

The session key is not a FIDO key. FIDO credential keys are created in the
Secure Enclave (Phase 2). Their list is a Keychain item (`…ThisDeviceOnly`)
that the phone reads without Touch ID. From Phase 3a the per-credential
`hmac-secret` secrets are stored with it, encrypted to the credential's Secure
Enclave key, and from 3c the PIN hash, encrypted to a Secure Enclave key of
its own; decrypting either needs Touch ID.

## 8. Security notes

- Logs MUST NOT contain private keys, PSKs, pairing URLs or decrypted payloads.
- Loopback only: in v1 nothing on the network can reach the phone. Anything on
  the host that can talk to usbmuxd can open a connection, which is why every
  session is authenticated.
- A pairing needs a confirmation on the phone and a secret that is only shown on
  the host's screen.
- The FIDO PIN (Phase 3c) is a formality for clients that insist on one: every
  token issued against it also needs Touch ID. A short PIN would be guessable
  offline from a copied Keychain if it were stored as a plain hash; it is
  encrypted to the Secure Enclave instead, and the phone allows 8 attempts.

## 9. usbmuxd notes

usbmuxd listens on `/var/run/usbmuxd` (Linux and macOS). libimobiledevice also
honours `USBMUXD_SOCKET_ADDRESS` (`UNIX:/path` or `host:port`); hosts SHOULD do
the same. Packets have a 16-byte little-endian header (`length` including the
header, `version` = 1, `message` = 8 for plist, `tag`) followed by an XML plist.

- `ListDevices` returns `DeviceList`, an array of dicts with `DeviceID` and
  `Properties` (`ConnectionType` `USB` or `Network`, `SerialNumber` = UDID).
- `Connect` takes `DeviceID` and `PortNumber`. `PortNumber` is the port in
  network byte order read as a little-endian integer: 20555 (`0x504B`) is sent
  as `0x4B50` = 19280.
- A `Result` with `Number` 0 means connected; from then on the socket is a raw
  TCP tunnel to the phone. 3 means connection refused (app not running or not in
  the foreground).

## 10. FIDO security key

What the phone implements, so host and phone agree on behaviour. References:
CTAP 2.1 (FIDO Alliance, "Client to Authenticator Protocol", Proposed Standard
2021, errata 2022) and WebAuthn Level 2. Status names below are CTAP's without
the `CTAP1_ERR_`/`CTAP2_ERR_` prefix.

Phase 2 is a CTAP 2.0 authenticator. Phase 3 adds the rest in three steps;
each step changes `authenticatorGetInfo`, so hosts never have to guess:

| Step | Adds | Unlocks |
|---|---|---|
| 3a | PIN/UV auth protocols 1 and 2, `getKeyAgreement`, `hmac-secret` | LUKS (`systemd-cryptenroll`) and other `hmac-secret` users |
| 3b | `pinUvAuthToken` via Touch ID, `authenticatorSelection`, credential management, `FIDO_2_1` | Listing and deleting passkeys with libfido2 (`fido2-token`), Touch ID only |
| 3c | A PIN, used only together with Touch ID | `ssh-keygen -K`, `ssh-add -K` and Chrome's key management: both insist on a PIN |

Until a step has landed on both sides, everything it adds answers as in the
step before. U2F (CTAP1) is not planned; it comes only if a service needs it.

### authenticatorGetInfo (`0x04`)

| Key | Phase 2 | Phase 3 (step) |
|---|---|---|
| 1 versions | `["FIDO_2_0"]` | `["FIDO_2_0", "FIDO_2_1"]` (3b) |
| 2 extensions | `["credProtect"]` | `["credProtect", "hmac-secret"]` (3a) |
| 3 aaguid | `4e3b1fe3-c75c-4055-b791-c999ff915951` | unchanged |
| 4 options | `{"rk": true, "up": true, "uv": true, "plat": false}` | adds `"pinUvAuthToken": true`, `"credMgmt": true` (3b); `"clientPin"` (3c): `false` until a PIN is set, then `true` |
| 5 maxMsgSize | 1200 | unchanged |
| 6 pinUvAuthProtocols | absent | `[2, 1]` (3a) |
| 7 maxCredentialCountInList | 16 | unchanged |
| 8 maxCredentialIdLength | 32 | unchanged |
| 9 transports | `["usb"]` | unchanged |
| 10 algorithms | `[{"alg": -7, "type": "public-key"}]` | unchanged |
| 13 minPINLength | absent | 4 (3c) |
| 17 preferredPlatformUvAttempts | absent | 1 (3b): Touch ID retries on its own |
| 18 uvModality | absent | 2, fingerprint (3b) |

Keys 7 and 8 matter for Chrome: without both it sends allow and exclude lists
one entry at a time, each first as a silent probe (`up = false`), which the
phone cannot answer with a signature (see getAssertion). With them, up to 16
IDs of at most 32 bytes go into one request with `up = true`. More than 16
matching candidates still end in probes; Chrome then reports the key as not
registered.

Touch ID is the user verification. `uv` and `pinUvAuthToken` stay `true` when a
PIN exists, so browsers and ssh keep verifying with Touch ID and never ask for
the PIN for a normal sign-in. `alwaysUv` and `makeCredUvNotRqd` are absent;
every operation needs Touch ID anyway.

### Session state ("power cycle")

CTAP ties some state to a power cycle. Here it is tied to the session with one
host (§3): the phone's key agreement key, the `pinUvAuthToken`, the count of
wrong PINs in a row and any credential management enumeration belong to that
session and are dropped when it ends. Another host's session cannot use them.
A reconnecting host starts over, just as its virtual USB key disappears and
comes back (see Host side).

### authenticatorMakeCredential (`0x01`)

- Only ES256 (`alg` -7). Without it in `pubKeyCredParams`: `0x26`
  (`UNSUPPORTED_ALGORITHM`).
- `excludeList` hit: the phone shows that the key is already registered, waits
  for a tap, then answers `0x19` (`CREDENTIAL_EXCLUDED`).
- `pinUvAuthParam` (key 8) of length zero (authenticator selection): after a
  tap on the phone, `0x35` (`PIN_NOT_SET`), or from 3c with a PIN set `0x31`
  (`PIN_INVALID`); declined or no answer: `0x27` (`OPERATION_DENIED`).
- Non-empty `pinUvAuthParam`: up to step 3a always `0x33`
  (`PIN_AUTH_INVALID`). Phase 2 answered `0x36`, which is `PUAT_REQUIRED`; that
  was a bug. From 3b the phone verifies it as described under
  [Using a pinUvAuthToken](#using-a-pinuvauthtoken).
- Without `pinUvAuthParam` the phone shows the site (`rp.id`), the account and
  whether it becomes a passkey (`rk`), and opens Touch ID at once, whatever
  `options.uv` says. Cancelling or failing Touch ID does not decline: the
  details stay on screen with a button to try Touch ID again. Only the explicit
  Decline button answers `0x27` (`OPERATION_DENIED`). No answer within 60 s:
  `0x2F` (`USER_ACTION_TIMEOUT`).
- The phone never answers `0x36` (`PUAT_REQUIRED`). CTAP 2.1 would ask for a
  token when built-in UV is configured and the request brings neither a token
  nor `uv`; the phone verifies with Touch ID instead, which is stricter, and
  clients that never ask for UV (`ssh-keygen -t ecdsa-sk` without
  `verify-required`) keep working.
- A new P-256 key is created in the Secure Enclave, usable only after Touch ID
  with any enrolled finger. The credential ID is 32 random bytes; it names the
  key on the phone and carries no key material.
- Attestation format `none` with an empty `attStmt`. Flags `UP | UV | AT`
  (`0x45`), counter 0.
- Extensions are returned in the authenticator data (flag `ED`, `0xC5` in
  total) when at least one is requested and supported:
  - `credProtect` (levels 1–3) is stored with the credential and echoed. Every
    use needs Touch ID, so all levels are always satisfied. OpenSSH requires
    this extension for resident and `verify-required` keys.
  - `hmac-secret: true` (3a): the phone creates a 32-byte random secret for the
    credential (CTAP's `CredRandomWithUV`) and answers `hmac-secret: true`.
    The secret is stored encrypted to the credential's own Secure Enclave key
    (ECIES: `SecKeyCreateEncryptedData`, X9.63 SHA-256 with AES-GCM), so only
    Touch ID can decrypt it. `CredRandomWithoutUV` is never needed: no
    assertion is made without UV.
  - Other extensions are ignored.
- Every credential is stored on the phone, discoverable or not. A new
  discoverable credential replaces the discoverable credentials of the same
  account (same `rp.id` and `user.id`), as CTAP 2.1 requires: metadata in one
  step, the old Secure Enclave keys right after. Non-discoverable credentials
  are never replaced; the site still holds their IDs.

### authenticatorGetAssertion (`0x02`)

- Candidates: the stored credentials in `allowList` for `rpId`, or without
  `allowList` all discoverable credentials for `rpId`. None: `0x2E`
  (`NO_CREDENTIALS`).
- Candidates are looked up first, so a silent lookup (`options.up = false`)
  without matching credentials answers `0x2E` without any prompt (OpenSSH does
  this before enrolling a resident key). With matching credentials `up = false`
  answers `0x2B` (`UNSUPPORTED_OPTION`): a Secure Enclave key cannot sign
  without Touch ID. With a `pinUvAuthToken` the token's Touch ID can sign
  silently; see [Using a pinUvAuthToken](#using-a-pinuvauthtoken).
- Several discoverable candidates: the phone lets the user pick one (it has a
  display), so the response never sets `numberOfCredentials` and
  `authenticatorGetNextAssertion` (`0x08`) answers `0x30` (`NOT_ALLOWED`).
- `pinUvAuthParam` (key 6) and `PUAT_REQUIRED`: as for makeCredential.
- The phone shows the site and the account and opens Touch ID at once. With
  several candidates it preselects one: an account the user marked as
  suggested for the site, else the one used last, else the newest. "Other
  account" lists them all. Cancelling Touch ID works as for makeCredential.
  That one Touch ID also unlocks the signature. Flags `UP | UV` (`0x05`, `0x85`
  with extensions); the per-credential counter goes up by one.
- After signing in with another account than the preselected one, the phone
  asks whether to suggest it for the site from now on, as well as or instead
  of the current suggestions. This happens after the answer has gone out and
  is only stored on the phone; hosts see nothing of it.
- Once the answer has gone out, the phone shows for a moment that the
  registration or sign-in is done, so one request is visibly over before the
  next one starts.
- `hmac-secret` (3a), input map `{1: keyAgreement, 2: saltEnc, 3: saltAuth,
  4: pinUvAuthProtocol}` (4 defaults to 1):
  - The shared secret comes from the platform's `keyAgreement` and the phone's
    key agreement key of this session (see `getKeyAgreement`).
  - `saltAuth` must verify over `saltEnc`, else `0x33` (`PIN_AUTH_INVALID`).
    `saltEnc` must decrypt to 32 or 64 bytes (one or two salts), else `0x02`
    (`INVALID_PARAMETER`). An unsupported protocol: `0x02`.
  - The output is `encrypt(shared secret, HMAC-SHA-256(secret, salt1)
    [|| HMAC-SHA-256(secret, salt2)])` under the key `hmac-secret` in the
    authenticator data extensions.
  - A credential made without `hmac-secret` gives no output. The same Touch ID
    unlocks the signature and decrypts the secret.
  - Unlike the signing keys, the secret leaves the Secure Enclave: the Secure
    Enclave cannot compute HMAC. It exists in plain text only in the app's
    memory while the output is computed.
- The response contains `credential`, `authData`, `signature` (DER) and, for
  discoverable credentials, `user` (`id`, `name`, `displayName`) as the site
  stored them. Names the user gave keys or sites on the phone never leave it.

### authenticatorClientPIN (`0x06`)

`pinUvAuthProtocol` (key 1) must be 1 or 2, else `0x02` (`INVALID_PARAMETER`);
missing parameters: `0x14` (`MISSING_PARAMETER`).

| subCommand | Phone |
|---|---|
| `0x02` getKeyAgreement (3a) | `{1: keyAgreement}`: the phone's P-256 key agreement key of this session as a COSE key `{1: 2, 3: -25, -1: 1, -2: x, -3: y}`. Created when first asked for, never stored, dropped with the session, replaced after a wrong PIN. |
| `0x06` getPinUvAuthTokenUsingUvWithPermissions (3b) | see below |
| `0x07` getUVRetries (3b) | `{5: 8}`, or `{5: 0}` while iOS has locked Touch ID after failed attempts |
| `0x01` getPINRetries (3c) | `{3: retries left, 4: true}` with `4` only while this session is blocked after three wrong PINs in a row; no PIN set: `0x35` (`PIN_NOT_SET`) |
| `0x03` setPIN (3c) | see [PIN](#pin-3c) |
| `0x04` changePIN (3c) | see [PIN](#pin-3c) |
| `0x05` getPinToken (3c) | see [PIN](#pin-3c) |
| `0x09` getPinUvAuthTokenUsingPinWithPermissions (3c) | see [PIN](#pin-3c) |
| anything else, and each subcommand before its step | `0x3E` (`INVALID_SUBCOMMAND`) |

The two PIN/UV auth protocols are implemented exactly as in CTAP 2.1 §6.5.6
and §6.5.7 (protocol 1: SHA-256 of the ECDH x coordinate, AES-256-CBC with a
zero IV, 16-byte HMAC; protocol 2: HKDF-SHA-256 into an HMAC key and an AES key,
random IV, 32-byte HMAC).

#### getPinUvAuthTokenUsingUvWithPermissions

Parameters: `pinUvAuthProtocol`, `keyAgreement` (key 3), `permissions` (key 9),
`rpId` (key 10). In order:

1. `permissions` 0: `0x02`. Bits other than `mc` (`0x01`), `ga` (`0x02`) and
   `cm` (`0x04`): `0x40` (`UNAUTHORIZED_PERMISSION`). `mc` or `ga` without
   `rpId`: `0x14`.
2. iOS has locked Touch ID: `0x3C` (`UV_BLOCKED`).
3. The phone shows a card like the makeCredential one: the host's name, the
   site (`rpId`) and what the token is for (registering or signing in for
   `mc`/`ga`, listing and deleting passkeys for `cm`), and opens Touch ID at
   once. From 3b on this is the path Chrome takes for every registration and
   sign-in (it sees `uv` and `pinUvAuthToken`), so Touch ID comes before the
   account choice there.
4. Cancelling or failing Touch ID does not decline, as for makeCredential: the
   card stays with Touch ID and Decline. Decline: `0x27` (`OPERATION_DENIED`).
   No answer within 60 s: `0x2F`. Locked by iOS: `0x3C` (`UV_BLOCKED`). The
   phone never sends `0x3F` (`UV_INVALID`): with `preferredPlatformUvAttempts`
   1, Chrome would take it as the cue to ask for the PIN.
5. Success: a new random 32-byte token replaces any earlier token of this
   session. It carries the permissions, `rpId` if given, and "user verified"
   and "user present" (Touch ID proves both). Answer `{2: encrypt(shared
   secret, token)}`.

The token expires when the session ends, when it is not used within 30 s of
being issued, and 600 s after being issued at the latest.

**Where the token's Touch ID goes.** The Secure Enclave only signs with an
`LAContext` that was evaluated for the credential keys' access control. So when
a token gets `mc` or `ga` (from `0x06`, `0x09` or `0x05`), the phone evaluates
Touch ID with `evaluateAccessControl(rule, .useKeySign, …)` and keeps that
context with the token. It serves exactly one operation with user presence
(the signature, plus the `hmac-secret` decryption in the same request) and,
before that, silent assertions (`up = false`) for the token's RP within 30 s of
the Touch ID (see "Silent assertions" below). It is invalidated
explicitly (`LAContext.invalidate()`) when the token loses `mc`/`ga`, when it
expires, when a new token replaces it and when the session ends, so a token's
lifetime never means keys stay unlocked. A token with only `cm` keeps
no context. A `.useKeySign` context also covers the ECIES decryption (a key
exchange in the Enclave) with the same key: checked on the iPhone 7 with
iOS 15.8.2 on 15 Nov 2026, with further prompts forbidden after the one
Touch ID (`interactionNotAllowed`); decryption and signature both succeeded,
and the same holds the other way round for a `.useKeyKeyExchange` context.

#### PIN (3c)

The PIN exists because OpenSSH (`ssh-keygen -K`, `ssh-add -K`) and Chrome's key
management refuse to work without one. It never replaces Touch ID: **every
token issued against the PIN also needs Touch ID on the phone**, so the PIN
alone unlocks nothing.

- **Storage.** The phone keeps only CTAP's `LEFT(SHA-256(PIN), 16)`, encrypted
  to a Secure Enclave key of its own (ECIES as for `hmac-secret`) that is
  usable only after Touch ID; `…ThisDeviceOnly`, never synced, never on the
  host. Comparing a PIN therefore always happens inside a Touch ID prompt, and
  a copied Keychain alone does not allow guessing it offline. The PIN key has
  the same Touch ID rule as the credential keys, so the prompt's one Touch ID
  both decrypts the stored hash and, for a token with `mc`/`ga`, signs.
- **Policy.** At least 4 Unicode code points (`minPINLength` counts code
  points) and at most 63 bytes of UTF-8 (`newPinEnc` is the PIN padded with
  zeros to 64 bytes, as in CTAP). Otherwise: `0x37` (`PIN_POLICY_VIOLATION`).
- **Retries.** 8 in total, stored on the phone (Keychain, `…ThisDeviceOnly`),
  so they survive sessions and app restarts; a correct PIN resets them. A
  wrong PIN answers `0x31` (`PIN_INVALID`) and replaces the session's key
  agreement key. Three wrong PINs in a row block only the session: `0x34`
  (`PIN_AUTH_BLOCKED`) until the host reconnects. At 0 retries the PIN is
  blocked: `0x32` (`PIN_BLOCKED`). As in CTAP a try is counted before the
  comparison; if decrypting the stored hash fails (Touch ID cancelled), nothing
  was compared and the try is given back.
- **setPIN** (`0x03`): parameters `keyAgreement`, `newPinEnc` (key 5),
  `pinUvAuthParam` = `authenticate(shared secret, newPinEnc)`. A PIN already
  set: `0x33` (`PIN_AUTH_INVALID`), as CTAP 2.1 §6.5.5.5 says. The phone shows
  the host's name, asks for Touch ID, then stores the PIN.
- **changePIN** (`0x04`): adds `pinHashEnc` (key 6); `pinUvAuthParam` =
  `authenticate(shared secret, newPinEnc || pinHashEnc)`. A new PIN that
  breaks the policy is refused (`0x37`) before anything is shown, so it costs
  no try. Otherwise Touch ID, then the old PIN is checked (retries as above),
  then the new one stored. Every token of every session is invalidated.
- **getPinToken** (`0x05`, for CTAP 2.0 clients): `keyAgreement`,
  `pinHashEnc`. Touch ID, then the PIN check; the token gets `mc` and `ga`
  without an RP ID. As in CTAP 2.1 it is bound to the `rp.id` of its first
  use. Because its prompt could not name the site, that first operation shows
  the site and account and waits for a tap before signing (no second
  Touch ID), so the phone still shows the site before every signature.
- **getPinUvAuthTokenUsingPinWithPermissions** (`0x09`): `keyAgreement`,
  `pinHashEnc`, `permissions`, `rpId`; permission checks as for `0x06`. The
  prompt says what the token is for, then Touch ID, then the PIN check.
- Declined, timeout and Touch ID failures answer as for `0x06`. Tokens from the
  PIN behave exactly like tokens from Touch ID.
- **Forgotten or blocked PIN.** Reset in the app with Touch ID: only the PIN is
  removed, the keys stay. `authenticatorReset` stays `0x30`.
- **In the app** the PIN can also be set, changed and removed, always with
  Touch ID. Setting or changing it there needs only Touch ID, not the old PIN.
  Changing or removing it invalidates every token, as `changePIN` does.

#### Using a pinUvAuthToken

From 3b, a makeCredential or getAssertion with a non-empty `pinUvAuthParam`:

- `pinUvAuthProtocol` missing: `0x14`; unsupported: `0x02`.
- `0x33` (`PIN_AUTH_INVALID`) if `pinUvAuthParam` does not verify over
  `clientDataHash` with the session's token, if `pinUvAuthProtocol` is not the
  protocol the token was issued over (CTAP keeps a token per protocol), if the
  token has expired, lacks the `mc` or `ga` permission, or names another RP ID.
- Otherwise there is no second Touch ID: the Touch ID of the token request
  authorizes this one operation (see "Where the token's Touch ID goes"). For a
  registration the phone shows the account and confirms it when done. For a
  sign-in with one candidate the signature follows without further
  interaction; with several, the card shows the preselected account (as in
  getAssertion) with Sign in and Other account, one tap and no second
  Touch ID. A token without an RP ID (`0x05`) first shows the site and waits
  for a tap. `excludeList` hits work as above.
- After an operation with user presence the token keeps no permissions for
  `mc` and `ga` (CTAP 2.1), and its Touch ID is dropped. This holds whatever
  the outcome, also after Decline, a timeout or `NO_CREDENTIALS`: a new
  operation needs a new token and a new Touch ID.
- **Silent assertions.** A getAssertion with `options.up = false` and a valid
  token with `ga` is answered as CTAP 2.1 §6.2.2 says, without a card and
  without a prompt:
  - The token's Touch ID signs for the first candidate (the first `allowList`
    hit, or the first discoverable credential of the RP). No candidates:
    `0x2E` (`NO_CREDENTIALS`).
  - Flags are `UV` only (`0x04`, `0x84` with extensions), so UP is 0. The
    counter goes up by one, and `hmac-secret` works as usual.
  - Only within 30 s of the token's Touch ID; later `0x33`. A silent assertion
    neither uses up the token's permissions nor counts as its first use, so it
    does not extend those 30 s, and the one operation with user presence must
    follow within them.

  Firefox checks this way whether a credential exists before it signs in.
  WebAuthn sites reject assertions without UP, so such a signature signs
  nobody in. OpenSSH rejects it too, unless the key was made with
  `no-touch-required`. Without a token, `up = false` stays as described under
  getAssertion. A token from `getPinToken` (`0x05`), whose prompt could not name
  the site, gets `0x2B` (`UNSUPPORTED_OPTION`): the phone never signs for a
  site it has not shown.

A `pinUvAuthParam` together with `options.uv = true` is treated as if `uv` were
absent.

### authenticatorCredentialManagement (`0x0A`, 3b)

Lists and deletes **discoverable** credentials. Parameters: `subCommand`
(key 1), `subCommandParams` (key 2), `pinUvAuthProtocol` (key 3),
`pinUvAuthParam` (key 4). The subcommands that need it verify `pinUvAuthParam`
over `subCommand || subCommandParams` with a token that has the `cm`
permission; failure: `0x33`. `subCommandParams` counts as the CBOR bytes exactly
as the host sent them, not re-encoded. A token with an RP ID only reaches that RP;
`getCredsMetadata` and `enumerateRPsBegin` need a token without one. Unlike
makeCredential and getAssertion, credential management never binds a token
without an RP ID to a site. The token is checked before a credential ID is
looked up, so a host without one cannot probe which IDs exist.

| subCommand | Auth | Phone |
|---|---|---|
| `0x01` getCredsMetadata | yes | `{1: discoverable credentials, 2: 100}`. There is no fixed limit; 100 keeps hosts from refusing. |
| `0x02` enumerateRPsBegin | yes | `{3: rp, 4: rpIDHash, 5: totalRPs}`. `rp` is `{"id": …}` plus the site's `name` if it sent one; the user's own site names stay on the phone. None: `0x2E`. |
| `0x03` enumerateRPsGetNextRP | no | `{3: rp, 4: rpIDHash}`; past the end or without a begin: `0x30` |
| `0x04` enumerateCredentialsBegin | yes | params `{1: rpIDHash}`. `{6: user, 7: credentialID, 8: publicKey, 9: totalCredentials, 10: credProtect}`, `user` as the site stored it, `credProtect` only if stored. None: `0x2E`. |
| `0x05` enumerateCredentialsGetNextCredential | no | as begin without `9`; past the end or without a begin: `0x30` |
| `0x06` deleteCredential | yes | params `{2: credentialID}`. The phone shows site and account and waits for a tap: deleting is final, keys are not backed up. Declined: `0x27`; 60 s: `0x2F`; unknown or not discoverable: `0x2E`. Deletes the credential and its Secure Enclave key. |
| `0x07` updateUserInformation | yes | params `{2: credentialID, 3: user}`. Unknown or not discoverable: `0x2E`. `user.id` must match, else `0x02`. Replaces `name` and `displayName`, no prompt. |

Any other command ends an enumeration. `0x41` (the CTAP 2.1 pre-release
command) answers `0x01` (`INVALID_COMMAND`).

### authenticatorSelection (`0x0B`, 3b)

The phone shows the host's name and waits for a tap: `0x00`. Declined: `0x27`.
No answer within 60 s: `0x2F`.

### Other commands

`authenticatorReset` (`0x07`) answers `0x30` (`NOT_ALLOWED`): credentials are
deleted only in the app, or one at a time with confirmation (3b). Anything else
answers `0x01` (`INVALID_COMMAND`).

All commands that wait for the user can be cancelled with `ctap.cancel`
(§5), which answers them with `0x2D` (`KEEPALIVE_CANCEL`).

### Host side

The host creates a virtual USB HID device (usage page `0xF1D0`) only while a
session with the phone is up, so applications see the key appear and disappear
like a real one. While a CBOR request waits for the phone it sends
`CTAPHID_KEEPALIVE` with status `UPNEEDED` every 100 ms, and it forwards
`CTAPHID_CANCEL` as `ctap.cancel`. CBOR is carried as is; Phase 3 needs nothing
else from the host. CTAPHID `MSG` (U2F) is not supported (`NMSG` capability).

`hmac-secret` with `systemd-cryptenroll` works for volumes opened after login,
while `phonekey fido run` is running. Unlocking the root volume at boot would
need the daemon and usbmuxd in the initramfs and is not covered. Keep the
LUKS passphrase: the secret exists only on the phone. Once a PIN exists (3c),
`systemd-cryptenroll` asks for it by default; for Touch ID alone enroll with
`--fido2-with-client-pin=no --fido2-with-user-verification=yes`.

## 11. Changes

| Version | Change |
|---|---|
| 1 | first version: session, pairing, hello, ping, status, photo |
| 1 + `fido` | `ctap.request`, `ctap.response`, `ctap.cancel` (Phase 2) |
| 1 + `fido`, Phase 3 | Authenticator behaviour of steps 3a–3c in §10 (`hmac-secret`, `pinUvAuthToken`, credential management, PIN). No message changes. |
| 1 + `camera` | `camera.start`, `camera.started`, `camera.keyframe`, `camera.changed`, `camera.stop`, `camera.stopped`, new `status` fields and error codes (Phase 4) |
| 1 + `camera`, preview | `camera.changed` may carry `camera` (switched on the phone); `camera.start` without `camera` uses the camera picked in the app; the app's preview (Phase 4a) |
