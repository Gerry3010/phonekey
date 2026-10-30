# phonekey wire protocol

**Protocol version 1** (Phase 1: session, pairing, status, photo).

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
 "camera":{"enabled":false,"available":true}}
```

- `battery.level`: 0…1, or `null` if unknown. `battery.state`: `unknown`,
  `unplugged`, `charging`, `full`.
- `thermal`: `nominal`, `fair`, `serious`, `critical`.
- `camera.enabled`: the user allows hosts to take photos (a switch in the app,
  off by default). `camera.available`: the device has a usable camera and the
  app has camera permission.

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
| `busy` | the phone is already handling a conflicting request |
| `capture_failed` | taking the photo failed |
| `internal` | anything else |

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

The session key is not the FIDO or approval key. Those are created later in the
Secure Enclave (Phase 2 and 3).

## 8. Security notes

- Logs MUST NOT contain private keys, PSKs, pairing URLs or decrypted payloads.
- Loopback only: in v1 nothing on the network can reach the phone. Anything on
  the host that can talk to usbmuxd can open a connection, which is why every
  session is authenticated.
- A pairing needs a confirmation on the phone and a secret that is only shown on
  the host's screen.

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

## 10. Changes

| Version | Change |
|---|---|
| 1 | first version: session, pairing, hello, ping, status, photo |
