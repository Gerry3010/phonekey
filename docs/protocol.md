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

### fido

Feature `fido` in the phone's `hello`. The phone is a complete CTAP2
authenticator; the host only carries CTAPHID payloads between a virtual USB
security key and the phone ([§10](#10-fido-security-key)).

```json
{"t":"ctap.request","id":4,"cmd":16,"data":"BKA…"}
{"t":"ctap.response","id":4,"data":"AKk…"}
{"t":"ctap.cancel","id":4}
```

- `cmd` is the CTAPHID command: `16` (`0x10`, CBOR), `8` (`0x08`, WINK) or,
  from Phase 3c, `3` (`0x03`, MSG: U2F, [§10](#u2f-over-ctaphid-msg-3c)).
- `data` is standard base64 with padding (the JSON encoding of a byte array in
  Go and Swift). For CBOR the request is the CTAP command byte followed by the
  CBOR parameters; the response is the CTAP status byte followed by the CBOR
  response. For WINK both are empty For MSG they are the
  U2F request and response APDUs.
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
`hmac-secret` secrets are Keychain items too and, like the keys, need Touch ID.

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

## 10. FIDO security key

What the phone implements, so host and phone agree on behaviour. References:
CTAP 2.1 (FIDO Alliance, "Client to Authenticator Protocol", Proposed Standard
2021, errata 2022), the FIDO U2F Raw Message Formats v1.2 and WebAuthn Level 2.
Status names below are CTAP's without the `CTAP1_ERR_`/`CTAP2_ERR_` prefix.

Phase 2 is a CTAP 2.0 authenticator. Phase 3 adds the rest in three steps;
each step changes `authenticatorGetInfo`, so hosts never have to guess:

| Step | Adds | Unlocks |
|---|---|---|
| 3a | PIN/UV auth protocols 1 and 2, `getKeyAgreement`, `hmac-secret` | LUKS (`systemd-cryptenroll`) and other `hmac-secret` users |
| 3b | `pinUvAuthToken` via Touch ID, `authenticatorSelection`, credential management, `FIDO_2_1` | `ssh-keygen -K`, key management in browsers |
| 3c | U2F (CTAP1) over CTAPHID `MSG` | U2F-only clients |

Until a step has landed on both sides, everything it adds answers as in the
step before.

### authenticatorGetInfo (`0x04`)

| Key | Phase 2 | Phase 3 (step) |
|---|---|---|
| 1 versions | `["FIDO_2_0"]` | `["FIDO_2_0", "FIDO_2_1"]` (3b), plus `"U2F_V2"` first (3c) |
| 2 extensions | `["credProtect"]` | `["credProtect", "hmac-secret"]` (3a) |
| 3 aaguid | `4e3b1fe3-c75c-4055-b791-c999ff915951` | unchanged |
| 4 options | `{"rk": true, "up": true, "uv": true, "plat": false}` | adds `"pinUvAuthToken": true`, `"credMgmt": true` (3b) |
| 5 maxMsgSize | 1200 | unchanged |
| 6 pinUvAuthProtocols | absent | `[2, 1]` (3a) |
| 9 transports | `["usb"]` | unchanged |
| 10 algorithms | `[{"alg": -7, "type": "public-key"}]` | unchanged |
| 17 preferredPlatformUvAttempts | absent | 1 (3b): Touch ID retries on its own |
| 18 uvModality | absent | 2, fingerprint (3b) |

There is never a `clientPin` option: the phone has no PIN, Touch ID is the only
user verification. `alwaysUv` and `makeCredUvNotRqd` are absent; every
operation needs Touch ID anyway.

### Session state ("power cycle")

CTAP ties some state to a power cycle. Here it is tied to the session with one
host (§3): the phone's key agreement key, the `pinUvAuthToken` and any
credential management enumeration belong to that session and are dropped when
it ends. Another host's session cannot use them. A reconnecting host starts
over, just as its virtual USB key disappears and comes back (see Host side).

### authenticatorMakeCredential (`0x01`)

- Only ES256 (`alg` -7). Without it in `pubKeyCredParams`: `0x26`
  (`UNSUPPORTED_ALGORITHM`).
- `excludeList` hit: the phone shows that the key is already registered, waits
  for a tap, then answers `0x19` (`CREDENTIAL_EXCLUDED`).
- `pinUvAuthParam` (key 8) of length zero (authenticator selection): after a
  tap on the phone, `0x35` (`PIN_NOT_SET`); declined or no answer: `0x27`
  (`OPERATION_DENIED`).
- Non-empty `pinUvAuthParam`: up to step 3a always `0x33`
  (`PIN_AUTH_INVALID`). Phase 2 answered `0x36`, which is `PUAT_REQUIRED`; that
  was a bug. From 3b the phone verifies it as described under
  [Using a pinUvAuthToken](#using-a-pinuvauthtoken).
- Without `pinUvAuthParam` the phone shows the site (`rp.id`), the account and
  whether it becomes a passkey (`rk`), then asks for Touch ID, whatever
  `options.uv` says. Declined or failed: `0x27` (`OPERATION_DENIED`). No answer
  within 60 s: `0x2F` (`USER_ACTION_TIMEOUT`).
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
    `CredRandomWithoutUV` is never needed: no assertion is made without UV.
  - Other extensions are ignored.
- Every credential is stored on the phone, discoverable or not.

### authenticatorGetAssertion (`0x02`)

- Candidates: the stored credentials in `allowList` whose RP ID hash matches
  `rpId`, or without `allowList` all discoverable credentials for `rpId`. None:
  `0x2E` (`NO_CREDENTIALS`). Credentials registered over U2F (3c) match by RP ID
  hash, as CTAP 2.1 §10 requires.
- Candidates are looked up first, so a silent lookup (`options.up = false`)
  without matching credentials answers `0x2E` without any prompt (OpenSSH does
  this before enrolling a resident key). With matching credentials `up = false`
  answers `0x2B` (`UNSUPPORTED_OPTION`): a Secure Enclave key cannot sign
  without Touch ID.
- Several discoverable candidates: the phone lets the user pick one (it has a
  display), so the response never sets `numberOfCredentials` and
  `authenticatorGetNextAssertion` (`0x08`) answers `0x30` (`NOT_ALLOWED`).
- `pinUvAuthParam` (key 6): as for makeCredential.
- Without `pinUvAuthParam` the phone shows the site and the account; Touch ID
  unlocks the signature. Flags `UP | UV` (`0x05`, `0x85` with extensions); the
  per-credential counter goes up by one.
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
    unlocks the signature and the secret.
- The response contains `credential`, `authData`, `signature` (DER) and, for
  discoverable credentials, `user` (`id`, `name`, `displayName`).

### authenticatorClientPIN (`0x06`)

Without a PIN only some subcommands make sense. `pinUvAuthProtocol` (key 1)
must be 1 or 2, else `0x02` (`INVALID_PARAMETER`); missing parameters: `0x14`
(`MISSING_PARAMETER`).

| subCommand | Phone |
|---|---|
| `0x02` getKeyAgreement (3a) | `{1: keyAgreement}`: the phone's P-256 key agreement key of this session as a COSE key `{1: 2, 3: -25, -1: 1, -2: x, -3: y}`. Created when first asked for, never stored, dropped with the session. |
| `0x06` getPinUvAuthTokenUsingUvWithPermissions (3b) | see below |
| `0x07` getUVRetries (3b) | `{5: 8}`, or `{5: 0}` while iOS has locked Touch ID after failed attempts |
| `0x01`, `0x03`, `0x04`, `0x05`, `0x09` (PIN) | `0x3E` (`INVALID_SUBCOMMAND`) |
| anything else, and `0x06`/`0x07` before 3b | `0x3E` |

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
3. The phone shows the host's name and what the token is for: registering or
   signing in at `rpId` (`mc`, `ga`), or listing and deleting passkeys (`cm`).
   Then Touch ID.
4. Declined: `0x27` (`OPERATION_DENIED`). No answer within 60 s: `0x2F`.
   Touch ID failed: `0x3F` (`UV_INVALID`). Locked during the attempt: `0x3C`.
5. Success: a new random 32-byte token replaces any earlier token of this
   session. It carries the permissions, `rpId` if given, and "user verified"
   and "user present" (Touch ID proves both). Answer `{2: encrypt(shared
   secret, token)}`.

The token expires when the session ends, when it is not used within 30 s of
being issued, and 600 s after being issued at the latest.

#### Using a pinUvAuthToken

From 3b, a makeCredential or getAssertion with a non-empty `pinUvAuthParam`:

- `pinUvAuthProtocol` missing: `0x14`; unsupported: `0x02`.
- `0x33` (`PIN_AUTH_INVALID`) if `pinUvAuthParam` does not verify over
  `clientDataHash` with the session's token, if the token has expired, lacks
  the `mc` or `ga` permission, or names another RP ID.
- Otherwise there is no second Touch ID: the Touch ID of the token request
  authorizes this one operation. The phone still shows the account it is
  registering, and the account picker if there are several discoverable
  candidates. `excludeList` hits work as above.
- Afterwards the token keeps no permissions for `mc` and `ga` (CTAP 2.1); a new
  operation needs a new token and a new Touch ID.

A `pinUvAuthParam` together with `options.uv = true` is treated as if `uv` were
absent.

### authenticatorCredentialManagement (`0x0A`, 3b)

Lists and deletes **discoverable** credentials. Parameters: `subCommand`
(key 1), `subCommandParams` (key 2), `pinUvAuthProtocol` (key 3),
`pinUvAuthParam` (key 4). The subcommands that need it verify `pinUvAuthParam`
over `subCommand || subCommandParams` (CBOR) with a token that has the `cm`
permission; failure: `0x33`. A token with an RP ID only reaches that RP;
`getCredsMetadata` and `enumerateRPsBegin` need a token without one.

| subCommand | Auth | Phone |
|---|---|---|
| `0x01` getCredsMetadata | yes | `{1: discoverable credentials, 2: 100}`. There is no fixed limit; 100 keeps hosts from refusing. |
| `0x02` enumerateRPsBegin | yes | `{3: rp, 4: rpIDHash, 5: totalRPs}`. `rp` is `{"id": …}`: RP names are not stored. None: `0x2E`. |
| `0x03` enumerateRPsGetNextRP | no | `{3: rp, 4: rpIDHash}`; past the end or without a begin: `0x30` |
| `0x04` enumerateCredentialsBegin | yes | params `{1: rpIDHash}`. `{6: user, 7: credentialID, 8: publicKey, 9: totalCredentials, 10: credProtect}`, `credProtect` only if stored. None: `0x2E`. |
| `0x05` enumerateCredentialsGetNextCredential | no | as begin without `9`; past the end or without a begin: `0x30` |
| `0x06` deleteCredential | yes | params `{2: credentialID}`. The phone shows site and account and waits for a tap: deleting is final, keys are not backed up. Declined: `0x27`; 60 s: `0x2F`; unknown: `0x2E`. Deletes the credential and its Secure Enclave key. |
| `0x07` updateUserInformation | yes | params `{2: credentialID, 3: user}`. `user.id` must match, else `0x02`. Replaces `name` and `displayName`, no prompt. |

Any other command ends an enumeration. `0x41` (the CTAP 2.1 pre-release
command) answers `0x01` (`INVALID_COMMAND`).

### authenticatorSelection (`0x0B`, 3b)

The phone shows the host's name and waits for a tap: `0x00`. Declined: `0x27`.
No answer within 60 s: `0x2F`.

### U2F over CTAPHID MSG (3c)

`ctap.request` with `cmd` 3 carries a U2F request APDU, `ctap.response` the
response APDU (data, then the two status bytes). Short and extended length
encodings are accepted.

| Status word | Value |
|---|---|
| `SW_NO_ERROR` | `0x9000` |
| `SW_CONDITIONS_NOT_SATISFIED` | `0x6985` |
| `SW_COMMAND_NOT_ALLOWED` | `0x6986` |
| `SW_WRONG_DATA` | `0x6A80` |
| `SW_WRONG_LENGTH` | `0x6700` |
| `SW_INS_NOT_SUPPORTED` | `0x6D00` |
| `SW_CLA_NOT_SUPPORTED` | `0x6E00` |

- `U2F_VERSION` (`INS 0x03`): `U2F_V2`.
- `U2F_REGISTER` (`INS 0x01`, any `P1`): `challenge (32) || application (32)`.
  The phone creates a non-discoverable credential bound to the application
  parameter and answers `0x05 || public key (65) || key handle length ||
  key handle || certificate || signature`, signed over `0x00 || application ||
  challenge || key handle || public key`. The key handle is the credential ID.
  The certificate is self-signed by a fresh P-256 key used for this one
  registration and then discarded, so no attestation links two registrations.
- `U2F_AUTHENTICATE` (`INS 0x02`): `challenge (32) || application (32) ||
  length || key handle`. Unknown key handle, or bound to another application:
  `0x6A80`. `P1 0x07` (check only): `0x6985` if the key handle is known.
  `P1 0x03` and `0x08`: Touch ID, then `0x01 || counter (4, big-endian) ||
  signature`, signed with the credential key over `application || 0x01 ||
  counter || challenge`. `0x08` gets Touch ID too; the phone cannot sign without it.
- **User presence by polling**, as U2F clients expect: the first request opens
  the prompt and gets `0x6985` at once. Repeats of the same request get
  `0x6985` while the prompt is open, and the result once Touch ID has
  succeeded (for 10 s). Declined or failed: `0x6986`. If no repeat arrives for
  3 s, the phone closes the prompt.
- U2F gives the phone only a hash of the site. The prompt shows the host's
  name and, if the credential was made over CTAP2, the site; otherwise "unknown
  site".

### Other commands

`authenticatorReset` (`0x07`) answers `0x30` (`NOT_ALLOWED`): credentials are
only deleted in the app, or one at a time with confirmation (3b). Anything else
answers `0x01` (`INVALID_COMMAND`).

All commands that wait for the user can be cancelled with `ctap.cancel`
(§5), which answers them with `0x2D` (`KEEPALIVE_CANCEL`).

### Host side

The host creates a virtual USB HID device (usage page `0xF1D0`) only while a
session with the phone is up, so applications see the key appear and disappear
like a real one. While a CBOR request waits for the phone it sends
`CTAPHID_KEEPALIVE` with status `UPNEEDED` every 100 ms, and it forwards
`CTAPHID_CANCEL` as `ctap.cancel`. CBOR is carried as is; steps 3a and 3b need
nothing else from the host.

CTAPHID `MSG` (U2F): the host reads `authenticatorGetInfo` once per session. If
`versions` lists `U2F_V2` (3c), `CTAPHID_INIT` reports the capabilities without
`NMSG` and `MSG` is forwarded as `cmd` 3, without keepalives (the phone answers
at once, see polling above). Otherwise it keeps `NMSG` and answers `MSG` with
`ERR_INVALID_CMD`, as in Phase 2.

`hmac-secret` with `systemd-cryptenroll` works for volumes opened after login,
while `phonekey fido run` is running. Unlocking the root volume at boot would
need the daemon and usbmuxd in the initramfs and is not covered. Keep the
LUKS passphrase: the secret exists only on the phone.

## 11. Changes

| Version | Change |
|---|---|
| 1 | first version: session, pairing, hello, ping, status, photo |
| 1 + `fido` | `ctap.request`, `ctap.response`, `ctap.cancel` (Phase 2) |
| 1 + `fido`, Phase 3 | `cmd` 3 (MSG) for U2F; authenticator behaviour of steps 3a–3c in §10. No message changes otherwise. |
