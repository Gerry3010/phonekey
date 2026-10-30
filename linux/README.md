# linux/

The Linux daemon for phonekey. It implements [../docs/protocol.md](../docs/protocol.md).
Nothing is here yet; work starts in Phase 1.

Planned responsibilities:

- connect to the phone through `usbmuxd` and run the encrypted session,
- pairing (show the QR code),
- virtual FIDO security key via `/dev/uhid`,
- webcam via `v4l2loopback`, microphone as a PipeWire source,
- an MCP server so a coding agent can take photos, record audio and ask for approvals.
