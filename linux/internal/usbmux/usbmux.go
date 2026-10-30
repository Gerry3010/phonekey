// Package usbmux talks to usbmuxd (Linux: usbmuxd/libimobiledevice, macOS:
// built in) to list iOS devices and open TCP tunnels to a port on a device.
package usbmux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"howett.net/plist"
)

// Device is one attached iOS device.
type Device struct {
	DeviceID       int
	UDID           string
	ConnectionType string // "USB" or "Network"
	ProductID      int
}

// ResultError is a non-zero usbmuxd result code.
type ResultError int

func (e ResultError) Error() string {
	switch e {
	case 2:
		return "usbmuxd: device not found"
	case 3:
		return "usbmuxd: connection refused (is PhoneKey open on the phone?)"
	case 6:
		return "usbmuxd: protocol version mismatch"
	default:
		return fmt.Sprintf("usbmuxd: result %d", int(e))
	}
}

// ErrConnectionRefused reports whether err means nothing listens on the port.
func ErrConnectionRefused(err error) bool {
	var re ResultError
	return errors.As(err, &re) && re == 3
}

// socketAddr follows libimobiledevice: USBMUXD_SOCKET_ADDRESS is
// "UNIX:/path" or "host:port"; the default is /var/run/usbmuxd.
func socketAddr() (network, address string) {
	if v := os.Getenv("USBMUXD_SOCKET_ADDRESS"); v != "" {
		if path, ok := strings.CutPrefix(v, "UNIX:"); ok {
			return "unix", path
		}
		return "tcp", v
	}
	return "unix", "/var/run/usbmuxd"
}

func dial() (net.Conn, error) {
	network, address := socketAddr()
	c, err := net.DialTimeout(network, address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("cannot reach usbmuxd at %s (is usbmuxd running?): %w", address, err)
	}
	return c, nil
}

const (
	headerSize     = 16
	versionPlist   = 1
	messagePlist   = 8
	maxPacketBytes = 1 << 20
)

func request(messageType string) map[string]any {
	return map[string]any{
		"MessageType":         messageType,
		"ClientVersionString": "phonekey",
		"ProgName":            "phonekey",
		"kLibUSBMuxVersion":   3,
	}
}

func send(c net.Conn, tag uint32, payload map[string]any) error {
	body, err := plist.Marshal(payload, plist.XMLFormat)
	if err != nil {
		return err
	}
	pkt := make([]byte, headerSize+len(body))
	binary.LittleEndian.PutUint32(pkt[0:], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(pkt[4:], versionPlist)
	binary.LittleEndian.PutUint32(pkt[8:], messagePlist)
	binary.LittleEndian.PutUint32(pkt[12:], tag)
	copy(pkt[headerSize:], body)
	_, err = c.Write(pkt)
	return err
}

func recv(c net.Conn, v any) error {
	var hdr [headerSize]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return fmt.Errorf("usbmuxd: %w", err)
	}
	n := binary.LittleEndian.Uint32(hdr[0:])
	if n < headerSize || n > maxPacketBytes {
		return fmt.Errorf("usbmuxd: bad packet length %d", n)
	}
	body := make([]byte, n-headerSize)
	if _, err := io.ReadFull(c, body); err != nil {
		return fmt.Errorf("usbmuxd: %w", err)
	}
	_, err := plist.Unmarshal(body, v)
	return err
}

// ListDevices returns all devices usbmuxd knows about.
func ListDevices() ([]Device, error) {
	c, err := dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := send(c, 1, request("ListDevices")); err != nil {
		return nil, err
	}
	var resp struct {
		DeviceList []struct {
			DeviceID   int `plist:"DeviceID"`
			Properties struct {
				ConnectionType string `plist:"ConnectionType"`
				SerialNumber   string `plist:"SerialNumber"`
				ProductID      int    `plist:"ProductID"`
			} `plist:"Properties"`
		} `plist:"DeviceList"`
	}
	if err := recv(c, &resp); err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(resp.DeviceList))
	for _, d := range resp.DeviceList {
		out = append(out, Device{
			DeviceID:       d.DeviceID,
			UDID:           d.Properties.SerialNumber,
			ConnectionType: d.Properties.ConnectionType,
			ProductID:      d.Properties.ProductID,
		})
	}
	return out, nil
}

// ErrNoDevice means no USB-connected iOS device was found.
var ErrNoDevice = errors.New("no iPhone connected over USB")

// Pick selects a USB device: the one with udid, or the only one.
func Pick(devices []Device, udid string) (Device, error) {
	var usb []Device
	for _, d := range devices {
		if d.ConnectionType == "USB" {
			usb = append(usb, d)
		}
	}
	if udid != "" {
		for _, d := range usb {
			if d.UDID == udid {
				return d, nil
			}
		}
		return Device{}, fmt.Errorf("no USB device with UDID %s", udid)
	}
	switch len(usb) {
	case 0:
		return Device{}, ErrNoDevice
	case 1:
		return usb[0], nil
	default:
		ids := make([]string, len(usb))
		for i, d := range usb {
			ids[i] = d.UDID
		}
		return Device{}, fmt.Errorf("several iPhones connected, pick one with -udid: %s", strings.Join(ids, ", "))
	}
}

// Connect opens a TCP tunnel to port on the device. The returned connection
// is the raw tunnel.
func Connect(deviceID int, port uint16) (net.Conn, error) {
	c, err := dial()
	if err != nil {
		return nil, err
	}
	req := request("Connect")
	req["DeviceID"] = deviceID
	// usbmuxd wants the port in network byte order, read as little endian.
	req["PortNumber"] = int(port>>8 | port<<8)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := send(c, 2, req); err != nil {
		c.Close()
		return nil, err
	}
	var resp struct {
		MessageType string `plist:"MessageType"`
		Number      int    `plist:"Number"`
	}
	if err := recv(c, &resp); err != nil {
		c.Close()
		return nil, err
	}
	if resp.Number != 0 {
		c.Close()
		return nil, ResultError(resp.Number)
	}
	c.SetDeadline(time.Time{})
	return c, nil
}
