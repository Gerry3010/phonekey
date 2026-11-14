//go:build linux

// Package uhid creates virtual HID devices through /dev/uhid
// (Documentation/hid/uhid.rst in the Linux kernel).
package uhid

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Event types (include/uapi/linux/uhid.h).
const (
	evDestroy = 1
	evStart   = 2
	evStop    = 3
	evOpen    = 4
	evClose   = 5
	evOutput  = 6
	evCreate2 = 11
	evInput2  = 12
)

const (
	dataMax   = 4096
	eventSize = 4 + 4372 // type + largest union member (uhid_create2_req), packed
	busUSB    = 0x03
)

// Device is one virtual HID device.
type Device struct {
	f       *os.File
	writeMu sync.Mutex
	once    sync.Once
}

// Config describes the device.
type Config struct {
	Name             string
	ReportDescriptor []byte
	Vendor, Product  uint32
}

// Create opens /dev/uhid and creates the device.
func Create(c Config) (*Device, error) {
	if len(c.ReportDescriptor) > dataMax {
		return nil, errors.New("report descriptor too large")
	}
	f, err := os.OpenFile("/dev/uhid", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/uhid: %w (see linux/README.md for the udev rule)", err)
	}
	ev := make([]byte, eventSize)
	binary.LittleEndian.PutUint32(ev[0:], evCreate2)
	copy(ev[4:4+127], c.Name)        // name[128]
	copy(ev[132:132+63], "phonekey") // phys[64]
	binary.LittleEndian.PutUint16(ev[260:], uint16(len(c.ReportDescriptor)))
	binary.LittleEndian.PutUint16(ev[262:], busUSB)
	binary.LittleEndian.PutUint32(ev[264:], c.Vendor)
	binary.LittleEndian.PutUint32(ev[268:], c.Product)
	binary.LittleEndian.PutUint32(ev[272:], 1) // version
	copy(ev[280:], c.ReportDescriptor)
	if _, err := f.Write(ev); err != nil {
		f.Close()
		return nil, fmt.Errorf("create uhid device: %w", err)
	}
	return &Device{f: f}, nil
}

// ReadOutput blocks until the host sends an output report and returns it
// without a report ID. Other events are skipped.
func (d *Device) ReadOutput() ([]byte, error) {
	buf := make([]byte, eventSize)
	for {
		n, err := d.f.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 4 {
			continue
		}
		if binary.LittleEndian.Uint32(buf) != evOutput {
			continue // start, stop, open, close
		}
		size := int(binary.LittleEndian.Uint16(buf[4+dataMax:]))
		if size > dataMax {
			continue
		}
		data := append([]byte{}, buf[4:4+size]...)
		// hidraw writes on devices without report IDs carry a leading 0.
		if len(data) == 65 && data[0] == 0 {
			data = data[1:]
		}
		return data, nil
	}
}

// Input sends an input report to the host.
func (d *Device) Input(report []byte) error {
	if len(report) > dataMax {
		return errors.New("report too large")
	}
	ev := make([]byte, eventSize)
	binary.LittleEndian.PutUint32(ev[0:], evInput2)
	binary.LittleEndian.PutUint16(ev[4:], uint16(len(report)))
	copy(ev[6:], report)
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.f.Write(ev)
	return err
}

// Close destroys the device; reads then fail.
func (d *Device) Close() error {
	var err error
	d.once.Do(func() {
		ev := make([]byte, eventSize)
		binary.LittleEndian.PutUint32(ev[0:], evDestroy)
		d.writeMu.Lock()
		_, _ = d.f.Write(ev)
		d.writeMu.Unlock()
		err = d.f.Close()
	})
	return err
}
