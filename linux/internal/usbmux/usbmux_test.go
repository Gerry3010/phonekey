package usbmux

import (
	"errors"
	"testing"
)

func TestPick(t *testing.T) {
	usbA := Device{DeviceID: 1, UDID: "a", ConnectionType: "USB"}
	usbB := Device{DeviceID: 2, UDID: "b", ConnectionType: "USB"}
	wifiA := Device{DeviceID: 3, UDID: "a", ConnectionType: "Network"}

	if _, err := Pick([]Device{wifiA}, ""); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("network-only: %v", err)
	}
	if d, err := Pick([]Device{wifiA, usbA}, ""); err != nil || d.DeviceID != 1 {
		t.Fatalf("single USB: %v %v", d, err)
	}
	if _, err := Pick([]Device{usbA, usbB}, ""); err == nil {
		t.Fatal("ambiguous pick succeeded")
	}
	if d, err := Pick([]Device{usbA, usbB}, "b"); err != nil || d.DeviceID != 2 {
		t.Fatalf("by UDID: %v %v", d, err)
	}
}

func TestResultError(t *testing.T) {
	if !ErrConnectionRefused(ResultError(3)) || ErrConnectionRefused(ResultError(2)) {
		t.Fatal("ErrConnectionRefused")
	}
}
