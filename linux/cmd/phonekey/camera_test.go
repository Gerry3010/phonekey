package main

import (
	"encoding/json"
	"testing"

	"github.com/Gerry3010/phonekey/linux/internal/proto"
)

func TestCameraChange(t *testing.T) {
	for _, tc := range []struct{ msg, want string }{
		{`{"t":"camera.changed","stream":2,"fps":15}`, "the phone now sends 15 fps"},
		{`{"t":"camera.changed","stream":2,"camera":"back"}`, "the phone switched to the back camera"},
		{`{"t":"camera.changed","stream":2,"camera":"front","fps":30}`, "the phone switched to the front camera and now sends 30 fps"},
		{`{"t":"camera.changed","stream":2,"zoom":2}`, ""},
	} {
		var c proto.CameraChanged
		if err := json.Unmarshal([]byte(tc.msg), &c); err != nil {
			t.Fatal(err)
		}
		if got := cameraChange(c); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.msg, got, tc.want)
		}
	}
}

func TestCameraStartWithoutCamera(t *testing.T) {
	b, err := json.Marshal(proto.CameraStart{T: "camera.start", ID: 5, Quality: "720p", FPS: 30})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	if _, ok := m["camera"]; ok {
		t.Fatalf("camera.start %s names a camera; the app's choice needs it absent", b)
	}
}
