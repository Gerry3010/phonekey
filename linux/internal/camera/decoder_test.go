package camera_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/Gerry3010/phonekey/linux/internal/camera"
	"github.com/Gerry3010/phonekey/linux/internal/testphone"
)

// The decoder turns the phone's H.264 into pictures of the webcam's size,
// also when the stream is smaller (the phone may step down; §5 "camera").
func TestDecoder(t *testing.T) {
	frames := testphone.Video(t, 640, 360, 30, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, size := range [][2]int{{640, 360}, {1280, 720}} {
		dec, err := camera.NewDecoder(ctx, size[0], size[1])
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for _, f := range frames {
				if dec.Write(f.Data) != nil {
					return
				}
			}
		}()
		placeholder := camera.Placeholder(size[0], size[1])
		pic := make([]byte, camera.PictureSize(size[0], size[1]))
		var last []byte
		for i := range 10 {
			if err := dec.ReadPicture(pic); err != nil {
				t.Fatalf("%dx%d picture %d: %v", size[0], size[1], i, err)
			}
			if bytes.Equal(pic, placeholder) || bytes.Equal(pic, last) {
				t.Fatalf("%dx%d picture %d is not the moving test picture", size[0], size[1], i)
			}
			last = bytes.Clone(pic)
		}
		dec.Close()
	}
}

func TestPlaceholder(t *testing.T) {
	pic := camera.Placeholder(1280, 720)
	if len(pic) != camera.PictureSize(1280, 720) {
		t.Fatalf("size %d", len(pic))
	}
	if pic[0] == pic[360*1280+640-4*30] {
		t.Fatal("no outline where the camera should be")
	}
}
