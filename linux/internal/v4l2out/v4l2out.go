//go:build linux

// Package v4l2out writes pictures to a v4l2loopback device, so applications
// see a webcam, and reports when they start and stop reading it.
package v4l2out

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ioctls and constants from linux/videodev2.h (64-bit layouts) and
// v4l2loopback.c.
const (
	vidiocSFmt           = 0xc0d05605 // _IOWR('V', 5, struct v4l2_format), 208 bytes
	vidiocSubscribeEvent = 0x4020565a // _IOW('V', 90, struct v4l2_event_subscription), 32 bytes
	vidiocDQEvent        = 0x80885659 // _IOR('V', 89, struct v4l2_event), 136 bytes

	bufTypeVideoOutput = 2
	pixFmtYUV420       = 0x32315559 // 'YU12', planar I420
	fieldNone          = 1
	colorspaceRec709   = 3

	eventSubSendInitial = 1
	// V4L2_EVENT_PRIVATE_START + V4L2LOOPBACK_EVENT_OFFSET + 1: the number of
	// applications streaming from the device (0 or 1) changed.
	eventClientUsage = 0x08000000 + 0x08E00000 + 1
)

// Device is the producer side of a v4l2loopback device.
type Device struct {
	Width, Height int
	f             *os.File
	writeMu       sync.Mutex
	usage         chan int
	done          chan struct{}
	wg            sync.WaitGroup
}

// Open sets the device to I420 at width×height and starts watching readers.
// The module should be loaded with exclusive_caps=1, so applications only see
// a webcam while a producer is open. They see it only after the first picture,
// so write one right away.
func Open(path string, width, height int) (*Device, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	d := &Device{Width: width, Height: height, f: f, usage: make(chan int, 8), done: make(chan struct{})}
	if err := d.setFormat(); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: setting the format: %w (is it a v4l2loopback device?)", path, err)
	}
	var sub [32]byte
	binary.LittleEndian.PutUint32(sub[0:], eventClientUsage)
	binary.LittleEndian.PutUint32(sub[8:], eventSubSendInitial)
	if err := ioctl(f, vidiocSubscribeEvent, unsafe.Pointer(&sub[0])); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: watching readers: %w (v4l2loopback 0.12.5 or later needed)", path, err)
	}
	d.wg.Add(1)
	go d.watch()
	return d, nil
}

func (d *Device) setFormat() error {
	var b [208]byte
	binary.LittleEndian.PutUint32(b[0:], bufTypeVideoOutput)
	pix := b[8:] // struct v4l2_pix_format, after the 8-byte aligned union start
	binary.LittleEndian.PutUint32(pix[0:], uint32(d.Width))
	binary.LittleEndian.PutUint32(pix[4:], uint32(d.Height))
	binary.LittleEndian.PutUint32(pix[8:], pixFmtYUV420)
	binary.LittleEndian.PutUint32(pix[12:], fieldNone)
	binary.LittleEndian.PutUint32(pix[16:], uint32(d.Width))
	binary.LittleEndian.PutUint32(pix[20:], uint32(d.Width*d.Height*3/2))
	binary.LittleEndian.PutUint32(pix[24:], colorspaceRec709)
	return ioctl(d.f, vidiocSFmt, unsafe.Pointer(&b[0]))
}

// Write shows one I420 picture of the device's size.
func (d *Device) Write(pic []byte) error {
	if len(pic) != d.Width*d.Height*3/2 {
		return errors.New("picture of the wrong size")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.f.Write(pic)
	return err
}

// Usage delivers the number of applications streaming from the device: once
// right after Open, then on every change.
func (d *Device) Usage() <-chan int { return d.usage }

// watch waits for client usage events. It polls with a timeout, so Close
// ends it.
func (d *Device) watch() {
	defer d.wg.Done()
	fd := int(d.f.Fd())
	for {
		select {
		case <-d.done:
			return
		default:
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLPRI}}
		n, err := unix.Poll(fds, 250)
		if err != nil && err != unix.EINTR {
			return
		}
		if n == 0 || fds[0].Revents&unix.POLLPRI == 0 {
			continue
		}
		// The fd blocks, and so would VIDIOC_DQEVENT without an event: take
		// exactly the ones pending (poll said one is, each says how many
		// more follow).
		for more := true; more; {
			var ev [136]byte
			if ioctl(d.f, vidiocDQEvent, unsafe.Pointer(&ev[0])) != nil {
				break
			}
			// struct v4l2_event: type (0), the 8-byte aligned union u (8),
			// pending (72).
			more = binary.LittleEndian.Uint32(ev[72:]) > 0
			if binary.LittleEndian.Uint32(ev[0:]) != eventClientUsage {
				continue
			}
			count := int(binary.LittleEndian.Uint32(ev[8:]))
			select {
			case d.usage <- count:
			case <-d.done:
				return
			}
		}
	}
}

// Close stops the producer; with exclusive_caps=1 applications stop seeing
// the webcam.
func (d *Device) Close() error {
	close(d.done)
	d.wg.Wait()
	return d.f.Close()
}

func ioctl(f *os.File, req uintptr, arg unsafe.Pointer) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var errno unix.Errno
	if err := conn.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, req, uintptr(arg))
	}); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	return nil
}
