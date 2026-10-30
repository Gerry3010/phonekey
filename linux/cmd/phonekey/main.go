// Command phonekey is the host side of phonekey: pair with the iPhone, ask
// for its status and take photos over USB (usbmuxd).
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Gerry3010/phonekey/linux/internal/client"
	"github.com/Gerry3010/phonekey/linux/internal/pairing"
	"github.com/Gerry3010/phonekey/linux/internal/store"
	"github.com/Gerry3010/phonekey/linux/internal/usbmux"
)

var version = "0.1.0"

const usage = `phonekey — use an iPhone as a peripheral

Usage:
  phonekey devices                 list iPhones usbmuxd sees
  phonekey pair [-name NAME]       pair with the PhoneKey app (shows a QR code)
  phonekey phones                  list paired phones
  phonekey unpair KEY              forget a paired phone
  phonekey status                  show the phone's status
  phonekey ping                    measure a round trip
  phonekey photo [-o FILE]         take a photo
  phonekey version

Connection flags (all commands that talk to the phone):
  -connect usb|tcp:HOST:PORT       default usb (usbmuxd); tcp:127.0.0.1:20555 reaches the iOS Simulator
  -udid UDID                       pick a phone when several are connected

Config: $PHONEKEY_CONFIG_DIR, default <user config dir>/phonekey
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "devices":
		err = devices()
	case "pair":
		err = pair(ctx, args)
	case "phones":
		err = phones()
	case "unpair":
		err = unpair(args)
	case "status":
		err = status(ctx, args)
	case "ping":
		err = ping(ctx, args)
	case "photo":
		err = photo(ctx, args)
	case "version", "-version", "--version":
		fmt.Println("phonekey", version)
	case "help", "-h", "-help", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "phonekey:", err)
		os.Exit(1)
	}
}

type connFlags struct {
	connect string
	udid    string
}

func (c *connFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.connect, "connect", "usb", "usb, or tcp:HOST:PORT")
	fs.StringVar(&c.udid, "udid", "", "UDID of the phone")
}

func (c *connFlags) client() (*client.Client, error) {
	st, err := store.Open()
	if err != nil {
		return nil, err
	}
	var tr client.Transport
	switch {
	case c.connect == "usb":
		tr = client.USBMux{UDID: c.udid}
	case strings.HasPrefix(c.connect, "tcp:"):
		tr = client.TCP{Addr: strings.TrimPrefix(c.connect, "tcp:")}
	default:
		return nil, fmt.Errorf("bad -connect %q", c.connect)
	}
	host, _ := os.Hostname()
	return &client.Client{Store: st, Transport: tr, HostName: host, Version: version}, nil
}

func (c *connFlags) session(ctx context.Context) (*client.Session, error) {
	cl, err := c.client()
	if err != nil {
		return nil, err
	}
	return cl.Connect(ctx)
}

func devices() error {
	list, err := usbmux.ListDevices()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("no devices")
	}
	for _, d := range list {
		fmt.Printf("%-8s %s (id %d)\n", d.ConnectionType, d.UDID, d.DeviceID)
	}
	return nil
}

func pair(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	var cf connFlags
	cf.register(fs)
	host, _ := os.Hostname()
	name := fs.String("name", host, "name shown on the phone")
	timeout := fs.Duration("timeout", 5*time.Minute, "how long to wait for the phone")
	fs.Parse(args)

	cl, err := cf.client()
	if err != nil {
		return err
	}
	hostKey, err := cl.Store.HostKey()
	if err != nil {
		return err
	}
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return err
	}
	url := pairing.URL(hostKey.Public, psk, *name)

	fmt.Println("In PhoneKey on the iPhone: Pair new host, then scan this code.")
	fmt.Println()
	if err := pairing.RenderQR(os.Stdout, url); err != nil {
		return err
	}
	fmt.Println()
	if strings.HasPrefix(cf.connect, "tcp:") {
		fmt.Printf("Simulator: xcrun simctl openurl booted '%s'\n\n", url)
	}
	fmt.Printf("Waiting for the phone (up to %s, Ctrl-C to stop)…\n", *timeout)

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	s, err := cl.Pair(ctx, psk)
	if err != nil {
		return err
	}
	defer s.Close()
	fmt.Printf("Paired with %s (%s, %s).\n", s.Phone.Name, s.Phone.Model, s.Hello.Device.System)
	return nil
}

func phones() error {
	st, err := store.Open()
	if err != nil {
		return err
	}
	list, err := st.Phones()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("no paired phones (run: phonekey pair)")
	}
	for _, p := range list {
		fmt.Printf("%s  %s (%s), paired %s\n", p.Key, p.Name, p.Model, p.PairedAt.Local().Format("2006-01-02 15:04"))
	}
	return nil
}

func unpair(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: phonekey unpair KEY (see phonekey phones)")
	}
	st, err := store.Open()
	if err != nil {
		return err
	}
	ok, err := st.RemovePhone(args[0])
	if err == nil && !ok {
		err = errors.New("no paired phone with that key")
	}
	return err
}

func status(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	var cf connFlags
	cf.register(fs)
	fs.Parse(args)
	s, err := cf.session(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Status(ctx)
	if err != nil {
		return err
	}
	battery := "unknown"
	if st.Battery.Level != nil {
		battery = fmt.Sprintf("%.0f%%", *st.Battery.Level*100)
	}
	d := s.Hello.Device
	fmt.Printf("Phone:          %s (%s, %s), app %s\n", d.Name, d.Model, d.System, s.Hello.AppVersion)
	fmt.Printf("Battery:        %s, %s\n", battery, st.Battery.State)
	fmt.Printf("Thermal state:  %s\n", st.Thermal)
	fmt.Printf("Desk mode:      %v (Guided Access %v)\n", st.DeskMode, st.GuidedAccess)
	fmt.Printf("Camera:         enabled %v, available %v\n", st.Camera.Enabled, st.Camera.Available)
	return nil
}

func ping(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	var cf connFlags
	cf.register(fs)
	fs.Parse(args)
	s, err := cf.session(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	rtt, err := s.Ping(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("pong from %s in %s\n", s.Phone.Name, rtt.Round(100*time.Microsecond))
	return nil
}

func photo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("photo", flag.ExitOnError)
	var cf connFlags
	cf.register(fs)
	out := fs.String("o", "", "output file (default photo-<time>.jpg, - for stdout)")
	camera := fs.String("camera", "back", "back or front")
	maxDim := fs.Int("max", 1568, "longest side in pixels, 0 for full resolution")
	quality := fs.Float64("quality", 0.8, "JPEG quality 0.1–1.0")
	fs.Parse(args)

	s, err := cf.session(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p, err := s.Photo(ctx, client.PhotoOptions{Camera: *camera, MaxDimension: *maxDim, Quality: *quality})
	if err != nil {
		return err
	}
	if *out == "-" {
		_, err := os.Stdout.Write(p.Data)
		return err
	}
	path := *out
	if path == "" {
		path = "photo-" + time.Now().Format("20060102-150405") + ".jpg"
	}
	if err := os.WriteFile(path, p.Data, 0o644); err != nil {
		return err
	}
	fmt.Printf("%s (%dx%d, %d KB)\n", path, p.Width, p.Height, len(p.Data)/1024)
	return nil
}
