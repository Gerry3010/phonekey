// Package store keeps the host's static key and the paired phones in the
// user config directory (~/.config/phonekey on Linux,
// ~/Library/Application Support/phonekey on macOS).
package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Gerry3010/phonekey/linux/internal/proto"
)

// Phone is a paired phone.
type Phone struct {
	Name     string    `json:"name"`
	Model    string    `json:"model,omitempty"`
	Key      string    `json:"key"` // static public key, base64url
	PairedAt time.Time `json:"paired_at"`
}

// PublicKey decodes Key.
func (p Phone) PublicKey() ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(p.Key)
}

// Store is a config directory.
type Store struct{ Dir string }

// Open uses PHONEKEY_CONFIG_DIR or the user config directory.
func Open() (*Store, error) {
	if dir := os.Getenv("PHONEKEY_CONFIG_DIR"); dir != "" {
		return &Store{Dir: dir}, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return &Store{Dir: filepath.Join(base, "phonekey")}, nil
}

func (s *Store) path(name string) string { return filepath.Join(s.Dir, name) }

// HostKey loads the host's static key, creating it on first use.
func (s *Store) HostKey() (proto.Keypair, error) {
	b, err := os.ReadFile(s.path("host.key"))
	if err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(raw) != 32 {
			return proto.Keypair{}, errors.New("host.key is corrupt")
		}
		return proto.KeypairFromPrivate(raw)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return proto.Keypair{}, err
	}
	kp, err := proto.GenerateKeypair()
	if err != nil {
		return proto.Keypair{}, err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return proto.Keypair{}, err
	}
	f, err := os.OpenFile(s.path("host.key"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return proto.Keypair{}, err
	}
	defer f.Close()
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(kp.Private) + "\n"); err != nil {
		return proto.Keypair{}, err
	}
	return kp, f.Sync()
}

// Phones returns all paired phones.
func (s *Store) Phones() ([]Phone, error) {
	b, err := os.ReadFile(s.path("phones.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var phones []Phone
	if err := json.Unmarshal(b, &phones); err != nil {
		return nil, errors.New("phones.json is corrupt")
	}
	return phones, nil
}

// PhoneByKey finds a paired phone by its static public key.
func (s *Store) PhoneByKey(pub []byte) (Phone, bool, error) {
	phones, err := s.Phones()
	if err != nil {
		return Phone{}, false, err
	}
	for _, p := range phones {
		if k, err := p.PublicKey(); err == nil && bytes.Equal(k, pub) {
			return p, true, nil
		}
	}
	return Phone{}, false, nil
}

// SavePhone adds a phone or replaces the entry with the same key.
func (s *Store) SavePhone(p Phone) error {
	phones, err := s.Phones()
	if err != nil {
		return err
	}
	out := []Phone{p}
	for _, q := range phones {
		if q.Key != p.Key {
			out = append(out, q)
		}
	}
	return s.writeJSON("phones.json", out)
}

// RemovePhone deletes a phone by key; it reports whether one was removed.
func (s *Store) RemovePhone(key string) (bool, error) {
	phones, err := s.Phones()
	if err != nil {
		return false, err
	}
	var out []Phone
	for _, q := range phones {
		if q.Key != key {
			out = append(out, q)
		}
	}
	if len(out) == len(phones) {
		return false, nil
	}
	return true, s.writeJSON("phones.json", out)
}

func (s *Store) writeJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path(name))
}

// EncodeKey is the textual form of a public key used in phones.json.
func EncodeKey(pub []byte) string { return base64.RawURLEncoding.EncodeToString(pub) }
