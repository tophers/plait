package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"plait/internal/protocol"
	"plait/internal/wg"
)

const cacheFormat = 1

var ErrCorruptCache = errors.New("cached state is corrupt or incompatible")

// Cache persists agent state under the state directory. Every file contains
// or protects secrets and is written 0600 with atomic replacement.
type Cache struct {
	Dir string
}

func (c *Cache) path(name string) string { return filepath.Join(c.Dir, name) }

func (c *Cache) ensureDir() error {
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(c.Dir, 0o700)
}

// writeAtomic writes data to a temp file in the same directory, syncs it,
// renames it over path, and syncs the directory so the rename is durable.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// LoadOrCreateKey returns the gateway private key, generating it on first
// use. The private key never leaves this host.
func (c *Cache) LoadOrCreateKey() (wg.Key, bool, error) {
	path := c.path("gateway.key")
	raw, err := os.ReadFile(path)
	if err == nil {
		fi, err := os.Stat(path)
		if err != nil {
			return wg.Key{}, false, err
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return wg.Key{}, false, fmt.Errorf("%s must not be accessible by group or others", path)
		}
		k, err := wg.ParseKey(strings.TrimSpace(string(raw)))
		return k, false, err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return wg.Key{}, false, err
	}
	if err := c.ensureDir(); err != nil {
		return wg.Key{}, false, err
	}
	k, err := wg.GeneratePrivateKey()
	if err != nil {
		return wg.Key{}, false, err
	}
	if err := writeAtomic(path, []byte(k.String()+"\n")); err != nil {
		return wg.Key{}, false, err
	}
	return k, true, nil
}

type desiredEnvelope struct {
	Format   int             `json:"format"`
	SHA256   string          `json:"sha256"`
	Snapshot json.RawMessage `json:"snapshot"`
}

// LoadDesired returns the cached desired snapshot, os.ErrNotExist if there is
// none, or ErrCorruptCache if it fails integrity or structural checks.
func (c *Cache) LoadDesired() (*protocol.SiteSnapshot, error) {
	raw, err := os.ReadFile(c.path("desired.json"))
	if err != nil {
		return nil, err
	}
	var env desiredEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Format != cacheFormat {
		return nil, ErrCorruptCache
	}
	sum := sha256.Sum256(env.Snapshot)
	if hex.EncodeToString(sum[:]) != env.SHA256 {
		return nil, ErrCorruptCache
	}
	var snap protocol.SiteSnapshot
	if err := json.Unmarshal(env.Snapshot, &snap); err != nil {
		return nil, ErrCorruptCache
	}
	if err := snap.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptCache, err)
	}
	return &snap, nil
}

func (c *Cache) StoreDesired(snap *protocol.SiteSnapshot) error {
	if err := c.ensureDir(); err != nil {
		return err
	}
	body, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	raw, err := json.Marshal(desiredEnvelope{Format: cacheFormat, SHA256: hex.EncodeToString(sum[:]), Snapshot: body})
	if err != nil {
		return err
	}
	return writeAtomic(c.path("desired.json"), raw)
}

// Applied records the last revision verified as fully applied. It is
// separate from the desired cache: a newer desired revision may be pending.
type Applied struct {
	Revision  int64     `json:"revision"`
	AppliedAt time.Time `json:"applied_at"`
}

func (c *Cache) LoadApplied() (Applied, error) {
	var a Applied
	raw, err := os.ReadFile(c.path("applied.json"))
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return a, err
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return Applied{}, ErrCorruptCache
	}
	return a, nil
}

func (c *Cache) StoreApplied(a Applied) error {
	if err := c.ensureDir(); err != nil {
		return err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return writeAtomic(c.path("applied.json"), raw)
}
