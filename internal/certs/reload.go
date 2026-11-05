package certs

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// Reloader serves a certificate pair from disk and picks up replacements
// without a restart. Files are checked at most once per Interval; a pair
// that fails to load (for example, the certificate was replaced but the key
// not yet) keeps the previous certificate in service and is retried.
type Reloader struct {
	CertFile, KeyFile string
	Interval          time.Duration
	OnError           func(error)

	mu        sync.Mutex
	cert      *tls.Certificate
	stamp     [2]time.Time
	checkedAt time.Time
}

// Load reads the pair; call it once at startup so bad files fail fast.
func (r *Reloader) Load() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reload()
}

func (r *Reloader) reload() error {
	stamp, err := r.stamps()
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(r.CertFile, r.KeyFile)
	if err != nil {
		return err
	}
	r.cert, r.stamp = &pair, stamp
	return nil
}

func (r *Reloader) stamps() ([2]time.Time, error) {
	var s [2]time.Time
	for i, p := range []string{r.CertFile, r.KeyFile} {
		fi, err := os.Stat(p)
		if err != nil {
			return s, err
		}
		s[i] = fi.ModTime()
	}
	return s, nil
}

// GetCertificate is a tls.Config.GetCertificate callback.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	interval := r.Interval
	if interval == 0 {
		interval = 30 * time.Second
	}
	if now := time.Now(); r.cert == nil || now.Sub(r.checkedAt) >= interval {
		r.checkedAt = now
		if s, err := r.stamps(); r.cert == nil || err != nil || s != r.stamp {
			if err := r.reload(); err != nil && r.OnError != nil {
				r.OnError(err)
			}
		}
	}
	if r.cert == nil {
		return nil, os.ErrNotExist
	}
	return r.cert, nil
}
