package model

import (
	"errors"
	"fmt"
	"net/netip"
)

var ErrPoolExhausted = errors.New("client address pool exhausted")

// Pool is the global client address pool. The network address, broadcast
// address, and first host (reserved for future use) are never allocated, nor
// are any configured exclusions.
type Pool struct {
	Prefix     netip.Prefix
	Exclusions []netip.Addr
}

// ParsePool parses and validates a pool prefix and its exclusions.
func ParsePool(prefix string, exclusions []string) (Pool, error) {
	p, err := ParsePrefix(prefix)
	if err != nil {
		return Pool{}, fmt.Errorf("client pool: %w", err)
	}
	pool := Pool{Prefix: p}
	for _, e := range exclusions {
		a, err := netip.ParseAddr(e)
		if err != nil {
			return Pool{}, fmt.Errorf("client pool exclusion %q: %w", e, err)
		}
		pool.Exclusions = append(pool.Exclusions, a)
	}
	return pool, pool.Validate()
}

func (p Pool) Validate() error {
	if !p.Prefix.IsValid() || !p.Prefix.Addr().Is4() {
		return errors.New("client pool must be an IPv4 prefix")
	}
	if p.Prefix != p.Prefix.Masked() {
		return fmt.Errorf("client pool %s is not canonical (use %s)", p.Prefix, p.Prefix.Masked())
	}
	if p.Prefix.Bits() > 29 {
		return fmt.Errorf("client pool %s is too small; use /29 or larger", p.Prefix)
	}
	if p.Prefix.Bits() < 8 {
		return fmt.Errorf("client pool %s is too large", p.Prefix)
	}
	for _, e := range p.Exclusions {
		if !e.Is4() || !p.Prefix.Contains(e) {
			return fmt.Errorf("client pool exclusion %s is outside %s", e, p.Prefix)
		}
	}
	return nil
}

func (p Pool) broadcast() netip.Addr {
	a := p.Prefix.Addr().As4()
	hostBits := 32 - p.Prefix.Bits()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= (1 << hostBits) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Reserved reports whether addr may never be allocated to a device.
func (p Pool) Reserved(addr netip.Addr) bool {
	network := p.Prefix.Addr()
	if addr == network || addr == network.Next() || addr == p.broadcast() {
		return true
	}
	for _, e := range p.Exclusions {
		if addr == e {
			return true
		}
	}
	return false
}

// Allocatable reports whether addr is a usable device address in this pool.
func (p Pool) Allocatable(addr netip.Addr) bool {
	return addr.Is4() && p.Prefix.Contains(addr) && !p.Reserved(addr)
}

// LowestFree returns the lowest allocatable address not present in used.
func (p Pool) LowestFree(used map[netip.Addr]bool) (netip.Addr, error) {
	for a := p.Prefix.Addr(); p.Prefix.Contains(a); a = a.Next() {
		if !p.Reserved(a) && !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w (%s)", ErrPoolExhausted, p.Prefix)
}
