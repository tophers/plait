package agent

import (
	"encoding/json"
	"errors"
	"fmt"

	"plait/internal/model"
	"plait/internal/protocol"
	"plait/internal/wg"
)

var (
	ErrRevisionRegression = errors.New("snapshot revision is older than the accepted revision")
	ErrRevisionConflict   = errors.New("snapshot contents conflict with the already accepted revision")
)

// Validator checks a snapshot against this host's identity before it is
// accepted or applied.
type Validator struct {
	SiteID    string
	PublicKey wg.Key
}

func (v Validator) Check(s *protocol.SiteSnapshot) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if s.SiteID != v.SiteID {
		return fmt.Errorf("snapshot is for site %s, this agent is site %s", s.SiteID, v.SiteID)
	}
	if !s.Interface.PublicKey.Equal(v.PublicKey) {
		// Never adopt an unexpected key: the controller and gateway disagree
		// about this gateway's identity and an administrator must resolve it.
		return errors.New("snapshot gateway public key does not match this gateway's private key")
	}
	if s.Interface.Name != model.InterfaceName {
		return fmt.Errorf("snapshot interface %q is not %s", s.Interface.Name, model.InterfaceName)
	}
	if err := model.ValidateMTU(s.Interface.MTU); err != nil {
		return err
	}
	if err := model.ValidateInterfaceName(s.Network.EgressInterface); err != nil {
		return err
	}
	if s.Network.EgressInterface == s.Interface.Name {
		return errors.New("egress interface must differ from the tunnel interface")
	}
	pool := model.Pool{Prefix: s.Network.ClientPool}
	if err := pool.Validate(); err != nil {
		return err
	}
	if s.Network.LANPrefixes == nil {
		return errors.New("snapshot missing lan_prefixes")
	}
	lans, err := model.ValidateSiteSubnets(pool, s.Network.LANPrefixes)
	if err != nil {
		return err
	}
	for i := range lans {
		if lans[i] != s.Network.LANPrefixes[i] {
			return errors.New("snapshot lan_prefixes are not canonical and sorted")
		}
	}
	if !s.Network.Masquerade {
		return errors.New("snapshot without masquerade is not supported in v1")
	}
	for _, p := range s.Peers {
		if !pool.Allocatable(p.AllowedIPs[0].Addr()) {
			return fmt.Errorf("peer %s address %s is reserved in the client pool", p.DeviceID, p.AllowedIPs[0])
		}
	}
	return nil
}

// Supersedes reports whether incoming should replace cached. Equal revisions
// with identical contents are not a change; anything older or conflicting is
// rejected rather than silently applied.
func Supersedes(cached, incoming *protocol.SiteSnapshot) (bool, error) {
	if cached == nil {
		return true, nil
	}
	switch {
	case incoming.Revision < cached.Revision:
		return false, fmt.Errorf("%w (%d < %d)", ErrRevisionRegression, incoming.Revision, cached.Revision)
	case incoming.Revision > cached.Revision:
		return true, nil
	}
	a, _ := json.Marshal(cached)
	b, _ := json.Marshal(incoming)
	if string(a) != string(b) {
		return false, fmt.Errorf("%w (revision %d)", ErrRevisionConflict, incoming.Revision)
	}
	return false, nil
}
