//go:build !linux

package network

import (
	"errors"
	"net/netip"
)

var errUnsupported = errors.New("plait-agent network management requires Linux")

type unsupported struct{}

func New() Manager { return unsupported{} }

func (unsupported) Link(string) (LinkState, error)             { return LinkState{}, errUnsupported }
func (unsupported) EnsureLink(string, int) error               { return errUnsupported }
func (unsupported) DeleteLink(string) error                    { return errUnsupported }
func (unsupported) LinkExists(string) (bool, error)            { return false, errUnsupported }
func (unsupported) Addrs(string) ([]netip.Prefix, error)       { return nil, errUnsupported }
func (unsupported) OwnedRoutes(string) ([]Route, error)        { return nil, errUnsupported }
func (unsupported) SetRoute(string, Route) error               { return errUnsupported }
func (unsupported) DeleteRoute(string, netip.Prefix) error     { return errUnsupported }
func (unsupported) ConflictingRoutes(string, netip.Prefix) ([]string, error) {
	return nil, errUnsupported
}
