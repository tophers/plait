//go:build linux

package network

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type Netlink struct{}

func New() Manager { return Netlink{} }

func (Netlink) Link(name string) (LinkState, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return LinkState{}, nil
		}
		return LinkState{}, err
	}
	a := l.Attrs()
	return LinkState{
		Exists: true,
		Owned:  a.Alias == OwnerAlias && l.Type() == "wireguard",
		Up:     a.Flags&net.FlagUp != 0,
		MTU:    a.MTU,
	}, nil
}

func (n Netlink) EnsureLink(name string, mtu int) error {
	st, err := n.Link(name)
	if err != nil {
		return err
	}
	if st.Exists && !st.Owned {
		return ErrNotOwned
	}
	if !st.Exists {
		la := netlink.NewLinkAttrs()
		la.Name = name
		la.MTU = mtu
		if err := netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}); err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if l.Attrs().Alias != OwnerAlias {
		if err := netlink.LinkSetAlias(l, OwnerAlias); err != nil {
			return fmt.Errorf("mark %s owned: %w", name, err)
		}
	}
	if l.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(l, mtu); err != nil {
			return fmt.Errorf("set %s mtu: %w", name, err)
		}
	}
	if l.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(l); err != nil {
			return fmt.Errorf("set %s up: %w", name, err)
		}
	}
	return nil
}

func (n Netlink) DeleteLink(name string) error {
	st, err := n.Link(name)
	if err != nil || !st.Exists {
		return err
	}
	if !st.Owned {
		return ErrNotOwned
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkDel(l)
}

func (Netlink) LinkExists(name string) (bool, error) {
	_, err := netlink.LinkByName(name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func ipNetToPrefix(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(a.Unmap(), ones).Masked(), true
}

func (Netlink) Addrs(dev string) ([]netip.Prefix, error) {
	l, err := netlink.LinkByName(dev)
	if err != nil {
		return nil, err
	}
	addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			ones, _ := a.Mask.Size()
			out = append(out, netip.PrefixFrom(ip.Unmap(), ones))
		}
	}
	return out, nil
}

func (Netlink) OwnedRoutes(dev string) ([]Route, error) {
	l, err := netlink.LinkByName(dev)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return nil, nil
		}
		return nil, err
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{LinkIndex: l.Attrs().Index, Table: unix.RT_TABLE_MAIN},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	var out []Route
	for _, r := range routes {
		if r.Protocol != RouteProtocol {
			continue
		}
		if p, ok := ipNetToPrefix(r.Dst); ok {
			src, _ := netip.AddrFromSlice(r.Src)
			out = append(out, Route{Dst: p, Src: src.Unmap()})
		}
	}
	return out, nil
}

func ownedRoute(dev string, dst netip.Prefix) (*netlink.Route, error) {
	l, err := netlink.LinkByName(dev)
	if err != nil {
		return nil, err
	}
	return &netlink.Route{
		LinkIndex: l.Attrs().Index,
		Dst:       prefixToIPNet(dst),
		Scope:     netlink.SCOPE_LINK,
		Protocol:  RouteProtocol,
		Table:     unix.RT_TABLE_MAIN,
	}, nil
}

func (Netlink) SetRoute(dev string, route Route) error {
	r, err := ownedRoute(dev, route.Dst)
	if err != nil {
		return err
	}
	if route.Src.IsValid() {
		r.Src = route.Src.AsSlice()
	}
	if err := netlink.RouteReplace(r); err != nil {
		return fmt.Errorf("set route %s dev %s src %s: %w", route.Dst, dev, route.Src, err)
	}
	return nil
}

func (Netlink) DeleteRoute(dev string, dst netip.Prefix) error {
	r, err := ownedRoute(dev, dst)
	if err != nil {
		return err
	}
	if err := netlink.RouteDel(r); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("delete route %s dev %s: %w", dst, dev, err)
	}
	return nil
}

func (Netlink) ConflictingRoutes(dev string, pool netip.Prefix) ([]string, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	devIndex := -1
	if l, err := netlink.LinkByName(dev); err == nil {
		devIndex = l.Attrs().Index
	}
	var out []string
	for _, r := range routes {
		p, ok := ipNetToPrefix(r.Dst)
		if !ok || p.Bits() == 0 || !p.Overlaps(pool) {
			continue
		}
		if r.LinkIndex == devIndex && r.Protocol == RouteProtocol {
			continue
		}
		name := fmt.Sprintf("ifindex %d", r.LinkIndex)
		if l, err := netlink.LinkByIndex(r.LinkIndex); err == nil {
			name = l.Attrs().Name
		}
		out = append(out, fmt.Sprintf("%s dev %s proto %d", p, name, r.Protocol))
	}
	return out, nil
}
