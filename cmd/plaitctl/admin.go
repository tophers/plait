package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"

	"plait/internal/compiler"
	"plait/internal/config"
	"plait/internal/controller"
	"plait/internal/model"
	"plait/internal/profile"
	"plait/internal/secrets"
	"plait/internal/store"
	"plait/internal/wg"
)

type admin struct {
	ctx    context.Context
	svc    *controller.Service
	stdout io.Writer
}

// withAdmin opens the controller database named by $PLAIT_CONFIG (default
// /etc/plait/plaitd.json) and runs fn against it.
func withAdmin(args []string, fn func(*admin, []string) error) error {
	path := configPath()
	cfg, pool, err := config.Load(path)
	if err != nil {
		return err
	}
	sealer, err := secrets.LoadSealer(cfg.EncryptionKeyFile)
	if err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer st.Close()
	svc, err := controller.New(st, pool, sealer)
	if err != nil {
		return err
	}
	return fn(&admin{ctx: controller.WithActor(ctx, "local:plaitctl"), svc: svc, stdout: os.Stdout}, args)
}

func sub(args []string, usage string) (string, []string, error) {
	if len(args) == 0 {
		return "", nil, fmt.Errorf("usage: %s", usage)
	}
	return args[0], args[1:], nil
}

// parse parses flags that may appear before or after positional arguments.
func parse(fs *flag.FlagSet, args []string, nPos int, usage string) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, fmt.Errorf("%w\nusage: %s", err, usage)
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if len(pos) != nPos {
		return nil, fmt.Errorf("usage: %s", usage)
	}
	return pos, nil
}

func (a *admin) state() (*model.State, error) { return a.svc.State(a.ctx) }

func (a *admin) siteByName(name string) (*model.Site, error) {
	st, err := a.state()
	if err != nil {
		return nil, err
	}
	for i := range st.Sites {
		if st.Sites[i].Name == name || st.Sites[i].ID == name {
			return &st.Sites[i], nil
		}
	}
	return nil, fmt.Errorf("site %q: %w", name, controller.ErrNotFound)
}

func (a *admin) deviceByName(name string) (*model.Device, error) {
	st, err := a.state()
	if err != nil {
		return nil, err
	}
	for i := range st.Devices {
		if st.Devices[i].Name == name || st.Devices[i].ID == name {
			return &st.Devices[i], nil
		}
	}
	return nil, fmt.Errorf("device %q: %w", name, controller.ErrNotFound)
}

func (a *admin) linkByNames(siteName, deviceName string) (string, error) {
	site, err := a.siteByName(siteName)
	if err != nil {
		return "", err
	}
	dev, err := a.deviceByName(deviceName)
	if err != nil {
		return "", err
	}
	st, err := a.state()
	if err != nil {
		return "", err
	}
	for _, l := range st.Links {
		if l.SiteID == site.ID && l.DeviceID == dev.ID {
			return l.ID, nil
		}
	}
	return "", fmt.Errorf("device %s is not linked to site %s: %w", deviceName, siteName, controller.ErrNotFound)
}

// --- site ---

type siteFlags struct {
	name, endpoint, pubkey, egress string
	port, mtu                      int
	subnets                        stringList
	gatewayPorts                   string
}

func (f *siteFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.name, "name", "", "site name")
	fs.StringVar(&f.endpoint, "endpoint", "", "public WireGuard endpoint host (DNS name or IP)")
	fs.IntVar(&f.port, "port", model.DefaultListenPort, "WireGuard UDP listen port")
	fs.StringVar(&f.pubkey, "pubkey", "", "gateway public key; omit and use enroll-token for agent enrollment")
	fs.StringVar(&f.egress, "egress", "", "gateway LAN egress interface")
	fs.IntVar(&f.mtu, "mtu", model.DefaultSiteMTU, "gateway plait0 MTU")
	fs.Var(&f.subnets, "subnet", "advertised LAN prefix (repeatable or comma-separated)")
	fs.StringVar(&f.gatewayPorts, "gateway-tcp-ports", "", `TCP ports on the gateway itself reachable from the tunnel, e.g. "22" ("" for none)`)
}

func (f *siteFlags) spec() (controller.SiteSpec, error) {
	sp := controller.SiteSpec{Name: f.name, EndpointHost: f.endpoint, EgressInterface: f.egress, MTU: f.mtu}
	if f.port < 1 || f.port > 65535 {
		return sp, &model.ValidationError{Msg: fmt.Sprintf("port %d out of range", f.port)}
	}
	sp.ListenPort = uint16(f.port)
	if f.pubkey != "" {
		k, err := wg.ParseKey(f.pubkey)
		if err != nil {
			return sp, &model.ValidationError{Msg: "invalid site public key"}
		}
		sp.PublicKey = k
	}
	for _, s := range f.subnets {
		p, err := model.ParsePrefix(s)
		if err != nil {
			return sp, err
		}
		sp.Subnets = append(sp.Subnets, p)
	}
	ports, err := model.ParseTCPPorts(f.gatewayPorts)
	if err != nil {
		return sp, err
	}
	sp.GatewayTCPPorts = ports
	return sp, nil
}

func cmdSite(a *admin, args []string) error {
	verb, args, err := sub(args, "plaitctl site add|update|list|enable|disable|snapshot|enroll-token|revoke-credentials|status")
	if err != nil {
		return err
	}
	switch verb {
	case "enroll-token":
		return cmdEnrollToken(a, args)

	case "revoke-credentials":
		if len(args) != 1 {
			return errors.New("usage: plaitctl site revoke-credentials <site>")
		}
		site, err := a.siteByName(args[0])
		if err != nil {
			return err
		}
		if err := a.svc.RevokeSiteCredentials(a.ctx, site.ID); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "credentials revoked; the gateway keeps serving its cached peers until changed locally or re-enrolled")
		return nil

	case "status":
		if len(args) != 1 {
			return errors.New("usage: plaitctl site status <site>")
		}
		site, err := a.siteByName(args[0])
		if err != nil {
			return err
		}
		st, err := a.svc.SiteStatus(a.ctx, site.ID)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "note: live reachability and health are held by the running plaitd; this shows durable acknowledgments only")
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)

	case "add":
		var f siteFlags
		fs := flag.NewFlagSet("site add", flag.ContinueOnError)
		f.register(fs)
		if _, err := parse(fs, args, 0, "plaitctl site add -name N -endpoint H -pubkey K -egress IF -subnet CIDR..."); err != nil {
			return err
		}
		sp, err := f.spec()
		if err != nil {
			return err
		}
		id, err := a.svc.CreateSite(a.ctx, sp)
		if err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, id)
		return nil

	case "update":
		const usage = "plaitctl site update <site> [-name N] [-endpoint H] [-port P] [-pubkey K] [-egress IF] [-mtu M] [-subnet CIDR...] [-gateway-tcp-ports 22,...]"
		var f siteFlags
		fs := flag.NewFlagSet("site update", flag.ContinueOnError)
		f.register(fs)
		pos, err := parse(fs, args, 1, usage)
		if err != nil {
			return err
		}
		cur, err := a.siteByName(pos[0])
		if err != nil {
			return err
		}
		set := map[string]bool{}
		fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
		sp, err := f.spec()
		if err != nil {
			return err
		}
		// Unspecified flags keep their current values.
		if !set["name"] {
			sp.Name = cur.Name
		}
		if !set["endpoint"] {
			sp.EndpointHost = cur.EndpointHost
		}
		if !set["port"] {
			sp.ListenPort = cur.ListenPort
		}
		if !set["pubkey"] {
			sp.PublicKey = cur.PublicKey
		} else if !sp.PublicKey.Equal(cur.PublicKey) {
			fmt.Fprintln(os.Stderr, "warning: replacing the gateway key requires every linked device to refresh its profile")
		}
		if !set["egress"] {
			sp.EgressInterface = cur.EgressInterface
		}
		if !set["mtu"] {
			sp.MTU = cur.MTU
		}
		if !set["subnet"] {
			sp.Subnets = cur.Subnets
		}
		if !set["gateway-tcp-ports"] {
			sp.GatewayTCPPorts = cur.GatewayTCPPorts
		}
		return a.svc.UpdateSite(a.ctx, cur.ID, sp)

	case "list":
		st, err := a.state()
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tENABLED\tREVISION\tENDPOINT\tSUBNETS\tGATEWAY\tID")
		for _, s := range st.Sites {
			subnets := make([]string, len(s.Subnets))
			for i, p := range s.Subnets {
				subnets[i] = p.String()
			}
			gateway := "enrolled"
			if s.Pending() {
				gateway = "pending enrollment"
			}
			fmt.Fprintf(tw, "%s\t%t\t%d\t%s\t%s\t%s\t%s\n", s.Name, s.Enabled, s.DesiredRevision,
				compiler.FormatEndpoint(s.EndpointHost, s.ListenPort), strings.Join(subnets, ","), gateway, s.ID)
		}
		return tw.Flush()

	case "enable", "disable":
		if len(args) != 1 {
			return fmt.Errorf("usage: plaitctl site %s <site>", verb)
		}
		site, err := a.siteByName(args[0])
		if err != nil {
			return err
		}
		return a.svc.SetSiteEnabled(a.ctx, site.ID, verb == "enable")

	case "snapshot":
		if len(args) != 1 {
			return errors.New("usage: plaitctl site snapshot <site>")
		}
		site, err := a.siteByName(args[0])
		if err != nil {
			return err
		}
		snap, err := a.svc.SiteSnapshot(a.ctx, site.ID)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "warning: snapshot contains preshared keys")
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	}
	return fmt.Errorf("unknown site command %q", verb)
}

// --- device ---

// keySource resolves -pubkey or -new -private-key-out into a public key. For
// -new it writes the private key locally before anything is sent anywhere,
// returning a cleanup to remove it if the controller operation fails.
func keySource(pubkey string, newKey bool, out string) (wg.Key, func(), error) {
	noop := func() {}
	switch {
	case pubkey != "" && newKey:
		return wg.Key{}, noop, errors.New("use either -pubkey or -new, not both")
	case pubkey != "":
		k, err := wg.ParseKey(pubkey)
		if err != nil {
			return wg.Key{}, noop, &model.ValidationError{Msg: "invalid device public key"}
		}
		return k, noop, nil
	case newKey:
		if out == "" {
			return wg.Key{}, noop, errors.New("-new requires -private-key-out")
		}
		priv, err := wg.GeneratePrivateKey()
		if err != nil {
			return wg.Key{}, noop, err
		}
		pub, err := priv.PublicKey()
		if err != nil {
			return wg.Key{}, noop, err
		}
		if err := writeSecretFile(out, priv.String()+"\n"); err != nil {
			return wg.Key{}, noop, err
		}
		return pub, func() { os.Remove(out) }, nil
	}
	return wg.Key{}, noop, errors.New("a key is required: -pubkey KEY or -new -private-key-out PATH")
}

func cmdDevice(a *admin, args []string) error {
	verb, args, err := sub(args, "plaitctl device enroll|list|enable|disable|retire|delete|rename|replace-key|settings")
	if err != nil {
		return err
	}
	switch verb {
	case "enroll":
		const usage = "plaitctl device enroll <name> (-pubkey KEY | -new -private-key-out PATH)"
		fs := flag.NewFlagSet("device enroll", flag.ContinueOnError)
		pubkey := fs.String("pubkey", "", "existing device public key")
		newKey := fs.Bool("new", false, "generate a new key pair locally")
		out := fs.String("private-key-out", "", "where to write a newly generated private key (mode 0600)")
		pos, err := parse(fs, args, 1, usage)
		if err != nil {
			return err
		}
		pub, cleanup, err := keySource(*pubkey, *newKey, *out)
		if err != nil {
			return err
		}
		id, addr, err := a.svc.EnrollDevice(a.ctx, pos[0], pub, controller.ClientSettings{})
		if err != nil {
			cleanup()
			return err
		}
		fmt.Fprintf(a.stdout, "%s\t%s\n", id, addr)
		return nil

	case "list":
		st, err := a.state()
		if err != nil {
			return err
		}
		exports, err := a.svc.ExportStatus(a.ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tADDRESS\tSTATE\tPROFILE\tEXPORTED\tID")
		for _, d := range st.Devices {
			state := "enabled"
			if d.Retired {
				state = "retired"
			} else if !d.Enabled {
				state = "disabled"
			}
			exported := "never"
			if e, ok := exports[d.ID]; ok && e.Revision > 0 {
				exported = fmt.Sprintf("r%d at %s", e.Revision, e.At)
				if e.Revision < d.ProfileRevision {
					exported += " (changed since export)"
				}
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\tr%d\t%s\t%s\n", d.Name, d.AssignedIPv4, state, d.ProfileRevision, exported, d.ID)
		}
		return tw.Flush()

	case "enable", "disable", "retire":
		if len(args) != 1 {
			return fmt.Errorf("usage: plaitctl device %s <device>", verb)
		}
		dev, err := a.deviceByName(args[0])
		if err != nil {
			return err
		}
		if verb == "retire" {
			return a.svc.RetireDevice(a.ctx, dev.ID)
		}
		return a.svc.SetDeviceEnabled(a.ctx, dev.ID, verb == "enable")

	case "delete":
		const usage = "plaitctl device delete <device> [-force]"
		fs := flag.NewFlagSet("device delete", flag.ContinueOnError)
		force := fs.Bool("force", false, "delete even if a linked site has not applied the removal")
		pos, err := parse(fs, args, 1, usage)
		if err != nil {
			return err
		}
		dev, err := a.deviceByName(pos[0])
		if err != nil {
			return err
		}
		if err := a.svc.DeleteDevice(a.ctx, dev.ID, *force); err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "deleted %s; %s is free\n", dev.Name, dev.AssignedIPv4)
		return nil

	case "rename":
		if len(args) != 2 {
			return errors.New("usage: plaitctl device rename <device> <new-name>")
		}
		dev, err := a.deviceByName(args[0])
		if err != nil {
			return err
		}
		return a.svc.RenameDevice(a.ctx, dev.ID, args[1])

	case "replace-key":
		const usage = "plaitctl device replace-key <device> (-pubkey KEY | -new -private-key-out PATH)"
		fs := flag.NewFlagSet("device replace-key", flag.ContinueOnError)
		pubkey := fs.String("pubkey", "", "replacement public key")
		newKey := fs.Bool("new", false, "generate a new key pair locally")
		out := fs.String("private-key-out", "", "where to write a newly generated private key (mode 0600)")
		pos, err := parse(fs, args, 1, usage)
		if err != nil {
			return err
		}
		dev, err := a.deviceByName(pos[0])
		if err != nil {
			return err
		}
		pub, cleanup, err := keySource(*pubkey, *newKey, *out)
		if err != nil {
			return err
		}
		if err := a.svc.ReplaceDeviceKey(a.ctx, dev.ID, pub); err != nil {
			cleanup()
			return err
		}
		fmt.Fprintln(os.Stderr, "the old key is invalid at every linked site once they apply the change; export a new profile")
		return nil

	case "settings":
		const usage = "plaitctl device settings <device> [-mtu N] [-dns ADDR,...] [-search DOMAIN,...]"
		fs := flag.NewFlagSet("device settings", flag.ContinueOnError)
		mtu := fs.Int("mtu", 0, "client interface MTU override (0: omit, client-selected)")
		var dns stringList
		fs.Var(&dns, "dns", "DNS servers in order (repeatable or comma-separated); empty: no tunnel DNS")
		var search stringList
		fs.Var(&search, "search", "DNS search domains in order (repeatable or comma-separated)")
		pos, err := parse(fs, args, 1, usage)
		if err != nil {
			return err
		}
		dev, err := a.deviceByName(pos[0])
		if err != nil {
			return err
		}
		cs := controller.ClientSettings{MTU: *mtu, SearchDomains: search}
		for _, s := range dns {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return &model.ValidationError{Msg: fmt.Sprintf("invalid DNS server %q", s)}
			}
			cs.DNSServers = append(cs.DNSServers, addr)
		}
		hasPrivate, hasPublic := false, false
		for _, d := range cs.DNSServers {
			if d.IsPrivate() {
				hasPrivate = true
			} else {
				hasPublic = true
			}
		}
		if hasPrivate && hasPublic {
			fmt.Fprintln(os.Stderr, "note: mixed internal and public resolvers; private-name queries may reach public resolvers and receive negative answers, and ordered fallback is not guaranteed")
		}
		return a.svc.SetClientSettings(a.ctx, dev.ID, cs)
	}
	return fmt.Errorf("unknown device command %q", verb)
}

// --- link ---

func cmdLink(a *admin, args []string) error {
	verb, args, err := sub(args, "plaitctl link add|enable|disable|keepalive|rotate-psk <site> <device>")
	if err != nil {
		return err
	}
	switch verb {
	case "add":
		fs := flag.NewFlagSet("link add", flag.ContinueOnError)
		keepalive := fs.Int("keepalive", model.DefaultKeepalive, "client-side persistent keepalive seconds (0 disables)")
		pos, err := parse(fs, args, 2, "plaitctl link add <site> <device> [-keepalive N]")
		if err != nil {
			return err
		}
		site, err := a.siteByName(pos[0])
		if err != nil {
			return err
		}
		dev, err := a.deviceByName(pos[1])
		if err != nil {
			return err
		}
		id, err := a.svc.LinkDevice(a.ctx, site.ID, dev.ID, *keepalive)
		if err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, id)
		return nil

	case "enable", "disable", "rotate-psk":
		if len(args) != 2 {
			return fmt.Errorf("usage: plaitctl link %s <site> <device>", verb)
		}
		id, err := a.linkByNames(args[0], args[1])
		if err != nil {
			return err
		}
		switch verb {
		case "rotate-psk":
			if err := a.svc.RotateLinkPSK(a.ctx, id); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "the link is interrupted until both the gateway applies the change and the device imports a refreshed profile")
			return nil
		default:
			return a.svc.SetLinkEnabled(a.ctx, id, verb == "enable")
		}

	case "keepalive":
		if len(args) != 3 {
			return errors.New("usage: plaitctl link keepalive <site> <device> <seconds>")
		}
		id, err := a.linkByNames(args[0], args[1])
		if err != nil {
			return err
		}
		var n int
		if _, err := fmt.Sscanf(args[2], "%d", &n); err != nil {
			return &model.ValidationError{Msg: "keepalive must be an integer"}
		}
		return a.svc.SetLinkKeepalive(a.ctx, id, n)
	}
	return fmt.Errorf("unknown link command %q", verb)
}

// --- profile ---

// cmdProfile assembles a complete client profile locally from controller
// material and a private key that never leaves this machine.
func cmdProfile(a *admin, args []string) error {
	const usage = "plaitctl profile <device> -private-key-file PATH [-minify] [-o FILE]"
	fs := flag.NewFlagSet("profile", flag.ContinueOnError)
	keyFile := fs.String("private-key-file", "", "the device's private key (mode 0600)")
	minify := fs.Bool("minify", false, "minimal profile for QR codes")
	out := fs.String("o", "", "write to FILE (mode 0600) instead of stdout")
	pos, err := parse(fs, args[1:], 1, usage)
	if err != nil {
		return err
	}
	if *keyFile == "" {
		return fmt.Errorf("usage: %s", usage)
	}
	dev, err := a.deviceByName(pos[0])
	if err != nil {
		return err
	}
	priv, err := readPrivateKeyFile(*keyFile)
	if err != nil {
		return err
	}
	m, err := a.svc.ProfileMaterial(a.ctx, dev.ID)
	if err != nil {
		return err
	}
	conf, err := profile.Render(m, priv, profile.Options{Minify: *minify})
	if err != nil {
		return err
	}
	for _, w := range m.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	if *out != "" {
		err = writeSecretFile(*out, conf)
	} else {
		_, err = io.WriteString(a.stdout, conf)
	}
	if err != nil {
		return err
	}
	return a.svc.RecordExport(a.ctx, dev.ID, m.Revision)
}
