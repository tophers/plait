// Command plait-agent reconciles a Linux site gateway's plait0 interface,
// routes, and nftables policy with the controller's desired state.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.zx2c4.com/wireguard/wgctrl"

	"plait/internal/agent"
	"plait/internal/firewall"
	"plait/internal/model"
	"plait/internal/network"
	"plait/internal/protocol"
)

var version = "dev"

const usage = `usage: plait-agent <command> [-config /etc/plait/agent.json]

  init                 create the gateway key if needed and print its public key
  enroll -controller URL -token TOKEN [-ca-file PEM | -ca-fingerprint sha256:HEX]
                       bind this gateway's key to its site and store the credential
  rotate-credential    replace the site credential (the old one expires shortly)
  run                  reconcile continuously, polling the controller
  apply-file <path>    accept and apply a snapshot from a file (local/emergency use)
  status               show cached, applied, and observed state
  configure -nft-include PATH
                       keep a copy of Plait's nftables table at PATH (*.nft) for a
                       host ruleset that flushes on reload to include ("" disables)
  uninstall            remove plait0, table inet plait, and the include file
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configPath := fs.String("config", agent.DefaultConfigPath, "agent configuration file")
	controllerURL := fs.String("controller", "", "enroll: controller base URL (https)")
	token := fs.String("token", "", "enroll: single-use enrollment token from the administrator")
	caFile := fs.String("ca-file", "", "enroll: PEM roots for the controller certificate")
	caPin := fs.String("ca-fingerprint", "", "enroll: trust the controller's own CA if its SHA-256 matches (shown with the token)")
	nftInclude := fs.String("nft-include", "", `configure: include file path for Plait's nftables table ("" disables)`)
	fs.Parse(os.Args[2:])

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var err error
	switch cmd {
	case "enroll":
		err = enroll(*configPath, *controllerURL, *token, *caFile, *caPin, log)
	case "configure":
		set := false
		fs.Visit(func(f *flag.Flag) { set = set || f.Name == "nft-include" })
		if !set {
			err = errors.New("usage: plait-agent configure -nft-include PATH   (\"\" disables)")
			break
		}
		err = configure(*configPath, *nftInclude, log)
	default:
		err = run(cmd, *configPath, fs.Args(), log)
	}
	if err != nil {
		log.Error("plait-agent failed", "err", err)
		os.Exit(1)
	}
}

func run(cmd, configPath string, args []string, log *slog.Logger) error {
	cfg, err := agent.LoadConfig(configPath)
	if err != nil {
		return err
	}
	if cmd == "uninstall" {
		// Needs neither enrollment nor the gateway key, so an unenrolled or
		// half-configured gateway can always be cleaned up.
		recon := &agent.Reconciler{
			Net:         network.New(),
			FW:          &firewall.Nft{Path: cfg.NftPath},
			Log:         log,
			IncludeFile: cfg.NftIncludeFile,
		}
		if err := recon.Teardown(context.Background(), model.InterfaceName); err != nil {
			return err
		}
		log.Info("removed plait0, table inet plait, and any nft include file; cached state and gateway key remain in " + cfg.StateDir)
		return nil
	}
	cache := &agent.Cache{Dir: cfg.StateDir}
	priv, created, err := cache.LoadOrCreateKey()
	if err != nil {
		return fmt.Errorf("gateway key: %w", err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		return err
	}
	if cmd == "init" {
		if created {
			fmt.Fprintln(os.Stderr, "generated a new gateway key")
		}
		fmt.Println(pub)
		return nil
	}
	if cfg.SiteID == "" {
		return errors.New("site_id is not configured; run `plait-agent enroll` first")
	}
	if cmd == "rotate-credential" {
		c, err := controllerClient(cfg)
		if err != nil {
			return err
		}
		tok, err := c.RotateCredential(context.Background())
		if err != nil {
			return err
		}
		if err := agent.WriteCredential(cfg.CredentialFile, tok); err != nil {
			return fmt.Errorf("new credential issued but not saved (the old one expires soon): %w", err)
		}
		log.Info("site credential rotated", "file", cfg.CredentialFile)
		return nil
	}

	wgc, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wireguard control: %w", err)
	}
	defer wgc.Close()
	recon := &agent.Reconciler{
		WG:          wgc,
		Net:         network.New(),
		FW:          &firewall.Nft{Path: cfg.NftPath},
		PrivateKey:  priv,
		Log:         log,
		IncludeFile: cfg.NftIncludeFile,
	}
	a := &agent.Agent{
		Cache:     cache,
		Validator: agent.Validator{SiteID: cfg.SiteID, PublicKey: pub},
		Recon:     recon,
		Version:   version,
		Log:       log,
	}
	if err := a.Load(); err != nil {
		// Never invent state: report and continue as not ready.
		log.Error("cached state unusable", "err", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "run":
		if cfg.ControllerURL == "" {
			log.Warn("no controller_url configured; serving cached state only")
		} else {
			c, err := controllerClient(cfg)
			if err != nil {
				return err
			}
			a.Client = c
		}
		err := a.Run(ctx)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err

	case "apply-file":
		if len(args) != 1 {
			return errors.New("usage: plait-agent apply-file <snapshot.json>")
		}
		raw, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var snap protocol.SiteSnapshot
		if err := json.Unmarshal(raw, &snap); err != nil {
			return fmt.Errorf("%s: malformed snapshot", args[0])
		}
		changed, err := a.Accept(&snap)
		if err != nil {
			return err
		}
		if !changed {
			log.Info("snapshot revision already accepted; reconciling", "revision", snap.Revision)
		}
		res, _ := a.ReconcileCached(ctx)
		if !res.Verified {
			return fmt.Errorf("revision %d not fully applied (%d errors)", res.Revision, len(res.Errors))
		}
		return nil

	case "status":
		out := struct {
			PublicKey       string   `json:"gateway_public_key"`
			SiteID          string   `json:"site_id"`
			CachedRevision  int64    `json:"cached_revision,omitempty"`
			AppliedRevision int64    `json:"applied_revision"`
			Drift           []string `json:"drift"`
		}{PublicKey: pub.String(), SiteID: cfg.SiteID, Drift: []string{}}
		st := a.Status()
		out.AppliedRevision = st.AppliedRevision
		if snap, err := cache.LoadDesired(); err == nil {
			out.CachedRevision = snap.Revision
			out.Drift = append(out.Drift, recon.Verify(ctx, snap)...)
		} else {
			out.Drift = append(out.Drift, "no valid cached desired state")
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	return fmt.Errorf("unknown command %q\n%s", cmd, usage)
}

func controllerClient(cfg *agent.Config) (*agent.Client, error) {
	if cfg.ControllerURL == "" {
		return nil, errors.New("controller_url is not configured")
	}
	tok, err := agent.ReadCredential(cfg.CredentialFile)
	if err != nil {
		return nil, err
	}
	c := agent.NewClient(cfg.ControllerURL, tok)
	c.TokenFile = cfg.CredentialFile
	if cfg.CAFile != "" {
		if err := c.UseCAFile(cfg.CAFile); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// enroll binds this gateway's locally generated key to the site named by an
// administrator-issued token, then records the site ID, controller URL, and
// credential in the agent's configuration.
func enroll(configPath, controllerURL, token, caFile, caPin string, log *slog.Logger) error {
	if controllerURL == "" || token == "" {
		return errors.New("usage: plait-agent enroll -controller URL -token TOKEN [-ca-file PEM | -ca-fingerprint sha256:HEX]")
	}
	if caFile != "" && caPin != "" {
		return errors.New("use -ca-file or -ca-fingerprint, not both")
	}
	cfg, err := agent.LoadConfig(configPath)
	if err != nil {
		return err
	}
	cfg.ControllerURL = controllerURL
	if caFile != "" {
		dst := filepath.Join(filepath.Dir(configPath), agent.CAFileName)
		if err := agent.InstallCAFile(caFile, dst); err != nil {
			return err
		}
		cfg.CAFile = dst
	}
	if caPin != "" {
		pem, err := agent.FetchPinnedCA(context.Background(), controllerURL, caPin)
		if err != nil {
			return err
		}
		dst := filepath.Join(filepath.Dir(configPath), agent.CAFileName)
		if err := agent.InstallCAPEM(pem, dst); err != nil {
			return err
		}
		cfg.CAFile = dst
		log.Info("trusting the controller CA", "fingerprint", caPin, "file", dst)
	}
	// Save first so an unwritable config fails before the token is consumed.
	if err := cfg.Save(configPath); err != nil {
		return err
	}
	priv, _, err := (&agent.Cache{Dir: cfg.StateDir}).LoadOrCreateKey()
	if err != nil {
		return err
	}
	pub, err := priv.PublicKey()
	if err != nil {
		return err
	}
	c := agent.NewClient(controllerURL, "")
	if cfg.CAFile != "" {
		if err := c.UseCAFile(cfg.CAFile); err != nil {
			return err
		}
	}
	siteID, cred, err := c.Enroll(context.Background(), token, pub)
	if err != nil {
		return err
	}
	if err := agent.WriteCredential(cfg.CredentialFile, cred); err != nil {
		return fmt.Errorf("enrolled site %s but could not save the credential; issue a new enrollment token: %w", siteID, err)
	}
	cfg.SiteID = siteID
	if err := cfg.Save(configPath); err != nil {
		return err
	}
	log.Info("enrolled", "site_id", siteID, "public_key", pub.String())
	return nil
}

// configure sets or clears nft_include_file. Clearing it removes the file so
// the host ruleset stops loading a table the agent no longer maintains.
func configure(configPath, include string, log *slog.Logger) error {
	if err := agent.CheckNftIncludeFile(include); err != nil {
		return err
	}
	cfg, err := agent.LoadConfig(configPath)
	if err != nil {
		return err
	}
	old := cfg.NftIncludeFile
	cfg.NftIncludeFile = include
	if err := cfg.Save(configPath); err != nil {
		return err
	}
	if old != "" && old != include {
		if err := os.Remove(old); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	log.Info("nft include file configured; restart plait-agent to apply", "file", include)
	return nil
}
