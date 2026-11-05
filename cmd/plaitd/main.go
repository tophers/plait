// Command plaitd is the Plait controller: it stores intent, compiles desired
// state, and serves the agent and administrator REST API.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"plait/internal/api"
	"plait/internal/certs"
	"plait/internal/compiler"
	"plait/internal/config"
	"plait/internal/controller"
	"plait/internal/secrets"
	"plait/internal/store"
	"plait/internal/ui"
)

func main() {
	configPath := flag.String("config", config.DefaultPath, "controller configuration file")
	check := flag.Bool("check", false, "validate configuration and stored state, then exit")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*configPath, *check, log); err != nil {
		log.Error("plaitd failed", "err", err)
		os.Exit(1)
	}
}

func run(configPath string, check bool, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, pool, err := config.Load(configPath)
	if err != nil {
		return err
	}
	tlsMode, err := cfg.TLSMode()
	if err != nil {
		return err
	}
	sealer, err := secrets.LoadSealer(cfg.EncryptionKeyFile)
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer st.Close()
	svc, err := controller.New(st, pool, sealer)
	if err != nil {
		return err
	}
	state, err := svc.State(ctx)
	if err != nil {
		return err
	}
	if err := compiler.Validate(state); err != nil {
		return fmt.Errorf("stored state is invalid: %w", err)
	}
	log.Info("stored state valid", "sites", len(state.Sites), "devices", len(state.Devices), "links", len(state.Links))

	var reloader *certs.Reloader
	var auto *certs.Auto
	switch tlsMode {
	case config.TLSFiles:
		reloader = &certs.Reloader{CertFile: cfg.TLSCertFile, KeyFile: cfg.TLSKeyFile}
		if err := reloader.Load(); err != nil {
			return fmt.Errorf("TLS certificate: %w", err)
		}
	case config.TLSAuto:
		// Generated material is written by the service, not by -check.
		auto = &certs.Auto{Dir: cfg.AutoTLSDir()}
		reloader = &certs.Reloader{CertFile: auto.CertFile(), KeyFile: auto.KeyFile()}
	}
	if check {
		log.Info("configuration valid", "tls", tlsMode)
		return nil
	}
	if n, err := svc.AdminCount(ctx); err != nil {
		return err
	} else if n == 0 {
		log.Warn("no administrators exist; create one with: plaitctl admin create <username>")
	}
	if rec, _ := svc.InRecovery(ctx); rec {
		log.Warn("controller is in recovery: desired state is withheld from agents until `plaitctl recover complete`")
	}

	apiSrv := api.New(svc, log)
	adminUI, err := ui.New(svc, log, apiSrv.Limiter())
	if err != nil {
		return err
	}
	if auto != nil {
		if err := ensureAutoTLS(auto, cfg.TLSNames, log); err != nil {
			return err
		}
		caPEM, fp, err := certs.ReadCA(auto.Dir)
		if err != nil {
			return err
		}
		if err := reloader.Load(); err != nil {
			return fmt.Errorf("generated TLS certificate: %w", err)
		}
		adminUI.SetControllerCA(caPEM, fp)
		log.Info("serving a controller-generated certificate; gateways pin the CA when enrolling", "ca_fingerprint", fp, "names", auto.Names)
		go func() {
			t := time.NewTicker(12 * time.Hour)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := ensureAutoTLS(auto, cfg.TLSNames, log); err != nil {
						log.Error("renewing the generated TLS certificate", "err", err)
					}
				}
			}
		}()
	}
	if reloader != nil {
		reloader.OnError = func(err error) {
			log.Warn("TLS certificate changed on disk but could not be loaded; still serving the previous one", "err", err)
		}
	}
	apiSrv.UI = adminUI.Handler()
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	if reloader != nil {
		srv.TLSConfig.GetCertificate = reloader.GetCertificate
	}
	errc := make(chan error, 1)
	go func() {
		if reloader != nil {
			log.Info("listening", "addr", cfg.Listen, "tls", tlsMode)
			errc <- srv.ListenAndServeTLS("", "")
		} else {
			log.Warn("listening without TLS on loopback; place a TLS-terminating proxy in front", "addr", cfg.Listen)
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
	return nil
}

// ensureAutoTLS (re)issues the generated server certificate when needed.
// It covers the host's current names and addresses plus the configured
// names (e.g. a public DNS name behind NAT), so an address change is picked
// up at the next check.
func ensureAutoTLS(auto *certs.Auto, names []string, log *slog.Logger) error {
	auto.Names = append(certs.DefaultNames(), names...)
	changed, err := auto.Ensure()
	if err != nil {
		return fmt.Errorf("generated TLS certificate: %w", err)
	}
	if changed {
		log.Info("issued TLS server certificate", "names", auto.Names)
	}
	return nil
}
