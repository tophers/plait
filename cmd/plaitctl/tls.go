package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"plait/internal/certs"
	"plait/internal/config"
)

func configPath() string {
	if p := os.Getenv("PLAIT_CONFIG"); p != "" {
		return p
	}
	return config.DefaultPath
}

// cmdTLS shows or changes how plaitd serves TLS. Changes rewrite the
// configuration file (run as root) and take effect when plaitd restarts.
func cmdTLS(args []string, stdout io.Writer) error {
	verb, rest, err := sub(args, "plaitctl tls status|auto [-name N]...|files -cert FILE -key FILE")
	if err != nil {
		return err
	}
	path := configPath()
	cfg, _, err := config.Load(path)
	if err != nil {
		return err
	}
	switch verb {
	case "status":
		return tlsStatus(cfg, stdout)
	case "auto":
		fs := flag.NewFlagSet("tls auto", flag.ContinueOnError)
		var names stringList
		fs.Var(&names, "name", "extra DNS name or IP address for the certificate, beyond this host's own (repeatable)")
		if _, err := parse(fs, rest, 0, "plaitctl tls auto [-name N]..."); err != nil {
			return err
		}
		cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSNames = "", "", names
	case "files":
		fs := flag.NewFlagSet("tls files", flag.ContinueOnError)
		cert := fs.String("cert", "", "certificate chain (PEM)")
		key := fs.String("key", "", "private key (PEM)")
		if _, err := parse(fs, rest, 0, "plaitctl tls files -cert FILE -key FILE"); err != nil {
			return err
		}
		if *cert == "" || *key == "" {
			return errors.New("usage: plaitctl tls files -cert FILE -key FILE")
		}
		if _, err := tls.LoadX509KeyPair(*cert, *key); err != nil {
			return err
		}
		cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSNames = *cert, *key, nil
	default:
		return fmt.Errorf("unknown tls command %q", verb)
	}
	mode, err := cfg.TLSMode()
	if err != nil {
		return err
	}
	if mode == config.TLSOff {
		return fmt.Errorf("listen %s is loopback, so plaitd serves plaintext behind a proxy; change listen first", cfg.Listen)
	}
	if err := cfg.Save(path); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "TLS mode is now %s; restart plaitd to apply.\n", mode)
	return nil
}

func tlsStatus(cfg *config.Controller, w io.Writer) error {
	mode, err := cfg.TLSMode()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "mode: %s\n", mode)
	certFile, keyFile := cfg.TLSCertFile, cfg.TLSKeyFile
	switch mode {
	case config.TLSOff:
		fmt.Fprintf(w, "listen %s is loopback: plaintext for a TLS-terminating reverse proxy\n", cfg.Listen)
		return nil
	case config.TLSAuto:
		dir := cfg.AutoTLSDir()
		_, fp, err := certs.ReadCA(dir)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(w, "not generated yet: plaitd creates %s on first start\n", dir)
			return nil
		} else if err != nil {
			return err
		}
		fmt.Fprintf(w, "ca_fingerprint: %s\n", fp)
		fmt.Fprintf(w, "ca_file: %s/%s (public; trust it in browsers to avoid warnings)\n", dir, certs.CAFile)
		extra := ""
		if len(cfg.TLSNames) > 0 {
			extra = " plus " + strings.Join(cfg.TLSNames, ", ")
		}
		fmt.Fprintf(w, "names: this host's names and addresses%s\n", extra)
		a := certs.Auto{Dir: dir}
		certFile, keyFile = a.CertFile(), a.KeyFile()
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	leaf := pair.Leaf
	names := append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	fmt.Fprintf(w, "certificate: %s\n", certFile)
	fmt.Fprintf(w, "covers: %s\n", strings.Join(names, ", "))
	fmt.Fprintf(w, "issuer: %s\n", leaf.Issuer.CommonName)
	fmt.Fprintf(w, "expires: %s (%d days)\n", leaf.NotAfter.UTC().Format(time.RFC3339), int(time.Until(leaf.NotAfter).Hours()/24))
	return nil
}
