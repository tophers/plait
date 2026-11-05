package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"plait/internal/secrets"
	"plait/internal/wg"
)

func cmdGenkey(stdout io.Writer) error {
	k, err := wg.GeneratePrivateKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, k)
	return err
}

func cmdPubkey(stdin io.Reader, stdout io.Writer) error {
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	priv, err := wg.ParseKey(strings.TrimSpace(line))
	if err != nil {
		return err
	}
	pub, err := priv.PublicKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, pub)
	return err
}

func cmdInitKey(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: plaitctl init-key <path>")
	}
	if err := secrets.GenerateKeyFile(args[0]); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s; back it up securely and separately from the database\n", args[0])
	return nil
}

func readPrivateKeyFile(path string) (wg.Key, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return wg.Key{}, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return wg.Key{}, fmt.Errorf("private key file %s must not be accessible by group or others", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return wg.Key{}, err
	}
	return wg.ParseKey(strings.TrimSpace(string(raw)))
}

// writeSecretFile creates path with mode 0600, refusing to overwrite.
func writeSecretFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
