package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
	_ "modernc.org/sqlite"

	"plait/internal/certs"
	"plait/internal/config"
	"plait/internal/controller"
)

// readPassword prompts without echo on a terminal, or reads one line from a
// pipe for scripted setup.
func readPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, prompt)
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(pw), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func cmdAdmin(a *admin, args []string) error {
	verb, args, err := sub(args, "plaitctl admin create|password|totp-reset <username> | count")
	if err != nil {
		return err
	}
	if verb == "totp-reset" {
		if len(args) != 1 {
			return errors.New("usage: plaitctl admin totp-reset <username>")
		}
		if err := a.svc.ResetTOTP(a.ctx, args[0]); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "two-factor authentication is off for %s and their sessions have ended\n", args[0])
		return nil
	}
	if verb == "count" {
		n, err := a.svc.AdminCount(a.ctx)
		if err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, n)
		return nil
	}
	if len(args) != 1 {
		return fmt.Errorf("usage: plaitctl admin %s <username>", verb)
	}
	pw, err := readPassword("Password: ")
	if err != nil {
		return err
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		again, err := readPassword("Repeat password: ")
		if err != nil {
			return err
		}
		if again != pw {
			return errors.New("passwords do not match")
		}
	}
	switch verb {
	case "create":
		return a.svc.CreateAdmin(a.ctx, args[0], pw)
	case "password":
		return a.svc.SetAdminPassword(a.ctx, args[0], pw)
	}
	return fmt.Errorf("unknown admin command %q", verb)
}

func cmdEnrollToken(a *admin, args []string) error {
	fs := flag.NewFlagSet("site enroll-token", flag.ContinueOnError)
	ttl := fs.Duration("ttl", controller.DefaultEnrollmentTTL, "token lifetime")
	pos, err := parse(fs, args, 1, "plaitctl site enroll-token <site> [-ttl 1h]")
	if err != nil {
		return err
	}
	site, err := a.siteByName(pos[0])
	if err != nil {
		return err
	}
	if !site.Pending() {
		fmt.Fprintln(os.Stderr, "warning: this site is already enrolled; using this token replaces its gateway key and credentials, and every linked device must refresh its profile")
	}
	tok, exp, err := a.svc.CreateEnrollmentToken(a.ctx, site.ID, *ttl)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "single-use token for %s, expires %s:\n", site.Name, exp.UTC().Format(time.RFC3339))
	fmt.Fprintln(a.stdout, tok)
	if cfg, _, err := config.Load(configPath()); err == nil {
		if mode, _ := cfg.TLSMode(); mode == config.TLSAuto {
			if _, fp, err := certs.ReadCA(cfg.AutoTLSDir()); err == nil {
				fmt.Fprintf(os.Stderr, "on the gateway: plait-agent enroll -controller https://<controller>:<port> -token <token> -ca-fingerprint %s\n", fp)
			}
		}
	}
	return nil
}

func cmdBackup(a *admin, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: plaitctl backup <destination.db>")
	}
	if err := a.svc.Backup(a.ctx, args[0]); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s. The PSK encryption key is NOT included; back it up separately.\n", args[0])
	return nil
}

// cmdRestore replaces the controller database with a backup and puts the
// controller into recovery. plaitd must be stopped.
func cmdRestore(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: plaitctl restore <backup.db>   (stop plaitd first)")
	}
	path := configPath()
	cfg, _, err := config.Load(path)
	if err != nil {
		return err
	}
	backup := args[0]
	if err := checkIntegrity(backup); err != nil {
		return fmt.Errorf("backup %s: %w", backup, err)
	}
	// Move the current database and its WAL aside; a stale WAL must never be
	// replayed onto the restored file.
	stamp := time.Now().UTC().Format("20060102T150405Z")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		cur := cfg.Database + suffix
		if _, err := os.Stat(cur); err == nil {
			if err := os.Rename(cur, cur+".pre-restore-"+stamp); err != nil {
				return err
			}
		}
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfg.Database+".restoring", data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(cfg.Database+".restoring", cfg.Database); err != nil {
		return err
	}
	err = withAdmin(nil, func(a *admin, _ []string) error { return a.svc.BeginRecovery(a.ctx) })
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, `restored %s (previous database kept with suffix .pre-restore-%s).
The controller is in RECOVERY: agents keep their cached state and receive no
desired state. Before completing recovery:
  1. Start plaitd and let agents report (plaitctl recover status).
  2. Re-apply every revocation and change made after the backup was taken.
  3. Run: plaitctl recover complete
`, cfg.Database, stamp)
	return nil
}

func checkIntegrity(path string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var res string
	if err := db.QueryRowContext(context.Background(), "PRAGMA integrity_check").Scan(&res); err != nil {
		return err
	}
	if res != "ok" {
		return fmt.Errorf("integrity check failed: %s", res)
	}
	return nil
}

func cmdRecover(a *admin, args []string) error {
	verb, _, err := sub(args, "plaitctl recover status|complete")
	if err != nil {
		return err
	}
	switch verb {
	case "status":
		rec, err := a.svc.InRecovery(a.ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "recovery pending: %t\n\n", rec)
		statuses, err := a.svc.SiteStatuses(a.ctx)
		if err != nil {
			return err
		}
		st, err := a.state()
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SITE\tDESIRED\tAGENT ACCEPTED\tAPPLIED\tNOTE")
		for _, s := range statuses {
			site, _ := st.Site(s.SiteID)
			note := ""
			if s.AheadOfDesired {
				note = "agent is ahead: changes after the backup may be lost"
			}
			fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\n", site.Name, s.DesiredRevision, s.AcceptedRevision, s.AppliedRevision, note)
		}
		return tw.Flush()
	case "complete":
		if err := a.svc.CompleteRecovery(a.ctx); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "recovery complete; site revisions advanced and desired state is distributed again")
		return nil
	}
	return fmt.Errorf("unknown recover command %q", verb)
}

func cmdAudit(a *admin, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	limit := fs.Int("n", 50, "number of events")
	if _, err := parse(fs, args, 0, "plaitctl audit [-n 50]"); err != nil {
		return err
	}
	events, err := a.svc.AuditLog(a.ctx, 0, *limit)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "AT\tACTOR\tACTION\tTARGET\tDETAILS")
	for _, e := range events {
		var compact json.RawMessage = e.Details
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s/%s\t%s\n", e.At, e.Actor, e.Action, e.TargetType, e.TargetID, compact)
	}
	return tw.Flush()
}
