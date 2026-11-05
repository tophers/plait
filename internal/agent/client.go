package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"plait/internal/protocol"
	"plait/internal/wg"
)

const maxSnapshotBytes = 4 << 20

// Client talks to plaitd with the site's bearer credential. The site is
// identified by the credential alone, never by a caller-supplied ID.
type Client struct {
	BaseURL string
	Token   string
	// TokenFile, when set, is re-read before every request and replaces
	// Token, so a running agent picks up a credential written by
	// `plait-agent rotate-credential` before the old one expires.
	TokenFile string
	HTTP      *http.Client
}

func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) bearer() (string, error) {
	if c.TokenFile != "" {
		tok, err := ReadCredential(c.TokenFile)
		if err != nil {
			return "", fmt.Errorf("site credential: %w", err)
		}
		c.Token = tok
	}
	return c.Token, nil
}

// UseCAFile verifies the controller against the PEM roots in path instead of
// the system pool.
func (c *Client) UseCAFile(path string) error {
	pem, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("%s contains no PEM certificates", path)
	}
	c.HTTP.Transport = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return nil
}

// HTTPError is a response from the controller with an unexpected status:
// the controller is reachable but refused the request.
type HTTPError struct {
	Op   string
	Code int
}

func (e *HTTPError) Error() string {
	switch e.Code {
	case http.StatusUnauthorized:
		return fmt.Sprintf("%s: HTTP 401: site credential rejected (revoked, expired, or replaced by re-enrollment)", e.Op)
	case http.StatusServiceUnavailable:
		return fmt.Sprintf("%s: HTTP 503: controller unavailable or in recovery", e.Op)
	}
	return fmt.Sprintf("%s: HTTP %d", e.Op, e.Code)
}

func statusError(op string, code int) error { return &HTTPError{Op: op, Code: code} }

// Enroll exchanges a single-use enrollment token and this gateway's public
// key for a site ID and credential. It needs no existing credential.
func (c *Client) Enroll(ctx context.Context, token string, publicKey wg.Key) (siteID, credential string, err error) {
	body, _ := json.Marshal(map[string]any{"token": token, "public_key": publicKey})
	var out struct {
		SiteID     string `json:"site_id"`
		Credential string `json:"credential"`
	}
	if err := c.postJSON(ctx, "/api/v1/agent/enroll", "", body, &out); err != nil {
		return "", "", fmt.Errorf("enroll: %w", err)
	}
	if out.SiteID == "" || out.Credential == "" {
		return "", "", errors.New("enroll: incomplete response")
	}
	return out.SiteID, out.Credential, nil
}

// RotateCredential obtains a new credential; the current one expires after
// a short overlap.
func (c *Client) RotateCredential(ctx context.Context) (string, error) {
	var out struct {
		Credential string `json:"credential"`
	}
	tok, err := c.bearer()
	if err != nil {
		return "", err
	}
	if err := c.postJSON(ctx, "/api/v1/agent/credential/rotate", tok, nil, &out); err != nil {
		return "", fmt.Errorf("rotate credential: %w", err)
	}
	if out.Credential == "" {
		return "", errors.New("rotate credential: incomplete response")
	}
	return out.Credential, nil
}

func (c *Client) postJSON(ctx context.Context, path, bearer string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return redactErr(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(data, &e)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, e.Error)
	}
	return json.Unmarshal(data, out)
}

// Fetch retrieves the complete desired snapshot. Any failure (transport,
// status, content type, malformed JSON) is an error, never an empty snapshot.
func (c *Client) Fetch(ctx context.Context) (*protocol.SiteSnapshot, error) {
	tok, err := c.bearer()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/v1/agent/sync", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch desired state: %w", redactErr(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, statusError("fetch desired state", resp.StatusCode)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/json" {
		return nil, fmt.Errorf("fetch desired state: unexpected content type %q", mt)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSnapshotBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch desired state: %w", err)
	}
	if len(body) > maxSnapshotBytes {
		return nil, errors.New("fetch desired state: response too large")
	}
	var snap protocol.SiteSnapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return nil, errors.New("fetch desired state: malformed JSON")
	}
	if err := snap.Validate(); err != nil {
		return nil, fmt.Errorf("fetch desired state: %w", err)
	}
	return &snap, nil
}

func (c *Client) Report(ctx context.Context, st *protocol.AgentStatus) error {
	tok, err := c.bearer()
	if err != nil {
		return err
	}
	body, err := json.Marshal(st)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v1/agent/status", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("report status: %w", redactErr(err))
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return statusError("report status", resp.StatusCode)
	}
	return nil
}

// redactErr drops the request URL from net/http errors; it is harmless
// today but keeps logs free of anything a future URL might carry.
func redactErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// FetchPinnedCA connects to the controller, finds the CA certificate in its
// TLS chain whose SHA-256 matches fingerprint ("sha256:<hex>", as shown on
// the enrollment page), and checks that it issued the server certificate for
// the controller's host name. It returns that CA in PEM form for UseCAFile.
// Nothing is sent over the connection.
func FetchPinnedCA(ctx context.Context, controllerURL, fingerprint string) ([]byte, error) {
	want, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(fingerprint)), "sha256:")
	if !ok || len(want) != 64 {
		return nil, fmt.Errorf("CA fingerprint must look like sha256:<64 hex digits>")
	}
	u, err := url.Parse(controllerURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("controller URL must be https://host[:port]")
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	var ca *x509.Certificate
	d := &tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: u.Hostname(),
		// The chain is verified below against the pinned CA instead.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("controller sent no certificate")
			}
			for _, c := range cs.PeerCertificates {
				if sum := sha256.Sum256(c.Raw); c.IsCA && hex.EncodeToString(sum[:]) == want {
					ca = c
				}
			}
			if ca == nil {
				return errors.New("no certificate in the controller's chain matches the CA fingerprint")
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca)
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: u.Hostname()})
			return err
		},
	}}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("fetching the controller CA: %w", err)
	}
	conn.Close()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), nil
}
