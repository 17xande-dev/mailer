// Package msauth acquires Microsoft access tokens for XOAUTH2 authentication,
// using the OAuth2 client-credentials flow (app-only auth).
//
// It exists because go-mail speaks XOAUTH2 but has no notion of where a token
// comes from: the caller hands it an already-valid access token as the password.
// This is the piece that gets one and keeps it fresh.
//
// # What the tenant needs
//
// For SMTP submission, the Entra ID app registration needs the SMTP.SendAsApp
// application permission with admin consent, a service principal registered in
// Exchange Online, Send As on the mailbox, and SMTP AUTH enabled for that mailbox
// — it is disabled tenant-wide by default. None of that is visible from here: a
// tenant that has not been set up returns a token perfectly happily and the
// mail server then refuses it.
package msauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ScopeSMTP is the resource for SMTP submission to Exchange Online, and the
// default. Graph would be "https://graph.microsoft.com/.default".
const ScopeSMTP = "https://outlook.office365.com/.default"

const defaultLoginBase = "https://login.microsoftonline.com"

// ClientCredentials fetches and caches an application access token.
//
// It is safe for concurrent use, and a cached token is shared: two sends
// happening at once make one token request between them, not two.
type ClientCredentials struct {
	tenantID     string
	clientID     string
	clientSecret string
	scope        string

	httpClient *http.Client
	// loginBase is the identity endpoint root, overridable in tests. Empty falls
	// back to the real Microsoft endpoint.
	loginBase string

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// Option configures a ClientCredentials.
type Option func(*ClientCredentials)

// WithScope overrides the default SMTP scope, so the same flow can serve another
// Microsoft resource.
func WithScope(scope string) Option {
	return func(c *ClientCredentials) { c.scope = scope }
}

// WithHTTPClient supplies the client used for token requests. The default has a
// 15 second timeout, which is the only setting this has ever needed.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *ClientCredentials) { c.httpClient = hc }
}

// New validates the credentials and returns a token source. It does not contact
// the identity provider: a failure to reach it at startup is not a reason to
// refuse to boot, and the first send is where it would surface anyway.
func New(tenantID, clientID, clientSecret string, opts ...Option) (*ClientCredentials, error) {
	c := &ClientCredentials{
		tenantID:     strings.TrimSpace(tenantID),
		clientID:     strings.TrimSpace(clientID),
		clientSecret: clientSecret,
		scope:        ScopeSMTP,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	switch {
	case c.tenantID == "":
		return nil, fmt.Errorf("msauth: a tenant ID is required")
	case c.clientID == "":
		return nil, fmt.Errorf("msauth: a client ID is required")
	case strings.TrimSpace(c.clientSecret) == "":
		return nil, fmt.Errorf("msauth: a client secret is required")
	}
	return c, nil
}

// Token returns a cached access token, fetching a new one when the cache is empty
// or near expiry.
func (c *ClientCredentials) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.expiry) {
		return c.token, nil
	}

	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"scope":         {c.scope},
		"grant_type":    {"client_credentials"},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.login(), url.PathEscape(c.tenantID))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("msauth: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("msauth: request token: %w", err)
	}
	defer resp.Body.Close()

	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("msauth: decode token response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		// error_description is the field that actually says what is wrong —
		// which permission is missing, which secret has expired — so it is worth
		// carrying through rather than reporting a bare status code.
		return "", fmt.Errorf("msauth: token endpoint: status %d: %s: %s",
			resp.StatusCode, tr.Error, tr.ErrorDesc)
	}

	c.token = tr.AccessToken
	// Refresh a minute early, so a token that expires mid-request is never used.
	c.expiry = time.Now().Add(time.Duration(tr.ExpiresIn)*time.Second - time.Minute)
	return c.token, nil
}

func (c *ClientCredentials) login() string {
	if c.loginBase != "" {
		return c.loginBase
	}
	return defaultLoginBase
}
