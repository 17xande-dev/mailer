package mailer

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GraphConfig is what GraphSender needs.
type GraphConfig struct {
	// TokenSource supplies the bearer token. Build one with msauth.New and
	// msauth.WithScope(msauth.ScopeGraph) — the Graph API needs a different
	// token audience than SMTP, so an SMTP TokenSource must not be reused here.
	TokenSource TokenSource

	// From is the mailbox to send as. The app registration's client credentials
	// grant needs the SMTP.SendAsApp permission is NOT what Graph uses — Graph
	// needs the Mail.Send *application* permission, admin-consented, scoped (via
	// an access policy) to this mailbox.
	From string
	// ReplyTo is the default for messages that do not set their own.
	ReplyTo string

	// HTTPClient is used for the sendMail call. nil uses a package default with
	// a 30 second timeout, applied only when the caller's context has no
	// deadline.
	HTTPClient *http.Client
	Timeout    time.Duration

	// graphBase is the API root, overridable in tests. Empty falls back to the
	// real Microsoft endpoint.
	graphBase string
}

// GraphSender delivers mail through the Microsoft Graph API's sendMail
// endpoint, as the mailbox named by From.
//
// It exists alongside SMTPSender rather than instead of it because Graph is not
// a drop-in replacement for a relay: it is a per-mailbox API with its own
// throttling and its own permission model, appropriate for a deployment that
// already has an Entra app registration and would rather not deal with SMTP
// AUTH at all. Most deployments want SMTPSender with a TokenSource, or a
// password, or a dedicated transactional relay — see the package doc.
type GraphSender struct{ cfg GraphConfig }

// NewGraphSender validates the configuration and returns a Sender.
//
// It deliberately does not fetch a token: an identity provider that is
// unreachable at boot is not a reason to refuse to start an application whose
// job does not depend on mail. The first send is where a credential or
// permission problem surfaces.
func NewGraphSender(cfg GraphConfig) (*GraphSender, error) {
	if cfg.TokenSource == nil {
		return nil, fmt.Errorf("mailer: a TokenSource is required")
	}
	if strings.TrimSpace(cfg.From) == "" {
		return nil, fmt.Errorf("mailer: a From address is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &GraphSender{cfg: cfg}, nil
}

func (s *GraphSender) graph() string {
	if s.cfg.graphBase != "" {
		return s.cfg.graphBase
	}
	return "https://graph.microsoft.com"
}

// Send delivers one message, as a raw RFC 5322 message posted to sendMail
// rather than through Graph's JSON message schema.
//
// Raw MIME is what lets a message carry both a plain-text and an HTML part —
// the JSON schema's body takes exactly one contentType, so a receipt that must
// stay readable in a client that refuses HTML would not be expressible through
// it. The cost is that Bcc, which the JSON schema has a field for, has to be
// written into the MIME as a real header instead (see mimeOptions.BccInHeaders):
// Microsoft's documented behaviour is that Graph reads recipients from the
// message headers on this path and strips Bcc before delivering, so it still
// ends up hidden from the other recipients — but that behaviour has not been
// verified against a live tenant by this package's author, and is worth
// confirming with a real send before relying on it for a deployment that uses
// Bcc.
func (s *GraphSender) Send(ctx context.Context, m Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.Timeout)
		defer cancel()
	}

	token, err := s.cfg.TokenSource.Token(ctx)
	if err != nil {
		return fmt.Errorf("mailer: acquire access token for %s: %w", s.cfg.From, err)
	}

	msg, err := buildMIME(m, mimeOptions{From: s.cfg.From, DefaultReplyTo: s.cfg.ReplyTo, BccInHeaders: true})
	if err != nil {
		return err
	}
	var raw bytes.Buffer
	if _, err := msg.WriteTo(&raw); err != nil {
		return fmt.Errorf("mailer: build MIME message: %w", err)
	}
	body := base64.StdEncoding.EncodeToString(raw.Bytes())

	endpoint := fmt.Sprintf("%s/v1.0/users/%s/sendMail", s.graph(), url.PathEscape(s.cfg.From))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("mailer: build sendMail request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// text/plain, not application/json: this is what tells Graph the body is a
	// raw MIME message rather than the JSON sendMail schema.
	req.Header.Set("Content-Type", "text/plain")

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("mailer: graph sendMail: %w", err)
	}
	defer resp.Body.Close()

	// sendMail returns 202 Accepted on success, with an empty body.
	if resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("mailer: graph sendMail: status %d: %s",
			resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}
