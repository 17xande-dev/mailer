package mailer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/wneessen/go-mail"
)

// TLSPolicy is how the connection to the mail server is secured.
type TLSPolicy string

const (
	// TLSStartTLS upgrades a plain connection and requires the upgrade to
	// succeed. This is the default and the right answer for port 587.
	TLSStartTLS TLSPolicy = "starttls"
	// TLSImplicit dials TLS directly, which is what port 465 expects.
	TLSImplicit TLSPolicy = "tls"
	// TLSNone sends credentials and message contents in the clear. It exists for
	// a local mail sink such as mailpit in development; it is never right against
	// a mail server that is not on the same machine.
	TLSNone TLSPolicy = "none"
)

// ParseTLSPolicy converts a configured string, naming the valid values on
// failure rather than falling back to a default — silently downgrading
// somebody's TLS because they wrote "ssl" would be the worst of the options.
func ParseTLSPolicy(s string) (TLSPolicy, error) {
	switch p := TLSPolicy(strings.ToLower(strings.TrimSpace(s))); p {
	case TLSStartTLS, TLSImplicit, TLSNone:
		return p, nil
	case "":
		return TLSStartTLS, nil
	default:
		return "", fmt.Errorf("mailer: TLS policy must be one of %s, %s, %s; got %q",
			TLSStartTLS, TLSImplicit, TLSNone, s)
	}
}

// SMTPConfig is what SMTPSender needs.
type SMTPConfig struct {
	Host string
	Port int

	// Username and Password may both be empty, for a relay on a private network
	// that authenticates by address — a local mail sink in development being the
	// obvious case. No credentials means no authentication is attempted at all,
	// rather than an empty PLAIN attempt that such a relay would refuse.
	Username string
	Password string

	// TokenSource, when set, selects XOAUTH2 instead of a password: Username is
	// the mailbox and the token is fetched fresh for each send. Password is then
	// ignored. This is the path to a Microsoft Exchange Online mailbox.
	TokenSource TokenSource

	// From is the envelope and header sender. A mail server will usually reject
	// a From it does not consider itself responsible for, so this has to be an
	// address on a domain the relay accepts.
	From string
	// ReplyTo is the default for messages that do not set their own, and is where
	// a reply should land when that is not the From address.
	ReplyTo string

	TLS     TLSPolicy
	Timeout time.Duration
}

// SMTPSender delivers mail over SMTP.
type SMTPSender struct{ cfg SMTPConfig }

// NewSMTPSender validates the configuration and returns a Sender.
//
// It deliberately does not connect, and does not fetch a token: a mail server
// that is down at boot is not a reason to refuse to start an application whose
// job does not depend on mail. The first send is where a connection or credential
// problem surfaces.
func NewSMTPSender(cfg SMTPConfig) (*SMTPSender, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, fmt.Errorf("mailer: SMTP host is required")
	}
	if strings.TrimSpace(cfg.From) == "" {
		return nil, fmt.Errorf("mailer: a From address is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("mailer: SMTP port %d is out of range", cfg.Port)
	}
	if cfg.TokenSource != nil && strings.TrimSpace(cfg.Username) == "" {
		// XOAUTH2 sends the mailbox alongside the token. An empty user would
		// authenticate as nobody, and would only fail at the first send.
		return nil, fmt.Errorf("mailer: a username is required with a TokenSource, " +
			"because XOAUTH2 authenticates as a named mailbox")
	}
	if cfg.TLS == "" {
		cfg.TLS = TLSStartTLS
	}
	if _, err := ParseTLSPolicy(string(cfg.TLS)); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &SMTPSender{cfg: cfg}, nil
}

// Send delivers one message.
//
// The order matters: the message is validated before a token is fetched, so a
// template that rendered nothing does not cost a round trip to an identity
// provider, and a credential problem is never reported for a message that was
// never sendable.
func (s *SMTPSender) Send(ctx context.Context, m Message) error {
	if err := m.Validate(); err != nil {
		return err
	}

	// Fetched per send, immediately before the client is built. This is what
	// makes an expiring token a non-problem: nothing here caches a client or a
	// connection, so there is no window in which a stale token could be reused.
	// See the note on client construction below before moving either.
	var token string
	if s.cfg.TokenSource != nil {
		t, err := s.cfg.TokenSource.Token(ctx)
		if err != nil {
			return fmt.Errorf("mailer: acquire access token for %s: %w", s.cfg.Username, err)
		}
		token = t
	}

	msg, err := s.build(m)
	if err != nil {
		return err
	}

	client, err := s.client(token)
	if err != nil {
		return err
	}
	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("mailer: send to %s: %w", strings.Join(m.To, ", "), err)
	}
	return nil
}

// build turns a Message into the library's representation.
func (s *SMTPSender) build(m Message) (*mail.Msg, error) {
	msg := mail.NewMsg()
	if err := msg.From(s.cfg.From); err != nil {
		return nil, fmt.Errorf("mailer: from address %q: %w", s.cfg.From, err)
	}
	to := nonBlank(m.To)
	if err := msg.To(to...); err != nil {
		return nil, fmt.Errorf("mailer: recipients %q: %w", strings.Join(to, ", "), err)
	}
	// Blind recipients go to the envelope only. The library writes To, Cc and
	// Reply-To into the headers and deliberately never writes Bcc, which is
	// exactly what keeps these addresses hidden from everyone else on the
	// message. Do not "fix" this by adding a Bcc header.
	if bcc := nonBlank(m.Bcc); len(bcc) > 0 {
		if err := msg.Bcc(bcc...); err != nil {
			return nil, fmt.Errorf("mailer: blind recipients %q: %w", strings.Join(bcc, ", "), err)
		}
	}
	// A message's own Reply-To wins over the deployment-wide default, so mail
	// sent on somebody's behalf can be answered to them.
	if replyTo := firstNonEmpty(m.ReplyTo, s.cfg.ReplyTo); replyTo != "" {
		if err := msg.ReplyTo(replyTo); err != nil {
			return nil, fmt.Errorf("mailer: reply-to %q: %w", replyTo, err)
		}
	}
	msg.Subject(m.Subject)

	// Plain text is the body and HTML is the alternative, in that order, which is
	// what makes a client that cannot or will not render HTML show the readable
	// version rather than nothing.
	msg.SetBodyString(mail.TypeTextPlain, m.Text)
	if m.HTML != "" {
		msg.AddAlternativeString(mail.TypeTextHTML, m.HTML)
	}
	return msg, nil
}

// client builds the SMTP client for one send.
//
// A fresh client is built per send rather than one being held on the struct. The
// library's client carries connection state, so sharing one would need a mutex
// that serialised every email behind whichever send was currently blocked on a
// slow server — and building one is a struct and a few options, next to nothing
// beside the TCP dial that follows it. It is also what lets an XOAUTH2 token be
// applied per send; holding a client would pin one token for its lifetime.
func (s *SMTPSender) client(token string) (*mail.Client, error) {
	opts := []mail.Option{
		mail.WithPort(s.cfg.Port),
		mail.WithTimeout(s.cfg.Timeout),
	}

	switch s.cfg.TLS {
	case TLSImplicit:
		opts = append(opts, mail.WithSSL())
	case TLSNone:
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	default:
		// Mandatory rather than opportunistic: a relay that offers no STARTTLS
		// should fail loudly, not quietly send a message in the clear.
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}

	switch {
	case s.cfg.TokenSource != nil:
		// Named explicitly rather than auto-discovered. A server that offers both
		// XOAUTH2 and a password mechanism must not be allowed to talk us into
		// the weaker one, and a server offering no XOAUTH2 should fail rather
		// than silently attempt to authenticate with a bearer token as a
		// password.
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthXOAUTH2),
			mail.WithUsername(s.cfg.Username),
			mail.WithPassword(token))
	case s.cfg.Username != "":
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(s.cfg.Username),
			mail.WithPassword(s.cfg.Password))
	default:
		// No credentials means no authentication at all, rather than an empty
		// PLAIN attempt that a relay would reject.
	}

	client, err := mail.NewClient(s.cfg.Host, opts...)
	if err != nil {
		return nil, fmt.Errorf("mailer: build SMTP client for %s: %w", s.cfg.Host, err)
	}
	return client, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
