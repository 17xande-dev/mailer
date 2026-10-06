// Package mailer sends transactional mail, and hides which mechanism does it
// behind a single Sender interface.
//
// The interface is the point of the package. An application's tests capture mail
// through Fake rather than talking to a mail server, and a deployment with no mail
// configured can use Discard, so an unconfigured relay is never the reason a
// request fails.
//
// # Scope
//
// Message carries only fields that mean the same thing to every transport. Adding
// one is a decision, not a convenience: if a field only makes sense to a single
// application, it belongs in that application's code, not here. That rule is the
// only thing keeping this struct from accumulating everything anyone ever needed.
//
// # Transports
//
// SMTPSender is the default and the one most deployments want: a password, or —
// for a Microsoft Exchange Online mailbox now that Basic Auth for SMTP client
// submission is going away — a TokenSource for XOAUTH2. GraphSender exists
// alongside it for a deployment that already has an Entra app registration and
// would rather call the Microsoft Graph API than deal with SMTP AUTH at all; it
// needs its own TokenSource, scoped to Graph rather than to SMTP. The msauth
// subpackage implements a TokenSource against Microsoft's client-credentials
// flow for either audience — see msauth.ScopeSMTP and msauth.ScopeGraph.
//
// Both Microsoft transports carry the same caveat: the tenant-side setup —
// admin consent, a service principal, mailbox-level permissions — is invisible
// from here, and a misconfigured tenant hands out a token happily and fails
// only at the send.
package mailer

import (
	"context"
	"fmt"
	"strings"
)

// Message is one email. Text is required and HTML is optional: a receipt has to
// arrive readable even in a client that refuses HTML, and a plain-text part is
// also what keeps a transactional message out of spam folders.
type Message struct {
	// To is the visible recipients. At least one must be a non-blank address.
	To []string
	// Bcc is the blind recipients, delivered through the SMTP envelope and never
	// written into the message headers — which is what keeps them blind.
	Bcc []string

	Subject string
	Text    string
	HTML    string

	// ReplyTo overrides the sender's configured default for this one message. It
	// exists for mail sent on somebody's behalf — an enquiry that a recipient
	// should be able to answer by replying to the person who sent it, rather than
	// to the mailbox the software sends from.
	ReplyTo string

	// Inline is images the HTML body shows by reference — <img src="cid:ID"> —
	// carried inside the message rather than fetched from a server. A ticket's
	// QR code is the case it exists for: an image a mail client will not block
	// as remote content, and that still shows with the reader offline at a door.
	//
	// It means the same thing to every transport, which is the bar for a field
	// here (see the package doc): both write the message as MIME, where an
	// inline part is a multipart/related sibling of the HTML.
	Inline []Inline
}

// Inline is one image an HTML body refers to as cid:ContentID.
type Inline struct {
	// ContentID is what the HTML names it by, without angle brackets — "qr-1",
	// referenced as <img src="cid:qr-1">. Unique within a message.
	ContentID string
	// ContentType is the image's MIME type, such as image/png.
	ContentType string
	Data        []byte
}

// Sender delivers a Message. Implementations must be safe for concurrent use:
// two requests can want to send at once.
//
// A Sender performs one delivery attempt and returns. It does not retry, does not
// queue and does not log. What a failed send means — a dropped receipt, an error
// shown to a visitor, a page that renders anyway — is the caller's decision, and
// different applications decide differently.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// TokenSource supplies an OAuth2 access token for XOAUTH2 authentication.
//
// It is declared here, where it is consumed, rather than in the package that
// implements it, so that a caller can substitute their own without this package
// importing anyone.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Validate checks a Message is sendable, so a template that produced nothing is
// caught here rather than as a puzzling rejection from a mail server.
func (m Message) Validate() error {
	switch {
	case len(nonBlank(m.To)) == 0:
		// Non-blank rather than merely non-empty: recipients are often derived
		// from a configured, comma-separated list, and splitting one of those
		// readily produces a []string{""} that would otherwise pass.
		return fmt.Errorf("mailer: message has no recipient")
	case m.Subject == "":
		return fmt.Errorf("mailer: message to %s has no subject", strings.Join(m.To, ", "))
	case strings.ContainsAny(m.Subject, "\r\n"):
		// A newline in a header value injects arbitrary extra headers — a Bcc:
		// line being the obvious abuse. The underlying library writes header
		// values verbatim, so this is a real hole and not a theoretical one.
		//
		// Rejected rather than stripped: silently rewriting somebody's subject
		// hides the fact that untrusted input reached a header at all, and the
		// caller is better placed to report it.
		return fmt.Errorf("mailer: subject of the message to %s contains a line break",
			strings.Join(m.To, ", "))
	case m.Text == "":
		return fmt.Errorf("mailer: message to %s has no plain-text body", strings.Join(m.To, ", "))
	case len(m.Inline) > 0 && m.HTML == "":
		// Nothing could show them: an inline part is only ever referenced from
		// HTML, and a text-only message with images inside it is a mistake.
		return fmt.Errorf("mailer: message to %s has inline images but no HTML body", strings.Join(m.To, ", "))
	}
	seen := make(map[string]bool, len(m.Inline))
	for _, in := range m.Inline {
		switch {
		case in.ContentID == "" || strings.ContainsAny(in.ContentID, "<>\r\n \t\"@"):
			// Written into a Content-ID header and matched against a cid: URL, so
			// it has to be a plain token — and a line break in it would be a
			// header injection like the subject's.
			return fmt.Errorf("mailer: inline image Content-ID %q must be a plain token", in.ContentID)
		case seen[in.ContentID]:
			return fmt.Errorf("mailer: inline image Content-ID %q is used twice", in.ContentID)
		case !strings.HasPrefix(in.ContentType, "image/") || strings.ContainsAny(in.ContentType, "\r\n"):
			return fmt.Errorf("mailer: inline %q has content type %q, want an image", in.ContentID, in.ContentType)
		case len(in.Data) == 0:
			return fmt.Errorf("mailer: inline image %q is empty", in.ContentID)
		}
		seen[in.ContentID] = true
	}
	return nil
}

// nonBlank drops empty and whitespace-only addresses, and trims the rest.
func nonBlank(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}
