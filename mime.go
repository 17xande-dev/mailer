package mailer

import (
	"fmt"
	"strings"

	"github.com/wneessen/go-mail"
)

// mimeOptions is what buildMIME needs beyond the message itself.
type mimeOptions struct {
	From           string
	DefaultReplyTo string
	// BccInHeaders writes Bcc directly into the MIME headers rather than only
	// handing it to the library's envelope-only Bcc method.
	//
	// SMTP wants BccInHeaders false: the library writes To, Cc and Reply-To into
	// the headers and deliberately never writes Bcc, and that omission is
	// exactly what keeps blind recipients hidden from everyone else on the
	// message — the SMTP envelope (RCPT TO) is where they are, invisibly.
	//
	// Graph wants it true: a raw MIME message posted to Graph has no envelope at
	// all, so a Bcc that only reached the library's envelope-only method would
	// vanish silently. Written as a header instead, Graph reads it as
	// recipients and — per Microsoft's documented behaviour — strips it before
	// delivering, so it still ends up hidden from the other recipients.
	BccInHeaders bool
}

// buildMIME turns a Message into the library's representation. It is the one
// place that happens, so the Bcc rule above cannot drift between transports.
func buildMIME(m Message, o mimeOptions) (*mail.Msg, error) {
	msg := mail.NewMsg()
	if err := msg.From(o.From); err != nil {
		return nil, fmt.Errorf("mailer: from address %q: %w", o.From, err)
	}
	to := nonBlank(m.To)
	if err := msg.To(to...); err != nil {
		return nil, fmt.Errorf("mailer: recipients %q: %w", strings.Join(to, ", "), err)
	}
	if bcc := nonBlank(m.Bcc); len(bcc) > 0 {
		if o.BccInHeaders {
			msg.SetGenHeader(mail.Header("Bcc"), bcc...)
		} else if err := msg.Bcc(bcc...); err != nil {
			return nil, fmt.Errorf("mailer: blind recipients %q: %w", strings.Join(bcc, ", "), err)
		}
	}
	// A message's own Reply-To wins over the deployment-wide default, so mail
	// sent on somebody's behalf can be answered to them.
	if replyTo := firstNonEmpty(m.ReplyTo, o.DefaultReplyTo); replyTo != "" {
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
