package mailer

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is a minimal SMTP server for testing SMTPSender. authMechs is what it
// offers in response to EHLO, which is the whole point of the type: a sink like
// mailpit offers none, an ordinary relay offers PLAIN and LOGIN, and Exchange
// offers XOAUTH2. What the client then does with that is what these tests are
// about.
type fakeSMTP struct {
	addr      string
	authMechs []string

	mu         sync.Mutex
	transcript []string
	data       string
}

func newFakeSMTP(t *testing.T, authMechs ...string) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	f := &fakeSMTP{addr: ln.Addr().String(), authMechs: authMechs}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	fmt.Fprint(conn, "220 fake ESMTP\r\n")

	inData := false
	inAuth := false
	var body strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		if inAuth {
			// The client's answer to a challenge, not a command.
			inAuth = false
			fmt.Fprint(conn, "235 2.7.0 Authentication successful\r\n")
			continue
		}

		if inData {
			if line == "." {
				inData = false
				f.mu.Lock()
				f.data = body.String()
				f.mu.Unlock()
				fmt.Fprint(conn, "250 OK\r\n")
				continue
			}
			body.WriteString(line + "\n")
			continue
		}

		f.mu.Lock()
		f.transcript = append(f.transcript, line)
		f.mu.Unlock()

		switch strings.ToUpper(strings.SplitN(line, " ", 2)[0]) {
		case "EHLO":
			if len(f.authMechs) == 0 {
				// No extensions offered — mailpit's behaviour.
				fmt.Fprint(conn, "250 fake\r\n")
				continue
			}
			fmt.Fprintf(conn, "250-fake\r\n250 AUTH %s\r\n", strings.Join(f.authMechs, " "))
		case "AUTH":
			// A challenge-response mechanism gets its challenge first; anything
			// carrying an initial response is done in one step. 235, not 250:
			// the client treats anything else as a failure.
			if fields := strings.Fields(line); len(fields) == 2 {
				inAuth = true
				fmt.Fprint(conn, "334 PENCPg==\r\n")
				continue
			}
			fmt.Fprint(conn, "235 2.7.0 Authentication successful\r\n")
		case "MAIL", "RCPT", "NOOP", "RSET":
			fmt.Fprint(conn, "250 OK\r\n")
		case "DATA":
			inData = true
			fmt.Fprint(conn, "354 send data\r\n")
		case "QUIT":
			fmt.Fprint(conn, "221 bye\r\n")
			return
		default:
			fmt.Fprint(conn, "250 OK\r\n")
		}
	}
}

// lines returns every command the server saw, in order.
func (f *fakeSMTP) lines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.transcript...)
}

// find returns the first command starting with verb, and whether there was one.
func (f *fakeSMTP) find(verb string) (string, bool) {
	for _, l := range f.lines() {
		if strings.HasPrefix(strings.ToUpper(l), strings.ToUpper(verb)) {
			return l, true
		}
	}
	return "", false
}

func (f *fakeSMTP) message() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data
}

// configFor points an SMTPConfig at the fake, with TLS off because the fake
// speaks none.
func configFor(t *testing.T, f *fakeSMTP) SMTPConfig {
	t.Helper()
	host, portStr, err := net.SplitHostPort(f.addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", f.addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	return SMTPConfig{Host: host, Port: port, From: "shop@example.com", TLS: TLSNone}
}

func sendOne(t *testing.T, cfg SMTPConfig, m Message) error {
	t.Helper()
	s, err := NewSMTPSender(cfg)
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	return s.Send(t.Context(), m)
}

func receipt() Message {
	return Message{To: []string{"jane@example.com"}, Subject: "Receipt", Text: "Thank you"}
}

// staticToken is a TokenSource that hands out a fixed token and counts calls.
type staticToken struct {
	token string
	err   error

	mu    sync.Mutex
	calls int
}

func (s *staticToken) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.token, s.err
}

func (s *staticToken) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// The regression this exists for, carried over from an earlier implementation:
// a credential-less configuration must not attempt AUTH at all. A relay that
// offers no AUTH — mailpit, and anything authenticating by network address — is
// the documented local development setup, and an unconditional attempt breaks
// every one of them.
func TestSend_WithoutCredentialsDoesNotAttemptAuth(t *testing.T) {
	f := newFakeSMTP(t) // no AUTH offered

	if err := sendOne(t, configFor(t, f), receipt()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if line, ok := f.find("AUTH"); ok {
		t.Errorf("authentication was attempted against a server offering none: %q", line)
	}
	if got := f.message(); !strings.Contains(got, "Thank you") {
		t.Errorf("the message did not arrive: %q", got)
	}
}

func TestSend_WithCredentialsAuthenticates(t *testing.T) {
	f := newFakeSMTP(t, "CRAM-MD5", "PLAIN", "LOGIN")

	cfg := configFor(t, f)
	cfg.Username, cfg.Password = "shop@example.com", "hunter2"
	if err := sendOne(t, cfg, receipt()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	line, ok := f.find("AUTH")
	if !ok {
		t.Fatal("no AUTH was attempted despite credentials being configured")
	}
	// Autodiscovery prefers the strongest mechanism on offer, so the password
	// is never sent in a form weaker than the server could have accepted.
	if !strings.HasPrefix(strings.ToUpper(line), "AUTH CRAM-MD5") {
		t.Errorf("AUTH line = %q, want the strongest offered mechanism", line)
	}
}

// A password is never sent in the clear. Autodiscovery will not select PLAIN or
// LOGIN on an unencrypted connection, even when the server offers nothing else —
// it fails the send instead.
//
// This matters for local development: a mail sink reached over TLSNone must be
// configured with no credentials at all, not with throwaway ones.
func TestSend_WillNotSendAPasswordWithoutEncryption(t *testing.T) {
	f := newFakeSMTP(t, "PLAIN", "LOGIN")

	cfg := configFor(t, f)
	cfg.Username, cfg.Password = "shop@example.com", "hunter2"
	err := sendOne(t, cfg, receipt())
	if err == nil {
		t.Fatal("a cleartext password was accepted over an unencrypted connection")
	}
	if _, ok := f.find("AUTH"); ok {
		t.Error("AUTH was attempted anyway")
	}
}

// XOAUTH2 is how an Exchange Online mailbox is reached. The token has to reach
// the wire, and the weaker mechanisms the server also offers must not be chosen
// in preference to it.
func TestSend_TokenSourceUsesXOAUTH2(t *testing.T) {
	f := newFakeSMTP(t, "PLAIN", "LOGIN", "XOAUTH2")
	src := &staticToken{token: "ya29.a-token"}

	cfg := configFor(t, f)
	cfg.Username, cfg.Password, cfg.TokenSource = "shop@example.com", "ignored", src
	if err := sendOne(t, cfg, receipt()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	line, ok := f.find("AUTH")
	if !ok {
		t.Fatal("no AUTH was attempted")
	}
	if !strings.HasPrefix(strings.ToUpper(line), "AUTH XOAUTH2") {
		t.Fatalf("AUTH line = %q, want XOAUTH2 rather than a password mechanism", line)
	}

	// The initial response carries the mailbox and the bearer token.
	fields := strings.Fields(line)
	if len(fields) < 3 {
		t.Fatalf("AUTH XOAUTH2 carried no initial response: %q", line)
	}
	raw, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		t.Fatalf("decode initial response: %v", err)
	}
	for _, want := range []string{"user=shop@example.com", "auth=Bearer ya29.a-token"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("initial response does not contain %q: %q", want, raw)
		}
	}
	if got := src.count(); got != 1 {
		t.Errorf("Token was called %d times for one send, want 1", got)
	}
	// The configured password must not have been offered as a fallback.
	if strings.Contains(f.message(), "hunter2") {
		t.Error("the static password reached the wire")
	}
}

// A token is fetched for every send, not once for the sender's lifetime. This is
// what keeps an expiring token from being reused, and it is why no client or
// connection is cached on the struct.
func TestSend_FetchesATokenPerSend(t *testing.T) {
	f := newFakeSMTP(t, "XOAUTH2")
	src := &staticToken{token: "a-token"}

	cfg := configFor(t, f)
	cfg.Username, cfg.TokenSource = "shop@example.com", src
	s, err := NewSMTPSender(cfg)
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	for range 3 {
		if err := s.Send(t.Context(), receipt()); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if got := src.count(); got != 3 {
		t.Errorf("Token was called %d times for three sends, want 3", got)
	}
}

// A token that cannot be acquired fails the send before anything is dialled, and
// says so — an authentication problem reported as a connection error would send
// the reader to the wrong place entirely.
func TestSend_TokenSourceFailureIsReportedBeforeDialing(t *testing.T) {
	src := &staticToken{err: errors.New("AADSTS7000215: invalid client secret")}

	// Port 1 will not connect, so reaching the dial at all would produce a
	// different error.
	cfg := SMTPConfig{
		Host: "127.0.0.1", Port: 1, From: "shop@example.com", TLS: TLSNone,
		Username: "shop@example.com", TokenSource: src,
	}
	err := sendOne(t, cfg, receipt())
	if err == nil {
		t.Fatal("Send succeeded with a failing token source")
	}
	for _, want := range []string{"access token", "invalid client secret"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

// Blind recipients reach the envelope and never the headers. The library writes
// To, Cc and Reply-To and deliberately omits Bcc, which is what keeps them
// hidden — this is the test that catches somebody "fixing" that.
func TestSend_KeepsBccOutOfTheHeaders(t *testing.T) {
	f := newFakeSMTP(t)

	m := receipt()
	m.Bcc = []string{"owner@example.com"}
	if err := sendOne(t, configFor(t, f), m); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if line, ok := f.find("RCPT TO:<owner@example.com>"); !ok {
		t.Errorf("the blind recipient never reached the envelope; saw %q", line)
	}
	if got := f.message(); strings.Contains(got, "owner@example.com") {
		t.Errorf("the blind recipient appears in the message headers:\n%s", got)
	}
}

// A receipt has to arrive readable in a client that refuses HTML, so the plain
// part is the body and HTML is the alternative — in that order.
func TestSend_HTMLBecomesTheAlternativePart(t *testing.T) {
	f := newFakeSMTP(t)

	m := receipt()
	m.HTML = "<p>Thank you</p>"
	if err := sendOne(t, configFor(t, f), m); err != nil {
		t.Fatalf("Send: %v", err)
	}

	got := f.message()
	if !strings.Contains(got, "multipart/alternative") {
		t.Fatalf("not a multipart/alternative message:\n%s", got)
	}
	plain, html := strings.Index(got, "text/plain"), strings.Index(got, "text/html")
	if plain < 0 || html < 0 {
		t.Fatalf("both parts are not present:\n%s", got)
	}
	if plain > html {
		t.Error("the HTML part comes first, so a text-only client would show nothing")
	}
}

// An inline image travels inside the message, related to the HTML that shows it
// and carrying the Content-ID that HTML names — otherwise the <img> is a broken
// picture in every client.
func TestSend_InlineImagesAreRelatedToTheHTML(t *testing.T) {
	f := newFakeSMTP(t)

	m := receipt()
	m.HTML = `<p>Your ticket</p><img src="cid:qr-1" alt="">`
	m.Inline = []Inline{{ContentID: "qr-1", ContentType: "image/png", Data: []byte("\x89PNG\r\n\x1a\nfake")}}
	if err := sendOne(t, configFor(t, f), m); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Lower-cased because header names are case-insensitive and the library
	// writes Content-Id; the value's angle brackets are what matters.
	got := strings.ToLower(f.message())
	for _, want := range []string{"multipart/related", "content-id: <qr-1>", "image/png", "text/plain", "text/html"} {
		if !strings.Contains(got, want) {
			t.Errorf("the message is missing %q:\n%s", want, got)
		}
	}
}

func TestSend_ReplyToPrefersTheMessageOverTheConfiguredDefault(t *testing.T) {
	t.Run("message wins", func(t *testing.T) {
		f := newFakeSMTP(t)
		cfg := configFor(t, f)
		cfg.ReplyTo = "shop@example.com"

		m := receipt()
		m.ReplyTo = "enquirer@example.com"
		if err := sendOne(t, cfg, m); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if got := f.message(); !strings.Contains(got, "Reply-To: <enquirer@example.com>") {
			t.Errorf("the message's own Reply-To was not used:\n%s", got)
		}
	})

	t.Run("config applies when the message has none", func(t *testing.T) {
		f := newFakeSMTP(t)
		cfg := configFor(t, f)
		cfg.ReplyTo = "shop@example.com"

		if err := sendOne(t, cfg, receipt()); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if got := f.message(); !strings.Contains(got, "Reply-To: <shop@example.com>") {
			t.Errorf("the configured Reply-To was not used:\n%s", got)
		}
	})

	t.Run("neither means no header", func(t *testing.T) {
		f := newFakeSMTP(t)
		if err := sendOne(t, configFor(t, f), receipt()); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if got := f.message(); strings.Contains(got, "Reply-To:") {
			t.Errorf("an empty Reply-To was written anyway:\n%s", got)
		}
	})
}

func TestParseTLSPolicy(t *testing.T) {
	good := map[string]TLSPolicy{
		"":          TLSStartTLS, // the default, correct for port 587
		"starttls":  TLSStartTLS,
		"STARTTLS":  TLSStartTLS,
		" starttls": TLSStartTLS,
		"tls":       TLSImplicit,
		"none":      TLSNone,
	}
	for in, want := range good {
		got, err := ParseTLSPolicy(in)
		if err != nil || got != want {
			t.Errorf("ParseTLSPolicy(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	// An unrecognised value is an error rather than a fallback. Silently
	// downgrading somebody's TLS because they wrote "ssl" would be the worst of
	// the available behaviours.
	for _, in := range []string{"ssl", "yes", "true", "opportunistic", "off"} {
		if got, err := ParseTLSPolicy(in); err == nil {
			t.Errorf("ParseTLSPolicy(%q) = %q with no error; want a refusal", in, got)
		}
	}
	// And the error names the valid values, because that is what the person
	// reading it needs.
	_, err := ParseTLSPolicy("ssl")
	for _, want := range []string{"starttls", "tls", "none"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %q: %v", want, err)
		}
	}
}

func TestNewSMTPSender_ValidatesConfiguration(t *testing.T) {
	valid := SMTPConfig{Host: "localhost", Port: 1025, From: "shop@example.com", TLS: TLSNone}
	if _, err := NewSMTPSender(valid); err != nil {
		t.Fatalf("a valid configuration was rejected: %v", err)
	}

	// The port and the TLS policy default rather than failing, since both have one
	// right answer for an ordinary relay.
	s, err := NewSMTPSender(SMTPConfig{Host: "localhost", Port: 587, From: "shop@example.com"})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	if s.cfg.TLS != TLSStartTLS {
		t.Errorf("TLS = %q, want it to default to starttls", s.cfg.TLS)
	}
	if s.cfg.Timeout <= 0 {
		t.Error("Timeout was not defaulted, so a hung relay would block forever")
	}

	cases := map[string]SMTPConfig{
		"no host":            {Port: 587, From: "shop@example.com"},
		"no from":            {Host: "localhost", Port: 587},
		"port zero":          {Host: "localhost", From: "shop@example.com"},
		"port too big":       {Host: "localhost", Port: 70000, From: "shop@example.com"},
		"bad TLS":            {Host: "localhost", Port: 587, From: "shop@example.com", TLS: "ssl"},
		"token, no username": {Host: "localhost", Port: 587, From: "shop@example.com", TokenSource: &staticToken{}},
	}
	for name, cfg := range cases {
		if _, err := NewSMTPSender(cfg); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestMessage_Validate(t *testing.T) {
	ok := Message{To: []string{"a@example.com"}, Subject: "Receipt", Text: "Thank you"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a valid message was rejected: %v", err)
	}

	// A template that produced nothing is caught here rather than as a puzzling
	// rejection from a relay. The HTML part is the only optional one.
	cases := map[string]Message{
		"no recipient":    {Subject: "Receipt", Text: "Thank you"},
		"blank recipient": {To: []string{"", "   "}, Subject: "Receipt", Text: "Thank you"},
		"no subject":      {To: []string{"a@example.com"}, Text: "Thank you"},
		"no text":         {To: []string{"a@example.com"}, Subject: "Receipt", HTML: "<p>Thank you</p>"},
		"subject newline": {To: []string{"a@example.com"}, Subject: "Receipt\r\nBcc: sneak@example.com", Text: "Thank you"},
	}
	png := []byte("\x89PNG")
	withHTML := func(in ...Inline) Message {
		return Message{To: []string{"a@example.com"}, Subject: "Receipt", Text: "Thank you", HTML: "<p>x</p>", Inline: in}
	}
	cases["inline without html"] = Message{To: []string{"a@example.com"}, Subject: "Receipt", Text: "Thank you",
		Inline: []Inline{{ContentID: "qr", ContentType: "image/png", Data: png}}}
	cases["inline id injection"] = withHTML(Inline{ContentID: "qr>\r\nBcc: x@example.com", ContentType: "image/png", Data: png})
	cases["inline id twice"] = withHTML(
		Inline{ContentID: "qr", ContentType: "image/png", Data: png},
		Inline{ContentID: "qr", ContentType: "image/png", Data: png})
	cases["inline not an image"] = withHTML(Inline{ContentID: "qr", ContentType: "text/html", Data: png})
	cases["inline empty"] = withHTML(Inline{ContentID: "qr", ContentType: "image/png"})
	if err := withHTML(Inline{ContentID: "qr-1", ContentType: "image/png", Data: png}).Validate(); err != nil {
		t.Errorf("a valid inline image was rejected: %v", err)
	}
	for name, m := range cases {
		if err := m.Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	// An invalid message never reaches the network.
	s, err := NewSMTPSender(SMTPConfig{Host: "127.0.0.1", Port: 1, From: "shop@example.com", TLS: TLSNone})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	// Port 1 would fail to connect, so an error mentioning the body proves the
	// check happened before the dial.
	err = s.Send(t.Context(), Message{To: []string{"a@example.com"}, Subject: "Receipt"})
	if err == nil || !strings.Contains(err.Error(), "plain-text") {
		t.Errorf("Send error = %v, want the validation failure rather than a dial error", err)
	}
}

// Validation runs before a token is fetched, so a message that was never
// sendable does not cost a round trip to an identity provider.
func TestSend_ValidatesBeforeFetchingAToken(t *testing.T) {
	src := &staticToken{token: "a-token"}
	cfg := SMTPConfig{
		Host: "127.0.0.1", Port: 1, From: "shop@example.com", TLS: TLSNone,
		Username: "shop@example.com", TokenSource: src, Timeout: time.Second,
	}
	if err := sendOne(t, cfg, Message{To: []string{"a@example.com"}, Subject: "Receipt"}); err == nil {
		t.Fatal("an invalid message was accepted")
	}
	if got := src.count(); got != 0 {
		t.Errorf("Token was called %d times for a message that never validated", got)
	}
}
