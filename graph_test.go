package mailer

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strings"
	"sync"
	"testing"
)

// capturedSend is what the fake Graph endpoint records about one sendMail call.
type capturedSend struct {
	auth        string
	contentType string
	rawMIME     string // decoded from base64
}

// fakeGraph stands in for the Microsoft Graph sendMail endpoint.
type fakeGraph struct {
	status int // defaults to 202

	mu    sync.Mutex
	calls []capturedSend
	paths []string
}

func newFakeGraph(t *testing.T, status int) (*fakeGraph, *httptest.Server) {
	t.Helper()
	f := &fakeGraph{status: status}
	if f.status == 0 {
		f.status = http.StatusAccepted
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		raw, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			t.Errorf("sendMail body was not base64: %v", err)
		}

		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.calls = append(f.calls, capturedSend{
			auth:        r.Header.Get("Authorization"),
			contentType: r.Header.Get("Content-Type"),
			rawMIME:     string(raw),
		})
		f.mu.Unlock()

		w.WriteHeader(f.status)
		if f.status != http.StatusAccepted {
			w.Write([]byte(`{"error":{"code":"Forbidden","message":"insufficient privileges"}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeGraph) last() capturedSend {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func (f *fakeGraph) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// staticGraphToken is a TokenSource that hands out a fixed token and counts
// calls, mirroring staticToken in smtp_test.go but kept separate since the two
// files test different senders.
type staticGraphToken struct {
	token string
	err   error
	calls int
}

func (s *staticGraphToken) Token(context.Context) (string, error) {
	s.calls++
	return s.token, s.err
}

func senderForGraph(t *testing.T, srv *httptest.Server, src TokenSource) *GraphSender {
	t.Helper()
	s, err := NewGraphSender(GraphConfig{
		TokenSource: src, From: "orders@example.com", graphBase: srv.URL,
	})
	if err != nil {
		t.Fatalf("NewGraphSender: %v", err)
	}
	return s
}

func TestGraphSend_PostsToTheMailboxEndpointWithTheBearerToken(t *testing.T) {
	f, srv := newFakeGraph(t, 0)
	src := &staticGraphToken{token: "a-token"}
	s := senderForGraph(t, srv, src)

	if err := s.Send(t.Context(), receipt()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if got := f.paths[0]; got != "/v1.0/users/orders@example.com/sendMail" {
		t.Errorf("path = %q, want the mailbox-scoped sendMail endpoint", got)
	}
	call := f.last()
	if call.auth != "Bearer a-token" {
		t.Errorf("Authorization = %q", call.auth)
	}
	if call.contentType != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain (which selects raw-MIME mode)", call.contentType)
	}
	if !strings.Contains(call.rawMIME, "Thank you") {
		t.Errorf("the raw MIME does not contain the body:\n%s", call.rawMIME)
	}
}

// The point of sending raw MIME instead of Graph's JSON schema: a message can
// carry both parts, which the JSON schema's single contentType cannot express.
func TestGraphSend_HTMLBecomesTheAlternativePart(t *testing.T) {
	f, srv := newFakeGraph(t, 0)
	s := senderForGraph(t, srv, &staticGraphToken{token: "a-token"})

	m := receipt()
	m.HTML = "<p>Thank you</p>"
	if err := s.Send(t.Context(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}

	got := f.last().rawMIME
	if !strings.Contains(got, "multipart/alternative") {
		t.Fatalf("not multipart/alternative:\n%s", got)
	}
	plain, html := strings.Index(got, "text/plain"), strings.Index(got, "text/html")
	if plain < 0 || html < 0 || plain > html {
		t.Errorf("expected the plain part before the HTML part:\n%s", got)
	}
}

// Graph posts the same MIME the SMTP sender writes, so an inline image arrives
// as a related part with its bracketed Content-ID here too.
func TestGraphSend_CarriesInlineImages(t *testing.T) {
	f, srv := newFakeGraph(t, 0)
	s := senderForGraph(t, srv, &staticGraphToken{token: "a-token"})

	m := receipt()
	m.HTML = `<img src="cid:qr-1" alt="">`
	m.Inline = []Inline{{ContentID: "qr-1", ContentType: "image/png", Data: []byte("\x89PNG\r\n\x1a\nfake")}}
	if err := s.Send(t.Context(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := strings.ToLower(f.last().rawMIME)
	for _, want := range []string{"multipart/related", "content-id: <qr-1>", "image/png"} {
		if !strings.Contains(got, want) {
			t.Errorf("the posted MIME is missing %q", want)
		}
	}
}

// Bcc has no envelope on this transport, so it must reach the wire as a real
// header rather than silently vanishing — the mistake buildMIME's BccInHeaders
// flag exists to prevent. See its doc comment for what happens on the other
// side (Microsoft's documented behaviour, unverified here).
func TestGraphSend_WritesBccAsAHeader(t *testing.T) {
	f, srv := newFakeGraph(t, 0)
	s := senderForGraph(t, srv, &staticGraphToken{token: "a-token"})

	m := receipt()
	m.Bcc = []string{"owner@example.com"}
	if err := s.Send(t.Context(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}

	parsed, err := mail.ReadMessage(strings.NewReader(f.last().rawMIME))
	if err != nil {
		t.Fatalf("the sent message did not parse as RFC 5322: %v", err)
	}
	if got := parsed.Header.Get("Bcc"); !strings.Contains(got, "owner@example.com") {
		t.Errorf("Bcc header = %q, want it to contain the blind recipient", got)
	}
}

func TestGraphSend_ReplyToPrefersTheMessageOverTheConfiguredDefault(t *testing.T) {
	f, srv := newFakeGraph(t, 0)
	s, err := NewGraphSender(GraphConfig{
		TokenSource: &staticGraphToken{token: "a-token"},
		From:        "orders@example.com", ReplyTo: "shop@example.com",
		graphBase: srv.URL,
	})
	if err != nil {
		t.Fatalf("NewGraphSender: %v", err)
	}

	m := receipt()
	m.ReplyTo = "enquirer@example.com"
	if err := s.Send(t.Context(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := f.last().rawMIME; !strings.Contains(got, "Reply-To: <enquirer@example.com>") {
		t.Errorf("the message's own Reply-To was not used:\n%s", got)
	}
}

func TestGraphSend_NonAcceptedStatusIsAnError(t *testing.T) {
	_, srv := newFakeGraph(t, http.StatusForbidden)
	s := senderForGraph(t, srv, &staticGraphToken{token: "a-token"})

	err := s.Send(t.Context(), receipt())
	if err == nil {
		t.Fatal("a 403 was reported as success")
	}
	for _, want := range []string{"403", "insufficient privileges"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestGraphSend_TokenSourceFailureIsReportedBeforeAnyRequest(t *testing.T) {
	f, srv := newFakeGraph(t, 0)
	src := &staticGraphToken{err: errors.New("AADSTS7000215: invalid client secret")}
	s := senderForGraph(t, srv, src)

	err := s.Send(t.Context(), receipt())
	if err == nil {
		t.Fatal("Send succeeded with a failing token source")
	}
	if !strings.Contains(err.Error(), "invalid client secret") {
		t.Errorf("error = %v, want it to mention the underlying failure", err)
	}
	if got := f.count(); got != 0 {
		t.Errorf("the endpoint was called %d times despite no token", got)
	}
}

func TestGraphSend_ValidatesBeforeFetchingAToken(t *testing.T) {
	_, srv := newFakeGraph(t, 0)
	src := &staticGraphToken{token: "a-token"}
	s := senderForGraph(t, srv, src)

	err := s.Send(t.Context(), Message{To: []string{"a@example.com"}, Subject: "Receipt"})
	if err == nil {
		t.Fatal("an invalid message was accepted")
	}
	if src.calls != 0 {
		t.Errorf("Token was called %d times for a message that never validated", src.calls)
	}
}

func TestNewGraphSender_ValidatesConfiguration(t *testing.T) {
	if _, err := NewGraphSender(GraphConfig{TokenSource: &staticGraphToken{}, From: "a@example.com"}); err != nil {
		t.Fatalf("a valid configuration was rejected: %v", err)
	}
	if _, err := NewGraphSender(GraphConfig{From: "a@example.com"}); err == nil {
		t.Error("a configuration with no TokenSource was accepted")
	}
	if _, err := NewGraphSender(GraphConfig{TokenSource: &staticGraphToken{}}); err == nil {
		t.Error("a configuration with no From was accepted")
	}
}
