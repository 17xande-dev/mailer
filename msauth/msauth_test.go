package msauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// tokenServer stands in for the Microsoft identity platform, recording what it
// was asked and answering with whatever the test needs.
type tokenServer struct {
	status    int
	expiresIn int
	body      string // when set, replaces the generated success response

	mu    sync.Mutex
	calls int
	form  url.Values
}

func newTokenServer(t *testing.T, ts *tokenServer) *ClientCredentials {
	t.Helper()
	if ts.status == 0 {
		ts.status = http.StatusOK
	}
	if ts.expiresIn == 0 {
		ts.expiresIn = 3600
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		ts.mu.Lock()
		ts.calls++
		ts.form = r.PostForm
		n := ts.calls
		ts.mu.Unlock()

		w.WriteHeader(ts.status)
		if ts.body != "" {
			fmt.Fprint(w, ts.body)
			return
		}
		// A distinct token per call, so a test can tell a cached one from a
		// freshly fetched one.
		fmt.Fprintf(w, `{"access_token":"token-%d","expires_in":%d}`, n, ts.expiresIn)
	}))
	t.Cleanup(srv.Close)

	c, err := New("tenant-id", "client-id", "client-secret")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.loginBase = srv.URL
	return c
}

func (ts *tokenServer) count() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.calls
}

func TestToken_RequestsClientCredentials(t *testing.T) {
	ts := &tokenServer{}
	c := newTokenServer(t, ts)

	token, err := c.Token(t.Context())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token != "token-1" {
		t.Errorf("Token = %q, want token-1", token)
	}

	ts.mu.Lock()
	form := ts.form
	ts.mu.Unlock()
	want := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     "client-id",
		"client_secret": "client-secret",
		"scope":         ScopeSMTP,
	}
	for k, v := range want {
		if got := form.Get(k); got != v {
			t.Errorf("form[%s] = %q, want %q", k, got, v)
		}
	}
}

// The token is cached, so two sends in quick succession make one request between
// them rather than one each.
func TestToken_IsCached(t *testing.T) {
	ts := &tokenServer{}
	c := newTokenServer(t, ts)

	for range 3 {
		token, err := c.Token(t.Context())
		if err != nil {
			t.Fatalf("Token: %v", err)
		}
		if token != "token-1" {
			t.Errorf("Token = %q, want the cached token-1", token)
		}
	}
	if got := ts.count(); got != 1 {
		t.Errorf("the identity provider was called %d times, want 1", got)
	}
}

// A token near expiry is replaced rather than handed out. The margin means a
// token that would expire mid-request is never used.
func TestToken_RefreshesBeforeExpiry(t *testing.T) {
	// Shorter than the one-minute safety margin, so the first token is already
	// considered stale.
	ts := &tokenServer{expiresIn: 30}
	c := newTokenServer(t, ts)

	first, err := c.Token(t.Context())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	second, err := c.Token(t.Context())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if first == second {
		t.Error("a token inside the refresh margin was reused")
	}
	if got := ts.count(); got != 2 {
		t.Errorf("the identity provider was called %d times, want 2", got)
	}
}

// error_description is the field that says which permission is missing or which
// secret has expired, so it has to survive into the error.
func TestToken_SurfacesTheProviderError(t *testing.T) {
	c := newTokenServer(t, &tokenServer{
		status: http.StatusUnauthorized,
		body:   `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`,
	})

	_, err := c.Token(t.Context())
	if err == nil {
		t.Fatal("a 401 was reported as success")
	}
	for _, want := range []string{"401", "invalid_client", "AADSTS7000215"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// A 200 carrying no token is still a failure. Treating it as success would cache
// an empty string and authenticate as nobody on every send afterwards.
func TestToken_RejectsAnEmptyToken(t *testing.T) {
	c := newTokenServer(t, &tokenServer{body: `{"expires_in":3600}`})

	if _, err := c.Token(t.Context()); err == nil {
		t.Fatal("an empty access token was accepted")
	}
}

func TestNew_ValidatesCredentials(t *testing.T) {
	if _, err := New("tenant", "client", "secret"); err != nil {
		t.Fatalf("a valid configuration was rejected: %v", err)
	}
	cases := map[string][3]string{
		"no tenant": {"", "client", "secret"},
		"no client": {"tenant", "", "secret"},
		"no secret": {"tenant", "client", "  "},
	}
	for name, args := range cases {
		if _, err := New(args[0], args[1], args[2]); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestWithScope_OverridesTheDefault(t *testing.T) {
	ts := &tokenServer{}
	c := newTokenServer(t, ts)
	c.scope = "https://graph.microsoft.com/.default"

	if _, err := c.Token(t.Context()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	ts.mu.Lock()
	got := ts.form.Get("scope")
	ts.mu.Unlock()
	if got != "https://graph.microsoft.com/.default" {
		t.Errorf("scope = %q, want the override", got)
	}
}

// The caller's context bounds the request, so a slow identity provider cannot
// hold a send open indefinitely.
func TestToken_RespectsTheContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Longer than the caller's deadline, but bounded so the test server can
		// still shut down.
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}))
	t.Cleanup(srv.Close)

	c, err := New("tenant", "client", "secret")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.loginBase = srv.URL

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Token(ctx); err == nil {
		t.Fatal("a hung identity provider was reported as success")
	}
}
