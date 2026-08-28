package mailer

import (
	"errors"
	"log/slog"
	"testing"
)

func TestFake_CapturesMessages(t *testing.T) {
	f := NewFake()

	for _, to := range []string{"a@example.com", "b@example.com", "a@example.com"} {
		if err := f.Send(t.Context(), Message{To: []string{to}, Subject: "s", Text: "t"}); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if got := len(f.Sent()); got != 3 {
		t.Errorf("Sent() = %d messages, want 3", got)
	}
	if got := len(f.To("a@example.com")); got != 2 {
		t.Errorf("To(a@example.com) = %d, want 2", got)
	}
	if got := len(f.To("nobody@example.com")); got != 0 {
		t.Errorf("To(nobody) = %d, want 0", got)
	}

	// Sent returns a copy, so a caller cannot edit the record it is reading.
	sent := f.Sent()
	sent[0].Subject = "tampered"
	if f.Sent()[0].Subject == "tampered" {
		t.Error("Sent() handed out the fake's own slice")
	}

	f.Err = errors.New("relay refused")
	if err := f.Send(t.Context(), Message{To: []string{"c@example.com"}, Subject: "s", Text: "t"}); err == nil {
		t.Error("Send succeeded with Err set")
	}
	if got := len(f.Sent()); got != 3 {
		t.Errorf("a failed send was recorded as delivered: %d messages", got)
	}
	// Attempted answers the other question: the caller did try.
	if got := len(f.Attempted()); got != 4 {
		t.Errorf("Attempted() = %d, want 4 including the refused send", got)
	}
}

// To matches a message with several recipients, which is what lets a test assert
// on one address without knowing who else was on the message.
func TestFake_ToMatchesAnyRecipient(t *testing.T) {
	f := NewFake()
	m := Message{
		To:      []string{"first@example.com", "second@example.com"},
		Bcc:     []string{"blind@example.com"},
		Subject: "s", Text: "t",
	}
	if err := f.Send(t.Context(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}

	for _, addr := range []string{"first@example.com", "second@example.com"} {
		if got := len(f.To(addr)); got != 1 {
			t.Errorf("To(%s) = %d, want 1", addr, got)
		}
	}
	// Bcc is a different question and deliberately not searched.
	if got := len(f.To("blind@example.com")); got != 0 {
		t.Errorf("To(blind) = %d, want 0; Bcc is not a To recipient", got)
	}
}

func TestDiscard_ReportsSuccess(t *testing.T) {
	// Reporting success is deliberate: an error would make every request log a
	// delivery failure for a deployment that has simply not configured mail,
	// burying the failures that matter. The startup warning is where that is
	// noticed.
	d := Discard{Log: slog.New(slog.DiscardHandler)}
	if err := d.Send(t.Context(), Message{To: []string{"a@example.com"}, Subject: "s", Text: "t"}); err != nil {
		t.Errorf("Discard.Send = %v, want nil", err)
	}
	// And a nil logger does not panic, since Discard is a zero-value-usable type.
	if err := (Discard{}).Send(t.Context(), Message{To: []string{"a@example.com"}}); err != nil {
		t.Errorf("Discard{}.Send = %v, want nil", err)
	}
}
