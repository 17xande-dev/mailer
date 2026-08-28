package mailer

import (
	"context"
	"log/slog"
	"slices"
	"sync"
)

// Discard is the Sender for a deployment with no mail configured. It logs what it
// would have sent, at warning level, and reports success.
//
// Reporting success is deliberate. The alternative — an error — would make every
// request log a delivery failure for a deployment that simply has not configured
// mail, burying the failures that matter. A loud warning at startup is where that
// problem is meant to be noticed.
type Discard struct{ Log *slog.Logger }

func (d Discard) Send(_ context.Context, m Message) error {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	log.Warn("email not configured; discarding message", "to", m.To, "subject", m.Subject)
	return nil
}

// Fake captures messages instead of sending them. It backs every test that
// involves mail, and lives here next to the interface rather than in a separate
// test-only package so that a caller needs one import rather than two.
type Fake struct {
	// Err, when set, is returned by every Send, standing in for a mail server
	// that is refusing or unreachable.
	Err error

	mu        sync.Mutex
	sent      []Message
	attempted []Message
}

func NewFake() *Fake { return &Fake{} }

// Send records the message unless Err is set. It does not validate: a test
// asserting on what a handler tried to send should see what the handler built,
// not a rejection this type invented.
func (f *Fake) Send(_ context.Context, m Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempted = append(f.attempted, m)
	if f.Err != nil {
		return f.Err
	}
	f.sent = append(f.sent, m)
	return nil
}

// Sent returns every message that was delivered, in order. A send that failed
// because Err was set is not among them — Sent answers "what went out".
func (f *Fake) Sent() []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sent)
}

// Attempted returns every message handed to Send, including ones Err refused.
// It answers the different question of whether the caller tried at all, which is
// what distinguishes "the handler never sent" from "the send was refused".
func (f *Fake) Attempted() []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.attempted)
}

// To returns the delivered messages addressed to one recipient, which is what a
// test usually wants to assert on. A message matches if the address is among its
// To recipients; Bcc is not searched, because a test asking "did this person get
// it" and a test asking "was this person blind-copied" are different questions.
func (f *Fake) To(address string) []Message {
	var out []Message
	for _, m := range f.Sent() {
		if slices.Contains(m.To, address) {
			out = append(out, m)
		}
	}
	return out
}
