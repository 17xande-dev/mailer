# mailer

Transactional mail for Go applications, behind one `Sender` interface.

```go
sender, err := mailer.NewSMTPSender(mailer.SMTPConfig{
    Host: "smtp.example.com", Port: 587,
    Username: "shop@example.com", Password: os.Getenv("SMTP_PASSWORD"),
    From: "shop@example.com",
    TLS:  mailer.TLSStartTLS,
})

err = sender.Send(ctx, mailer.Message{
    To:      []string{"jane@example.com"},
    Subject: "Order 1042 — payment received",
    Text:    plain,
    HTML:    html, // optional; becomes the multipart/alternative part
})
```

Delivery is SMTP, via [go-mail](https://github.com/wneessen/go-mail). `Discard` and
`Fake` implement `Sender` too — the first for a deployment with no mail configured, the
second for tests.

## Microsoft Exchange Online

Basic Auth for SMTP client submission is going away, so an Exchange mailbox is reached
with **XOAUTH2**: the password becomes an OAuth2 access token. go-mail speaks XOAUTH2
but has no notion of where a token comes from, which is what `mailer/msauth` is for.

```go
tokens, err := msauth.New(tenantID, clientID, clientSecret)

sender, err := mailer.NewSMTPSender(mailer.SMTPConfig{
    Host: "smtp.office365.com", Port: 587,
    Username:    "shop@example.com", // the mailbox; XOAUTH2 authenticates as a named one
    TokenSource: tokens,             // Password is then ignored
    From:        "shop@example.com",
    TLS:         mailer.TLSStartTLS,
})
```

A token is fetched for each send and cached until a minute before it expires, so nothing
here has to reason about expiry.

**The tenant-side setup is the part that bites**, and none of it is visible from this
library — a tenant that has not been set up returns a token perfectly happily and the
mail server then refuses it. You need, at minimum:

- an Entra ID app registration with the **`SMTP.SendAsApp`** application permission
  (Office 365 Exchange Online), with admin consent;
- a service principal for that app registered in Exchange Online;
- **Send As** granted on the mailbox;
- **SMTP AUTH enabled for that mailbox** — it is disabled tenant-wide by default.

Check each against current Microsoft documentation; these requirements move.

## Behaviour worth knowing

- **A password is never sent in the clear.** Authentication mechanism selection refuses
  PLAIN and LOGIN on an unencrypted connection. A local mail sink reached over
  `TLSNone` must therefore be configured with *no* credentials, not throwaway ones —
  which is also the right shape, since such a sink does not check them.
- **STARTTLS is mandatory, not opportunistic.** A relay that offers no STARTTLS fails
  loudly rather than quietly sending in the clear. `TLSNone` is the explicit opt-out.
- **`Bcc` reaches the envelope and never the headers**, which is what keeps blind
  recipients blind.
- **Nothing retries, queues or logs.** A `Sender` performs one delivery attempt and
  returns. What a failure means is the caller's decision.
- **`Message.ReplyTo` overrides `SMTPConfig.ReplyTo`**, for mail sent on somebody's
  behalf that should be answered to them.

## Message rules

`Text` is required; `HTML` is optional and becomes the alternative part, so a client
that refuses HTML still shows something readable. `Subject` must be present and must not
contain a line break — header values are written verbatim, so a newline would inject
arbitrary headers, and it is rejected rather than silently rewritten.

`Message` carries only fields that mean the same thing to every transport. Adding one is
a decision, not a convenience.
