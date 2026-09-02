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

## Graph, as an alternative to SMTP

`GraphSender` sends through the Microsoft Graph API's `sendMail` endpoint instead of SMTP,
for a deployment that already has an Entra app registration and would rather not deal with
SMTP AUTH. It needs its own token, scoped to Graph rather than SMTP:

```go
tokens, err := msauth.New(tenantID, clientID, clientSecret, msauth.WithScope(msauth.ScopeGraph))

sender, err := mailer.NewGraphSender(mailer.GraphConfig{
    TokenSource: tokens,
    From:        "shop@example.com", // needs the Mail.Send application permission, admin-consented
})
```

The app registration needs a **different** permission than the SMTP path: **`Mail.Send`**
(application, admin-consented), not `SMTP.SendAsApp`. The two are not interchangeable, and a
token that works for one will be rejected by the other.

Sends go as **raw MIME** rather than through Graph's JSON message schema, which is what lets a
message carry both a plain-text and an HTML part — the JSON schema's `body` takes exactly one
`contentType`. The cost is that **Bcc has no envelope on this transport**: it is written into
the MIME as a real header, which Microsoft's documented behaviour says Graph reads as
recipients and strips before delivering. That behaviour has not been verified against a live
tenant by this module's maintainer — confirm it with a real send before relying on Bcc through
Graph in production.

Which transport to reach for: **SMTPSender is the default.** `GraphSender` is for a
deployment where the tenant-side XOAUTH2 setup (SMTP AUTH enabled per mailbox, a service
principal, `SMTP.SendAsApp`) is a bigger lift than a `Mail.Send` grant, or where Graph is
already how the deployment talks to that tenant for something else.

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
