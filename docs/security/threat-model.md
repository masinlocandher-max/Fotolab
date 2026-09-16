# Fotolab — Threat Model

Status: **pre-launch**. This document is the authority on what the platform
defends against. If an attack is listed as `open`, it is not defended and the
launch gate has not cleared.

The organising principle:

> Authorization is a property of a verified relationship, not of an identity.
> Not "this user is logged in" but "this actor is authorized for this action on
> this resource in this state."

Everything outside the core is hostile until proven otherwise: the customer
browser, the photographer browser, the Capture Bridge, the camera filename, the
image metadata, the uploaded bytes, the realtime message, the queue message, the
payment redirect, the QR URL, any object id, and anyone holding a signed URL.

The only trusted truths are server-side authorization, database constraints,
verified payment-provider data, and verified object relationships.

---

## Part 1 — Attacks the schema now defends

Each row links to the mechanism that stops it, and to the test that proves it
still does. `closed` here means *closed at the data layer* — application and
infrastructure work still sits on top.

| # | Attack | Mechanism | Test | Status |
|---|---|---|---|---|
| 1 | Buy one photo, download the rest | `app.authorize_download()` walks session → order → item → entitlement → capture → deliverable. Capture id is an input to be checked, never a source of authority | `substituting an unpurchased capture id yields nothing` | closed |
| 2 | Forge an entitlement onto a paid line item | `guard_entitlement_activation` requires `entitlement.capture_id = order_item.capture_id` and a matching session | `an entitlement cannot point at a capture the line item does not contain` | closed |
| 3 | Cross-tenant breakout by id substitution | RLS on every table, keyed to `organization_members`, not to authentication | five `RLS hides another organization's …` assertions | closed |
| 4 | Price manipulation | `orders.amount_minor` is derived from line items by trigger; the browser sends a capture id and nothing else | `a tampered order total is recomputed away` | closed |
| 5 | Forged payment | No transition to `paid` exists without a `signature_verified` provider event whose amount and currency match | `an order cannot reach paid without a verified provider event` | closed |
| 6 | Wrong-amount payment | The same guard compares provider amount to the derived total | `a verified event for the wrong amount does not mark the order paid` | closed |
| 7 | Webhook replay | `unique (provider, provider_event_id)` — replay defeated by the schema, not by application memory | `replaying a provider event id is rejected` | closed |
| 8 | Unpaid session reaching for HD | Same chokepoint; no paid order, no rows | `a session that never paid gets no HD asset` | closed |
| 9 | Queue poisoning / duplicate expensive jobs | `unique (order_item_id, processing_version)` collapses at-least-once redelivery into one billable job | `a duplicate fulfillment job … collapses` | closed |
| 10 | Compromised Bridge swaps bytes behind a capture | Masters are write-once; `content_hash` and object path immutable after first write; `unique (device_id, device_sequence)` blocks sequence replay | three immutability assertions | closed |
| 11 | Public-bucket mistake | A trigger on `storage.buckets` rejects `public = true` for quarantine / master / preview / deliverable | `the deliverable bucket cannot be flipped public` | closed |
| 12 | Erase the trail | `audit_log` is append-only by trigger | `the audit log cannot be deleted` | closed |
| 13 | Table shipped without RLS | Structural gate over `pg_class.relrowsecurity` fails the build | `every public table has RLS enabled` | closed |
| 15 | Order booked to the wrong tenant | `guard_order_tenancy` ties `orders.organization_id` to the event's owner and the session's event | `an order cannot be booked to an organization that does not own the event` | closed |
| 16 | Cross-event line item — buy another photographer's photo through your own checkout | `guard_order_item_integrity` requires the capture's event to be the order's event; `app.authorize_download()` re-checks it | `a line item cannot reference a capture from another event` | closed |
| 17 | Direct write of a tampered order total | `guard_order_amount` re-derives `amount_minor` on every write to `orders`, not only when a line item is touched | `a total written directly onto the order is overwritten immediately` | closed |
| 18 | Test-mode webhook against a live platform | `payment_events.livemode` must equal `app.platform_livemode()` before the event may bind to an order, and again at the `paid` transition | `a test-mode payment event cannot bind to an order on a live platform` | closed |
| 19 | Poisoned denormalized tenancy | `guard_denormalized_org` derives `organization_id` from the parent when omitted and rejects it when supplied and wrong | `a capture cannot claim an organization its event does not belong to` | closed |
| 20 | Client-supplied storage path / traversal | `guard_asset_path` requires the server-derived prefix and rejects `..` | `an asset path that is not server-derived is rejected` | closed |
| 21 | Price written by a buggy or compromised server | `guard_order_item_price` resolves the price from the event's published price list and discards whatever the caller supplied | `a caller-supplied line price is replaced by the published price list` | closed |
| 22 | Selling from an unpriced event | `app.resolve_price` fails closed — no published list means nothing may be sold | `a published price list is immutable` | closed |
| 23 | Serving an asset that is not ready | `authorize_download` requires `assets.status = 'ready'`; an asset row existing is not the bytes being servable | `a deliverable that is not READY is not downloadable` | closed |
| 24 | Entitlement outliving its grant | `entitlements.expires_at` honoured in the chokepoint | `an expired entitlement stops authorizing downloads` | closed |
| 25 | Bookkeeper reads photos / photographer reads revenue | Role-scoped RLS: FINANCE reaches orders, PHOTOGRAPHER reaches captures, neither reaches both | four role-split assertions | closed |
| 14 | Chargeback / refund after delivery | Entitlement revocation is a first-class operation, separate from payment state | `a revoked entitlement stops authorizing downloads` | partial — see §3 |

Rows 18–25 come from reconciling Hardened Architecture v2. Three of them —
`livemode`, order-scoped deliverables, and asset status — are places where v2 is
genuinely stronger than the first schema, and are credited as such in
`supabase/migrations/0004_v2_reconciliation.sql`.

Rows 15–17 were not found by reading the design. They were found by executing
the attacks against the schema and watching them succeed, after an earlier
version of this suite reported all green. Two of the three were straightforward
BOLA — the object id was checked against the wrong parent. That is the argument
for negative tests over review: the first suite passed while the platform would
have handed one photographer's HD files to another photographer's customer for
one peso.

---

## Part 2 — Attacks that need application and infrastructure work

The database cannot close these. They are open until the named control exists.

| # | Attack | Consequence | Severity | Control | Status |
|---|---|---|---|---|---|
| 15 | Malicious upload through a compromised Bridge | Worker RCE or decoder DoS | Critical | Quarantine bucket → extension allowlist → magic bytes → real decoder probe → size, pixel-dimension and decompression-ratio limits → sandboxed decode → re-encode. Never trust declared `Content-Type` | open |
| 16 | Dependency compromise in a RAW/image parser | Worker takeover | Critical | Workers run non-root, read-only FS, no cloud or DB credentials, no egress by default, CPU/RAM/timeout caps, disposable workspace. Blast radius = one worker | open |
| 17 | Signed-URL theft | HD leak for the URL's lifetime | Critical | 60–120s lifetimes, `Referrer-Policy: no-referrer`, and a hard rule that a signed URL never enters logs, analytics, error reports, emails, or third-party scripts | open |
| 18 | Device theft | Upload and read event data | High | Device keypair in OS-protected storage, short-lived event-scoped credentials, server-side revocation that bites immediately (`app.device_session_is_live`), encrypted local spool | partial |
| 19 | Resource / cost attack | Runaway cloud bill, outage | Critical | Quotas at every layer: device uploads/min, event captures/hour, org storage and processing credits, IP limits on anonymous requests, checkout attempts per session, worker concurrency ceiling, AI daily spend cap, global circuit breaker. Columns exist; enforcement does not | partial |
| 20 | Realtime leakage | Customer and order data exposure | Critical | Three trust domains, three channel scopes: event-level gallery (preview published only), customer-scoped private (order state), org-scoped (metrics). Never one event room | open |
| 21 | CDN cache of a private final | Permanent HD exposure | Critical | Only the preview route is cacheable; `Cache-Control: private, no-store` on every authorized download response | open |
| 22 | EXIF surveillance | GPS, camera serial, owner name, device ids | High | Previews are *reconstructed*, not copied. Strip all metadata from anything customer-facing | open |
| 23 | Recovery-link theft | HD theft | High | High-entropy tokens, stored as `sha256` only (`download_grants.token_hash`), short expiry, use caps. Schema ready; issuance flow not built | partial |
| 24 | Gallery scraping | Bulk preview theft | Medium/High | Watermark + low resolution + per-IP and per-session rate limits + event access policy. Accept that watermarks are deterrence, not protection | open |
| 25 | Admin takeover | Whole business compromised | Critical | MFA for owners/admins; step-up auth for payouts, device enrollment, API credential creation, member changes. `organization_members.mfa_required` exists; enforcement does not | partial |
| 26 | Face-search abuse | Serious privacy exposure | High | Out of V1 — see §4 | deferred |

---

## Part 3 — Attacks the original red-team missed

These came out of reviewing the red-team against how this business actually
operates, rather than against the architecture diagram.

### 27. Chargeback after download — Critical, and partly unfixable

The eighteen-attack review treated refunds as a state, not as an attack. The real
sequence is: buy → download the HD in four seconds → dispute the transaction with
the wallet provider three weeks later. Revoking the entitlement afterwards does
nothing. The bytes are on their phone.

There is no technical fix, which is exactly why it needs saying out loud. The
controls are commercial:

- Risk-score before fulfillment, not after: new session, unverified contact,
  high basket value, and a first-ever card together should slow delivery, not
  block it.
- Keep the dispute evidence the provider actually asks for — order, timestamps,
  IP prefix, download log, event and capture references. `audit_log` is shaped
  for this on purpose.
- Price and package so a single successful chargeback is an annoyance, not a
  month. In this market, wallet rails (GCash, Maya) and card rails have very
  different dispute profiles — **verify the current dispute windows and
  liability rules with PayMongo before setting the risk thresholds.** Do not
  take a number from this document.

### 28. The paying tenant is an attacker too — High

Every one of the original eighteen attacks casts the photographer as victim.
But the photographer is the one with upload rights, and the cheapest attack on a
photo platform is using it as free cloud storage: 400 GB of unrelated files
uploaded as "an event". Also in this class: self-purchasing to game any future
payout, leaderboard or social-proof mechanic; running a third party's photos
through the AI editor; and inviting fake customer sessions to inflate an event.

Controls: per-organization storage quota and processing credits as hard ceilings
(columns exist on `organizations`), anomaly alerting on upload volume per event,
and a suspension path (`organizations.suspended_at`) that does not require a
database migration to use at 2am.

### 29. The customer session cannot be the entitlement anchor — High

A cookie-only anonymous session breaks on the most ordinary journey in this
business: buy on mobile data at the event, want the photo that night on a laptop.
The session is gone. Recovery links then become load-bearing for the entire
entitlement chain — which makes the weakest credential in the system the one
every customer uses.

The fix is a design change, not token hygiene: **bind the entitlement to a
verified contact at checkout** — email or phone, OTP-confirmed before payment —
and treat the cookie as a convenience. `customer_sessions.verified_email`,
`verified_phone` and `contact_verified_at` exist for this. A later session that
proves the same contact inherits the entitlement; it never guesses a URL.

### 30. Shared devices — Medium/High, and near-certain in this market

One phone passed around a group. The photographer's own iPad used for customer
selection at the booth. An HttpOnly session cookie survives the handoff and the
next person sees the previous buyer's orders and downloads.

Controls: an explicit "done / not me" session termination on every order screen,
a short idle timeout on booth devices, a kiosk mode that clears session state
between customers, and never rendering full contact details in the gallery UI.

### 31. v2 §15 and v2 §29 contradict each other — High

This is not a new attack; it is the session-portability hole from §29 above,
surfacing as an internal inconsistency in the v2 document.

§15 gives the customer a cookie-only anonymous session and no account. §29 then
says: do not email the signed file URL — email a link to the order page, and
"the order page re-authorizes the customer."

Re-authorizes them with what? The cookie is on the phone they paid with. The
email is open on a laptop. There are exactly two ways to resolve this, and v2
picks neither:

1. The emailed link carries a bearer token — which is the recovery-link
   credential §29 was written to avoid, now load-bearing for every customer.
2. The order page proves a verified contact — which means the contact must have
   been verified at checkout, which §15 does not do.

Option 2 is the right one, and it is a change to §15, not to §29.
`customer_sessions.verified_email`, `verified_phone` and `contact_verified_at`
exist for it. Until then, §29's advice is sound and unimplementable.

### 32. Refund-timing race — Medium

Refund issued while the HD worker is mid-job: the entitlement revokes, the worker
finishes, the deliverable lands, and a stale signed URL or a retried request
picks it up. Workers must re-check entitlement immediately before writing the
deliverable and again before any URL is minted — the chokepoint is a function so
that this is one call, not a reimplementation.

---

## Part 4 — Face recognition

Keep it out of V1. Not because it is hard, but because it converts an event-photo
product into a biometric identification system, which is a different legal
posture and a different class of breach.

In the Philippines the Data Privacy Act of 2012 (RA 10173) treats biometric data
as sensitive personal information with heightened consent and processing
obligations. **This needs a real legal review before any face feature ships —
treat that sentence as a flag, not as advice.**

If it ever ships: explicit opt-in consent, event-scoped indexes with no
cross-event identity, encrypted templates, a hard retention limit tied to event
archival, subject deletion controls, and a separate access policy from
everything above.

---

## Part 5 — Assumptions we accept

Stating these keeps effort out of places it cannot help.

1. **Anything shown as a preview is obtainable.** Screenshots exist. AI watermark
   removal exists. The preview is marketing; the resolution is the product.
2. **A signed URL is a bearer capability.** Whoever holds it, within its lifetime,
   gets the bytes. The control is lifetime and non-leakage, not revocation.
3. **A stolen production database is catastrophic but not total.** It must not by
   itself yield RAW files, HD deliverables, payment credentials, or device private
   keys. That is why storage credentials, payment secrets and device keys live in
   different systems from the database.

---

## Vendor claims that must be verified, not assumed

Written down because getting these wrong silently is worse than not knowing:

- **PayMongo webhook verification.** The signature header name, the exact HMAC
  construction, whether it is computed over the raw body, and the test/live
  signature split — confirm against current PayMongo documentation before writing
  the verifier, and write a test with a known-good fixture.
- **Supabase signed-URL lifetime semantics.** The working assumption here is that
  an issued Storage signed URL remains valid until it expires, independently of
  session or key rotation. If that holds, revocation is not a control and short
  lifetimes are the only lever. Confirm it.
- **Supabase public-bucket behaviour.** The working assumption is that a public
  bucket bypasses retrieval access control entirely. The trigger in
  `0003_storage_buckets.sql` assumes this is true and makes it unreachable.
- **OWASP references.** Broken Object Level Authorization and Unrestricted
  Resource Consumption are the two categories this model leans on most heavily.
  Cite the current API Security Top 10 revision directly rather than this file.
