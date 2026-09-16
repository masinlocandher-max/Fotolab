# Launch Gate

Production is not authorized until every gate below passes. The gates are
sequenced by cost, because a business that needs revenue cannot build all ten
before shipping anything — but the sequence is about *order of work*, not about
which ones are optional. None are optional.

## Tier 1 — cheap, and unfixable later

These are structural. Retrofitting any of them means rewriting the data model,
so they are done before the first line of product code.

| # | Gate | Passes when | Status |
|---|---|---|---|
| 1 | Cross-tenant isolation | Every table denies a neighbouring org's ids under RLS, for `anon` and `authenticated` | schema + tests in place |
| 2 | No HD without payment | An unpaid or unentitled session gets zero rows from `app.authorize_download()` | schema + tests in place |
| 3 | Server-authoritative pricing | A tampered client amount cannot survive to fulfillment | schema + tests in place |
| 4 | Payment integrity | Forged and replayed webhooks create nothing | schema + tests in place |
| 7 | Private buckets | Masters and deliverables are private and cannot be made public | schema + tests in place |
| 10 | Tests gate the deploy | `tests/security/authorization_tests.sql` runs on every deploy and blocks on failure | `.github/workflows/security.yml` |

### On v2's Phase 6

Hardened Architecture v2 §41 puts rate limiting, resource quotas, worker
sandboxing, device revocation and MFA in a final phase called "Hardening."

That name is the problem. A phase called Hardening gives everything in it
permission to be late, and three of those five cannot be:

- **Device revocation** is needed the day the second device is enrolled — Phase 2.
  A stolen laptop before Phase 6 has no off switch.
- **Rate limiting and quotas** are needed the day a gallery is reachable from the
  public internet — Phase 3. That is the first moment someone who is not a
  customer can cost you money.
- **MFA** is needed before the dashboard holds revenue — Phase 4. Shipping
  commerce with password-only admin access means a credential stuffing list is
  a business takeover.

Only worker sandboxing, chaos tests and penetration testing are genuinely
Phase 6 work. The rest belongs in the phase that creates the exposure.

The tiers below are ordered on that principle: what creates the exposure, not
what feels like security work.

## Tier 2 — moderate, before first paying customer

| # | Gate | Passes when | Status |
|---|---|---|---|
| 5 | Bridge holds no platform credential | A full filesystem dump of a Bridge install yields a device key and nothing else | **built** — `bridge/`, Ed25519 identity encrypted at rest, no service key anywhere |
| 9 | Device revocation is immediate | Revoking a device kills new sessions within seconds, not at token expiry | **built** — `app.device_session_is_live` plus Bridge-side halt; covered by two Bridge tests |
| 8 | Cost abuse hits a limit | Automated create/upload/checkout/edit loops trip quotas instead of compute | columns exist, enforcement missing; `platform_settings.processing_halted` is the kill switch |
| — | Entitlement anchored to a verified contact | A customer with no cookie recovers their photos by proving contact, not by holding a URL | not built |
| — | MFA on owners and admins | Password alone does not reach payouts, device enrollment or credential creation | not built |

## Tier 3 — expensive, before scale

| # | Gate | Passes when | Status |
|---|---|---|---|
| 6 | Malicious uploads contained | A crafted file cannot escape the sandboxed processor or exhaust it | not built |
| — | Realtime channel separation | Three scopes — gallery, customer-private, org — with server-side authorization | not built |
| — | EXIF stripped from customer-facing images | No GPS, serial, owner or device id in any preview or deliverable | not built |
| — | Chargeback posture decided | Risk scoring before fulfillment; dispute evidence captured; pricing absorbs the residual | not built |

## Running the tests

```bash
./tests/security/run.sh                              # ephemeral local Postgres
SCRATCH_DATABASE_URL=postgres://… ./tests/security/run.sh   # a Supabase branch
```

Every assertion is a negative one — the attack is performed and must fail. A
suite that only proves the happy path works proves nothing about security.

The suite runs inside a transaction and rolls back, so it is safe against a
scratch or branch database. **Never point it at production.**

## Phase 2 exit criteria

The Bridge milestone, as executable claims rather than intentions
(`bridge/test/`, 31 tests plus the soak):

| Criterion | Test |
|---|---|
| A capture is durable before any processing | `a discovered row is committed before anything else happens` |
| Bad or absent wifi loses nothing | `wifi disappearing mid-event loses nothing and resumes on reconnect` |
| Reconnection resumes automatically | same, plus `recovery rewinds interrupted uploads and nothing else` |
| Duplicate filesystem events do not duplicate captures | `repeated scans of an unchanged card create nothing new` |
| Duplicate camera filenames stay separate photographs | `duplicate camera filenames on different cards stay separate photographs` |
| Success is never inferred from a local HTTP result | `a corrupted upload is never confirmed, and is re-sent until it matches` |
| Local cleanup waits for server confirmation | `local files are never deleted before the server confirms the master` |
| Power loss after detection | `the spool survives a kill with no torn or unreadable rows` |
| Restart during upload | `every photograph survives repeated kill -9` |
| Commit-then-lost-acknowledgement | `a kill between server commit and our acknowledgement still yields one capture` |
| Partial / corrupt / replaced files | four scenario tests |
| Revoked, compromised, wrong event, expired session | four scenario tests |
| 500+ photographs through an unstable event | `npm run test:soak` |

Not yet done in Phase 2, and named rather than left implicit: resumable
multipart upload for very large masters, RAW embedded-preview extraction, and
OS keychain storage for the device key.

## Keeping the suite honest

A suite that passes is not evidence until you have watched it fail. Three real
authorization holes survived an all-green run of the first version of this file:
the tests asserted the right *outcomes* but reached them through paths that
happened to avoid the bug.

So: when you add a control, delete it once and confirm the suite goes red. When
you add a test, run it against the unpatched schema first. `run.sh` exits
non-zero on the first failed assertion, which is what makes it a gate rather
than a report.

## Adding a table

A new table with no RLS fails gate 1 automatically via the structural check over
`pg_class.relrowsecurity`. That is intentional: the gate should catch the
omission, not a reviewer on a Friday.
