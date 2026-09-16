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

## Tier 2 — moderate, before first paying customer

| # | Gate | Passes when | Status |
|---|---|---|---|
| 5 | Bridge holds no platform credential | A full filesystem dump of a Bridge install yields a device key and nothing else | not built |
| 9 | Device revocation is immediate | Revoking a device kills new sessions within seconds, not at token expiry | schema ready, flow not built |
| 8 | Cost abuse hits a limit | Automated create/upload/checkout/edit loops trip quotas instead of compute | columns exist, enforcement missing |
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
