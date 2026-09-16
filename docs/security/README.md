# Fotolab Security

The foundation the rest of the platform is built on. Read in this order:

1. **[threat-model.md](threat-model.md)** — what we defend against, what is still
   open, and what we have decided to accept. Includes the attacks the first
   red-team pass missed.
2. **[authorization-model.md](authorization-model.md)** — three trust domains,
   the entitlement chain, and the single download chokepoint.
3. **[data-handling.md](data-handling.md)** — buckets, signed URLs, the upload
   pipeline, metadata, and cost as a security perimeter.
4. **[launch-gate.md](launch-gate.md)** — what must pass before production, in
   the order it should be built.

## Code

| Path | What it is |
|---|---|
| `supabase/migrations/0001_security_foundation.sql` | Schema, state machines, integrity triggers, `app.authorize_download()` |
| `supabase/migrations/0002_row_level_security.sql` | RLS policies and grant revocations |
| `supabase/migrations/0003_storage_buckets.sql` | Private buckets and the never-public guard |
| `supabase/migrations/0004_v2_reconciliation.sql` | Hardened Architecture v2 deltas: price lists, livemode, denormalized tenancy, asset status, order-scoped deliverables, role split |
| `tests/security/authorization_tests.sql` | The suite that gates deploys |
| `bridge/` | The Capture Bridge — durable spool, device identity, server-acknowledged uploads. See `bridge/README.md` |

## The one idea

The v1 blueprint trusted identities. This one trusts verified relationships.

Not *"this user is logged in"* but *"this exact actor is authorized for this
exact action on this exact resource, in this exact state."*

Everything above is that sentence, made structural.
