# Authorization Model

One rule, applied everywhere:

> **authenticated ≠ authorized**

Being logged in establishes who is asking. It establishes nothing about whether
this particular resource, in this particular state, may be handed over. Random
UUIDs do not help — they make ids hard to guess, which is not the same as making
them safe to accept.

---

## Three trust domains

They share a database and nothing else. Mixing them is how object-level
authorization bugs get written.

### 1. Photographer

Supabase Auth user → Data API → RLS keyed on `organization_members`.

The chain is `auth.uid() → organization_members → organization_id → resource`.
Authorization is the *relationship*, checked by the database on every row, so a
handler that forgets to filter still returns nothing.

MFA is required for owners and admins, with step-up re-authentication for
payouts, device enrollment, API credential creation, and membership changes. A
stolen password must not equal a stolen business.

### 2. Capture device

A device keypair, and nothing else. The Bridge must never hold a `service_role`
key, a database password, a storage master key, a payment secret, or a platform
admin token.

```
account → enroll device → device private key (OS-protected storage)
       → authenticate → short-lived credential scoped to (org, event, device)
```

That credential may write to one organization, one event, from one device. If
the laptop is stolen, revoking the device kills future sessions immediately —
`app.device_session_is_live()` checks the revocation, not just the expiry.

### 3. Customer

Anonymous session, and **no Data API access at all**. Every customer read and
write goes through a server endpoint. The relevant tables have their grants
revoked from `anon` and `authenticated` outright, so no future permissive policy
can open them by accident.

This is a deliberate choice over writing RLS for anonymous sessions. Customer
authorization depends on payment state, fulfillment state and entitlement state
at once; expressing that as a row filter invites a policy that is subtly wrong
and silently permissive. Instead it lives in one function.

---

## The entitlement chain

The most important structural change from the v1 blueprint: **payment and
permission are different objects.**

```
CUSTOMER SESSION
      │
      ▼
    ORDER              status = paid, amount derived from items
      │
      ▼
  ORDER_ITEM           capture_id + server-set price
      │
      ▼
  ENTITLEMENT          active | revoked, source = purchase | comp | replacement
      │
      ▼
    CAPTURE
      │
      ▼
  DELIVERABLE          fulfillment ready
```

Separating them is what makes refunds, complimentary photos, packages,
all-access purchases, manual replacements and support cases ordinary operations
instead of lies told to the payment table.

### The chokepoint

Every HD download in the system resolves through one function:

```sql
app.authorize_download(p_customer_session uuid, p_capture uuid)
```

Note what is **not** a parameter: no bucket, no object path, no asset id. The
caller names a capture; the database decides which bytes, if any, and returns
zero rows when the answer is no. No endpoint reimplements the chain, so no
endpoint gets to get it wrong.

Conceptually it asserts, in one query:

```
session is live and unrevoked
AND session owns the order
AND order.status = paid
AND order_item belongs to that order
AND entitlement belongs to that order_item
AND entitlement.status = active
AND entitlement.capture_id = order_item.capture_id = requested capture
AND fulfillment.status = ready
```

Anything else: **deny**.

---

## Entitlement anchoring

A cookie is a convenience, not an anchor. The customer who buys at the event on
mobile data and opens their laptop at home has no cookie, and a system that
anchors entitlement to the cookie forces recovery links to carry the whole
weight of the entitlement chain.

So: **bind the entitlement to a verified contact at checkout.** Email or phone,
OTP-confirmed before payment. A later session proving the same contact inherits
the entitlement. Recovery links become a fallback rather than the main road.

Session token rules, regardless:

- high entropy, generated server-side
- `HttpOnly`, `Secure`, `SameSite=Lax`, rotatable
- **never** in a query string, a URL fragment, or a QR payload
- stored as `sha256` only — `customer_sessions.token_hash`

Recovery and download grants follow the password-reset pattern exactly: the
email carries the raw token, the database carries only its hash, the grant has a
short expiry and a use cap.

---

## State machines

Every transition has an allowed predecessor. There is no arbitrary
`UPDATE status = 'paid'` reachable from application code.

```
ORDER         draft → awaiting_payment → paid → partially_refunded → refunded
                    ↘ cancelled | expired

ENTITLEMENT   inactive → active → revoked

FULFILLMENT   waiting_for_master → queued → processing → ready | failed
```

The `paid` transition additionally requires a `signature_verified` provider
event whose amount and currency match the derived order total. That check lives
in `app.guard_order_transition()`, in the database, where no handler can skip it.

---

## Payment flow

The thank-you page is not a security boundary. Anyone can navigate to
`/payment-success`. It must accomplish nothing.

The only path to `paid`:

```
webhook received
  → verify signature over the RAW body
  → verify timestamp is inside the accepted window
  → verify the provider event id has not been consumed   (unique index)
  → verify the order exists and is awaiting_payment
  → verify amount and currency match the derived total
  → single atomic transaction:
        payment_event consumed
        order → paid
        entitlement → active
        fulfillment_request created
```

One verified provider event, one effect. Always.

**Workers still distrust the queue.** A message saying "edit order_item X" is a
hint, not an authorization. Before spending money the worker re-derives: order
paid, item belongs to the order, entitlement active, capture exists, master
verified, deliverable not already produced. Defense in depth, because the queue
is the easiest thing in the system to inject into.

---

## The race worth naming

A customer buys before the RAW has finished uploading. This is normal at a live
event, not an edge case.

```
paid → entitlement active → master not ready
     → fulfillment waiting_for_master
     → Bridge prioritises that capture's upload
     → checksum verified
     → queued → processing → ready
```

Never process a partial or unverified file. `waiting_for_master` is a real state
so this is visible rather than a worker retry loop nobody is watching.

---

## Logging

Security logs carry: actor kind and id, organization, device, event, operation,
target, result, timestamp, request correlation id, and a **truncated** IP.

They must never carry: service secrets, full payment instrument data, raw
authentication or session tokens, signed download URLs, face embeddings, or RAW
image content. `audit_log` has no column that could hold one, which is easier to
keep true than a review rule.
