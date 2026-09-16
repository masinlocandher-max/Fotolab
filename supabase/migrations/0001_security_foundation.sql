-- =============================================================================
-- Fotolab :: 0001 :: Security foundation
-- =============================================================================
-- Design rule for every table below:
--   Authorization is a property of a *verified relationship*, not of an identity.
--   "This actor is authorized for this action on this resource in this state."
--
-- Two trust domains that never mix:
--   PHOTOGRAPHER  -> Supabase Auth user, reaches Postgres through the Data API,
--                    constrained by RLS on organization membership.
--   CUSTOMER      -> anonymous session, NEVER reaches the Data API. All reads and
--                    writes go through server endpoints. The entitlement chain is
--                    enforced by app.authorize_download(), a single chokepoint no
--                    endpoint may bypass or reimplement.
-- =============================================================================

-- Supabase ships pgcrypto in the `extensions` schema; a plain Postgres puts it
-- in `public`. Functions that need digest()/gen_random_bytes() therefore pin a
-- fixed search_path of 'public, extensions' rather than the usual '' — still
-- fixed, still not attacker-mutable, just resolvable in both layouts.
create schema if not exists extensions;
create extension if not exists "pgcrypto";
create extension if not exists "citext";

-- Helper schema is NOT exposed through the Data API.
create schema if not exists app;
revoke all on schema app from anon, authenticated;

-- =============================================================================
-- 1. Tenancy
-- =============================================================================

create table public.organizations (
  id              uuid primary key default gen_random_uuid(),
  slug            citext not null unique,
  display_name    text   not null,
  -- Cost perimeter. Exceeding these is a security event, not just a billing one.
  storage_quota_bytes      bigint not null default 214748364800,   -- 200 GiB
  processing_credits_month integer not null default 5000,
  suspended_at    timestamptz,
  suspended_reason text,
  created_at      timestamptz not null default now()
);

create type public.org_role as enum ('owner', 'admin', 'photographer', 'viewer');

create table public.organization_members (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id         uuid not null references auth.users(id) on delete cascade,
  role            public.org_role not null,
  mfa_required    boolean not null default true,
  created_at      timestamptz not null default now(),
  revoked_at      timestamptz,
  primary key (organization_id, user_id)
);

create index on public.organization_members (user_id) where revoked_at is null;

-- -----------------------------------------------------------------------------
-- Membership helpers. SECURITY DEFINER so RLS policies can read membership
-- without recursing into organization_members' own policy.
-- `set search_path = ''` forces fully-qualified names (Supabase hardening rec).
-- -----------------------------------------------------------------------------

create or replace function app.is_org_member(org uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.organization_members m
    where m.organization_id = org
      and m.user_id = (select auth.uid())
      and m.revoked_at is null
  );
$$;

create or replace function app.has_org_role(org uuid, allowed public.org_role[])
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.organization_members m
    where m.organization_id = org
      and m.user_id = (select auth.uid())
      and m.revoked_at is null
      and m.role = any(allowed)
  );
$$;

-- =============================================================================
-- 2. Events
-- =============================================================================

create table public.events (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name            text not null,
  starts_at       timestamptz,
  ends_at         timestamptz,
  -- Gallery reachability. Public link is still rate-limited and preview-only.
  access_mode     text not null default 'link' check (access_mode in ('link','code','invite')),
  access_code_hash bytea,                       -- never store the raw code
  capture_quota_per_hour integer not null default 2000,
  archived_at     timestamptz,
  created_at      timestamptz not null default now()
);

create index on public.events (organization_id);

-- =============================================================================
-- 3. Capture devices
-- =============================================================================
-- The Bridge holds a device keypair and nothing else. No service_role key, no
-- DB password, no storage master key, no payment secret. It trades a device
-- signature for a short-lived, event-scoped upload credential.

create table public.devices (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  label           text not null,
  public_key      bytea not null,
  enrolled_by     uuid references auth.users(id),
  enrolled_at     timestamptz not null default now(),
  last_seen_at    timestamptz,
  revoked_at      timestamptz,
  revoked_reason  text,
  uploads_per_minute integer not null default 120
);

create unique index on public.devices (organization_id, public_key);
create index on public.devices (organization_id) where revoked_at is null;

create table public.device_sessions (
  id           uuid primary key default gen_random_uuid(),
  device_id    uuid not null references public.devices(id) on delete cascade,
  event_id     uuid not null references public.events(id) on delete cascade,
  issued_at    timestamptz not null default now(),
  expires_at   timestamptz not null,
  revoked_at   timestamptz,
  check (expires_at > issued_at)
);

create index on public.device_sessions (device_id, expires_at desc);

-- Revocation must bite immediately, not at token expiry.
create or replace function app.device_session_is_live(p_session uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1
    from public.device_sessions s
    join public.devices d on d.id = s.device_id
    where s.id = p_session
      and s.revoked_at is null
      and s.expires_at > now()
      and d.revoked_at is null
  );
$$;

-- =============================================================================
-- 4. Captures and assets
-- =============================================================================

create type public.capture_status as enum ('announced','uploading','verified','quarantined','rejected');

create table public.captures (
  id              uuid primary key default gen_random_uuid(),
  event_id        uuid not null references public.events(id) on delete cascade,
  device_id       uuid not null references public.devices(id),
  device_sequence bigint not null,
  captured_at     timestamptz not null,
  content_hash    bytea,                       -- sha256 of the master, set once
  status          public.capture_status not null default 'announced',
  created_at      timestamptz not null default now()
);

-- A device cannot replay or overwrite its own sequence numbers.
create unique index on public.captures (device_id, device_sequence);
create index on public.captures (event_id, captured_at desc);

create type public.asset_kind as enum ('master','preview','deliverable');

create table public.assets (
  id          uuid primary key default gen_random_uuid(),
  capture_id  uuid not null references public.captures(id) on delete cascade,
  kind        public.asset_kind not null,
  -- The SERVER owns this path. The Bridge and the browser never supply it.
  bucket      text not null,
  object_path text not null,
  byte_size   bigint,
  checksum    bytea,
  version     integer not null default 1,
  created_at  timestamptz not null default now()
);

create unique index on public.assets (bucket, object_path);
create unique index on public.assets (capture_id, kind, version);

-- Masters are write-once. A compromised Bridge must not be able to swap the
-- file behind an existing capture id.
create or replace function app.guard_master_immutability()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if old.kind = 'master' then
    if new.bucket is distinct from old.bucket
       or new.object_path is distinct from old.object_path
       or (old.checksum is not null and new.checksum is distinct from old.checksum) then
      raise exception 'master asset % is immutable', old.id
        using errcode = 'integrity_constraint_violation';
    end if;
  end if;
  return new;
end;
$$;

create trigger assets_master_immutable
  before update on public.assets
  for each row execute function app.guard_master_immutability();

-- Once a capture's content hash is established it cannot be rewritten.
create or replace function app.guard_capture_hash()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if old.content_hash is not null and new.content_hash is distinct from old.content_hash then
    raise exception 'capture % content_hash is immutable', old.id
      using errcode = 'integrity_constraint_violation';
  end if;
  return new;
end;
$$;

create trigger captures_hash_immutable
  before update on public.captures
  for each row execute function app.guard_capture_hash();

-- =============================================================================
-- 5. Customer sessions
-- =============================================================================
-- Anonymous by default. A *verified contact* is what survives a lost cookie —
-- see docs/security/authorization-model.md on why the cookie alone cannot be
-- the entitlement anchor.

create table public.customer_sessions (
  id                uuid primary key default gen_random_uuid(),
  event_id          uuid not null references public.events(id) on delete cascade,
  token_hash        bytea not null,            -- sha256(raw token); raw never stored
  verified_email    citext,
  verified_phone    text,
  contact_verified_at timestamptz,
  created_at        timestamptz not null default now(),
  last_seen_at      timestamptz,
  expires_at        timestamptz not null,
  revoked_at        timestamptz
);

create unique index on public.customer_sessions (token_hash);
create index on public.customer_sessions (event_id);
create index on public.customer_sessions (verified_email) where verified_email is not null;

-- =============================================================================
-- 6. Commerce
-- =============================================================================

create type public.order_status as enum
  ('draft','awaiting_payment','paid','partially_refunded','refunded','cancelled','expired');

create table public.orders (
  id                  uuid primary key default gen_random_uuid(),
  event_id            uuid not null references public.events(id),
  organization_id     uuid not null references public.organizations(id),
  customer_session_id uuid not null references public.customer_sessions(id),
  status              public.order_status not null default 'draft',
  -- Minor units only. Never a float, never a client-supplied value.
  amount_minor        bigint not null default 0 check (amount_minor >= 0),
  currency            char(3) not null default 'PHP',
  created_at          timestamptz not null default now(),
  paid_at             timestamptz
);

create index on public.orders (customer_session_id);
create index on public.orders (organization_id, created_at desc);

create table public.order_items (
  id               uuid primary key default gen_random_uuid(),
  order_id         uuid not null references public.orders(id) on delete cascade,
  capture_id       uuid not null references public.captures(id),
  -- Written by the pricing service from the event's price list. The browser
  -- sends a capture id and nothing else.
  unit_price_minor bigint not null check (unit_price_minor >= 0),
  quantity         integer not null default 1 check (quantity > 0),
  created_at       timestamptz not null default now()
);

create unique index on public.order_items (order_id, capture_id);
create index on public.order_items (capture_id);

-- The order total is DERIVED. Any write that disagrees with the line items is
-- overwritten, so a tampered total is structurally impossible rather than
-- merely validated against.
create or replace function app.recompute_order_total()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_order uuid := coalesce(new.order_id, old.order_id);
begin
  update public.orders o
     set amount_minor = coalesce((
           select sum(i.unit_price_minor * i.quantity)
           from public.order_items i
           where i.order_id = v_order
         ), 0)
   where o.id = v_order;
  return coalesce(new, old);
end;
$$;

create trigger order_items_recompute_total
  after insert or update or delete on public.order_items
  for each row execute function app.recompute_order_total();

-- Line items are frozen at payment, and a line item may only reference a capture
-- from the order's own event. Without that second check a customer shopping in
-- event A can have an item pointing at event B's capture, pay for it, and
-- receive another organization's HD file — tenant breakout through commerce.
create or replace function app.guard_order_item_integrity()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_status       public.order_status;
  v_order_event  uuid;
  v_capture_event uuid;
begin
  select o.status, o.event_id into v_status, v_order_event
  from public.orders o
  where o.id = coalesce(new.order_id, old.order_id);

  if v_status is distinct from 'draft' and v_status is distinct from 'awaiting_payment' then
    raise exception 'order items are frozen once the order leaves the pre-payment states (status=%)', v_status
      using errcode = 'integrity_constraint_violation';
  end if;

  if new.capture_id is not null then
    select c.event_id into v_capture_event
    from public.captures c where c.id = new.capture_id;

    if v_capture_event is distinct from v_order_event then
      raise exception 'capture % belongs to event %, not to this order''s event %',
        new.capture_id, v_capture_event, v_order_event
        using errcode = 'integrity_constraint_violation';
    end if;
  end if;

  return coalesce(new, old);
end;
$$;

create trigger order_items_integrity_guard
  before insert or update or delete on public.order_items
  for each row execute function app.guard_order_item_integrity();

-- -----------------------------------------------------------------------------
-- An order's organization must be the event's organization, and its customer
-- session must belong to that same event. Otherwise revenue can be booked to
-- the wrong tenant — and then shown to the wrong photographer by RLS.
-- -----------------------------------------------------------------------------

create or replace function app.guard_order_tenancy()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_event_org     uuid;
  v_session_event uuid;
begin
  select e.organization_id into v_event_org
  from public.events e where e.id = new.event_id;

  if new.organization_id is distinct from v_event_org then
    raise exception 'order organization % does not own event % (owned by %)',
      new.organization_id, new.event_id, v_event_org
      using errcode = 'integrity_constraint_violation';
  end if;

  select cs.event_id into v_session_event
  from public.customer_sessions cs where cs.id = new.customer_session_id;

  if v_session_event is distinct from new.event_id then
    raise exception 'customer session belongs to event %, not %', v_session_event, new.event_id
      using errcode = 'integrity_constraint_violation';
  end if;

  return new;
end;
$$;

-- -----------------------------------------------------------------------------
-- The order total is DERIVED on every write, not merely recomputed when a line
-- item happens to be touched. A handler that writes a client-supplied amount
-- straight onto the order has that value overwritten before the payment guard
-- ever compares it, so "pay ₱1 for a ₱150 photo" has no window to live in.
--
-- If an order-level discount is ever added, it belongs INSIDE this derivation.
-- Never as a writable column the client can influence.
-- -----------------------------------------------------------------------------

create or replace function app.guard_order_amount()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  new.amount_minor := coalesce((
    select sum(i.unit_price_minor * i.quantity)
    from public.order_items i
    where i.order_id = new.id
  ), 0);
  return new;
end;
$$;

-- -----------------------------------------------------------------------------
-- Order state machine. There is no path to 'paid' except through a verified
-- provider event (enforced below), and no arbitrary UPDATE status = 'paid'.
-- -----------------------------------------------------------------------------

create or replace function app.guard_order_transition()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  ok boolean;
begin
  if new.status = old.status then
    return new;
  end if;

  ok := case old.status
    when 'draft'              then new.status in ('awaiting_payment','cancelled','expired')
    when 'awaiting_payment'   then new.status in ('paid','cancelled','expired')
    when 'paid'               then new.status in ('partially_refunded','refunded')
    when 'partially_refunded' then new.status in ('refunded')
    else false
  end;

  if not ok then
    raise exception 'illegal order transition % -> %', old.status, new.status
      using errcode = 'integrity_constraint_violation';
  end if;

  if new.status = 'paid' then
    if not exists (
      select 1 from public.payment_events pe
      where pe.order_id = new.id
        and pe.signature_verified
        and pe.amount_minor = new.amount_minor
        and pe.currency = new.currency
        and pe.kind = 'paid'
    ) then
      raise exception 'order % cannot be marked paid without a verified, amount-matched provider event', new.id
        using errcode = 'integrity_constraint_violation';
    end if;
    new.paid_at := coalesce(new.paid_at, now());
  end if;

  return new;
end;
$$;

-- =============================================================================
-- 7. Payment ledger
-- =============================================================================
-- One verified provider event => exactly one effect. Replay is defeated by the
-- unique constraint, not by application memory.

create table public.payment_events (
  id                  uuid primary key default gen_random_uuid(),
  provider            text not null default 'paymongo',
  provider_event_id   text not null,
  kind                text not null,            -- 'paid' | 'refunded' | 'failed' | ...
  order_id            uuid references public.orders(id),
  amount_minor        bigint,
  currency            char(3),
  signature_verified  boolean not null default false,
  provider_timestamp  timestamptz,
  received_at         timestamptz not null default now(),
  consumed_at         timestamptz,
  raw_payload         jsonb not null
);

-- Replay protection lives in the schema.
create unique index on public.payment_events (provider, provider_event_id);
create index on public.payment_events (order_id);

-- An unverified webhook must never be able to move money-adjacent state.
alter table public.payment_events
  add constraint payment_events_verified_before_binding
  check (order_id is null or signature_verified);

-- Postgres fires BEFORE row triggers in name order, so the numbering is load
-- bearing: tenancy, then the derived amount, then the state machine that
-- compares the verified provider amount against it.
create trigger orders_01_tenancy_guard
  before insert or update on public.orders
  for each row execute function app.guard_order_tenancy();

create trigger orders_02_amount_guard
  before insert or update on public.orders
  for each row execute function app.guard_order_amount();

create trigger orders_03_transition_guard
  before update on public.orders
  for each row execute function app.guard_order_transition();

-- =============================================================================
-- 8. Entitlements
-- =============================================================================
-- The single most important table in the system: it separates "was paid for"
-- from "is permitted to receive". Refunds, comps, packages, support replacements
-- and chargebacks all become entitlement operations rather than payment lies.

create type public.entitlement_status as enum ('inactive','active','revoked');

create table public.entitlements (
  id                  uuid primary key default gen_random_uuid(),
  order_item_id       uuid not null references public.order_items(id) on delete cascade,
  capture_id          uuid not null references public.captures(id),
  customer_session_id uuid not null references public.customer_sessions(id),
  status              public.entitlement_status not null default 'inactive',
  source              text not null default 'purchase'
                        check (source in ('purchase','complimentary','support_replacement','package')),
  granted_at          timestamptz,
  revoked_at          timestamptz,
  revoked_reason      text,
  download_count      integer not null default 0,
  created_at          timestamptz not null default now()
);

create unique index on public.entitlements (order_item_id);
create index on public.entitlements (customer_session_id, status);
create index on public.entitlements (capture_id);

-- An entitlement may only become active behind a paid order, and its capture
-- must be the capture actually on the line item. This closes the "buy one,
-- download all" attack at the storage layer rather than the endpoint layer.
create or replace function app.guard_entitlement_activation()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_order_status public.order_status;
  v_item_capture uuid;
  v_item_session uuid;
begin
  select o.status, i.capture_id, o.customer_session_id
    into v_order_status, v_item_capture, v_item_session
  from public.order_items i
  join public.orders o on o.id = i.order_id
  where i.id = new.order_item_id;

  if new.capture_id is distinct from v_item_capture then
    raise exception 'entitlement capture % does not match order item capture %',
      new.capture_id, v_item_capture
      using errcode = 'integrity_constraint_violation';
  end if;

  if new.customer_session_id is distinct from v_item_session then
    raise exception 'entitlement session does not match the ordering session'
      using errcode = 'integrity_constraint_violation';
  end if;

  if new.status = 'active' then
    if new.source = 'purchase' and v_order_status <> 'paid' then
      raise exception 'cannot activate a purchase entitlement on a % order', v_order_status
        using errcode = 'integrity_constraint_violation';
    end if;
    new.granted_at := coalesce(new.granted_at, now());
  end if;

  if new.status = 'revoked' then
    new.revoked_at := coalesce(new.revoked_at, now());
  end if;

  return new;
end;
$$;

create trigger entitlements_activation_guard
  before insert or update on public.entitlements
  for each row execute function app.guard_entitlement_activation();

-- =============================================================================
-- 9. Fulfillment
-- =============================================================================
-- Only the payment reconciliation service writes here. Workers still distrust
-- the queue and re-derive authority from this table.

create type public.fulfillment_status as enum
  ('waiting_for_master','queued','processing','ready','failed');

create table public.fulfillment_requests (
  id                 uuid primary key default gen_random_uuid(),
  order_item_id      uuid not null references public.order_items(id) on delete cascade,
  entitlement_id     uuid not null references public.entitlements(id) on delete cascade,
  processing_version integer not null default 1,
  status             public.fulfillment_status not null default 'waiting_for_master',
  attempts           integer not null default 0,
  last_error         text,
  created_at         timestamptz not null default now(),
  completed_at       timestamptz
);

-- At-least-once queues deliver the same job repeatedly. This collapses them
-- into one billable unit of work.
create unique index on public.fulfillment_requests (order_item_id, processing_version);
create index on public.fulfillment_requests (status) where status <> 'ready';

-- =============================================================================
-- 10. Download grants
-- =============================================================================
-- A recovery link is a bearer capability. Store only its hash, exactly as a
-- password reset token.

create table public.download_grants (
  id             uuid primary key default gen_random_uuid(),
  entitlement_id uuid not null references public.entitlements(id) on delete cascade,
  token_hash     bytea not null,
  issued_to      text,                          -- email/phone the link was sent to
  expires_at     timestamptz not null,
  max_uses       integer not null default 10 check (max_uses > 0),
  use_count      integer not null default 0,
  consumed_at    timestamptz,
  created_at     timestamptz not null default now()
);

create unique index on public.download_grants (token_hash);
create index on public.download_grants (entitlement_id);

-- =============================================================================
-- 11. The authorization chokepoint
-- =============================================================================
-- Every HD download in the system resolves through this one function. No
-- endpoint gets to reimplement the chain, so no endpoint gets to get it wrong.
--
--   session -> order -> order_item -> entitlement -> capture -> deliverable
--
-- Note what is NOT a parameter: any storage path, bucket, or asset id. The
-- caller asks for a capture; the database decides which bytes, if any.

create or replace function app.authorize_download(
  p_customer_session uuid,
  p_capture          uuid
)
returns table (asset_id uuid, bucket text, object_path text, entitlement_id uuid)
language sql stable security definer set search_path = '' as $$
  select a.id, a.bucket, a.object_path, e.id
  from public.entitlements e
  join public.order_items  i on i.id = e.order_item_id
  join public.orders       o on o.id = i.order_id
  join public.customer_sessions cs on cs.id = o.customer_session_id
  join public.fulfillment_requests f on f.entitlement_id = e.id
  join public.captures cap on cap.id = e.capture_id
  join public.assets a on a.capture_id = e.capture_id and a.kind = 'deliverable'
  where cs.id     = p_customer_session
    and cs.revoked_at is null
    and cs.expires_at > now()
    and o.customer_session_id = p_customer_session
    and o.status  = 'paid'
    and e.status  = 'active'
    and e.capture_id = i.capture_id     -- belt and braces; also trigger-enforced
    and e.capture_id = p_capture
    and cap.event_id = o.event_id       -- the capture is in the event that was shopped
    and cs.event_id  = o.event_id
    and f.status  = 'ready'
  order by a.version desc
  limit 1;
$$;

-- =============================================================================
-- 12. Audit log
-- =============================================================================
-- Append-only. Records who did what to which resource and how it ended.
-- Deliberately has no column that could hold a secret, a token, or a signed URL.

create table public.audit_log (
  id              bigserial primary key,
  occurred_at     timestamptz not null default now(),
  actor_kind      text not null check (actor_kind in ('user','device','customer','service','anonymous')),
  actor_id        uuid,
  organization_id uuid,
  event_id        uuid,
  operation       text not null,
  target_kind     text,
  target_id       uuid,
  result          text not null check (result in ('allow','deny','error')),
  request_id      uuid,
  ip_prefix       inet,                          -- truncated, not the full address
  detail          jsonb not null default '{}'::jsonb
);

create index on public.audit_log (organization_id, occurred_at desc);
create index on public.audit_log (result, occurred_at desc) where result = 'deny';

create or replace function app.audit_log_is_append_only()
returns trigger language plpgsql as $$
begin
  raise exception 'audit_log is append-only' using errcode = 'insufficient_privilege';
end;
$$;

create trigger audit_log_no_mutation
  before update or delete on public.audit_log
  for each row execute function app.audit_log_is_append_only();
