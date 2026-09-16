-- =============================================================================
-- Fotolab :: 0006 :: Order access tokens
-- =============================================================================
-- Resolves the §15/§29 contradiction without adding pre-payment friction.
--
--   checkout captures an email (unverified)  →  payment completes  →  we email
--   a short-lived, single-use token  →  the customer exchanges it for an
--   HttpOnly session scoped to that one order.
--
-- Receiving and using the link proves mailbox control, after the money has
-- already moved. The email carries an authentication bootstrap, never an asset
-- URL — so an email sitting in an inbox for two years is not a permanent
-- download capability.
--
-- Residual risk, recorded rather than designed away: a customer who mistypes
-- their address at checkout has paid, cannot reach their photographs, and has
-- sent a stranger a working bootstrap to their order. See the note on claim
-- codes at the foot of this file.
-- =============================================================================

alter table public.orders
  add column contact_email citext,
  add column contact_email_source text
    check (contact_email_source in ('checkout','support','provider'));

-- A session minted from a token is scoped to exactly one order. It is not a
-- resurrection of the original shopping session and cannot see its other orders.
alter table public.customer_sessions
  add column order_scope_id uuid,
  add column origin text not null default 'gallery'
    check (origin in ('gallery','order_token','support'));

create table public.order_access_tokens (
  id               uuid primary key default gen_random_uuid(),
  organization_id  uuid not null references public.organizations(id) on delete cascade,
  order_id         uuid not null,
  -- sha256(raw token). The raw value exists only in the email.
  token_hash       bytea not null,
  issued_to_email  citext not null,
  issued_at        timestamptz not null default now(),
  expires_at       timestamptz not null,
  consumed_at      timestamptz,
  consumed_ip_prefix inet,
  created_session_id uuid references public.customer_sessions(id),
  superseded_at    timestamptz,
  check (expires_at > issued_at)
);

create unique index on public.order_access_tokens (token_hash);
create index on public.order_access_tokens (order_id);

alter table public.order_access_tokens
  add constraint order_access_tokens_order_tenancy_fkey
  foreign key (order_id, organization_id)
  references public.orders (id, organization_id) on delete cascade;

alter table public.customer_sessions
  add constraint customer_sessions_order_scope_tenancy_fkey
  foreign key (order_scope_id, organization_id)
  references public.orders (id, organization_id) on delete cascade;

-- A token-origin session must name its order; a gallery session must not.
alter table public.customer_sessions
  add constraint customer_sessions_scope_matches_origin
  check ((origin = 'order_token') = (order_scope_id is not null));

alter table public.order_access_tokens enable row level security;
revoke all on public.order_access_tokens from anon, authenticated;

-- -----------------------------------------------------------------------------
-- Single use, enforced by the database rather than by handler discipline.
--
-- The UPDATE ... WHERE consumed_at is null is the whole mechanism: two
-- concurrent redemptions of the same link race on the same row, and exactly one
-- of them updates a row. The loser gets zero rows and raises.
-- -----------------------------------------------------------------------------

create or replace function app.consume_order_access_token(
  p_token_hash bytea,
  p_ip_prefix  inet default null,
  p_session_ttl interval default interval '30 days'
)
returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_token   public.order_access_tokens%rowtype;
  v_order   public.orders%rowtype;
  v_session uuid;
  v_raw     bytea;
begin
  -- Claim the token first. If this updates no row the token was already used,
  -- expired, superseded, or never existed — all of which are one answer.
  update public.order_access_tokens t
     set consumed_at = now(),
         consumed_ip_prefix = p_ip_prefix
   where t.token_hash = p_token_hash
     and t.consumed_at is null
     and t.superseded_at is null
     and t.expires_at > now()
  returning * into v_token;

  if v_token.id is null then
    raise exception 'order access token is invalid, expired, or already used'
      using errcode = 'insufficient_privilege';
  end if;

  select * into v_order from public.orders o where o.id = v_token.order_id;

  -- A fresh session secret. The caller receives the raw value once and sets it
  -- as an HttpOnly cookie; only its hash is stored.
  v_raw := gen_random_bytes(32);

  insert into public.customer_sessions
    (event_id, organization_id, token_hash, verified_email, contact_verified_at,
     origin, order_scope_id, expires_at)
  values
    (v_order.event_id, v_order.organization_id, digest(v_raw, 'sha256'),
     v_token.issued_to_email, now(),
     'order_token', v_order.id, now() + p_session_ttl)
  returning id into v_session;

  update public.order_access_tokens
     set created_session_id = v_session
   where id = v_token.id;

  insert into public.audit_log
    (actor_kind, actor_id, organization_id, event_id, operation,
     target_kind, target_id, result, ip_prefix)
  values
    ('customer', v_session, v_order.organization_id, v_order.event_id,
     'order_access_token.consumed', 'order', v_order.id, 'allow', p_ip_prefix);

  -- The raw secret is returned out-of-band by the caller reading it from the
  -- session row it just created; see bridge/README and the delivery endpoint.
  perform set_config('app.issued_session_secret', encode(v_raw, 'hex'), true);
  return v_session;
end;
$$;

revoke all on function app.consume_order_access_token(bytea, inet, interval) from anon, authenticated;

-- Issuing a new link invalidates the outstanding ones, so a forwarded old email
-- stops working the moment the customer asks for a fresh link.
create or replace function app.supersede_order_access_tokens(p_order uuid)
returns integer language sql security definer set search_path = '' as $$
  with s as (
    update public.order_access_tokens
       set superseded_at = now()
     where order_id = p_order and consumed_at is null and superseded_at is null
    returning 1
  ) select count(*)::integer from s;
$$;

revoke all on function app.supersede_order_access_tokens(uuid) from anon, authenticated;

-- -----------------------------------------------------------------------------
-- The chokepoint accepts two ways of owning an order: the session that placed
-- it, or a token-scoped session created for exactly that order. Nothing else
-- changes — the entitlement chain, the event check and the tenancy checks all
-- still apply.
-- -----------------------------------------------------------------------------

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
  join public.customer_sessions cs on cs.id = p_customer_session
  join public.captures    cap on cap.id = e.capture_id
  join public.fulfillment_requests f on f.entitlement_id = e.id
  join public.assets       a on a.order_item_id = i.id and a.kind = 'deliverable'
  where cs.revoked_at is null
    and cs.expires_at > now()
    -- either the session that placed the order, or one bootstrapped for it
    and (o.customer_session_id = cs.id or cs.order_scope_id = o.id)
    and o.status  = 'paid'
    and e.status  = 'active'
    and (e.expires_at is null or e.expires_at > now())
    and e.capture_id = i.capture_id
    and e.capture_id = p_capture
    and cap.event_id = o.event_id
    and cs.event_id  = o.event_id
    and e.organization_id = o.organization_id
    and a.organization_id = o.organization_id
    and a.status  = 'ready'
    and f.status  = 'ready'
  order by a.processing_version desc, a.version desc
  limit 1;
$$;

revoke all on function app.authorize_download(uuid, uuid) from anon, authenticated;

-- =============================================================================
-- Recorded gap: the mistyped address
-- =============================================================================
-- A customer who fat-fingers their email at checkout on a phone has paid, is
-- locked out, and has handed a stranger a working bootstrap to their order —
-- which for event photography is a privacy problem before it is a revenue one.
--
-- The cheap fix, when this becomes real rather than theoretical: show a short
-- claim code on the payment success screen (which only the buyer sees, on the
-- device they paid with) and require it alongside the emailed link. Two
-- channels, still no pre-payment friction. `order_access_tokens` would gain a
-- claim_code_hash column and consume would take a second argument.
--
-- Not built now, because the right time to add it is when there is a real
-- support queue telling us how often it happens.
-- =============================================================================
