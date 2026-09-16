-- =============================================================================
-- Fotolab :: 0004 :: Hardened Architecture v2 reconciliation
-- =============================================================================
-- Implements the v2 deltas that carry security weight. Three of them are
-- genuinely stronger than 0001 and are called out where they appear:
--
--   * livemode on payment events  — a test-mode webhook must not grant a live
--     entitlement. 0001 had no notion of mode at all.
--   * order-scoped deliverables   — v2 §9/§26 put the deliverable under
--     (order, order_item) rather than under the capture. That is correct:
--     it makes processing_version reproducible per customer.
--   * asset status                — 0001 treated "an asset row exists" as
--     "these bytes are servable". v2 §7 does not.
--
-- What v2 asks for that is NOT implemented here, and why, is recorded at the
-- bottom of this file rather than left silently missing.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Roles: v2 §3 adds EVENT_MANAGER and FINANCE.
-- FINANCE is the one that earns its keep — it lets a bookkeeper read revenue
-- without reading a single photograph, and a photographer shoot without reading
-- a single peso. Least privilege between two people who both work here.
-- -----------------------------------------------------------------------------

-- Policies that reference has_org_role must be dropped before the enum it
-- takes can be swapped. They are recreated below, unchanged.
drop policy org_update      on public.organizations;
drop policy members_write   on public.organization_members;
drop policy events_write    on public.events;
drop policy devices_write   on public.devices;

drop function if exists app.has_org_role(uuid, public.org_role[]);

alter type public.org_role rename to org_role_v1;
create type public.org_role as enum
  ('owner','admin','event_manager','photographer','finance','viewer');

alter table public.organization_members
  alter column role type public.org_role using role::text::public.org_role;

drop type public.org_role_v1;

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

revoke all on function app.has_org_role(uuid, public.org_role[]) from anon, authenticated;

create policy org_update on public.organizations
  for update to authenticated
  using (app.has_org_role(id, array['owner','admin']::public.org_role[]))
  with check (app.has_org_role(id, array['owner','admin']::public.org_role[]));

create policy members_write on public.organization_members
  for all to authenticated
  using (app.has_org_role(organization_id, array['owner','admin']::public.org_role[]))
  with check (app.has_org_role(organization_id, array['owner','admin']::public.org_role[]));

create policy events_write on public.events
  for all to authenticated
  using (app.has_org_role(organization_id, array['owner','admin','event_manager','photographer']::public.org_role[]))
  with check (app.has_org_role(organization_id, array['owner','admin','event_manager','photographer']::public.org_role[]));

create policy devices_write on public.devices
  for all to authenticated
  using (app.has_org_role(organization_id, array['owner','admin']::public.org_role[]))
  with check (app.has_org_role(organization_id, array['owner','admin']::public.org_role[]));

-- -----------------------------------------------------------------------------
-- Lifecycle states: v2 §4.
-- COMPROMISED is deliberately distinct from REVOKED. "We retired this laptop"
-- and "this laptop is in someone else's hands" demand different incident
-- response, and collapsing them loses that signal exactly when it matters.
-- -----------------------------------------------------------------------------

create type public.device_status as enum ('pending','active','revoked','compromised');

alter table public.devices
  add column status public.device_status not null default 'active';

update public.devices set status = 'revoked' where revoked_at is not null;

create type public.event_status as enum ('draft','live','paused','ended','archived');

alter table public.events
  add column status public.event_status not null default 'draft';

update public.events set status = 'archived' where archived_at is not null;

-- A device session is live only while the device itself is. Revocation and
-- compromise both bite immediately rather than at token expiry.
create or replace function app.device_session_is_live(p_session uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1
    from public.device_sessions s
    join public.devices d on d.id = s.device_id
    join public.events  e on e.id = s.event_id
    where s.id = p_session
      and s.revoked_at is null
      and s.expires_at > now()
      and d.revoked_at is null
      and d.status = 'active'
      and e.status in ('live','paused')
  );
$$;

revoke all on function app.device_session_is_live(uuid) from anon, authenticated;

-- =============================================================================
-- Denormalized organization_id — v2 §2
-- =============================================================================
-- v2 asks every tenant-owned row to carry organization_id even where it is
-- derivable. That is right for RLS directness and for audit, but it introduces
-- a failure mode the v2 document does not mention: a row whose denormalized
-- organization_id disagrees with its parent's. That row is now a tenant
-- boundary violation that every join-free policy will happily honour.
--
-- So the column is never merely added. It is auto-filled from the parent when
-- omitted, and rejected when supplied and wrong.
-- =============================================================================

create or replace function app.guard_denormalized_org()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_fk         uuid;
  v_parent_org uuid;
begin
  -- TG_ARGV: [0] local fk column, [1] parent table, [2] parent's org column
  execute format('select ($1).%I', TG_ARGV[0]) into v_fk using new;

  if v_fk is null then
    raise exception '%.% is required to establish tenancy', TG_TABLE_NAME, TG_ARGV[0]
      using errcode = 'integrity_constraint_violation';
  end if;

  execute format('select %I from public.%I where id = $1', TG_ARGV[2], TG_ARGV[1])
    into v_parent_org using v_fk;

  if new.organization_id is null then
    new.organization_id := v_parent_org;          -- omitted: derive it
  elsif new.organization_id is distinct from v_parent_org then
    raise exception
      '%.organization_id (%) disagrees with %.% (%) — denormalized tenancy must match its parent',
      TG_TABLE_NAME, new.organization_id, TG_ARGV[1], TG_ARGV[2], v_parent_org
      using errcode = 'integrity_constraint_violation';
  end if;

  return new;
end;
$$;

alter table public.captures            add column organization_id uuid references public.organizations(id);
alter table public.assets              add column organization_id uuid references public.organizations(id);
alter table public.customer_sessions   add column organization_id uuid references public.organizations(id);
alter table public.order_items         add column organization_id uuid references public.organizations(id);
alter table public.entitlements        add column organization_id uuid references public.organizations(id);
alter table public.fulfillment_requests add column organization_id uuid references public.organizations(id);
alter table public.download_grants     add column organization_id uuid references public.organizations(id);

create trigger captures_org_guard before insert or update on public.captures
  for each row execute function app.guard_denormalized_org('event_id','events','organization_id');

create trigger assets_org_guard before insert or update on public.assets
  for each row execute function app.guard_denormalized_org('capture_id','captures','organization_id');

create trigger customer_sessions_org_guard before insert or update on public.customer_sessions
  for each row execute function app.guard_denormalized_org('event_id','events','organization_id');

create trigger order_items_org_guard before insert or update on public.order_items
  for each row execute function app.guard_denormalized_org('order_id','orders','organization_id');

create trigger entitlements_org_guard before insert or update on public.entitlements
  for each row execute function app.guard_denormalized_org('order_item_id','order_items','organization_id');

create trigger fulfillment_requests_org_guard before insert or update on public.fulfillment_requests
  for each row execute function app.guard_denormalized_org('entitlement_id','entitlements','organization_id');

create trigger download_grants_org_guard before insert or update on public.download_grants
  for each row execute function app.guard_denormalized_org('entitlement_id','entitlements','organization_id');

create index on public.captures (organization_id);
create index on public.assets (organization_id);
create index on public.order_items (organization_id);
create index on public.entitlements (organization_id);

-- =============================================================================
-- Asset status and order-scoped deliverables — v2 §7, §9, §26
-- =============================================================================

create type public.asset_status as enum
  ('pending','quarantined','verified','ready','rejected','deleted');

alter table public.assets
  add column status public.asset_status not null default 'pending',
  add column order_item_id uuid references public.order_items(id) on delete cascade,
  add column processing_version integer not null default 1;

-- A deliverable belongs to the order item that paid for it, not to the capture.
-- Two customers buying the same photograph get two outputs, and a later style
-- change cannot retroactively alter what an earlier customer received.
alter table public.assets
  add constraint assets_deliverable_is_order_scoped
  check ((kind = 'deliverable') = (order_item_id is not null));

drop index if exists public.assets_capture_id_kind_version_idx;
create unique index assets_capture_kind_version_idx
  on public.assets (capture_id, kind, version) where kind <> 'deliverable';
create unique index assets_deliverable_version_idx
  on public.assets (order_item_id, processing_version, version) where kind = 'deliverable';

-- -----------------------------------------------------------------------------
-- Server-owned storage paths — v2 §9.
-- The path is derived from ids the server already holds, and any other shape is
-- rejected. This is what makes "never let the client supply a path" a property
-- of the database rather than a convention in one handler.
-- -----------------------------------------------------------------------------

create or replace function app.guard_asset_path()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_event   uuid;
  v_order   uuid;
  v_expect  text;
begin
  if new.kind = 'deliverable' then
    select i.order_id into v_order from public.order_items i where i.id = new.order_item_id;
    v_expect := new.organization_id || '/' || v_order || '/' || new.order_item_id || '/';
  else
    select c.event_id into v_event from public.captures c where c.id = new.capture_id;
    v_expect := new.organization_id || '/' || v_event || '/' || new.capture_id || '/';
  end if;

  if position(v_expect in new.object_path) <> 1 then
    raise exception 'asset path % must be server-derived and begin with %',
      new.object_path, v_expect
      using errcode = 'integrity_constraint_violation';
  end if;

  if new.object_path like '%..%' then
    raise exception 'asset path % contains a traversal sequence', new.object_path
      using errcode = 'integrity_constraint_violation';
  end if;

  return new;
end;
$$;

create trigger assets_path_guard
  before insert or update on public.assets
  for each row execute function app.guard_asset_path();

-- =============================================================================
-- Price authority — v2 §16
-- =============================================================================
-- v2 says the browser never decides price. 0001 enforced that, but stopped one
-- level short: it trusted whatever the *server* wrote into unit_price_minor. A
-- buggy or compromised pricing path could still write ₱1.
--
-- With a published price list, neither the browser nor the handler supplies a
-- price. The line item's price is resolved by the database from a published
-- rule, and a caller-supplied value is overwritten.
-- =============================================================================

create table public.price_lists (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  event_id        uuid not null references public.events(id) on delete cascade,
  currency        char(3) not null default 'PHP',
  version         integer not null default 1,
  published_at    timestamptz,
  retired_at      timestamptz,
  created_by      uuid references auth.users(id),
  created_at      timestamptz not null default now()
);

create unique index on public.price_lists (event_id, version);
create unique index price_lists_one_published_per_event
  on public.price_lists (event_id) where published_at is not null and retired_at is null;

create table public.price_items (
  id              uuid primary key default gen_random_uuid(),
  price_list_id   uuid not null references public.price_lists(id) on delete cascade,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  -- null capture_id is the list's default single-photo price.
  capture_id      uuid references public.captures(id) on delete cascade,
  unit_price_minor bigint not null check (unit_price_minor >= 0),
  created_at      timestamptz not null default now()
);

create unique index price_items_default_idx
  on public.price_items (price_list_id) where capture_id is null;
create unique index price_items_override_idx
  on public.price_items (price_list_id, capture_id) where capture_id is not null;

create trigger price_lists_org_guard before insert or update on public.price_lists
  for each row execute function app.guard_denormalized_org('event_id','events','organization_id');

create trigger price_items_org_guard before insert or update on public.price_items
  for each row execute function app.guard_denormalized_org('price_list_id','price_lists','organization_id');

-- A published price list is immutable. Changing prices means publishing a new
-- version, so what a customer was quoted stays reconstructable during a dispute.
create or replace function app.guard_published_price_immutability()
returns trigger language plpgsql security definer set search_path = '' as $$
declare v_published timestamptz;
begin
  if TG_TABLE_NAME = 'price_lists' then
    if old.published_at is not null
       and (new.currency is distinct from old.currency or new.version is distinct from old.version) then
      raise exception 'published price list % is immutable; publish a new version', old.id
        using errcode = 'integrity_constraint_violation';
    end if;
    return new;
  end if;

  select pl.published_at into v_published
  from public.price_lists pl where pl.id = coalesce(new.price_list_id, old.price_list_id);

  if v_published is not null then
    raise exception 'price items of a published list are immutable; publish a new version'
      using errcode = 'integrity_constraint_violation';
  end if;
  return coalesce(new, old);
end;
$$;

create trigger price_lists_immutable before update on public.price_lists
  for each row execute function app.guard_published_price_immutability();

create trigger price_items_immutable before insert or update or delete on public.price_items
  for each row execute function app.guard_published_price_immutability();

-- The resolver. Fails closed: no published list, or no applicable rule, means
-- the photograph cannot be sold rather than sold for nothing.
create or replace function app.resolve_price(p_event uuid, p_capture uuid)
returns bigint language plpgsql stable security definer set search_path = '' as $$
declare
  v_list  uuid;
  v_price bigint;
begin
  select pl.id into v_list
  from public.price_lists pl
  where pl.event_id = p_event
    and pl.published_at is not null
    and pl.retired_at is null;

  if v_list is null then
    raise exception 'event % has no published price list; nothing may be sold', p_event
      using errcode = 'integrity_constraint_violation';
  end if;

  select pi.unit_price_minor into v_price
  from public.price_items pi
  where pi.price_list_id = v_list and pi.capture_id = p_capture;

  if v_price is null then
    select pi.unit_price_minor into v_price
    from public.price_items pi
    where pi.price_list_id = v_list and pi.capture_id is null;
  end if;

  if v_price is null then
    raise exception 'no price rule covers capture % in event %', p_capture, p_event
      using errcode = 'integrity_constraint_violation';
  end if;

  return v_price;
end;
$$;

revoke all on function app.resolve_price(uuid, uuid) from anon, authenticated;

-- Force the line item's price from the published list. Whatever the caller
-- supplied — browser, handler, or a compromised service — is discarded.
alter table public.order_items
  add column price_list_id uuid references public.price_lists(id),
  add column processing_profile_version integer not null default 1;

create or replace function app.guard_order_item_price()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_event uuid;
  v_list  uuid;
begin
  select o.event_id into v_event from public.orders o where o.id = new.order_id;

  select pl.id into v_list
  from public.price_lists pl
  where pl.event_id = v_event and pl.published_at is not null and pl.retired_at is null;

  new.price_list_id    := v_list;
  new.unit_price_minor := app.resolve_price(v_event, new.capture_id);
  return new;
end;
$$;

-- Fires after the integrity guard (name order), so the capture is already known
-- to belong to this order's event before a price is resolved for it.
create trigger order_items_zz_price_guard
  before insert or update on public.order_items
  for each row execute function app.guard_order_item_price();

-- =============================================================================
-- Order totals — v2 §17
-- =============================================================================

alter table public.orders
  add column subtotal_minor bigint not null default 0 check (subtotal_minor >= 0),
  add column discount_minor bigint not null default 0 check (discount_minor >= 0),
  add column discount_reason text;

alter table public.orders
  add constraint orders_discount_within_subtotal check (discount_minor <= subtotal_minor),
  -- A discount with no recorded reason is indistinguishable from revenue loss.
  add constraint orders_discount_needs_reason
    check (discount_minor = 0 or discount_reason is not null);

create or replace function app.guard_order_amount()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  new.subtotal_minor := coalesce((
    select sum(i.unit_price_minor * i.quantity)
    from public.order_items i
    where i.order_id = new.id
  ), 0);

  if new.discount_minor > new.subtotal_minor then
    new.discount_minor := new.subtotal_minor;
  end if;

  new.amount_minor := new.subtotal_minor - new.discount_minor;
  return new;
end;
$$;

-- =============================================================================
-- Payment mode — v2 §19, §39
-- =============================================================================
-- The best addition v2 makes. A test-mode webhook that can mark a live order
-- paid is free photographs for anyone who reads the integration guide, and it
-- leaves a perfectly well-formed, correctly-signed audit trail behind it.

create table public.platform_settings (
  id        boolean primary key default true check (id),
  livemode  boolean not null default false,
  processing_halted boolean not null default false,   -- v2 §33 global kill switch
  halted_reason text,
  updated_at timestamptz not null default now()
);

insert into public.platform_settings (id, livemode) values (true, false)
on conflict (id) do nothing;

revoke all on public.platform_settings from anon, authenticated;

create or replace function app.platform_livemode()
returns boolean language sql stable security definer set search_path = '' as $$
  select livemode from public.platform_settings where id;
$$;

alter table public.payment_events
  add column livemode boolean not null default false,
  add column payload_hash bytea,
  add column failure_reason text;

-- A cross-mode event may not be bound to an order at all.
create or replace function app.guard_payment_event_mode()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.order_id is not null and new.livemode is distinct from app.platform_livemode() then
    raise exception
      'payment event % is livemode=% but this platform is livemode=%; refusing to bind it to an order',
      new.provider_event_id, new.livemode, app.platform_livemode()
      using errcode = 'integrity_constraint_violation';
  end if;
  return new;
end;
$$;

create trigger payment_events_mode_guard
  before insert or update on public.payment_events
  for each row execute function app.guard_payment_event_mode();

-- =============================================================================
-- Order states — v2 §18
-- =============================================================================
-- DISPUTED is the chargeback state raised in the previous threat-model pass.
-- It exists so a dispute is a first-class, queryable condition rather than a
-- refund that silently loses the fact that the customer already has the file.

alter table public.orders alter column status drop default;
alter type public.order_status rename to order_status_v1;
create type public.order_status as enum
  ('draft','awaiting_payment','processing','paid','disputed',
   'partially_refunded','refunded','cancelled','expired','failed');
alter table public.orders
  alter column status type public.order_status using status::text::public.order_status;
alter table public.orders alter column status set default 'draft';
drop type public.order_status_v1;

create or replace function app.guard_order_transition()
returns trigger language plpgsql security definer set search_path = '' as $$
declare ok boolean;
begin
  if new.status = old.status then
    return new;
  end if;

  ok := case old.status
    when 'draft'              then new.status in ('awaiting_payment','cancelled','expired')
    when 'awaiting_payment'   then new.status in ('processing','paid','failed','cancelled','expired')
    when 'processing'         then new.status in ('paid','failed','expired')
    when 'paid'               then new.status in ('disputed','partially_refunded','refunded')
    when 'disputed'           then new.status in ('paid','refunded')   -- won or lost
    when 'partially_refunded' then new.status in ('disputed','refunded')
    else false
  end;

  if not ok then
    raise exception 'illegal order transition % -> %', old.status, new.status
      using errcode = 'integrity_constraint_violation';
  end if;

  if new.status = 'paid' and old.status <> 'disputed' then
    if not exists (
      select 1 from public.payment_events pe
      where pe.order_id = new.id
        and pe.signature_verified
        and pe.livemode = app.platform_livemode()
        and pe.amount_minor = new.amount_minor
        and pe.currency = new.currency
        and pe.kind = 'paid'
    ) then
      raise exception
        'order % cannot be marked paid without a verified, mode-matched, amount-matched provider event', new.id
        using errcode = 'integrity_constraint_violation';
    end if;
    new.paid_at := coalesce(new.paid_at, now());
  end if;

  return new;
end;
$$;

-- =============================================================================
-- Entitlement types and expiry — v2 §22
-- =============================================================================

create type public.entitlement_type as enum
  ('hd_download','package_access','complimentary','replacement');

alter table public.entitlements
  add column type public.entitlement_type not null default 'hd_download',
  add column expires_at timestamptz;

-- `source` in 0001 and `type` in v2 describe the same thing. Keep one.
alter table public.entitlements drop column source;

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
    if new.type = 'hd_download' and v_order_status <> 'paid' then
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

-- =============================================================================
-- The chokepoint, updated — v2 §23, §28
-- =============================================================================
-- v2 §23 states the check as "does this session hold an ACTIVE entitlement for
-- an order item pointing at CAPTURE_X". That is still the v1 chain: it never
-- mentions the event, so it passes for a line item referencing another
-- organization's capture. The event and tenancy clauses below are why it does
-- not pass here.

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
  join public.captures    cap on cap.id = e.capture_id
  join public.fulfillment_requests f on f.entitlement_id = e.id
  join public.assets       a on a.order_item_id = i.id and a.kind = 'deliverable'
  where cs.id     = p_customer_session
    and cs.revoked_at is null
    and cs.expires_at > now()
    and o.customer_session_id = p_customer_session
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
-- RLS for the new tables, and the FINANCE / PHOTOGRAPHER split — v2 §3
-- =============================================================================

alter table public.price_lists       enable row level security;
alter table public.price_items       enable row level security;
alter table public.platform_settings enable row level security;

create policy price_lists_read on public.price_lists
  for select to authenticated using (app.is_org_member(organization_id));

create policy price_items_read on public.price_items
  for select to authenticated using (app.is_org_member(organization_id));

-- Only the roles that own commercial terms may set them.
create policy price_lists_write on public.price_lists
  for all to authenticated
  using (app.has_org_role(organization_id, array['owner','admin','finance']::public.org_role[]))
  with check (app.has_org_role(organization_id, array['owner','admin','finance']::public.org_role[]));

create policy price_items_write on public.price_items
  for all to authenticated
  using (app.has_org_role(organization_id, array['owner','admin','finance']::public.org_role[]))
  with check (app.has_org_role(organization_id, array['owner','admin','finance']::public.org_role[]));

-- A bookkeeper reads revenue and no photographs; a photographer shoots and
-- reads no revenue. Both are org members — membership alone decides nothing.
drop policy orders_read_own_org on public.orders;
create policy orders_read_own_org on public.orders
  for select to authenticated
  using (app.has_org_role(organization_id,
         array['owner','admin','finance','event_manager']::public.org_role[]));

drop policy order_items_read_own_org on public.order_items;
create policy order_items_read_own_org on public.order_items
  for select to authenticated
  using (app.has_org_role(organization_id,
         array['owner','admin','finance','event_manager']::public.org_role[]));

drop policy captures_read on public.captures;
create policy captures_read on public.captures
  for select to authenticated
  using (app.has_org_role(organization_id,
         array['owner','admin','event_manager','photographer','viewer']::public.org_role[]));

drop policy assets_read on public.assets;
create policy assets_read on public.assets
  for select to authenticated
  using (app.has_org_role(organization_id,
         array['owner','admin','event_manager','photographer']::public.org_role[]));

revoke all on public.price_lists, public.price_items from anon;

-- =============================================================================
-- Deliberately NOT implemented from v2, so the gap is recorded rather than
-- assumed closed:
--
--   §16 packages and promotions. Adding a writable discount without a
--       server-side rules table reproduces the price-manipulation hole one
--       level up: a handler that can write discount_minor can write a free
--       order. discount_minor exists, is capped at the subtotal, and requires
--       a reason — but promotions must get the price_lists treatment before
--       any discount feature ships.
--   §6  camera_filename, capture_session_id. Bookkeeping, no security weight.
--       camera_filename must never be an identifier; it is display metadata.
--   §7  THUMBNAIL asset type. Derive from SAFE_PREVIEW when the gallery needs it.
--   §35 correlation_id. audit_log.request_id already serves this; the work is
--       propagating one id across services, which is application-side.
-- =============================================================================
