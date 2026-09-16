-- =============================================================================
-- Fotolab :: 0002 :: Row Level Security
-- =============================================================================
-- Supabase's Data API reaches Postgres as `anon` or `authenticated`. RLS is the
-- layer that must reject a tenant breakout even when the application layer has a
-- bug, so it is written to stand alone: assume every API handler above it is
-- wrong and the attacker is submitting somebody else's object ids.
--
-- Posture per table:
--   ORG-SCOPED  photographers read/write their own organization's rows.
--   SEALED      no anon/authenticated access at all. Server-side only
--               (service_role), because the customer trust domain never touches
--               the Data API. RLS here is a tripwire, not a filter.
--
-- service_role bypasses RLS entirely. That key must exist only in server
-- processes — never in a browser bundle, never in the Capture Bridge.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Enable RLS everywhere. A table added later without RLS is a launch blocker;
-- tests/security/authorization_tests.sql fails the build if one appears.
-- -----------------------------------------------------------------------------

alter table public.organizations        enable row level security;
alter table public.organization_members enable row level security;
alter table public.events               enable row level security;
alter table public.devices              enable row level security;
alter table public.device_sessions      enable row level security;
alter table public.captures             enable row level security;
alter table public.assets               enable row level security;
alter table public.customer_sessions    enable row level security;
alter table public.orders               enable row level security;
alter table public.order_items          enable row level security;
alter table public.payment_events       enable row level security;
alter table public.entitlements         enable row level security;
alter table public.fulfillment_requests enable row level security;
alter table public.download_grants      enable row level security;
alter table public.audit_log            enable row level security;

-- Force RLS so even a table owner connecting outside service_role is filtered.
alter table public.orders        force row level security;
alter table public.order_items   force row level security;
alter table public.entitlements  force row level security;
alter table public.payment_events force row level security;

-- =============================================================================
-- ORG-SCOPED: the photographer trust domain
-- =============================================================================

create policy org_read on public.organizations
  for select to authenticated
  using (app.is_org_member(id));

create policy org_update on public.organizations
  for update to authenticated
  using (app.has_org_role(id, array['owner','admin']::public.org_role[]))
  with check (app.has_org_role(id, array['owner','admin']::public.org_role[]));

-- Members may see their own organization's roster; only owners/admins mutate it.
create policy members_read on public.organization_members
  for select to authenticated
  using (app.is_org_member(organization_id));

create policy members_write on public.organization_members
  for all to authenticated
  using (app.has_org_role(organization_id, array['owner','admin']::public.org_role[]))
  with check (app.has_org_role(organization_id, array['owner','admin']::public.org_role[]));

-- Events. Substituting another organization's event id returns zero rows here,
-- regardless of what the API handler believed.
create policy events_read on public.events
  for select to authenticated
  using (app.is_org_member(organization_id));

create policy events_write on public.events
  for all to authenticated
  using (app.has_org_role(organization_id, array['owner','admin','photographer']::public.org_role[]))
  with check (app.has_org_role(organization_id, array['owner','admin','photographer']::public.org_role[]));

-- Device enrollment and revocation are privileged operations.
create policy devices_read on public.devices
  for select to authenticated
  using (app.is_org_member(organization_id));

create policy devices_write on public.devices
  for all to authenticated
  using (app.has_org_role(organization_id, array['owner','admin']::public.org_role[]))
  with check (app.has_org_role(organization_id, array['owner','admin']::public.org_role[]));

create policy device_sessions_read on public.device_sessions
  for select to authenticated
  using (exists (
    select 1 from public.devices d
    where d.id = device_sessions.device_id
      and app.is_org_member(d.organization_id)
  ));

-- Captures and assets are reachable only through an event the caller's
-- organization owns. The join is the authorization.
create policy captures_read on public.captures
  for select to authenticated
  using (exists (
    select 1 from public.events e
    where e.id = captures.event_id
      and app.is_org_member(e.organization_id)
  ));

create policy assets_read on public.assets
  for select to authenticated
  using (exists (
    select 1
    from public.captures c
    join public.events e on e.id = c.event_id
    where c.id = assets.capture_id
      and app.is_org_member(e.organization_id)
  ));

-- Photographers see their own revenue, and only their own.
create policy orders_read_own_org on public.orders
  for select to authenticated
  using (app.is_org_member(organization_id));

create policy order_items_read_own_org on public.order_items
  for select to authenticated
  using (exists (
    select 1 from public.orders o
    where o.id = order_items.order_id
      and app.is_org_member(o.organization_id)
  ));

create policy audit_read_own_org on public.audit_log
  for select to authenticated
  using (organization_id is not null and app.is_org_member(organization_id));

-- =============================================================================
-- SEALED: no Data API access, at any privilege below service_role
-- =============================================================================
-- These carry customer identity, payment truth, and download authority. There is
-- no policy granting anon or authenticated a row, and the grants are revoked so
-- a future permissive policy still cannot open them by accident.

revoke all on public.customer_sessions    from anon, authenticated;
revoke all on public.payment_events       from anon, authenticated;
revoke all on public.entitlements         from anon, authenticated;
revoke all on public.fulfillment_requests from anon, authenticated;
revoke all on public.download_grants      from anon, authenticated;

-- Photographers read commerce through the org policies above (SELECT only);
-- every write to orders/order_items belongs to the server.
revoke insert, update, delete on public.orders      from anon, authenticated;
revoke insert, update, delete on public.order_items from anon, authenticated;
revoke all on public.audit_log from anon;
revoke insert, update, delete on public.audit_log from authenticated;

-- The authorization chokepoint is server-side only. Exposing it to the Data API
-- would let a caller probe entitlements by capture id.
revoke all on function app.authorize_download(uuid, uuid) from anon, authenticated;
revoke all on function app.device_session_is_live(uuid)   from anon, authenticated;

-- =============================================================================
-- Anonymous surface
-- =============================================================================
-- `anon` gets nothing through the Data API. The public gallery is served by an
-- edge function that reads previews with a server credential and applies event
-- access policy and rate limits before returning anything. This is deliberate:
-- an anon-readable previews policy is one `select *` away from leaking capture
-- ids, device ids, and event structure to a scraper.

revoke all on all tables in schema public from anon;
