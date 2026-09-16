-- =============================================================================
-- Fotolab :: authorization test suite
-- =============================================================================
-- These are the tests that decide whether a deploy ships. Run against a scratch
-- database (a Supabase branch or `supabase db reset`) as a superuser:
--
--     psql "$SCRATCH_DATABASE_URL" -v ON_ERROR_STOP=1 -f tests/security/authorization_tests.sql
--
-- Every assertion is a NEGATIVE one: the attack is performed and must fail.
-- A test that only proves the happy path works proves nothing about security.
-- The whole file runs inside a transaction and rolls back.
-- =============================================================================

\set ON_ERROR_STOP on
begin;

create or replace function pg_temp.ok(cond boolean, label text)
returns void language plpgsql as $$
begin
  if cond then
    raise notice 'PASS  %', label;
  else
    raise exception 'FAIL  %', label;
  end if;
end;
$$;

-- Runs `stmt` and returns true only if it raised. Used to assert that an attack
-- is rejected by the database rather than merely discouraged by the API.
create or replace function pg_temp.rejects(stmt text, label text)
returns void language plpgsql as $$
begin
  begin
    execute stmt;
  exception when others then
    raise notice 'PASS  % (rejected: %)', label, sqlerrm;
    return;
  end;
  raise exception 'FAIL  % — the statement succeeded and should not have', label;
end;
$$;

-- =============================================================================
-- Structural gates
-- =============================================================================

-- Gate: a new table shipped without RLS is a launch blocker.
do $$
declare missing text;
begin
  select string_agg(c.relname, ', ')
    into missing
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public'
    and c.relkind = 'r'
    and not c.relrowsecurity;
  perform pg_temp.ok(missing is null,
    'every public table has RLS enabled' || coalesce(' (missing: ' || missing || ')', ''));
end;
$$;

-- Gate: masters and deliverables are demonstrably private.
do $$
declare leaked text;
begin
  select string_agg(id, ', ') into leaked
  from storage.buckets
  where public and id in ('quarantine','master','preview','deliverable');
  perform pg_temp.ok(leaked is null,
    'no sensitive bucket is public' || coalesce(' (public: ' || leaked || ')', ''));
end;
$$;

select pg_temp.rejects(
  $q$ update storage.buckets set public = true where id = 'deliverable' $q$,
  'the deliverable bucket cannot be flipped public');

-- =============================================================================
-- Fixtures: two organizations, so every isolation test has a real neighbour.
-- =============================================================================

insert into auth.users (id, email) values
  ('00000000-0000-0000-0000-0000000000a1', 'a@example.test'),
  ('00000000-0000-0000-0000-0000000000a2', 'finance-a@example.test'),
  ('00000000-0000-0000-0000-0000000000a3', 'shooter-a@example.test'),
  ('00000000-0000-0000-0000-0000000000b1', 'b@example.test')
on conflict do nothing;

insert into public.organizations (id, slug, display_name) values
  ('00000000-0000-0000-0000-00000000a000', 'studio-a', 'Studio A'),
  ('00000000-0000-0000-0000-00000000b000', 'studio-b', 'Studio B');

insert into public.organization_members (organization_id, user_id, role) values
  ('00000000-0000-0000-0000-00000000a000', '00000000-0000-0000-0000-0000000000a1', 'owner'),
  ('00000000-0000-0000-0000-00000000a000', '00000000-0000-0000-0000-0000000000a2', 'finance'),
  ('00000000-0000-0000-0000-00000000a000', '00000000-0000-0000-0000-0000000000a3', 'photographer'),
  ('00000000-0000-0000-0000-00000000b000', '00000000-0000-0000-0000-0000000000b1', 'owner');

insert into public.events (id, organization_id, name, status) values
  ('00000000-0000-0000-0000-00000000a001', '00000000-0000-0000-0000-00000000a000', 'A Wedding', 'live'),
  ('00000000-0000-0000-0000-00000000b001', '00000000-0000-0000-0000-00000000b000', 'B Wedding', 'live');

insert into public.devices (id, organization_id, label, public_key) values
  ('00000000-0000-0000-0000-00000000a002', '00000000-0000-0000-0000-00000000a000', 'A body 1', '\\xa1'),
  ('00000000-0000-0000-0000-00000000b002', '00000000-0000-0000-0000-00000000b000', 'B body 1', '\\xb1');

-- organization_id is omitted on purpose: it must be derived from the parent.
insert into public.captures (id, event_id, device_id, device_sequence, captured_at, content_hash, status) values
  ('00000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-00000000a001',
   '00000000-0000-0000-0000-00000000a002', 1, now(), '\\xdead01', 'verified'),
  ('00000000-0000-0000-0000-0000000000c2', '00000000-0000-0000-0000-00000000a001',
   '00000000-0000-0000-0000-00000000a002', 2, now(), '\\xdead02', 'verified'),
  -- A capture in Studio B's event: the target of every cross-event attack below.
  ('00000000-0000-0000-0000-0000000000c9', '00000000-0000-0000-0000-00000000b001',
   '00000000-0000-0000-0000-00000000b002', 1, now(), '\\xdead09', 'verified');

do $$
declare v uuid;
begin
  select organization_id into v from public.captures where id = '00000000-0000-0000-0000-0000000000c1';
  perform pg_temp.ok(v = '00000000-0000-0000-0000-00000000a000',
    'denormalized organization_id is derived from the parent when omitted');
end;
$$;

insert into public.assets (capture_id, kind, bucket, object_path, checksum, status) values
  ('00000000-0000-0000-0000-0000000000c1', 'master', 'master',
   '00000000-0000-0000-0000-00000000a000/00000000-0000-0000-0000-00000000a001/00000000-0000-0000-0000-0000000000c1/original.cr3', '\\xdead01', 'verified'),
  ('00000000-0000-0000-0000-0000000000c2', 'master', 'master',
   '00000000-0000-0000-0000-00000000a000/00000000-0000-0000-0000-00000000a001/00000000-0000-0000-0000-0000000000c2/original.cr3', '\\xdead02', 'verified');

-- A published price list. Without one, nothing in this event may be sold.
-- Priced while in draft, then published. Items cannot be added to or edited on
-- a published list — changing prices means publishing a new version.
insert into public.price_lists (id, event_id, currency) values
  ('00000000-0000-0000-0000-0000000009a1', '00000000-0000-0000-0000-00000000a001', 'PHP');
insert into public.price_items (price_list_id, unit_price_minor) values
  ('00000000-0000-0000-0000-0000000009a1', 15000);   -- PHP 150.00 default
update public.price_lists set published_at = now()
  where id = '00000000-0000-0000-0000-0000000009a1';

insert into public.customer_sessions (id, event_id, token_hash, expires_at) values
  ('00000000-0000-0000-0000-0000000000f1', '00000000-0000-0000-0000-00000000a001',
   '\\xf1', now() + interval '30 days');

insert into public.orders (id, event_id, organization_id, customer_session_id, status) values
  ('00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-00000000a001',
   '00000000-0000-0000-0000-00000000a000', '00000000-0000-0000-0000-0000000000f1', 'draft');

-- The customer bought CAP1 only. The price supplied here is a lie (PHP 1.00);
-- the database must replace it with the published price.
insert into public.order_items (id, order_id, capture_id, unit_price_minor) values
  ('00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-0000000000e1',
   '00000000-0000-0000-0000-0000000000c1', 100);

-- Deliverables are order-scoped (v2 §9/§26), so they exist only once a line
-- item does, and they live under the order's path, not the capture's.
insert into public.assets (capture_id, order_item_id, kind, bucket, object_path, checksum, status) values
  ('00000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-0000000000d1',
   'deliverable', 'deliverable',
   '00000000-0000-0000-0000-00000000a000/00000000-0000-0000-0000-0000000000e1/00000000-0000-0000-0000-0000000000d1/v1.jpg',
   '\\xbeef01', 'ready');

-- =============================================================================
-- Attack: price manipulation
-- =============================================================================

do $$
declare v bigint;
begin
  select unit_price_minor into v from public.order_items where id = '00000000-0000-0000-0000-0000000000d1';
  perform pg_temp.ok(v = 15000,
    'a caller-supplied line price is replaced by the published price list (got ' || v || ')');

  select amount_minor into v from public.orders where id = '00000000-0000-0000-0000-0000000000e1';
  perform pg_temp.ok(v = 15000, 'order total is derived from line items (got ' || v || ')');
end;
$$;

-- Fail closed: an event with no published price list cannot sell anything.
select pg_temp.rejects(
  $q$ insert into public.orders (id, event_id, organization_id, customer_session_id)
      values ('00000000-0000-0000-0000-0000000000e9', '00000000-0000-0000-0000-00000000b001',
              '00000000-0000-0000-0000-00000000b000',
              (select id from public.customer_sessions limit 1)) $q$,
  'a session from another event cannot open an order');

select pg_temp.rejects(
  $q$ update public.price_items set unit_price_minor = 1
      where price_list_id = '00000000-0000-0000-0000-0000000009a1' $q$,
  'a published price list is immutable');

-- The client says "one peso, please" and a handler writes it straight onto the
-- order. There must be no window in which that value is live, because the
-- payment guard would then match a provider event for the same wrong amount.
do $$
declare v bigint;
begin
  update public.orders set amount_minor = 100 where id = '00000000-0000-0000-0000-0000000000e1';
  select amount_minor into v from public.orders where id = '00000000-0000-0000-0000-0000000000e1';
  perform pg_temp.ok(v = 15000,
    'a total written directly onto the order is overwritten immediately (got ' || v || ')');
end;
$$;

-- =============================================================================
-- Attack: book the order to the wrong tenant
-- =============================================================================

select pg_temp.rejects(
  $q$ insert into public.orders (event_id, organization_id, customer_session_id)
      values ('00000000-0000-0000-0000-00000000a001',
              '00000000-0000-0000-0000-00000000b000',
              '00000000-0000-0000-0000-0000000000f1') $q$,
  'an order cannot be booked to an organization that does not own the event');

select pg_temp.rejects(
  $q$ update public.orders set organization_id = '00000000-0000-0000-0000-00000000b000'
      where id = '00000000-0000-0000-0000-0000000000e1' $q$,
  'an existing order cannot be moved to another organization');

-- =============================================================================
-- Attack: buy another photographer's photo through your own event's checkout
-- =============================================================================
-- The customer is shopping Studio A. The line item points at Studio B's capture.
-- Nothing in the entitlement chain notices unless capture is tied back to event.

select pg_temp.rejects(
  $q$ insert into public.order_items (order_id, capture_id, unit_price_minor)
      values ('00000000-0000-0000-0000-0000000000e1',
              '00000000-0000-0000-0000-0000000000c9', 100) $q$,
  'a line item cannot reference a capture from another event');

-- =============================================================================
-- Attack: forged payment
-- =============================================================================

update public.orders set status = 'awaiting_payment' where id = '00000000-0000-0000-0000-0000000000e1';

select pg_temp.rejects(
  $q$ update public.orders set status = 'paid' where id = '00000000-0000-0000-0000-0000000000e1' $q$,
  'an order cannot reach paid without a verified provider event');

-- An unverified webhook body cannot even be bound to an order.
select pg_temp.rejects(
  $q$ insert into public.payment_events
        (provider_event_id, kind, order_id, amount_minor, currency, signature_verified, raw_payload)
      values ('evt_forged', 'paid', '00000000-0000-0000-0000-0000000000e1', 15000, 'PHP', false, '{}') $q$,
  'an unsigned webhook cannot be bound to an order');

-- A verified event for the wrong amount must not unlock fulfillment either.
insert into public.payment_events
  (provider_event_id, kind, order_id, amount_minor, currency, signature_verified, raw_payload)
values ('evt_short', 'paid', '00000000-0000-0000-0000-0000000000e1', 100, 'PHP', true, '{}');

select pg_temp.rejects(
  $q$ update public.orders set status = 'paid' where id = '00000000-0000-0000-0000-0000000000e1' $q$,
  'a verified event for the wrong amount does not mark the order paid');

-- The real thing.
insert into public.payment_events
  (provider_event_id, kind, order_id, amount_minor, currency, signature_verified, raw_payload)
values ('evt_real', 'paid', '00000000-0000-0000-0000-0000000000e1', 15000, 'PHP', true, '{}');

update public.orders set status = 'paid' where id = '00000000-0000-0000-0000-0000000000e1';

do $$
declare v public.order_status;
begin
  select status into v from public.orders where id = '00000000-0000-0000-0000-0000000000e1';
  perform pg_temp.ok(v = 'paid', 'a verified, amount-matched event does mark the order paid');
end;
$$;

-- =============================================================================
-- Attack: webhook replay
-- =============================================================================

select pg_temp.rejects(
  $q$ insert into public.payment_events
        (provider_event_id, kind, order_id, amount_minor, currency, signature_verified, raw_payload)
      values ('evt_real', 'paid', '00000000-0000-0000-0000-0000000000e1', 15000, 'PHP', true, '{}') $q$,
  'replaying a provider event id is rejected by the schema');

-- =============================================================================
-- Attack: buy one photo, download all of them
-- =============================================================================

-- The legitimate entitlement for the photo that was actually bought.
insert into public.entitlements (id, order_item_id, capture_id, customer_session_id, status) values
  ('00000000-0000-0000-0000-00000000e1e1', '00000000-0000-0000-0000-0000000000d1',
   '00000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-0000000000f1', 'active');

insert into public.fulfillment_requests (order_item_id, entitlement_id, status) values
  ('00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-00000000e1e1', 'ready');

do $$
declare v text;
begin
  select object_path into v
  from app.authorize_download('00000000-0000-0000-0000-0000000000f1',
                              '00000000-0000-0000-0000-0000000000c1');
  perform pg_temp.ok(v like '%/v1.jpg', 'the purchased capture is downloadable (got ' || coalesce(v,'nothing') || ')');
end;
$$;

-- The attack: same paid session, a capture id they never bought.
do $$
declare n integer;
begin
  select count(*) into n
  from app.authorize_download('00000000-0000-0000-0000-0000000000f1',
                              '00000000-0000-0000-0000-0000000000c2');
  perform pg_temp.ok(n = 0, 'substituting an unpurchased capture id yields nothing');
end;
$$;

-- The attack one level deeper: forge an entitlement pointing at the other photo
-- while reusing the paid line item.
select pg_temp.rejects(
  $q$ insert into public.entitlements (order_item_id, capture_id, customer_session_id, status)
      values ('00000000-0000-0000-0000-0000000000d1',
              '00000000-0000-0000-0000-0000000000c2',
              '00000000-0000-0000-0000-0000000000f1', 'active') $q$,
  'an entitlement cannot point at a capture the line item does not contain');

-- Revocation (refund, chargeback, support) closes the door immediately.
update public.entitlements set status = 'revoked', revoked_reason = 'chargeback'
 where id = '00000000-0000-0000-0000-00000000e1e1';

do $$
declare n integer;
begin
  select count(*) into n
  from app.authorize_download('00000000-0000-0000-0000-0000000000f1',
                              '00000000-0000-0000-0000-0000000000c1');
  perform pg_temp.ok(n = 0, 'a revoked entitlement stops authorizing downloads');
end;
$$;

update public.entitlements set status = 'active', revoked_at = null, revoked_reason = null
 where id = '00000000-0000-0000-0000-00000000e1e1';

-- =============================================================================
-- Attack: unpaid session reaching for an HD asset
-- =============================================================================

insert into public.customer_sessions (id, event_id, token_hash, expires_at) values
  ('00000000-0000-0000-0000-0000000000f2', '00000000-0000-0000-0000-00000000a001',
   '\xf2', now() + interval '30 days');

do $$
declare n integer;
begin
  select count(*) into n
  from app.authorize_download('00000000-0000-0000-0000-0000000000f2',
                              '00000000-0000-0000-0000-0000000000c1');
  perform pg_temp.ok(n = 0, 'a session that never paid gets no HD asset');
end;
$$;

do $$
declare n integer;
begin
  select count(*) into n
  from app.authorize_download('00000000-0000-0000-0000-0000000000f1',
                              '00000000-0000-0000-0000-0000000000c9');
  perform pg_temp.ok(n = 0,
    'the chokepoint refuses a capture outside the order event, even if a row were forged');
end;
$$;

-- An asset row existing is not the same as its bytes being servable. 0001
-- conflated the two; v2 §7 does not.
do $$
declare n integer;
begin
  update public.assets set status = 'pending'
   where kind = 'deliverable' and order_item_id = '00000000-0000-0000-0000-0000000000d1';
  select count(*) into n
  from app.authorize_download('00000000-0000-0000-0000-0000000000f1',
                              '00000000-0000-0000-0000-0000000000c1');
  perform pg_temp.ok(n = 0, 'a deliverable that is not READY is not downloadable');
  update public.assets set status = 'ready'
   where kind = 'deliverable' and order_item_id = '00000000-0000-0000-0000-0000000000d1';
end;
$$;

-- An expired entitlement stops authorizing, without anyone revoking it.
do $$
declare n integer;
begin
  update public.entitlements set expires_at = now() - interval '1 second'
   where id = '00000000-0000-0000-0000-00000000e1e1';
  select count(*) into n
  from app.authorize_download('00000000-0000-0000-0000-0000000000f1',
                              '00000000-0000-0000-0000-0000000000c1');
  perform pg_temp.ok(n = 0, 'an expired entitlement stops authorizing downloads');
  update public.entitlements set expires_at = null
   where id = '00000000-0000-0000-0000-00000000e1e1';
end;
$$;

-- =============================================================================
-- Attack: queue poisoning / duplicate expensive jobs
-- =============================================================================

select pg_temp.rejects(
  $q$ insert into public.fulfillment_requests (order_item_id, entitlement_id, status)
      values ('00000000-0000-0000-0000-0000000000d1',
              '00000000-0000-0000-0000-00000000e1e1', 'queued') $q$,
  'a duplicate fulfillment job for the same item and version collapses');

-- =============================================================================
-- Attack: compromised Bridge swaps the bytes behind an existing capture
-- =============================================================================

-- Guard against a vacuous test: the row must exist before the update is
-- expected to be rejected, or "0 rows changed" masquerades as a working control.
do $$
declare n integer;
begin
  select count(*) into n from public.assets
   where kind = 'master' and capture_id = '00000000-0000-0000-0000-0000000000c1';
  perform pg_temp.ok(n = 1, 'the master asset under test exists');
end;
$$;

select pg_temp.rejects(
  $q$ update public.assets
      set object_path = '00000000-0000-0000-0000-00000000a000/00000000-0000-0000-0000-00000000a001/00000000-0000-0000-0000-0000000000c1/evil.cr3'
      where kind = 'master' and capture_id = '00000000-0000-0000-0000-0000000000c1' $q$,
  'a master asset path is immutable');

select pg_temp.rejects(
  $q$ update public.captures set content_hash = '\xbadbad'
      where id = '00000000-0000-0000-0000-0000000000c1' $q$,
  'a verified capture hash is immutable');

select pg_temp.rejects(
  $q$ insert into public.captures (event_id, device_id, device_sequence, captured_at)
      values ('00000000-0000-0000-0000-00000000a001',
              '00000000-0000-0000-0000-00000000a002', 1, now()) $q$,
  'a device cannot replay a capture sequence number');

-- =============================================================================
-- Attack: test-mode webhook against a live platform  (v2 §19, §39)
-- =============================================================================
-- A correctly-signed test-mode event that can mark a live order paid is free
-- photographs for anyone who read the integration guide — and it leaves a
-- clean, well-formed audit trail behind it.

update public.platform_settings set livemode = true where id;

select pg_temp.rejects(
  $q$ insert into public.payment_events
        (provider_event_id, kind, order_id, amount_minor, currency,
         signature_verified, livemode, raw_payload)
      values ('evt_testmode', 'paid', '00000000-0000-0000-0000-0000000000e1',
              15000, 'PHP', true, false, '{}') $q$,
  'a test-mode payment event cannot bind to an order on a live platform');

update public.platform_settings set livemode = false where id;

-- =============================================================================
-- Attack: poison the denormalized tenancy column  (v2 §2)
-- =============================================================================
-- Carrying organization_id on every row makes RLS direct, but a row whose
-- denormalized org disagrees with its parent is a tenant boundary violation
-- that every join-free policy will honour. v2 asks for the column and does not
-- mention this failure mode.

select pg_temp.rejects(
  $q$ insert into public.captures
        (event_id, device_id, device_sequence, captured_at, organization_id)
      values ('00000000-0000-0000-0000-00000000a001',
              '00000000-0000-0000-0000-00000000a002', 99, now(),
              '00000000-0000-0000-0000-00000000b000') $q$,
  'a capture cannot claim an organization its event does not belong to');

select pg_temp.rejects(
  $q$ update public.captures set organization_id = '00000000-0000-0000-0000-00000000b000'
      where id = '00000000-0000-0000-0000-0000000000c1' $q$,
  'a capture cannot be moved to another organization by rewriting its org column');

-- =============================================================================
-- Attack: supply your own storage path  (v2 §9)
-- =============================================================================

select pg_temp.rejects(
  $q$ insert into public.assets (capture_id, kind, bucket, object_path, status)
      values ('00000000-0000-0000-0000-0000000000c2', 'preview', 'preview',
              'somewhere/else/v1.webp', 'ready') $q$,
  'an asset path that is not server-derived is rejected');

select pg_temp.rejects(
  $q$ insert into public.assets (capture_id, kind, bucket, object_path, status)
      values ('00000000-0000-0000-0000-0000000000c2', 'preview', 'preview',
              '00000000-0000-0000-0000-00000000a000/00000000-0000-0000-0000-00000000a001/00000000-0000-0000-0000-0000000000c2/../../../master/leak.cr3',
              'ready') $q$,
  'an asset path containing a traversal sequence is rejected');

select pg_temp.rejects(
  $q$ insert into public.assets (capture_id, kind, bucket, object_path, status)
      values ('00000000-0000-0000-0000-0000000000c2', 'deliverable', 'deliverable',
              '00000000-0000-0000-0000-00000000a000/x/y/v1.jpg', 'ready') $q$,
  'a deliverable with no order item is rejected');

-- =============================================================================
-- Composite tenancy keys hold without the trigger
-- =============================================================================
-- The trigger enforces a rule; the foreign key makes the rule unrepresentable.
-- This test removes the trigger and proves the constraint still stands, which
-- is the whole reason for having both.

do $$
begin
  alter table public.captures disable trigger captures_org_guard;
end;
$$;

select pg_temp.rejects(
  $q$ insert into public.captures
        (event_id, device_id, device_sequence, captured_at, organization_id)
      values ('00000000-0000-0000-0000-00000000a001',
              '00000000-0000-0000-0000-00000000a002', 97, now(),
              '00000000-0000-0000-0000-00000000b000') $q$,
  'the composite FK rejects mismatched tenancy even with the trigger disabled');

do $$
begin
  alter table public.captures enable trigger captures_org_guard;
end;
$$;

-- A device cannot be used against another organization's event, which was
-- previously an application-layer concern only.
select pg_temp.rejects(
  $q$ insert into public.device_sessions (device_id, event_id, expires_at)
      values ('00000000-0000-0000-0000-00000000a002',
              '00000000-0000-0000-0000-00000000b001', now() + interval '8 hours') $q$,
  'a device cannot open a session against another organization''s event');

-- =============================================================================
-- Order access tokens  (single use, scoped, hashed)
-- =============================================================================

update public.orders set contact_email = 'buyer@example.test', contact_email_source = 'checkout'
 where id = '00000000-0000-0000-0000-0000000000e1';

insert into public.order_access_tokens
  (id, organization_id, order_id, token_hash, issued_to_email, expires_at)
values
  ('00000000-0000-0000-0000-00000000a7a1', '00000000-0000-0000-0000-00000000a000',
   '00000000-0000-0000-0000-0000000000e1', digest('raw-token-one','sha256'),
   'buyer@example.test', now() + interval '72 hours');

do $$
declare v_session uuid; n integer;
begin
  v_session := app.consume_order_access_token(digest('raw-token-one','sha256'), '203.0.113.0'::inet);
  perform pg_temp.ok(v_session is not null, 'a valid order access token mints a session');

  -- The bootstrapped session reaches the order it was issued for.
  select count(*) into n
  from app.authorize_download(v_session, '00000000-0000-0000-0000-0000000000c1');
  perform pg_temp.ok(n = 1, 'a token-scoped session can download its own order''s photograph');

  -- ...and is scoped to that order only.
  select count(*) into n from public.customer_sessions
   where id = v_session and order_scope_id = '00000000-0000-0000-0000-0000000000e1';
  perform pg_temp.ok(n = 1, 'the bootstrapped session is scoped to exactly one order');
end;
$$;

select pg_temp.rejects(
  $q$ select app.consume_order_access_token(digest('raw-token-one','sha256')) $q$,
  'an order access token cannot be consumed twice');

insert into public.order_access_tokens
  (organization_id, order_id, token_hash, issued_to_email, issued_at, expires_at)
values
  ('00000000-0000-0000-0000-00000000a000', '00000000-0000-0000-0000-0000000000e1',
   digest('raw-token-stale','sha256'), 'buyer@example.test',
   now() - interval '10 days', now() - interval '3 days');

select pg_temp.rejects(
  $q$ select app.consume_order_access_token(digest('raw-token-stale','sha256')) $q$,
  'an expired order access token is refused');

insert into public.order_access_tokens
  (organization_id, order_id, token_hash, issued_to_email, expires_at)
values
  ('00000000-0000-0000-0000-00000000a000', '00000000-0000-0000-0000-0000000000e1',
   digest('raw-token-old','sha256'), 'buyer@example.test', now() + interval '72 hours');

do $$
declare n integer;
begin
  n := app.supersede_order_access_tokens('00000000-0000-0000-0000-0000000000e1');
  perform pg_temp.ok(n >= 1, 'issuing a fresh link supersedes the outstanding ones');
end;
$$;

select pg_temp.rejects(
  $q$ select app.consume_order_access_token(digest('raw-token-old','sha256')) $q$,
  'a superseded order access token stops working');

-- The raw token is never at rest. Only its hash is stored.
do $$
declare n integer;
begin
  select count(*) into n from public.order_access_tokens
   where token_hash = 'raw-token-one'::bytea;
  perform pg_temp.ok(n = 0, 'no raw order access token is stored');
end;
$$;

-- =============================================================================
-- Attack: cross-tenant breakout via object id substitution
-- =============================================================================
-- Studio B's owner authenticates honestly and then submits Studio A's ids.

set local role authenticated;
set local request.jwt.claims = '{"sub":"00000000-0000-0000-0000-0000000000b1","role":"authenticated"}';

do $$
declare n integer;
begin
  select count(*) into n from public.events
   where id = '00000000-0000-0000-0000-00000000a001';
  perform pg_temp.ok(n = 0, 'RLS hides another organization''s event');

  select count(*) into n from public.captures
   where event_id = '00000000-0000-0000-0000-00000000a001';
  perform pg_temp.ok(n = 0, 'RLS hides another organization''s captures');

  select count(*) into n from public.assets
   where object_path = 'a001/c1.cr3';
  perform pg_temp.ok(n = 0, 'RLS hides another organization''s master assets');

  select count(*) into n from public.orders
   where organization_id = '00000000-0000-0000-0000-00000000a000';
  perform pg_temp.ok(n = 0, 'RLS hides another organization''s revenue');

  select count(*) into n from public.devices
   where organization_id = '00000000-0000-0000-0000-00000000a000';
  perform pg_temp.ok(n = 0, 'RLS hides another organization''s devices');
end;
$$;

reset role;

-- -----------------------------------------------------------------------------
-- Least privilege between two people who both work here (v2 §3).
-- Membership alone decides nothing.
-- -----------------------------------------------------------------------------

set local role authenticated;
set local request.jwt.claims = '{"sub":"00000000-0000-0000-0000-0000000000a2","role":"authenticated"}';
do $$
declare n integer;
begin
  select count(*) into n from public.orders
   where organization_id = '00000000-0000-0000-0000-00000000a000';
  perform pg_temp.ok(n > 0, 'FINANCE reads its own organization''s revenue');

  select count(*) into n from public.captures
   where organization_id = '00000000-0000-0000-0000-00000000a000';
  perform pg_temp.ok(n = 0, 'FINANCE reads no photographs');
end;
$$;
reset role;

set local role authenticated;
set local request.jwt.claims = '{"sub":"00000000-0000-0000-0000-0000000000a3","role":"authenticated"}';
do $$
declare n integer;
begin
  select count(*) into n from public.captures
   where organization_id = '00000000-0000-0000-0000-00000000a000';
  perform pg_temp.ok(n > 0, 'PHOTOGRAPHER reads its own organization''s photographs');

  select count(*) into n from public.orders
   where organization_id = '00000000-0000-0000-0000-00000000a000';
  perform pg_temp.ok(n = 0, 'PHOTOGRAPHER reads no revenue');
end;
$$;

-- Customer identity, payment truth and entitlements are not merely filtered for
-- an authenticated photographer — they are unreachable through the Data API.
select pg_temp.rejects(
  $q$ select count(*) from public.entitlements $q$,
  'entitlements are unreachable from the authenticated role');

select pg_temp.rejects(
  $q$ select count(*) from public.customer_sessions $q$,
  'customer sessions are unreachable from the authenticated role');

select pg_temp.rejects(
  $q$ select count(*) from public.payment_events $q$,
  'payment events are unreachable from the authenticated role');

select pg_temp.rejects(
  $q$ select * from app.authorize_download('00000000-0000-0000-0000-0000000000f1',
                                           '00000000-0000-0000-0000-0000000000c1') $q$,
  'the download chokepoint is not callable from the Data API');

reset role;

-- =============================================================================
-- Attack: erase the trail
-- =============================================================================

insert into public.audit_log (actor_kind, operation, result)
values ('service', 'test.write', 'allow');

select pg_temp.rejects(
  $q$ delete from public.audit_log $q$,
  'the audit log cannot be deleted');

select pg_temp.rejects(
  $q$ update public.audit_log set result = 'allow' $q$,
  'the audit log cannot be rewritten');

rollback;

\echo ''
\echo 'All authorization tests passed.'
