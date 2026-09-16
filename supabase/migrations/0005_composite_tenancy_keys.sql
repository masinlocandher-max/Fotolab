-- =============================================================================
-- Fotolab :: 0005 :: Composite tenancy foreign keys
-- =============================================================================
-- 0004 enforced denormalized tenancy with a trigger. A trigger enforces a rule;
-- a composite foreign key makes the rule unrepresentable. Both are kept, and
-- they do different jobs:
--
--   trigger  — derives organization_id from the parent when a caller omits it
--   FK       — makes a row whose organization_id disagrees with its parent's
--              impossible to write at all, including by a superuser, a
--              service_role handler, or a future migration that forgets
--
-- The pattern throughout:
--     parent  UNIQUE (id, organization_id)
--     child   FOREIGN KEY (parent_id, organization_id)
--               REFERENCES parent (id, organization_id)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- device_sessions had no tenancy column at all, which left "this device
-- uploaded into another organization's event" as an application-layer concern.
-- -----------------------------------------------------------------------------

alter table public.device_sessions
  add column organization_id uuid references public.organizations(id);

update public.device_sessions ds
   set organization_id = d.organization_id
  from public.devices d
 where d.id = ds.device_id and ds.organization_id is null;

create trigger device_sessions_org_guard before insert or update on public.device_sessions
  for each row execute function app.guard_denormalized_org('device_id','devices','organization_id');

-- -----------------------------------------------------------------------------
-- organization_id becomes mandatory. The BEFORE triggers from 0004 still derive
-- it when omitted, so this tightens the invariant without changing any caller.
-- -----------------------------------------------------------------------------

alter table public.captures             alter column organization_id set not null;
alter table public.assets               alter column organization_id set not null;
alter table public.customer_sessions    alter column organization_id set not null;
alter table public.order_items          alter column organization_id set not null;
alter table public.entitlements         alter column organization_id set not null;
alter table public.fulfillment_requests alter column organization_id set not null;
alter table public.download_grants      alter column organization_id set not null;
alter table public.device_sessions      alter column organization_id set not null;

-- -----------------------------------------------------------------------------
-- Parent-side composite uniqueness. Redundant with each primary key on its own,
-- which is exactly what lets it serve as an FK target.
-- -----------------------------------------------------------------------------

alter table public.events          add constraint events_id_org_key          unique (id, organization_id);
alter table public.devices         add constraint devices_id_org_key         unique (id, organization_id);
alter table public.captures        add constraint captures_id_org_key        unique (id, organization_id);
alter table public.orders          add constraint orders_id_org_key          unique (id, organization_id);
alter table public.order_items     add constraint order_items_id_org_key     unique (id, organization_id);
alter table public.entitlements    add constraint entitlements_id_org_key    unique (id, organization_id);
alter table public.price_lists     add constraint price_lists_id_org_key     unique (id, organization_id);
alter table public.customer_sessions add constraint customer_sessions_id_org_key unique (id, organization_id);

-- -----------------------------------------------------------------------------
-- Child-side composite foreign keys. Each one replaces a single-column FK that
-- could point anywhere in the table, including into another tenant.
-- -----------------------------------------------------------------------------

alter table public.captures drop constraint if exists captures_event_id_fkey;
alter table public.captures
  add constraint captures_event_tenancy_fkey
  foreign key (event_id, organization_id)
  references public.events (id, organization_id) on delete cascade;

alter table public.captures drop constraint if exists captures_device_id_fkey;
alter table public.captures
  add constraint captures_device_tenancy_fkey
  foreign key (device_id, organization_id)
  references public.devices (id, organization_id);

alter table public.device_sessions drop constraint if exists device_sessions_device_id_fkey;
alter table public.device_sessions
  add constraint device_sessions_device_tenancy_fkey
  foreign key (device_id, organization_id)
  references public.devices (id, organization_id) on delete cascade;

-- A device session may only exist against an event in its own organization.
alter table public.device_sessions drop constraint if exists device_sessions_event_id_fkey;
alter table public.device_sessions
  add constraint device_sessions_event_tenancy_fkey
  foreign key (event_id, organization_id)
  references public.events (id, organization_id) on delete cascade;

alter table public.assets drop constraint if exists assets_capture_id_fkey;
alter table public.assets
  add constraint assets_capture_tenancy_fkey
  foreign key (capture_id, organization_id)
  references public.captures (id, organization_id) on delete cascade;

-- A deliverable cannot be attached to another organization's order item.
alter table public.assets drop constraint if exists assets_order_item_id_fkey;
alter table public.assets
  add constraint assets_order_item_tenancy_fkey
  foreign key (order_item_id, organization_id)
  references public.order_items (id, organization_id) on delete cascade;

alter table public.customer_sessions drop constraint if exists customer_sessions_event_id_fkey;
alter table public.customer_sessions
  add constraint customer_sessions_event_tenancy_fkey
  foreign key (event_id, organization_id)
  references public.events (id, organization_id) on delete cascade;

alter table public.orders drop constraint if exists orders_event_id_fkey;
alter table public.orders
  add constraint orders_event_tenancy_fkey
  foreign key (event_id, organization_id)
  references public.events (id, organization_id);

alter table public.orders drop constraint if exists orders_customer_session_id_fkey;
alter table public.orders
  add constraint orders_session_tenancy_fkey
  foreign key (customer_session_id, organization_id)
  references public.customer_sessions (id, organization_id);

alter table public.order_items drop constraint if exists order_items_order_id_fkey;
alter table public.order_items
  add constraint order_items_order_tenancy_fkey
  foreign key (order_id, organization_id)
  references public.orders (id, organization_id) on delete cascade;

-- The cross-event line item from the earlier pass, now structurally impossible
-- rather than trigger-rejected.
alter table public.order_items drop constraint if exists order_items_capture_id_fkey;
alter table public.order_items
  add constraint order_items_capture_tenancy_fkey
  foreign key (capture_id, organization_id)
  references public.captures (id, organization_id);

alter table public.entitlements drop constraint if exists entitlements_order_item_id_fkey;
alter table public.entitlements
  add constraint entitlements_order_item_tenancy_fkey
  foreign key (order_item_id, organization_id)
  references public.order_items (id, organization_id) on delete cascade;

alter table public.entitlements drop constraint if exists entitlements_capture_id_fkey;
alter table public.entitlements
  add constraint entitlements_capture_tenancy_fkey
  foreign key (capture_id, organization_id)
  references public.captures (id, organization_id);

alter table public.entitlements drop constraint if exists entitlements_customer_session_id_fkey;
alter table public.entitlements
  add constraint entitlements_session_tenancy_fkey
  foreign key (customer_session_id, organization_id)
  references public.customer_sessions (id, organization_id);

alter table public.fulfillment_requests drop constraint if exists fulfillment_requests_order_item_id_fkey;
alter table public.fulfillment_requests
  add constraint fulfillment_requests_order_item_tenancy_fkey
  foreign key (order_item_id, organization_id)
  references public.order_items (id, organization_id) on delete cascade;

alter table public.fulfillment_requests drop constraint if exists fulfillment_requests_entitlement_id_fkey;
alter table public.fulfillment_requests
  add constraint fulfillment_requests_entitlement_tenancy_fkey
  foreign key (entitlement_id, organization_id)
  references public.entitlements (id, organization_id) on delete cascade;

alter table public.download_grants drop constraint if exists download_grants_entitlement_id_fkey;
alter table public.download_grants
  add constraint download_grants_entitlement_tenancy_fkey
  foreign key (entitlement_id, organization_id)
  references public.entitlements (id, organization_id) on delete cascade;

alter table public.price_lists drop constraint if exists price_lists_event_id_fkey;
alter table public.price_lists
  add constraint price_lists_event_tenancy_fkey
  foreign key (event_id, organization_id)
  references public.events (id, organization_id) on delete cascade;

alter table public.price_items drop constraint if exists price_items_price_list_id_fkey;
alter table public.price_items
  add constraint price_items_list_tenancy_fkey
  foreign key (price_list_id, organization_id)
  references public.price_lists (id, organization_id) on delete cascade;

-- Composite FKs need an index on the referencing side for cascade performance.
create index if not exists captures_event_org_idx    on public.captures (event_id, organization_id);
create index if not exists assets_capture_org_idx    on public.assets (capture_id, organization_id);
create index if not exists order_items_order_org_idx on public.order_items (order_id, organization_id);
create index if not exists entitlements_item_org_idx on public.entitlements (order_item_id, organization_id);
