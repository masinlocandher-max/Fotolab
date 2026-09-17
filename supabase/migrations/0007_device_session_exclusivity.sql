-- =============================================================================
-- Fotolab :: 0007 :: One live session per device
-- =============================================================================
-- Enrollment recovery resolves a repeated enrollment of the same public key to
-- the same device. That is required: a Bridge killed between the server
-- creating the device and the laptop recording its id has already spent its
-- enrollment code, and without recovery the machine is bricked before the event.
--
-- The security consequence is that copying a Bridge's state directory to a
-- second laptop produces two installations the server cannot tell apart by
-- identity alone. They are not harmless independent devices: they share a
-- sequence counter, they shoot into the same event, and one of them is a theft.
--
-- The invariant that makes cloning visible rather than silent is narrow:
--
--     a device has at most one live session at a time
--
-- Two clones then cannot upload concurrently. Each new session supersedes the
-- other's, and that supersession — of a session that was active seconds ago,
-- rather than one left behind by a crash — is the signal. A restarting Bridge
-- supersedes an idle session; a clone supersedes a working one.
-- =============================================================================

alter table public.device_sessions
  add column superseded_at timestamptz,
  add column superseded_by uuid references public.device_sessions(id),
  add column opened_from_ip inet,
  -- The heartbeat that makes "was it still working?" answerable. 0001 put
  -- last_seen_at on devices but not on the session, and the session is the
  -- thing being taken away.
  add column last_seen_at timestamptz;

alter table public.devices
  add column clone_suspected_at timestamptz,
  add column clone_signal_count integer not null default 0,
  add column session_epoch integer not null default 0;

-- The invariant, in the database rather than in a handler. A second live
-- session for one device cannot be written, by any caller, including one
-- holding service_role.
create unique index device_sessions_one_live_per_device
  on public.device_sessions (device_id)
  where revoked_at is null and superseded_at is null;

-- -----------------------------------------------------------------------------
-- How recently a session must have been active for its supersession to look
-- like a clone rather than a restart. A Bridge that crashed stops touching
-- last_seen_at immediately; a Bridge that is working touches it constantly.
-- -----------------------------------------------------------------------------
create or replace function app.clone_activity_window()
returns interval language sql immutable as $$ select interval '90 seconds' $$;

create or replace function app.clone_signal_threshold()
returns integer language sql immutable as $$ select 3 $$;

-- -----------------------------------------------------------------------------
-- Opening a session. Atomic: the old session is superseded and the new one
-- created in one transaction, so the unique index above is never transiently
-- violated and two racing clones cannot both win.
-- -----------------------------------------------------------------------------

create or replace function app.open_device_session(
  p_device   uuid,
  p_event    uuid,
  p_ttl      interval default interval '8 hours',
  p_ip       inet default null
)
returns table (session_id uuid, epoch integer, clone_suspected boolean)
language plpgsql security definer set search_path = '' as $$
declare
  v_device   public.devices%rowtype;
  v_event    public.events%rowtype;
  v_prior    public.device_sessions%rowtype;
  v_new      uuid;
  v_signal   boolean := false;
  v_count    integer;
  v_suspect  boolean;
begin
  select * into v_device from public.devices d where d.id = p_device;
  if v_device.id is null or v_device.status <> 'active' then
    raise exception 'device % is not active', p_device using errcode = 'insufficient_privilege';
  end if;

  select * into v_event from public.events e where e.id = p_event;
  if v_event.id is null or v_event.organization_id <> v_device.organization_id then
    raise exception 'device % may not shoot event %', p_device, p_event
      using errcode = 'insufficient_privilege';
  end if;

  -- Supersede whatever is live, and notice whether it was still working.
  select * into v_prior
  from public.device_sessions s
  where s.device_id = p_device and s.revoked_at is null and s.superseded_at is null
  for update;

  if v_prior.id is not null then
    v_signal := coalesce(v_prior.last_seen_at, v_prior.issued_at)
                  > now() - app.clone_activity_window();
    update public.device_sessions
       set superseded_at = now()
     where id = v_prior.id;
  end if;

  insert into public.device_sessions
    (device_id, event_id, organization_id, expires_at, opened_from_ip)
  values (p_device, p_event, v_device.organization_id, now() + p_ttl, p_ip)
  returning id into v_new;

  if v_prior.id is not null then
    update public.device_sessions set superseded_by = v_new where id = v_prior.id;
  end if;

  -- Taking a session away from an installation that was actively uploading is
  -- what a clone looks like. One such event is a coincidence — a laptop that
  -- froze and was force-restarted. Repeated ones are two machines fighting.
  if v_signal then
    update public.devices
       set clone_signal_count = clone_signal_count + 1,
           session_epoch = session_epoch + 1
     where id = p_device
    returning clone_signal_count into v_count;

    if v_count >= app.clone_signal_threshold() then
      update public.devices
         set clone_suspected_at = coalesce(clone_suspected_at, now())
       where id = p_device;
    end if;
  else
    update public.devices set session_epoch = session_epoch + 1 where id = p_device;
  end if;

  select (d.clone_suspected_at is not null) into v_suspect
  from public.devices d where d.id = p_device;

  insert into public.audit_log
    (actor_kind, actor_id, organization_id, event_id, operation,
     target_kind, target_id, result, ip_prefix, detail)
  values
    ('device', p_device, v_device.organization_id, p_event, 'device_session.opened',
     'device_session', v_new, 'allow', p_ip,
     jsonb_build_object('superseded_active_session', v_signal, 'clone_suspected', v_suspect));

  return query select v_new, (select d.session_epoch from public.devices d where d.id = p_device), v_suspect;
end;
$$;

revoke all on function app.open_device_session(uuid, uuid, interval, inet) from anon, authenticated;

-- Heartbeat. Cheap, and it is what makes the activity window meaningful.
create or replace function app.touch_device_session(p_session uuid)
returns void language sql security definer set search_path = '' as $$
  update public.device_sessions set last_seen_at = now()
   where id = p_session and revoked_at is null and superseded_at is null;
$$;

revoke all on function app.touch_device_session(uuid) from anon, authenticated;

-- An operator clearing a false positive, or accepting a real one.
create or replace function app.resolve_clone_suspicion(p_device uuid, p_action text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if p_action = 'cleared' then
    update public.devices
       set clone_suspected_at = null, clone_signal_count = 0
     where id = p_device;
  elsif p_action = 'compromised' then
    update public.devices set status = 'compromised', revoked_at = now() where id = p_device;
    update public.device_sessions set revoked_at = now()
     where device_id = p_device and revoked_at is null;
  else
    raise exception 'unknown action %', p_action using errcode = 'invalid_parameter_value';
  end if;
end;
$$;

revoke all on function app.resolve_clone_suspicion(uuid, text) from anon, authenticated;
