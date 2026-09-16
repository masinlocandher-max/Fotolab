-- =============================================================================
-- Fotolab :: 0003 :: Storage
-- =============================================================================
-- A public Supabase bucket bypasses retrieval access control: anyone holding the
-- URL gets the object, forever, with no session and no log line worth having.
-- So the rule here is not "be careful with the public toggle" — it is that the
-- masters and deliverables live in buckets that are never eligible to be public,
-- and a guard trigger rejects the migration or console click that tries.
-- =============================================================================

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values
  -- Untrusted bytes land here first and nothing else may read them.
  ('quarantine',  'quarantine',  false, 1073741824, null),
  -- Write-once originals. The business asset. Never public, never overwritten.
  ('master',      'master',      false, 1073741824, null),
  -- Derived, watermarked, downscaled, metadata-stripped. CDN-eligible, still
  -- served through an access-checked edge route rather than a raw public URL.
  ('preview',     'preview',     false, 26214400,
     array['image/jpeg','image/webp','image/avif']),
  -- The thing customers paid for. Private, short-lived signed access only.
  ('deliverable', 'deliverable', false, 268435456,
     array['image/jpeg','image/png','image/tiff','image/webp'])
on conflict (id) do nothing;

-- -----------------------------------------------------------------------------
-- Make "let's just make the bucket public to fix the slow gallery" impossible.
-- -----------------------------------------------------------------------------

create or replace function app.forbid_public_sensitive_buckets()
returns trigger language plpgsql set search_path = '' as $$
begin
  if new.public and new.id in ('quarantine','master','deliverable','preview') then
    raise exception
      'bucket % may never be public; serve it through an authorized route instead', new.id
      using errcode = 'insufficient_privilege',
            hint = 'See docs/security/data-handling.md. If you are here because the gallery is slow, cache the preview route, do not open the bucket.';
  end if;
  return new;
end;
$$;

create trigger buckets_never_public
  before insert or update on storage.buckets
  for each row execute function app.forbid_public_sensitive_buckets();

-- -----------------------------------------------------------------------------
-- Object access. No policy for anon or authenticated on any of these buckets:
-- storage reads are mediated by the server, which calls app.authorize_download()
-- and then mints a signed URL measured in seconds.
--
-- A signed URL is a bearer capability. Supabase honours it until it expires,
-- independently of the session that requested it, so treat leak-resistance as a
-- lifetime problem: 60-120s, Referrer-Policy: no-referrer, and never write one
-- into logs, analytics, error reports, or an email body.
-- -----------------------------------------------------------------------------

create policy photographers_read_own_masters on storage.objects
  for select to authenticated
  using (
    bucket_id = 'master'
    and exists (
      select 1
      from public.assets a
      join public.captures c on c.id = a.capture_id
      join public.events   e on e.id = c.event_id
      where a.bucket = 'master'
        and a.object_path = storage.objects.name
        and app.is_org_member(e.organization_id)
    )
  );

-- Deliverables and quarantine have no non-service policy at all, by design.
