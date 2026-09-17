-- =============================================================================
-- Fotolab :: 0008 :: Revoke function EXECUTE from PUBLIC
-- =============================================================================
-- Every earlier migration wrote
--
--     revoke all on function app.something(...) from anon, authenticated;
--
-- believing that closed the function to the Data API. It did not. PostgreSQL
-- grants EXECUTE on a new function to PUBLIC by default, and revoking from a
-- role does not remove a grant held by PUBLIC. `anon` kept EXECUTE on every
-- one of them the whole time.
--
-- The practical exposure was nil, because USAGE on schema `app` is revoked and
-- a function cannot be called without reaching its schema. But that makes the
-- entire protection rest on a single grant: anyone exposing one helper by
-- granting USAGE would silently hand anon the download chokepoint, the price
-- resolver, the order-token consumer and the session opener at the same time.
--
-- Defence in depth means the second layer has to actually be there.
-- =============================================================================

do $$
declare fn record;
begin
  for fn in
    select p.oid::regprocedure as sig
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'app'
  loop
    execute format('revoke all on function %s from public', fn.sig);
  end loop;
end;
$$;

-- And for everything added later, so this cannot regress by omission.
alter default privileges in schema app revoke execute on functions from public;

-- -----------------------------------------------------------------------------
-- Two functions genuinely must be callable by the Data API: RLS policy
-- expressions are evaluated as the querying role, and every org-scoped policy
-- calls one of these membership predicates. They were working only because of
-- PUBLIC's default grant, which is not a thing to depend on.
--
-- So they are granted explicitly, by name, to `authenticated` alone. Both are
-- read-only predicates that answer one question — "is the caller a member of
-- this organization, in this role?" — and reveal nothing a member could not
-- already read. `anon` is not granted them: an anonymous caller has no
-- membership to test.
-- -----------------------------------------------------------------------------

grant usage on schema app to authenticated;
grant execute on function app.is_org_member(uuid) to authenticated;
grant execute on function app.has_org_role(uuid, public.org_role[]) to authenticated;

-- Granting schema USAGE above is now safe in a way it would not have been an
-- hour ago: every other function in `app` has had EXECUTE revoked from PUBLIC,
-- so reaching the schema no longer means reaching the download chokepoint, the
-- price resolver, the order-token consumer or the session opener.
--
-- Anything else that needs to be callable from the Data API must be granted
-- explicitly, by name, in its own migration — never by default.
