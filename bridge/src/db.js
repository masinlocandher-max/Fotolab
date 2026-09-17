// Durable local store for the capture spool.
//
// Everything in the Bridge rests on one property: a row that has been committed
// here survives `kill -9` and survives the laptop losing power. WAL plus
// synchronous=FULL is what buys that — WAL alone will happily lose the last
// transactions on power loss, which for us means losing a photograph somebody
// already paid for.
//
// node:sqlite is still flagged experimental by Node. The durability itself is
// SQLite's, not Node's, so the risk is API churn on upgrade rather than data
// loss; the surface we use is deliberately tiny (exec/prepare/run/get/all).

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const SCHEMA = `
create table if not exists meta (
  key   text primary key,
  value text not null
);

-- One installation, one device identity.
create table if not exists device (
  id               integer primary key check (id = 1),
  device_id        text,               -- server-authoritative; null until enrolled
  organization_id  text,               -- server-authoritative
  public_key_pem   text not null,
  private_key      text not null,      -- PKCS8 PEM, or an encrypted envelope
  key_encrypted    integer not null default 0,
  label            text,
  status           text not null default 'pending',
  enrolled_at      text,
  revoked_noticed_at text
);

-- The current short-lived, event-scoped credential. Deliberately a single row:
-- a Bridge shoots one event at a time, and holding several live event
-- credentials at once is authority we have no use for.
create table if not exists session (
  id              integer primary key check (id = 1),
  session_id      text,
  event_id        text,
  organization_id text,
  token           text,
  expires_at      text,
  obtained_at     text
);

-- A "capture" is one photograph, which on disk may be one file or two: a
-- camera shooting JPEG+RAW writes DSC0123.JPG and DSC0123.CR3 for a single
-- press of the shutter. Keying on the file path would make that two
-- photographs, charge for it twice, and show it twice in the gallery. The
-- group key is (directory, basename-without-extension).
create table if not exists captures (
  id                  integer primary key autoincrement,
  idempotency_key     text not null unique,
  group_key           text not null unique,
  master_path         text not null,
  event_id            text not null,
  device_sequence     integer not null,
  state               text not null,

  discovered_at       text not null,
  observed_size       integer,
  observed_mtime_ms   integer,
  stable_since_ms     integer,

  content_sha256      text,
  byte_size           integer,
  captured_at         text,

  preview_path        text,
  preview_sha256      text,
  preview_size        integer,
  preview_skipped     integer not null default 0,

  server_capture_id   text,
  preview_asset_id    text,
  master_asset_id     text,

  attempts            integer not null default 0,
  last_error          text,
  last_attempt_at     text,
  next_attempt_at_ms  integer not null default 0,

  completed_at        text,
  cleanup_eligible_at text,
  local_deleted_at    text,
  rejected_reason     text,
  duplicate_of        integer
);

-- Duplicate filesystem notifications for one file collapse here.
create unique index if not exists captures_group_idx on captures(group_key);
-- The same bytes arriving twice in one event is one photograph, whatever the
-- camera called the file.
create unique index if not exists captures_content_idx
  on captures(event_id, content_sha256) where content_sha256 is not null;
create unique index if not exists captures_sequence_idx on captures(device_sequence);
create index if not exists captures_state_idx on captures(state, next_attempt_at_ms);
`;

/**
 * Open (and if needed create) the spool database.
 * @param {string} file absolute path to the sqlite file
 */
export function openDb(file) {
  if (file !== ':memory:') mkdirSync(dirname(file), { recursive: true });
  const db = new DatabaseSync(file);

  // Order matters: journal_mode before synchronous, foreign_keys per-connection.
  db.exec('pragma journal_mode = WAL');
  db.exec('pragma synchronous = FULL');
  db.exec('pragma foreign_keys = ON');
  db.exec('pragma busy_timeout = 5000');
  db.exec(SCHEMA);
  migrate(db);

  return db;
}

// Columns added after the first release. `create table if not exists` will not
// add them to a spool that already exists on a photographer's laptop, and that
// spool may be holding an unfinished event, so it is migrated in place rather
// than recreated.
const ADDED_COLUMNS = [
  ['captures', 'sibling_group_key',   'text'],
  ['captures', 'source_missing_since', 'integer'],
  ['captures', 'role_collision',       'integer not null default 0'],
];

function migrate(db) {
  for (const [table, column, type] of ADDED_COLUMNS) {
    const cols = db.prepare(`pragma table_info(${table})`).all().map((c) => c.name);
    if (!cols.includes(column)) {
      db.exec(`alter table ${table} add column ${column} ${type}`);
    }
  }

  // Early spools used a NUL byte between directory and basename. SQLite
  // truncates text at the NUL for every string operation, so those keys are
  // unreadable and ambiguous. They are rebuilt from master_path, which is
  // intact, rather than left for someone to repair by hand at an event.
  const legacy = db.prepare(
    `select id, master_path from captures where instr(group_key, char(0)) > 0 or group_key not like '%/%'`
  ).all();
  for (const row of legacy) {
    const path = row.master_path;
    const slash = path.lastIndexOf('/');
    const dot = path.lastIndexOf('.');
    const rebuilt = dot > slash ? path.slice(0, dot) : path;
    try {
      db.prepare('update captures set group_key = ? where id = ?').run(rebuilt, row.id);
    } catch {
      // A collision means two legacy rows shared a stem; leave the second one
      // under its old key rather than destroying the first.
    }
  }
}

/**
 * Run `fn` inside an IMMEDIATE transaction. Rolls back on throw.
 * IMMEDIATE rather than DEFERRED so two Bridge processes racing on the same
 * spool fail fast on the write lock instead of mid-transaction.
 */
export function tx(db, fn) {
  db.exec('begin immediate');
  try {
    const out = fn();
    db.exec('commit');
    return out;
  } catch (err) {
    try { db.exec('rollback'); } catch { /* already rolled back */ }
    throw err;
  }
}

export function getMeta(db, key, fallback = null) {
  const row = db.prepare('select value from meta where key = ?').get(key);
  return row ? row.value : fallback;
}

export function setMeta(db, key, value) {
  db.prepare(
    'insert into meta(key, value) values(?, ?) on conflict(key) do update set value = excluded.value'
  ).run(key, String(value));
}
