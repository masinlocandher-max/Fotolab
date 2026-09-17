// The capture spool state machine.
//
//   DISCOVERED → HASHED → QUEUED → UPLOADING_PREVIEW → PREVIEW_CONFIRMED
//              → UPLOADING_MASTER → MASTER_CONFIRMED → COMPLETE
//
// Two rules the rest of the Bridge is built to respect:
//
//  1. Failure is not a state. A failed attempt records an error and a backoff
//     on the row it failed in; it never rewinds or erases progress. Restarting
//     the process resumes every non-terminal row exactly where it stopped.
//
//  2. A *_CONFIRMED transition may only be driven by a server acknowledgement
//     that names the asset the server stored. An HTTP request completing on
//     this laptop tells us nothing about what the server durably has.

import { randomUUID } from 'node:crypto';
import { tx } from './db.js';

export const S = {
  DISCOVERED:        'discovered',
  HASHED:            'hashed',
  QUEUED:            'queued',
  UPLOADING_PREVIEW: 'uploading_preview',
  PREVIEW_CONFIRMED: 'preview_confirmed',
  UPLOADING_MASTER:  'uploading_master',
  MASTER_CONFIRMED:  'master_confirmed',
  COMPLETE:          'complete',
  REJECTED:          'rejected',   // terminal: corrupt, oversized, duplicate
};

export const TERMINAL = new Set([S.COMPLETE, S.REJECTED]);

// A row may only move along these edges. Anything else is a bug, and is raised
// as one rather than silently tolerated.
const ALLOWED = {
  [S.DISCOVERED]:        new Set([S.HASHED, S.REJECTED]),
  [S.HASHED]:            new Set([S.QUEUED, S.DISCOVERED, S.REJECTED]),
  [S.QUEUED]:            new Set([S.UPLOADING_PREVIEW, S.REJECTED]),
  [S.UPLOADING_PREVIEW]: new Set([S.PREVIEW_CONFIRMED, S.QUEUED, S.REJECTED]),
  [S.PREVIEW_CONFIRMED]: new Set([S.UPLOADING_MASTER, S.REJECTED]),
  [S.UPLOADING_MASTER]:  new Set([S.MASTER_CONFIRMED, S.PREVIEW_CONFIRMED, S.REJECTED]),
  [S.MASTER_CONFIRMED]:  new Set([S.COMPLETE]),
  [S.COMPLETE]:          new Set([]),
  [S.REJECTED]:          new Set([]),
};

// HASHED → DISCOVERED and UPLOADING_* → previous are the "resume" edges: a file
// that changed under us re-stabilises, an interrupted upload re-arms. They are
// explicit so that a rewind is a deliberate move and not an accident.

export class Spool {
  constructor(db, { now = () => Date.now() } = {}) {
    this.db = db;
    this.now = now;
  }

  /**
   * Record a newly seen file. This is the durability boundary: the row is
   * committed before the Bridge hashes a byte or opens a socket, so a crash
   * one millisecond later still leaves evidence that the photograph exists.
   *
   * Returns the row, or null if this path is already known — which is how
   * duplicate filesystem notifications collapse.
   */
  discover({ groupKey, masterPath, previewPath, eventId, size, mtimeMs, capturedAt,
             roleCollision = false, hasRaw = false }) {
    return tx(this.db, () => {
      const existing = this.db.prepare('select * from captures where group_key = ?').get(groupKey);

      if (existing) {
        return this.#reconcileExisting(existing, {
          groupKey, masterPath, previewPath, eventId, size, mtimeMs, capturedAt, hasRaw,
        });
      }

      return this.#insert({
        groupKey, masterPath, previewPath, eventId, size, mtimeMs, capturedAt, roleCollision,
      });
    });
  }

  #insert({ groupKey, masterPath, previewPath, eventId, size, mtimeMs, capturedAt,
            roleCollision = false, siblingGroupKey = null }) {
    const seq = this.#allocateSequence();
    this.db.prepare(`
      insert into captures
        (idempotency_key, group_key, master_path, preview_path, event_id, device_sequence,
         state, discovered_at, observed_size, observed_mtime_ms, stable_since_ms, captured_at,
         role_collision, sibling_group_key)
      values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      randomUUID(), groupKey, masterPath, previewPath ?? null, eventId, seq, S.DISCOVERED,
      new Date(this.now()).toISOString(), size, mtimeMs, this.now(),
      capturedAt ?? new Date(mtimeMs).toISOString(),
      roleCollision ? 1 : 0, siblingGroupKey
    );
    return this.byGroup(groupKey);
  }

  /**
   * A group key we have seen before. Three genuinely different situations hide
   * behind that, and collapsing them into "already known" loses photographs.
   *
   * They are told apart by the path, not by guesswork:
   *
   *   same path, different bytes      → the camera reused the filename
   *   different path, same stem       → the other half of one shutter press
   *   same path, same bytes           → a repeated scan; nothing to do
   */
  #reconcileExisting(row, incoming) {
    const { masterPath, previewPath, size, mtimeMs, hasRaw } = incoming;
    const preAnnounce = row.state === S.DISCOVERED || row.state === S.HASHED;
    const isSibling = masterPath !== row.master_path;

    // The RAW half of a pair, arriving after we settled on the JPEG.
    if (isSibling && hasRaw) {
      // Before announcing, the capture is simply upgraded: the RAW becomes the
      // master and the JPEG the preview, which is what one shutter press
      // always meant.
      if (preAnnounce) {
        this.db.prepare(`
          update captures
             set master_path = ?, preview_path = ?, observed_size = ?, observed_mtime_ms = ?,
                 content_sha256 = null, byte_size = null,
                 preview_sha256 = null, preview_size = null,
                 state = ?, last_error = 'master upgraded to RAW; re-hashing'
           where id = ?
        `).run(masterPath, previewPath ?? row.preview_path, size, mtimeMs, S.DISCOVERED, row.id);
        return null;
      }

      // Too late to change what the server was told. The RAW goes up as its
      // own capture with the relationship recorded, so the server can
      // reconcile two rows rather than us losing a master. This is the
      // documented cost of a RAW that lands after its JPEG was announced.
      const own = this.db.prepare('select * from captures where group_key = ?').get(masterPath);
      if (!own) {
        this.#insert({ ...incoming, groupKey: masterPath, previewPath: null,
                       siblingGroupKey: row.group_key });
      }
      return null;
    }

    // The JPEG half arriving after the RAW. The master path does not change —
    // the RAW was already the master — so this is not a sibling swap, only a
    // preview appearing. It can be attached until we have told the server what
    // the preview digest is.
    if (previewPath && !row.preview_path && preAnnounce) {
      this.db.prepare(`
        update captures set preview_path = ?, preview_sha256 = null, preview_size = null,
                            state = ?
         where id = ?
      `).run(previewPath, S.DISCOVERED, row.id);
      return null;
    }

    // Same path, different bytes: the counter wrapped past 9999, or the card
    // was reformatted and reused. The finished capture keeps its history; the
    // new photograph gets its own row rather than vanishing.
    if (!isSibling && TERMINAL.has(row.state) &&
        (size !== row.observed_size || mtimeMs !== row.observed_mtime_ms)) {
      const retired = `${row.group_key}#superseded-${row.id}`;
      this.db.prepare('update captures set group_key = ? where id = ?').run(retired, row.id);
      return this.#insert(incoming);
    }

    return null;
  }

  // Sequence numbers are per-device and must never be reused, so they come from
  // a high-water mark that only moves forward — not from max(device_sequence),
  // which would recycle a number after a row is pruned.
  #allocateSequence() {
    const row = this.db.prepare(`select value from meta where key = 'sequence_hwm'`).get();
    const next = (row ? Number(row.value) : 0) + 1;
    this.db.prepare(
      `insert into meta(key, value) values('sequence_hwm', ?)
       on conflict(key) do update set value = excluded.value`
    ).run(String(next));
    return next;
  }

  /** Force the high-water mark forward, e.g. after a server sequence conflict. */
  bumpSequenceTo(value) {
    tx(this.db, () => {
      const row = this.db.prepare(`select value from meta where key = 'sequence_hwm'`).get();
      const cur = row ? Number(row.value) : 0;
      if (value > cur) {
        this.db.prepare(
          `insert into meta(key, value) values('sequence_hwm', ?)
           on conflict(key) do update set value = excluded.value`
        ).run(String(value));
      }
    });
  }

  reassignSequence(id) {
    return tx(this.db, () => {
      const seq = this.#allocateSequence();
      this.db.prepare('update captures set device_sequence = ? where id = ?').run(seq, id);
      return seq;
    });
  }

  byId(id)        { return this.db.prepare('select * from captures where id = ?').get(id); }
  byGroup(key)    { return this.db.prepare('select * from captures where group_key = ?').get(key); }

  /**
   * Move a row to `next`, optionally writing more columns in the same commit.
   * The state change and the facts that justify it land atomically — a
   * capture_id is never visible without the state that earned it.
   */
  transition(id, next, patch = {}) {
    return tx(this.db, () => {
      const row = this.db.prepare('select * from captures where id = ?').get(id);
      if (!row) throw new Error(`capture ${id} not found`);

      const allowed = ALLOWED[row.state];
      if (!allowed) throw new Error(`capture ${id} is in unknown state ${row.state}`);
      if (row.state !== next && !allowed.has(next)) {
        throw new Error(`illegal capture transition ${row.state} -> ${next}`);
      }

      const cols = Object.keys(patch);
      const sets = ['state = ?', ...cols.map((c) => `${c} = ?`)];
      const vals = [next, ...cols.map((c) => patch[c])];
      this.db.prepare(`update captures set ${sets.join(', ')} where id = ?`).run(...vals, id);
      return this.db.prepare('select * from captures where id = ?').get(id);
    });
  }

  /**
   * Record a failed attempt without losing position. Backoff is exponential
   * with jitter so a fleet of Bridges reconnecting after venue wifi returns
   * does not arrive as one thundering herd.
   */
  recordFailure(id, error, { baseMs = 1000, maxMs = 60_000 } = {}) {
    return tx(this.db, () => {
      const row = this.db.prepare('select attempts from captures where id = ?').get(id);
      const attempts = (row?.attempts ?? 0) + 1;
      const backoff = Math.min(maxMs, baseMs * 2 ** Math.min(attempts - 1, 16));
      const jittered = Math.floor(backoff * (0.5 + Math.random() * 0.5));
      this.db.prepare(`
        update captures
           set attempts = ?, last_error = ?, last_attempt_at = ?, next_attempt_at_ms = ?
         where id = ?
      `).run(attempts, String(error?.message ?? error).slice(0, 500),
             new Date(this.now()).toISOString(), this.now() + jittered, id);
      return attempts;
    });
  }

  /** Record when a source file first went missing; returns that timestamp. */
  noteSourceMissing(id) {
    return tx(this.db, () => {
      const row = this.db.prepare('select source_missing_since from captures where id = ?').get(id);
      if (row?.source_missing_since) return row.source_missing_since;
      const now = this.now();
      this.db.prepare('update captures set source_missing_since = ? where id = ?').run(now, id);
      return now;
    });
  }

  clearSourceMissing(id) {
    this.db.prepare('update captures set source_missing_since = null where id = ? and source_missing_since is not null').run(id);
  }

  clearFailure(id) {
    this.db.prepare(
      'update captures set attempts = 0, last_error = null, next_attempt_at_ms = 0 where id = ?'
    ).run(id);
  }

  reject(id, reason, extra = {}) {
    return this.transition(id, S.REJECTED, { rejected_reason: reason, ...extra });
  }

  /**
   * Reject a capture and hand its group key back, so the file on disk can be
   * rediscovered as a new photograph.
   *
   * Used when the bytes behind a filename change after we already told the
   * server what was there. The announced capture is dead — the server is
   * holding a digest that no longer exists — but the image now on disk is real
   * and must not be silently dropped just because it inherited a filename.
   */
  rejectAndRelease(id, reason, extra = {}) {
    return tx(this.db, () => {
      const row = this.db.prepare('select * from captures where id = ?').get(id);
      const freed = `${row.group_key}#retired-${id}`;
      this.db.prepare('update captures set group_key = ? where id = ?').run(freed, id);
      this.db.prepare(`
        update captures set state = ?, rejected_reason = ?, last_error = ? where id = ?
      `).run(S.REJECTED, reason, String(extra.last_error ?? reason).slice(0, 500), id);
      return this.db.prepare('select * from captures where id = ?').get(id);
    });
  }

  /**
   * The next row due for work, oldest first. Ordering by device_sequence rather
   * than id keeps uploads in shutter order, which is what a photographer
   * watching a gallery fill expects to see.
   */
  claimNext(states = null) {
    const list = states ?? [
      S.DISCOVERED, S.HASHED, S.QUEUED, S.UPLOADING_PREVIEW,
      S.PREVIEW_CONFIRMED, S.UPLOADING_MASTER, S.MASTER_CONFIRMED,
    ];
    const marks = list.map(() => '?').join(',');
    return this.db.prepare(`
      select * from captures
       where state in (${marks}) and next_attempt_at_ms <= ?
       order by device_sequence asc
       limit 1
    `).get(...list, this.now());
  }

  /** Every non-terminal row, for resume-on-start. */
  pending() {
    return this.db.prepare(`
      select * from captures where state not in (?, ?) order by device_sequence asc
    `).all(S.COMPLETE, S.REJECTED);
  }

  /**
   * Called once at startup. Rows caught mid-flight by a crash are rewound to
   * the last state they can safely retry from — never past a confirmation the
   * server already gave us.
   */
  recover() {
    const rewind = {
      [S.UPLOADING_PREVIEW]: S.QUEUED,
      [S.UPLOADING_MASTER]:  S.PREVIEW_CONFIRMED,
    };
    let n = 0;
    for (const row of this.pending()) {
      const target = rewind[row.state];
      if (target) {
        this.transition(row.id, target, { last_error: 'interrupted; resuming' });
        n++;
      }
    }
    return n;
  }

  counts() {
    const rows = this.db.prepare('select state, count(*) n from captures group by state').all();
    return Object.fromEntries(rows.map((r) => [r.state, r.n]));
  }
}
