// Advancing one capture, one step at a time.
//
// The pipeline is written so that stopping it at any instant is safe. Every
// step reads its position from the database, does one externally-visible thing,
// and commits the result. There is no in-memory progress to lose, which is why
// `kill -9` costs at most one repeated step and never a photograph.

import { readFile, stat } from 'node:fs/promises';
import { unlink } from 'node:fs/promises';
import { extname } from 'node:path';
import { S } from './spool.js';
import { hashStable, sha256Buffer } from './hash.js';
import { PREVIEW_EXTENSIONS, RAW_EXTENSIONS } from './scanner.js';
import { recordServerContact, recordNetworkFailure } from './status.js';
import { TransientError, PermanentError, AuthorityError } from './client.js';

// =============================================================================
// The memory envelope, and the file-size ceiling derived from it.
// =============================================================================
// Uploads buffer whole files. That was a correctness choice — a consumed
// stream cannot be retried, and silently re-sending an empty body is worse
// than the memory cost — and it is kept, but it has to be bounded by a number
// rather than by optimism.
//
// Measured on this implementation (bridge/test/memory.test.js and the scaling
// probe recorded in docs/field-qualification.md), a single file under a retry
// storm costs roughly:
//
//     peak RSS  ~=  150 MiB baseline  +  3.6 x file size
//
//      60 MiB file -> 389 MiB      120 MiB file -> 474 MiB
//     200 MiB file -> 720 MiB
//
// The envelope is 1 GiB: a photographer's laptop is commonly 8 GB with
// Lightroom and a browser already open, and the Bridge's share has to be
// small enough to be uninteresting.
//
// Solving the relation for the envelope gives roughly 240 MiB. The shipped
// ceiling is 192 MiB, which keeps a margin and still clears every RAW format
// in ordinary use (a 61MP full-frame RAW is around 70-120 MiB).
//
// A file above the ceiling is rejected before it is read, with a reason the
// operator can act on. That is deliberately not silent and deliberately not a
// crash: exceeding the envelope would invite the OOM killer, and a Bridge
// killed by the OOM killer restarts and meets the same file again — an event
// that stalls forever on one photograph. Resumable multipart upload is the
// named follow-up that lifts this ceiling properly.
export const MEMORY_ENVELOPE_BYTES = 1024 * 1024 ** 2;
export const MEASURED_RSS_BASELINE_BYTES = 150 * 1024 ** 2;
export const MEASURED_RSS_PER_FILE_BYTE = 3.6;
export const DEFAULT_MAX_BYTES = 192 * 1024 ** 2;

const MAX_ATTEMPTS_BEFORE_REJECT = 12;
// How long a source file may be absent before the capture is given up on.
// Generous on purpose: a card reader pulled for thirty seconds, a network
// volume remounting, or a laptop waking from sleep must not cost a photograph.
// But a file the photographer moved or deleted must not wedge the spool
// forever either, so the wait is bounded.
const SOURCE_MISSING_GRACE_MS = 10 * 60_000;
// A bounded failure (checksum mismatch) gets fewer chances than a network
// outage, which gets unlimited ones.
const MAX_BOUNDED_ATTEMPTS = 5;

export class Pipeline {
  /**
   * @param {object} deps
   * @param {import('./spool.js').Spool} deps.spool
   * @param {object} deps.client
   * @param {object} deps.identity
   * @param {object} deps.sessions
   * @param {number} [deps.maxBytes] reject anything larger, rather than
   *   discovering the limit halfway through a venue's upload window
   */
  constructor({
    spool, client, identity, sessions,
    maxBytes = DEFAULT_MAX_BYTES,
    sourceMissingGraceMs = SOURCE_MISSING_GRACE_MS,
    log = () => {},
  }) {
    this.spool = spool;
    this.client = client;
    this.identity = identity;
    this.sessions = sessions;
    this.maxBytes = maxBytes;
    this.sourceMissingGraceMs = sourceMissingGraceMs;
    this.log = log;
  }

  /**
   * Advance a single capture by one step.
   * @returns {Promise<'advanced'|'idle'|'halted'>}
   */
  async step() {
    const row = this.spool.claimNext();
    if (!row) return 'idle';

    try {
      await this.#advance(row);
      this.spool.clearFailure(row.id);
      return 'advanced';
    } catch (err) {
      if (err instanceof AuthorityError) {
        // Authority was withdrawn mid-flight. The spool is untouched: every row
        // keeps its state and resumes if the device is re-authorised. Losing
        // permission must never look like losing photographs.
        this.log('authority', { code: err.code, message: err.message });
        if (err.code === 'device_revoked' || err.code === 'device_compromised') {
          this.identity.markRevoked(err.code === 'device_compromised' ? 'compromised' : 'revoked');
        }
        if (err.code === 'session_superseded') {
          // Not ours to resolve here: the run loop decides whether this was a
          // restart race or a second machine holding the same identity.
          this.lastAuthorityCode = err.code;
        }
        if (err.code?.startsWith('session')) this.sessions.clear();
        return 'halted';
      }

      if (err instanceof PermanentError) {
        this.spool.reject(row.id, err.code ?? 'permanent_error', { last_error: err.message });
        this.log('rejected', { id: row.id, reason: err.code ?? err.message });
        return 'advanced';
      }

      // A source file that is not there right now: the card may be out, or the
      // photographer may have moved it. Wait, then give up — and release the
      // group key so the file, if it merely moved, is picked up where it now is.
      if (err?.code === 'ENOENT') {
        const since = this.spool.noteSourceMissing(row.id);
        this.spool.recordFailure(row.id, err);
        if (Date.now() - since > this.sourceMissingGraceMs) {
          this.spool.rejectAndRelease(row.id, 'source_vanished',
            { last_error: `source absent for over ${Math.round(this.sourceMissingGraceMs / 1000)}s` });
          this.log('source-vanished', { id: row.id, path: row.master_path });
        }
        return 'advanced';
      }
      this.spool.clearSourceMissing(row.id);

      // A transient failure that never reached the server is what "offline"
      // actually means to a photographer.
      if (err instanceof TransientError && /network|fetch|socket|ECONN/i.test(err.message)) {
        recordNetworkFailure(this.spool.db);
      }

      const attempts = this.spool.recordFailure(row.id, err);

      if (err.bounded && attempts >= MAX_BOUNDED_ATTEMPTS) {
        this.spool.reject(row.id, 'checksum_mismatch_persistent', { last_error: err.message });
        this.log('rejected', { id: row.id, reason: 'checksum_mismatch_persistent' });
        return 'advanced';
      }
      if (err.bounded) {
        // Re-arm the upload so the next attempt actually re-sends the bytes
        // rather than asking the server to confirm the same bad object again.
        const rewind = { [S.UPLOADING_PREVIEW]: S.QUEUED, [S.UPLOADING_MASTER]: S.PREVIEW_CONFIRMED };
        const back = rewind[row.state];
        if (back) this.spool.transition(row.id, back, {});
        return 'advanced';
      }

      if (attempts >= MAX_ATTEMPTS_BEFORE_REJECT && row.state === S.DISCOVERED) {
        // Only local-side failures give up. A row that has reached the server
        // keeps retrying forever: the venue's wifi will come back, and a
        // photograph somebody may already have paid for is not ours to discard.
        this.spool.reject(row.id, 'unreadable', { last_error: err.message });
      }
      this.log('retry', { id: row.id, state: row.state, attempts, error: err.message });
      return 'advanced';
    }
  }

  async #advance(row) {
    switch (row.state) {
      case S.DISCOVERED:        return this.#hash(row);
      case S.HASHED:            return this.#announce(row);
      case S.QUEUED:            return this.#startPreview(row);
      case S.UPLOADING_PREVIEW: return this.#finishPreview(row);
      case S.PREVIEW_CONFIRMED: return this.#startMaster(row);
      case S.UPLOADING_MASTER:  return this.#finishMaster(row);
      case S.MASTER_CONFIRMED:  return this.#complete(row);
      default: throw new Error(`nothing to do for state ${row.state}`);
    }
  }

  // --- DISCOVERED → HASHED --------------------------------------------------

  async #hash(row) {
    // Before committing to a JPEG as the master, look directly for the RAW
    // half of the pair.
    //
    // The scanner would find it too, but only on a later tick — and a capture
    // carried over from a previous run is drained to completion before that
    // tick ever arrives, which splits one shutter press into two. Whether a
    // photograph is one capture or two must not depend on scan timing, so the
    // check is made here, against the filesystem, at the moment it matters.
    if (PREVIEW_EXTENSIONS.has(extname(row.master_path).toLowerCase())) {
      const sibling = await this.#findRawSibling(row.master_path);
      if (sibling) {
        this.spool.upgradeMasterToRaw(row.id, sibling.path, row.master_path, sibling.stat);
        this.log('master-upgraded', { id: row.id, raw: sibling.path });
        return;
      }
    }

    const result = await hashStable(row.master_path);

    if (result.changed) {
      // The camera or the operating system rewrote the file while we read it.
      // The digest belongs to neither version, so it is discarded and the row
      // waits for the file to settle again.
      this.spool.recordFailure(row.id, new Error('file changed while hashing'));
      return;
    }
    if (result.size > this.maxBytes) {
      this.spool.reject(row.id, 'too_large', { byte_size: result.size });
      return;
    }
    if (result.size === 0) {
      this.spool.reject(row.id, 'empty_file');
      return;
    }

    const patch = {
      content_sha256: result.sha256,
      byte_size: result.size,
      observed_size: result.size,
      observed_mtime_ms: result.mtimeMs,
    };

    if (row.preview_path && row.preview_path !== row.master_path) {
      const p = await hashStable(row.preview_path);
      if (p.changed) {
        this.spool.recordFailure(row.id, new Error('preview changed while hashing'));
        return;
      }
      patch.preview_sha256 = p.sha256;
      patch.preview_size = p.size;
    } else if (row.preview_path) {
      patch.preview_sha256 = result.sha256;
      patch.preview_size = result.size;
    }

    try {
      this.spool.transition(row.id, S.HASHED, patch);
    } catch (err) {
      // The unique index on (event_id, content_sha256) fired: these exact bytes
      // are already a capture in this event. One photograph, one capture.
      if (String(err.message).includes('UNIQUE')) {
        this.spool.reject(row.id, 'duplicate_content', { content_sha256: null });
        this.log('duplicate', { id: row.id, path: row.master_path });
        return;
      }
      throw err;
    }
  }

  /** The RAW sitting next to a JPEG, if the camera wrote one. */
  async #findRawSibling(masterPath) {
    const stem = masterPath.slice(0, masterPath.length - extname(masterPath).length);
    for (const ext of RAW_EXTENSIONS) {
      for (const cased of [ext, ext.toUpperCase()]) {
        const candidate = stem + cased;
        try {
          const st = await stat(candidate);
          if (st.isFile() && st.size > 0) return { path: candidate, stat: st };
        } catch { /* not this one */ }
      }
    }
    return null;
  }

  // --- HASHED → QUEUED ------------------------------------------------------

  /**
   * Announce the capture and hold on to the upload authorizations.
   *
   * The idempotency key was written at discovery, before any of this, so a
   * crash between the server creating the capture and us recording its id
   * resolves on retry to the same capture rather than to a second one.
   */
  async #announce(row) {
    // Cheap guard before the digest becomes a promise to the server: if size or
    // mtime moved since hashing, re-hash instead of announcing a stale digest.
    //
    // A file that is not there right now is deliberately NOT rejected here.
    // This used to reject on the spot, which meant a card reader pulled for two
    // seconds permanently discarded every capture in this window — and because
    // the rejection kept the group key, the file coming back was never
    // rediscovered. Photographs were lost by unplugging a cable. The error is
    // raised instead, so the missing-source grace in step() applies: wait, then
    // give up, then release the key.
    const st = await stat(row.master_path);
    if (st.size !== row.observed_size || st.mtimeMs !== row.observed_mtime_ms) {
      this.spool.transition(row.id, S.DISCOVERED, { last_error: 'changed before announce; re-hashing' });
      return;
    }

    const res = await this.#announceRaw(row);
    this.spool.transition(row.id, S.QUEUED, { server_capture_id: res.capture_id });
    this.#targets.set(row.id, { ...res, at: Date.now() });
  }

  /** @type {Map<number, any>} upload targets are short-lived; never persisted. */
  #targets = new Map();

  async #announceRaw(row) {
    const session = this.sessions.current();
    if (!session?.token) throw new AuthorityError('no event session', { code: 'session_expired' });

    try {
      return await this.client.announceCapture({
        idempotency_key: row.idempotency_key,
        event_id: row.event_id,
        device_sequence: row.device_sequence,
        captured_at: row.captured_at,
        content_sha256: row.content_sha256,
        byte_size: row.byte_size,
        preview_sha256: row.preview_sha256 ?? null,
        preview_size: row.preview_size ?? null,
        filename_hint: row.master_path.split('/').pop(),
      });
    } catch (err) {
      // Another Bridge, or an earlier install of this one, already used this
      // sequence number. Take the next one and retry rather than stalling.
      if (err instanceof PermanentError && err.code === 'sequence_conflict') {
        const next = this.spool.reassignSequence(row.id);
        this.log('sequence-conflict', { id: row.id, newSequence: next });
        throw new TransientError('sequence reassigned; retrying');
      }
      throw err;
    }
  }

  async #freshTargets(row) {
    const cached = this.#targets.get(row.id);
    if (cached && Date.now() - cached.at < 5 * 60_000) return cached;
    const res = await this.#announceRaw(row);   // idempotent; returns fresh URLs
    const entry = { ...res, at: Date.now() };
    this.#targets.set(row.id, entry);
    return entry;
  }

  // --- QUEUED → PREVIEW_CONFIRMED ------------------------------------------

  async #startPreview(row) {
    if (!row.preview_path) {
      // RAW-only capture. There is no camera JPEG to send ahead, and the Bridge
      // deliberately does not render one: customer-facing pixels are produced
      // by the sandboxed server-side worker, not by a laptop at a venue.
      this.spool.transition(row.id, S.UPLOADING_PREVIEW, { preview_skipped: 1 });
      this.spool.transition(row.id, S.PREVIEW_CONFIRMED, {});
      return;
    }
    this.spool.transition(row.id, S.UPLOADING_PREVIEW, {});
  }

  async #finishPreview(row) {
    const targets = await this.#freshTargets(row);
    const body = await readFile(row.preview_path);

    // Re-verify before sending. Between hashing and uploading the file may have
    // been replaced; uploading bytes whose digest we never computed would give
    // the server something to confirm that we cannot vouch for.
    const digest = sha256Buffer(body);
    if (digest !== row.preview_sha256) {
      // The server has already been told this capture's digest. We cannot
      // quietly substitute different bytes, and re-announcing under the same
      // idempotency key would be refused. Retire this capture and free the
      // group key so the image now on disk is rediscovered on its own terms.
      this.spool.rejectAndRelease(row.id, 'content_changed_after_announce',
        { last_error: 'preview bytes changed between hashing and upload' });
      this.log('content-changed', { id: row.id, path: row.preview_path });
      return;
    }

    await this.client.uploadAsset({ target: targets.preview_upload, body });

    // The upload returning 200 proves nothing. This does.
    const ack = await this.client.confirmAsset({
      captureId: row.server_capture_id, kind: 'preview',
      sha256: digest, byteSize: body.byteLength,
    });
    if (ack?.status !== 'confirmed' || !ack.asset_id) {
      throw new TransientError('preview not confirmed by server');
    }
    if (ack.sha256 && ack.sha256 !== digest) {
      throw new TransientError('server stored a different preview digest');
    }

    recordServerContact(this.spool.db);
    this.spool.transition(row.id, S.PREVIEW_CONFIRMED, { preview_asset_id: ack.asset_id });
  }

  // --- PREVIEW_CONFIRMED → MASTER_CONFIRMED --------------------------------

  async #startMaster(row) {
    this.spool.transition(row.id, S.UPLOADING_MASTER, {});
  }

  async #finishMaster(row) {
    const targets = await this.#freshTargets(row);
    const body = await readFile(row.master_path);

    const digest = sha256Buffer(body);
    if (digest !== row.content_sha256) {
      this.spool.rejectAndRelease(row.id, 'content_changed_after_announce',
        { last_error: 'master bytes changed between hashing and upload' });
      this.log('content-changed', { id: row.id, path: row.master_path });
      return;
    }

    await this.client.uploadAsset({ target: targets.master_upload, body });

    const ack = await this.client.confirmAsset({
      captureId: row.server_capture_id, kind: 'master',
      sha256: digest, byteSize: body.byteLength,
    });
    if (ack?.status !== 'confirmed' || !ack.asset_id) {
      throw new TransientError('master not confirmed by server');
    }
    if (ack.sha256 && ack.sha256 !== digest) {
      throw new TransientError('server stored a different master digest');
    }

    recordServerContact(this.spool.db);
    this.spool.transition(row.id, S.MASTER_CONFIRMED, { master_asset_id: ack.asset_id });
  }

  // --- MASTER_CONFIRMED → COMPLETE -----------------------------------------

  async #complete(row) {
    this.spool.transition(row.id, S.COMPLETE, {
      completed_at: new Date().toISOString(),
      cleanup_eligible_at: null,   // set by the retention policy, never here
    });
    this.#targets.delete(row.id);
  }

  /**
   * Local cleanup. Note what it is not: a step in the pipeline. Reaching
   * COMPLETE makes a file *eligible* for deletion and nothing more.
   *
   * Deletion requires, all at once: the server confirmed the master, the
   * retention window has elapsed, and the bytes on disk still hash to what the
   * server acknowledged. The default retention is null — never delete — because
   * the correct default for somebody's only copy of a wedding is to keep it.
   */
  async sweepCleanup({ retentionMs = null, now = Date.now() } = {}) {
    if (retentionMs == null) return { deleted: 0, skipped: 0, reason: 'retention disabled' };

    const rows = this.spool.db.prepare(`
      select * from captures
       where state = ? and master_asset_id is not null and local_deleted_at is null
    `).all(S.COMPLETE);

    let deleted = 0, skipped = 0;
    for (const row of rows) {
      const completedAt = Date.parse(row.completed_at ?? '');
      if (!completedAt || now - completedAt < retentionMs) { skipped++; continue; }

      let st;
      try { st = await stat(row.master_path); } catch { skipped++; continue; }
      if (st.size !== row.byte_size) { skipped++; continue; }

      const check = await hashStable(row.master_path);
      if (check.changed || check.sha256 !== row.content_sha256) {
        // Something else is on disk under that name now. Deleting it would
        // destroy a file the server has never seen.
        this.log('cleanup-skip', { id: row.id, reason: 'content no longer matches' });
        skipped++; continue;
      }

      await unlink(row.master_path);
      this.spool.db.prepare('update captures set local_deleted_at = ? where id = ?')
        .run(new Date(now).toISOString(), row.id);
      deleted++;
    }
    return { deleted, skipped };
  }
}
