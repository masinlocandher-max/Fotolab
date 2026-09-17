// Field qualification harness.
//
// A simulated multi-hour event: photographs arriving over time in the mixes a
// real camera produces, while everything that can go wrong at a venue does.
//
// The harness is built around one rule it enforces on itself: a fault that did
// not actually happen, or happened when there was no work in flight, proves
// nothing. Every injection is recorded with the spool depth at that instant,
// and the run fails its own audit if any fault type never landed on live work.

import { fork } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  writeFileSync, mkdirSync, renameSync, rmSync, existsSync, appendFileSync, statSync,
} from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FakeServer } from './fake-server.js';
import { openDb } from '../src/db.js';

const WORKER = fileURLToPath(new URL('./worker.js', import.meta.url));
const MiB = 1024 ** 2;

export const FAULTS = [
  'process_death', 'machine_restart', 'network_down', 'request_timeout',
  'lost_ack', 'server_5xx', 'corrupt_transfer', 'duplicate_fs_event',
  'card_removed', 'low_disk', 'slow_write', 'interrupted_write',
  'file_renamed', 'file_moved',
];

function sha(buf) { return createHash('sha256').update(buf).digest('hex'); }
const rnd = (n) => Math.floor(Math.random() * n);
const pick = (a) => a[rnd(a.length)];

export class FieldHarness {
  /**
   * @param {object} opts
   * @param {number} opts.shutterPresses how many photographs the event produces
   * @param {number} [opts.batches] how many worker lifetimes the run spans
   */
  /**
   * @param {number} [opts.sizeScale] multiplier on file sizes. 1 is realistic
   *   (2 MiB JPEG, 12 MiB RAW, 40 MiB big RAW). The short CI run scales down so
   *   the harness itself stays exercised without spending ten minutes on I/O;
   *   the qualification gate runs at 1.
   */
  constructor({ shutterPresses = 1200, batches = 30, verbose = false, sizeScale = 1 } = {}) {
    this.target = shutterPresses;
    // Every fault type must get its scheduled turn, so the run cannot be
    // shorter than the rotation. A run that skips fault types is a run whose
    // audit passes only because it never asked the question.
    this.batches = Math.max(batches, FAULTS.length);
    this.verbose = verbose;
    this.sizeScale = sizeScale;

    this.home = join('/tmp', `fq-home-${randomUUID().slice(0, 8)}`);
    this.card = join('/tmp', `fq-card-${randomUUID().slice(0, 8)}`);
    mkdirSync(this.home, { recursive: true });
    mkdirSync(this.card, { recursive: true });

    /** Every shutter press the "camera" performed: stem -> expected digests. */
    this.pressed = new Map();
    /** Faults actually injected, with the spool depth at the moment. */
    this.ledger = [];
    this.peakRssBytes = 0;
    this.cardDir = 0;
    this.pressCount = 0;
  }

  log(...a) { if (this.verbose) console.log('   ', ...a); }

  async start() {
    this.server = new FakeServer();
    await this.server.listen();
    this.enrollCode = this.server.enrollDevice();
  }

  async stop() {
    await this.server?.close();
    rmSync(this.home, { recursive: true, force: true });
    rmSync(this.card, { recursive: true, force: true });
  }

  // --- the camera ----------------------------------------------------------

  #dir() {
    // Cameras roll to a new folder every 999 frames and restart numbering.
    const d = join(this.card, `${100 + this.cardDir}CANON`);
    if (!existsSync(d)) mkdirSync(d, { recursive: true });
    return d;
  }

  /**
   * One press of the shutter. Returns the stem so faults can target it.
   * The mix is deliberately uneven: most frames are ordinary, a few are the
   * awkward ones that break naive implementations.
   */
  press({ slow = false, interrupted = false } = {}) {
    const n = this.pressCount++;
    if (n > 0 && n % 999 === 0) this.cardDir++;
    const dir = this.#dir();
    const name = `IMG_${String(n % 10000).padStart(4, '0')}`;
    const stem = join(dir, name);

    const roll = rnd(100);
    const kind = roll < 45 ? 'pair' : roll < 80 ? 'jpeg' : roll < 95 ? 'raw' : 'bigraw';

    const files = {};
    const scale = this.sizeScale;
    const jpegBody = Buffer.from(`jpeg-${n}-${randomUUID()}`.padEnd(Math.max(4096, 2 * MiB * scale), 'j'));
    const rawSize = Math.max(8192, (kind === 'bigraw' ? 40 * MiB : 12 * MiB) * scale);
    const rawBody = Buffer.from(`raw-${n}-${randomUUID()}`.padEnd(rawSize, 'r'));

    if (kind === 'pair' || kind === 'jpeg') {
      files[`${stem}.JPG`] = jpegBody;
    }
    if (kind === 'pair' || kind === 'raw' || kind === 'bigraw') {
      files[`${stem}.CR3`] = rawBody;
    }

    for (const [path, body] of Object.entries(files)) {
      if (interrupted) {
        // A write that dies halfway: the truncated file is left on the card
        // and completed on the next pass, as a stalled card transfer does.
        writeFileSync(path, body.subarray(0, Math.floor(body.length / 3)));
        this.pendingCompletions ??= [];
        this.pendingCompletions.push([path, body]);
      } else if (slow) {
        // Left half-written here; completed by finishSlowWrites() after the
        // scanner has had a chance to see it mid-growth.
        writeFileSync(path, body.subarray(0, Math.floor(body.length / 2)));
        this.pendingSlowWrites ??= [];
        this.pendingSlowWrites.push([path, body]);
      } else {
        writeFileSync(path, body);
      }
    }

    // Expected content is only recorded for files that will actually be
    // complete; an interrupted write is finished later and recorded then.
    // Expected content is recorded for every file, including the slow ones —
    // a slow write is still the same photograph, it just arrives late.
    if (!interrupted) {
      this.pressed.set(stem, Object.fromEntries(
        Object.entries(files).map(([p, b]) => [p, sha(b)])));
    }
    return { stem, kind, files: Object.keys(files) };
  }

  /** Complete the writes that were left growing, as a slow card eventually does. */
  finishSlowWrites() {
    for (const [path, body] of this.pendingSlowWrites ?? []) {
      if (existsSync(path)) writeFileSync(path, body);
    }
    this.pendingSlowWrites = [];
  }

  finishInterruptedWrites() {
    for (const [path, body] of this.pendingCompletions ?? []) {
      writeFileSync(path, body);
      const stem = path.slice(0, path.lastIndexOf('.'));
      const existing = this.pressed.get(stem) ?? {};
      existing[path] = sha(body);
      this.pressed.set(stem, existing);
    }
    this.pendingCompletions = [];
  }

  // --- faults --------------------------------------------------------------

  /** Spool depth right now: the anti-vacuous measure. */
  inFlight() {
    const dbPath = join(this.home, 'spool.db');
    if (!existsSync(dbPath)) return 0;
    try {
      const db = openDb(dbPath);
      const n = db.prepare(
        "select count(*) n from captures where state not in ('complete','rejected')").get().n;
      db.close();
      return n;
    } catch { return 0; }
  }

  /**
   * Record a fault as scheduled for the current batch.
   *
   * The in-flight count is deliberately NOT taken here. A fault is configured
   * before the worker starts, when the spool is often empty, and measuring at
   * that moment would report every fault as landing on nothing — which is both
   * wrong and, worse, would look like a passing audit if the comparison were
   * the other way round. It is filled in after the batch from the peak spool
   * depth observed while the fault was actually in force.
   */
  record(fault, extra = {}) {
    const entry = { fault, at: Date.now(), batch: this.currentBatch, inFlight: null, ...extra };
    this.ledger.push(entry);
    this.log(`fault: ${fault}`);
    return entry;
  }

  /** A snapshot of every capture's state, for detecting work done in a batch. */
  #snapshot() {
    const dbPath = join(this.home, 'spool.db');
    if (!existsSync(dbPath)) return new Map();
    try {
      const db = openDb(dbPath);
      const rows = db.prepare('select id, state, attempts from captures').all();
      db.close();
      return new Map(rows.map((r) => [r.id, `${r.state}:${r.attempts}`]));
    } catch { return new Map(); }
  }

  /**
   * Score a batch by how much work was actually live while its faults were in
   * force.
   *
   * Polling the spool alone under-counts: a capture can be created, uploaded
   * and completed between two samples, and the fault that hit it would then be
   * scored as landing on nothing. So the measure is the greater of the sampled
   * depth and the number of captures that visibly moved during the batch —
   * a transition is proof that the Bridge was working while the fault was on.
   */
  async #sampleWhile(promise, intervalMs = 20) {
    const before = this.#snapshot();
    let peak = 0;
    const timer = setInterval(() => {
      const n = this.inFlight();
      if (n > peak) peak = n;
    }, intervalMs);
    let result;
    try { result = await promise; }
    finally { clearInterval(timer); }

    const after = this.#snapshot();
    let moved = 0;
    for (const [id, state] of after) {
      if (before.get(id) !== state) moved++;
    }
    return { result, peak: Math.max(peak, moved) };
  }

  /**
   * Record the spool depth seen during a batch. Faults are scored against a
   * window rather than a single batch, because a fault's effect outlives its
   * injection: a renamed file is not discovered until the next scan, a pulled
   * card is not noticed until something reads it, and a server fault counter
   * sits armed until a request consumes it. Crediting only the injecting
   * batch would under-count real coverage; crediting the whole run would
   * over-count it. The window is the batch it was injected in and the next.
   */
  #scoreBatch(batch, peakInFlight) {
    this.batchPeaks ??= new Map();
    this.batchPeaks.set(batch, peakInFlight);
  }

  #creditLedger() {
    const peaks = this.batchPeaks ?? new Map();
    for (const e of this.ledger) {
      const own = peaks.get(e.batch) ?? 0;
      const next = peaks.get(e.batch + 1) ?? 0;
      e.inFlight = Math.max(own, next);
      e.inFlightOwnBatch = own;
    }
  }

  // --- the worker ----------------------------------------------------------

  /**
   * @param {object} [opts]
   * @param {boolean} [opts.killOnProgress] kill once the server has seen this
   *   run do something, rather than after a fixed delay. Under load a worker
   *   can sit unscheduled through a fixed window and be killed having done
   *   nothing, which makes the fault land on an empty spool and proves
   *   nothing. Progress-triggered kills land on live work by construction.
   */
  runWorker({ killAfterMs = null, killOnProgress = false, env = {}, timeoutMs = 120_000 } = {}) {
    const before = this.server.counters.announce + this.server.counters.upload
                 + this.server.counters.confirm;
    return new Promise((resolve) => {
      const child = fork(WORKER, [], {
        env: {
          ...process.env,
          BRIDGE_DB: join(this.home, 'spool.db'),
          BRIDGE_CARD: this.card,
          BRIDGE_URL: this.server.baseUrl,
          BRIDGE_EVENT: 'event-a',
          BRIDGE_ENROLL_CODE: this.enrollCode,
          BRIDGE_PAIR_GRACE_MS: '150',
          // Non-zero on purpose: a file must hold still before it is spooled,
          // which is how a half-written frame is kept out of the spool.
          BRIDGE_QUIET_MS: '120',
          BRIDGE_REPORT_MEMORY: '1',
          ...env,
        },
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      });
      let report = null;
      child.on('message', (m) => { if (m?.done) report = m; });
      const stop = () => { try { child.kill('SIGKILL'); } catch {} };
      const timers = [];

      if (killOnProgress) {
        let armed = 0;
        timers.push(setInterval(() => {
          const now = this.server.counters.announce + this.server.counters.upload
                    + this.server.counters.confirm;
          if (now <= before) return;
          if (armed === 0) armed = Date.now() + rnd(200);
          if (Date.now() >= armed) stop();
        }, 10));
        timers.push(setTimeout(stop, Math.min(timeoutMs, 15_000)));
      } else if (killAfterMs != null) {
        timers.push(setTimeout(stop, killAfterMs));
      } else {
        timers.push(setTimeout(stop, timeoutMs));
      }

      child.on('exit', (code, signal) => {
        for (const t of timers) { clearInterval(t); clearTimeout(t); }
        if (report?.peakRssBytes > this.peakRssBytes) this.peakRssBytes = report.peakRssBytes;
        resolve({ code, signal, report });
      });
    });
  }

  // --- the run -------------------------------------------------------------

  async run() {
    // Presses are spread across every batch. Exhausting them early leaves the
    // later batches with nothing to do, and a fault injected into an idle
    // batch is a fault that tested nothing.
    const perBatch = Math.max(1, Math.floor(this.target / this.batches));

    for (let batch = 0; batch < this.batches; batch++) {
      const last = batch === this.batches - 1;
      this.currentBatch = batch;

      // Coverage is scheduled, not hoped for. Random rolls alone leave whole
      // fault types uninjected on a short run, and a fault that never fired
      // proves nothing — so each batch deterministically takes the next fault
      // in rotation on top of whatever the dice produce.
      const scheduled = FAULTS[batch % FAULTS.length];

      // The camera shoots this batch, sometimes in a burst.
      const burst = rnd(100) < 25;
      for (let i = 0; i < perBatch; i++) {
        if (this.pressCount >= this.target) break;
        const slow = scheduled === 'slow_write' ? i === 0 : (!burst && rnd(100) < 10);
        const interrupted = scheduled === 'interrupted_write' ? i === 0 : (!burst && rnd(100) < 5);
        if (slow) this.record('slow_write');
        if (interrupted) this.record('interrupted_write');
        this.press({ slow, interrupted });
      }
      if (burst) this.log(`burst of ${perBatch}`);

      // Occasionally the photographer tidies the card.
      if (scheduled === 'file_renamed') this.#renameOrMove('file_renamed');
      else if (scheduled === 'file_moved') this.#renameOrMove('file_moved');
      else if (rnd(100) < 15) this.#renameOrMove();

      // Faults for this batch.
      const env = {};
      let killOnProgress = false;

      // The scheduled fault takes precedence: an `else if` chain where a
      // random roll can pre-empt the scheduled one makes rotation coverage a
      // claim rather than a fact.
      const on = (fault, chance) =>
        scheduled === fault || (scheduled !== 'process_death' && scheduled !== 'machine_restart'
                                && rnd(100) < chance);

      if (on('process_death', 30)) {
        this.record('process_death');
        killOnProgress = true;
      } else if (on('machine_restart', 10)) {
        // A machine restart: the process dies and the spool is reopened cold.
        this.record('machine_restart');
        killOnProgress = true;
      }

      if (on('network_down', 25)) { this.record('network_down'); this.server.faults.networkDead = true; }
      if (on('server_5xx', 35)) { this.record('server_5xx'); this.server.faults.announce5xx = 1 + rnd(3); this.server.faults.upload5xx = 1 + rnd(3); }
      if (on('lost_ack', 20)) { this.record('lost_ack'); this.server.faults.dropAckAfterCommit = 1 + rnd(2); }
      if (on('corrupt_transfer', 20)) { this.record('corrupt_transfer'); this.server.faults.corruptUpload = 1 + rnd(2); }
      if (on('request_timeout', 15)) { this.record('request_timeout'); this.server.faults.confirm5xx = 1 + rnd(2); }
      if (on('low_disk', 12)) { this.record('low_disk'); env.BRIDGE_DISK_CRITICAL = '1'; }

      let removed = null;
      if (on('card_removed', 12)) removed = this.#removeCard();

      const { peak } = await this.#sampleWhile(
        this.runWorker({ killOnProgress, env, timeoutMs: last ? 180_000 : 60_000 }));
      this.#scoreBatch(batch, peak);

      // Clear this batch's faults.
      this.server.faults.networkDead = false;
      if (removed) this.#returnCard(removed);
      this.finishSlowWrites();
      this.finishInterruptedWrites();
      if (scheduled === 'duplicate_fs_event' || rnd(100) < 20) {
        this.record('duplicate_fs_event', { note: 'rescan of unchanged card' });
        this.ledger[this.ledger.length - 1].inFlight = peak;
      }
    }

    // Everything the card was still writing has now landed.
    this.finishSlowWrites();
    this.finishInterruptedWrites();

    // Let it finish cleanly, as a photographer packing up would.
    this.server.faults = {
      announce5xx: 0, upload5xx: 0, confirm5xx: 0,
      dropAckAfterCommit: 0, corruptUpload: 0, networkDead: false,
    };
    for (let i = 0; i < 10; i++) {
      const { result, peak } = await this.#sampleWhile(this.runWorker({ timeoutMs: 180_000 }));
      this.#scoreBatch(this.batches + i, peak);
      if (result.code === 0) break;
    }
    this.#creditLedger();
  }

  #renameOrMove(force = null) {
    const stems = [...this.pressed.keys()];
    if (!stems.length) return;
    const stem = pick(stems);
    const files = this.pressed.get(stem);
    const which = force ?? (rnd(100) < 50 ? 'file_renamed' : 'file_moved');

    const updated = {};
    for (const [path, digest] of Object.entries(files)) {
      if (!existsSync(path)) { updated[path] = digest; continue; }
      let target;
      if (which === 'file_moved') {
        const keep = join(this.card, 'keepers');
        mkdirSync(keep, { recursive: true });
        target = join(keep, path.slice(path.lastIndexOf('/') + 1));
      } else {
        target = path.replace(/IMG_/, 'EDIT_');
      }
      if (existsSync(target)) { updated[path] = digest; continue; }
      try { renameSync(path, target); updated[target] = digest; }
      catch { updated[path] = digest; }
    }
    this.record(which);
    this.pressed.delete(stem);
    // The photograph is still expected, just under a new path.
    const newStem = Object.keys(updated)[0]?.replace(/\.[^.]+$/, '') ?? stem;
    this.pressed.set(newStem, updated);
  }

  #removeCard() {
    const stash = join('/tmp', `fq-stash-${randomUUID().slice(0, 8)}`);
    try {
      renameSync(this.card, stash);
      mkdirSync(this.card, { recursive: true });
      this.record('card_removed');
      return stash;
    } catch { return null; }
  }

  #returnCard(stash) {
    try {
      rmSync(this.card, { recursive: true, force: true });
      renameSync(stash, this.card);
    } catch { /* leave it */ }
  }

  // --- the audit -----------------------------------------------------------

  /**
   * Did the run prove anything? A fault type that never fired, or only ever
   * fired against an empty spool, is a test that did not happen.
   */
  auditFaults() {
    const problems = [];
    const byType = new Map();
    for (const e of this.ledger) {
      const cur = byType.get(e.fault) ?? { total: 0, onLiveWork: 0 };
      cur.total++;
      if (e.inFlight > 0) cur.onLiveWork++;
      byType.set(e.fault, cur);
    }
    for (const fault of FAULTS) {
      const seen = byType.get(fault);
      if (!seen) { problems.push(`${fault}: never injected`); continue; }
      if (seen.onLiveWork === 0) {
        problems.push(`${fault}: injected ${seen.total}x but never while work was in flight`);
      }
    }
    return { byType: Object.fromEntries(byType), problems };
  }

  /** Every claim Phase 2.5 makes about a field event, checked. */
  verify() {
    const db = openDb(join(this.home, 'spool.db'));
    const rows = db.prepare('select * from captures').all();
    db.close();

    const captures = this.server.allCaptures();
    const storedDigests = new Set(
      captures.flatMap((c) => Object.values(c.assets)).map((a) => a.sha256));

    const failures = [];

    // Every complete file still on the card must be on the server, byte-exact.
    let expectedFiles = 0, arrived = 0;
    const missing = [];
    for (const files of this.pressed.values()) {
      for (const [path, digest] of Object.entries(files)) {
        if (!existsSync(path)) continue;          // moved away mid-run
        if (statSync(path).size === 0) continue;
        expectedFiles++;
        if (storedDigests.has(digest)) { arrived++; continue; }

        // Say exactly what happened to it, so a failure here is diagnosable
        // rather than a number to stare at.
        const onDisk = statSync(path).size;
        const row = rows.find((r) => r.master_path === path || r.preview_path === path);
        missing.push({
          path: path.slice(path.lastIndexOf('/') + 1),
          sizeOnDisk: onDisk,
          spoolState: row?.state ?? 'never spooled',
          spoolSize: row?.byte_size ?? null,
          rejected: row?.rejected_reason ?? null,
          digestMatchesSpool: row?.content_sha256 === digest,
        });
      }
    }
    if (arrived < expectedFiles) {
      failures.push(
        `${expectedFiles - arrived} of ${expectedFiles} files on the card never reached the server byte-exact:\n` +
        missing.slice(0, 8).map((m) => `      ${JSON.stringify(m)}`).join('\n'));
    }

    // No capture may be left in flight.
    const stuck = rows.filter((r) => !['complete', 'rejected'].includes(r.state));
    if (stuck.length) {
      failures.push(`${stuck.length} capture(s) left in flight: ` +
        stuck.slice(0, 5).map((r) => `#${r.device_sequence}=${r.state}`).join(', '));
    }

    // No duplicated shutter press: one server capture per idempotency key,
    // and no two captures sharing a device sequence.
    const keys = new Set(captures.map((c) => c.idempotency_key));
    if (keys.size !== captures.length) {
      failures.push('a capture was created twice under different keys');
    }
    const seqs = captures.map((c) => c.device_sequence);
    if (new Set(seqs).size !== seqs.length) failures.push('a device sequence was reused');

    // Tenancy.
    for (const c of captures) {
      if (c.event_id !== 'event-a' || c.organization_id !== 'org-a') {
        failures.push(`capture ${c.capture_id} crossed a boundary: ${c.organization_id}/${c.event_id}`);
        break;
      }
    }

    // Nothing may need hand repair: every row is readable and self-consistent.
    for (const r of rows) {
      if (!r.idempotency_key || !r.group_key || !r.master_path) {
        failures.push(`capture #${r.device_sequence} is missing identity fields`);
        break;
      }
      if (['preview_confirmed', 'uploading_master', 'master_confirmed', 'complete'].includes(r.state)
          && !r.server_capture_id) {
        failures.push(`capture #${r.device_sequence} claims ${r.state} without a server capture id`);
        break;
      }
      if (r.group_key.includes('\u0000')) {
        failures.push(`capture #${r.device_sequence} has an unreadable group key`);
        break;
      }
    }

    return {
      failures,
      shutterPresses: this.pressCount,
      serverCaptures: captures.length,
      spoolRows: rows.length,
      completed: rows.filter((r) => r.state === 'complete').length,
      rejected: rows.filter((r) => r.state === 'rejected').length,
      rejectionReasons: rows.filter((r) => r.state === 'rejected')
        .reduce((a, r) => ({ ...a, [r.rejected_reason]: (a[r.rejected_reason] ?? 0) + 1 }), {}),
      filesOnCard: expectedFiles,
      filesArrivedByteExact: arrived,
      missing,
      peakRssMiB: Math.round(this.peakRssBytes / MiB),
    };
  }
}
