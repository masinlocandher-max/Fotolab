// A real Bridge process, for the crash tests to murder.
//
// It is deliberately a separate process: killing a thread or rejecting a
// promise inside the test runner proves nothing about what SQLite flushed to
// disk. SIGKILL on a child is the real thing.

import { Bridge } from '../src/bridge.js';

const {
  BRIDGE_DB, BRIDGE_CARD, BRIDGE_URL, BRIDGE_EVENT,
  BRIDGE_ENROLL_CODE, BRIDGE_CHAOS_MS, BRIDGE_STOP_AT, BRIDGE_STOP_BEFORE_ENROLL,
} = process.env;

// Disk pressure is applied by moving the thresholds across the volume's real
// free space, so the code path exercised is the real one.
const HUGE = 2 ** 60;
const diskThresholds = process.env.BRIDGE_DISK_CRITICAL
  ? { criticalFreeBytes: HUGE, warningFreeBytes: HUGE, criticalFreeRatio: 0.99, warningFreeRatio: 0.99 }
  : undefined;

const bridge = new Bridge({
  dbFile: BRIDGE_DB,
  roots: [BRIDGE_CARD],
  diskThresholds,
  diskCheckMs: 0,
  eventId: BRIDGE_EVENT ?? 'event-a',
  baseUrl: BRIDGE_URL,
  quietMs: 0,
  pairGraceMs: Number(process.env.BRIDGE_PAIR_GRACE_MS ?? 0),
  pollMs: 5,
  log: (kind, data) => {
    if (process.env.BRIDGE_VERBOSE) console.error(kind, JSON.stringify(data));
  },
});

// Optional self-inflicted death, so a crash can land mid-upload rather than
// only between polls.
if (BRIDGE_CHAOS_MS) {
  setTimeout(() => process.kill(process.pid, 'SIGKILL'), Number(BRIDGE_CHAOS_MS));
}

// Peak RSS, sampled from inside the process that is actually doing the work.
// Measured rather than reasoned about: uploads buffer whole files, and whether
// that is defensible on a photographer's laptop is a number, not an opinion.
let peakRss = 0;
let memTimer = null;
if (process.env.BRIDGE_REPORT_MEMORY) {
  const sample = () => {
    const rss = process.memoryUsage().rss;
    if (rss > peakRss) peakRss = rss;
  };
  sample();
  memTimer = setInterval(sample, 10);
  memTimer.unref();
}

// Die with the keypair on disk but the enrollment unrecorded — the window in
// which the enrollment code is already spent server-side.
if (BRIDGE_STOP_BEFORE_ENROLL) {
  bridge.identity.ensureKeypair();
  process.kill(process.pid, 'SIGKILL');
}

try {
  bridge.recover();
  if (BRIDGE_ENROLL_CODE) await bridge.enrollIfNeeded(BRIDGE_ENROLL_CODE);
  process.send?.({ ready: true });

  // Deterministic crash point: die the instant any capture first reaches the
  // named state. Random kills prove crash safety in aggregate; this proves it
  // at each specific transition, which is what "converges without operator
  // repair" has to mean one state at a time.
  if (BRIDGE_STOP_AT) {
    const atTarget = () => bridge.db
      .prepare('select count(*) n from captures where state = ?').get(BRIDGE_STOP_AT).n > 0;
    // The scanner needs more than one tick before a file counts as settled, so
    // quiescence is only believed after several consecutive quiet passes —
    // otherwise the loop concludes "nothing to do" before the first capture
    // has even been committed, and the crash point is never reached.
    let quiet = 0;
    for (let pass = 0; pass < 2000; pass++) {
      await bridge.ensureSession();
      const found = await bridge.ingestOnce();
      if (atTarget()) process.kill(process.pid, 'SIGKILL');
      const r = await bridge.pipeline.step();
      if (atTarget()) process.kill(process.pid, 'SIGKILL');
      if (r === 'halted') break;
      if (r === 'idle' && found === 0 && bridge.isQuiescent()) {
        if (++quiet >= 4) break;
      } else quiet = 0;
      await new Promise((res) => setTimeout(res, 2));
    }
    process.send?.({ done: true, note: 'target state never reached' });
    bridge.close();
    process.exit(0);
  }

  // Run until killed, or until the spool is drained and quiet twice over.
  let quiet = 0;
  for (;;) {
    let found = 0;
    try {
      await bridge.ensureSession();
      found = await bridge.ingestOnce();
      await bridge.drain(500);
    } catch (err) {
      process.send?.({ error: err.message });
    }
    if (bridge.isQuiescent() && found === 0) {
      if (++quiet >= 3) break;
    } else quiet = 0;
    await new Promise((r) => setTimeout(r, 5));
  }
  if (memTimer) clearInterval(memTimer);
  process.send?.({
    done: true, counts: bridge.spool.counts(),
    peakRssBytes: peakRss, heapTotalBytes: process.memoryUsage().heapTotal,
  });
  bridge.close();
  process.exit(0);
} catch (err) {
  process.send?.({ fatal: err.message });
  process.exit(3);
}
