// A real Bridge process, for the crash tests to murder.
//
// It is deliberately a separate process: killing a thread or rejecting a
// promise inside the test runner proves nothing about what SQLite flushed to
// disk. SIGKILL on a child is the real thing.

import { Bridge } from '../src/bridge.js';

const {
  BRIDGE_DB, BRIDGE_CARD, BRIDGE_URL, BRIDGE_EVENT,
  BRIDGE_ENROLL_CODE, BRIDGE_CHAOS_MS,
} = process.env;

const bridge = new Bridge({
  dbFile: BRIDGE_DB,
  roots: [BRIDGE_CARD],
  eventId: BRIDGE_EVENT ?? 'event-a',
  baseUrl: BRIDGE_URL,
  quietMs: 0,
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

try {
  bridge.recover();
  if (BRIDGE_ENROLL_CODE) await bridge.enrollIfNeeded(BRIDGE_ENROLL_CODE);
  process.send?.({ ready: true });

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
    const pending = bridge.spool.pending().length;
    if (pending === 0 && found === 0) {
      if (++quiet >= 3) break;
    } else quiet = 0;
    await new Promise((r) => setTimeout(r, 5));
  }
  process.send?.({ done: true, counts: bridge.spool.counts() });
  bridge.close();
  process.exit(0);
} catch (err) {
  process.send?.({ fatal: err.message });
  process.exit(3);
}
