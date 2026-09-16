import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Bridge } from '../src/bridge.js';
import { FakeServer } from './fake-server.js';

export function tempDir(prefix = 'fotolab-') {
  return mkdtempSync(join(tmpdir(), prefix));
}

export function writeShot(dir, name, { bytes = 2048, seed = null } = {}) {
  const buf = seed ? Buffer.from(seed.padEnd(bytes, '.')) : randomBytes(bytes);
  const p = join(dir, name);
  writeFileSync(p, buf);
  return p;
}

/** A Bridge wired to a running FakeServer, enrolled and in session. */
export async function makeBridge({ eventId = 'event-a', quietMs = 0, roots, server } = {}) {
  const srv = server ?? new FakeServer();
  if (!srv.baseUrl) await srv.listen();

  const home = tempDir('bridge-home-');
  const cards = roots ?? [tempDir('card-')];

  const bridge = new Bridge({
    dbFile: join(home, 'spool.db'),
    roots: cards,
    eventId,
    baseUrl: srv.baseUrl,
    quietMs,
    log: () => {},
  });

  return { bridge, server: srv, home, cards, cleanup() {
    bridge.close();
    rmSync(home, { recursive: true, force: true });
    if (!roots) for (const c of cards) rmSync(c, { recursive: true, force: true });
  } };
}

export async function enrollAndSession(bridge, server) {
  const code = server.enrollDevice();
  await bridge.enrollIfNeeded(code);
  await bridge.ensureSession();
}

/**
 * Tick the scanner until it commits at least one capture. A file is never
 * spooled on first sighting — it has to hold still first — so a single
 * ingestOnce() legitimately discovers nothing.
 */
export async function ingestUntilFound(bridge, maxTicks = 10) {
  for (let i = 0; i < maxTicks; i++) {
    if (await bridge.ingestOnce() > 0) return true;
  }
  return false;
}

/**
 * Run scan+drain until the spool stops changing.
 *
 * "Nothing pending" is not on its own a finish line — before the first scan
 * completes, nothing is pending because nothing has been discovered yet. So a
 * round only counts as settled if it also discovered nothing new, and the
 * scanner needs at least two ticks to call a file stable.
 */
export async function settle(bridge, rounds = 60) {
  let quiet = 0;
  let lastFingerprint = null;
  let stuckRounds = 0;

  for (let i = 0; i < rounds; i++) {
    let found = 0;
    try { found = await bridge.ingestOnce(); } catch { /* offline */ }
    try { await bridge.drain(200); } catch { /* offline */ }

    const pending = bridge.spool.pending();
    if (pending.length === 0 && found === 0) {
      if (++quiet >= 2) return true;
    } else {
      quiet = 0;
    }

    // Detect a livelock: same rows in the same states, round after round.
    // Better to fail the assertion than to hang the suite for 15 seconds.
    const fp = pending.map((r) => `${r.id}:${r.state}`).join(',');
    stuckRounds = fp === lastFingerprint ? stuckRounds + 1 : 0;
    lastFingerprint = fp;
    if (stuckRounds >= 8) return false;

    bridge.db.prepare('update captures set next_attempt_at_ms = 0').run();
  }
  return bridge.spool.pending().length === 0;
}
