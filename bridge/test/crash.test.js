// The brutal test.
//
// Kill the Bridge at random points, over and over, while photographs are
// arriving and the network is misbehaving. Then let it finish and demand:
// every accepted photograph is exactly one capture on the server, byte-exact,
// or still recoverable on disk. Never zero, never two.

import test from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FakeServer } from './fake-server.js';
import { tempDir } from './helpers.js';

const WORKER = fileURLToPath(new URL('./worker.js', import.meta.url));

/**
 * Run a worker, optionally killing it.
 *
 * `killWhen` is preferred over a fixed delay. Test files run concurrently and
 * these tests fork heavily, so a worker can sit unscheduled through a 200ms
 * window and be killed having done nothing — which makes the run prove nothing
 * and, under load, fail its own anti-vacuous guard. Killing on observed
 * progress makes the crash land on live work by construction rather than by
 * hoping the timing holds.
 */
function runWorker(env, { killAfterMs = null, killWhen = null, killDeadlineMs = 8000 } = {}) {
  return new Promise((resolve) => {
    const child = fork(WORKER, [], {
      env: { ...process.env, ...env },
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    const timers = [];
    const stop = () => { try { child.kill('SIGKILL'); } catch {} };

    if (killWhen) {
      const poll = setInterval(() => { if (killWhen()) { clearInterval(poll); stop(); } }, 10);
      timers.push(poll);
      timers.push(setTimeout(stop, killDeadlineMs));   // never hang on a stall
    } else if (killAfterMs != null) {
      timers.push(setTimeout(stop, killAfterMs));
    }

    child.on('exit', (code, signal) => {
      for (const t of timers) { clearInterval(t); clearTimeout(t); }
      resolve({ code, signal });
    });
  });
}

function sha(buf) { return createHash('sha256').update(buf).digest('hex'); }

test('every photograph survives repeated kill -9', { timeout: 180_000 }, async (t) => {
  const server = new FakeServer();
  await server.listen();
  const home = tempDir('crash-home-');
  const card = tempDir('crash-card-');
  t.after(async () => {
    await server.close();
    rmSync(home, { recursive: true, force: true });
    rmSync(card, { recursive: true, force: true });
  });

  const SHOTS = 40;
  const expected = new Map();
  for (let i = 0; i < SHOTS; i++) {
    const name = `DSC${String(i).padStart(4, '0')}.JPG`;
    const buf = Buffer.from(`photograph-${i}-`.padEnd(3000 + i * 7, 'x'));
    writeFileSync(join(card, name), buf);
    expected.set(name, sha(buf));
  }

  const env = {
    BRIDGE_DB: join(home, 'spool.db'),
    BRIDGE_CARD: card,
    BRIDGE_URL: server.baseUrl,
    BRIDGE_EVENT: 'event-a',
    BRIDGE_ENROLL_CODE: server.enrollDevice(),
  };

  // Round after round of sudden death at unpredictable moments.
  for (let round = 0; round < 14; round++) {
    // Keep the network unreliable throughout, so kills land during retries too.
    server.faults.announce5xx = 1;
    server.faults.upload5xx = 1;
    if (round % 4 === 3) server.faults.dropAckAfterCommit = 1;

    // Kill once this round has visibly moved work, with a little jitter after
    // that so the crash lands at varying points rather than always the same one.
    const announcesBefore = server.counters.announce;
    const uploadsBefore = server.counters.upload;
    let armed = 0;
    await runWorker(env, {
      killWhen: () => {
        const moved = server.counters.announce > announcesBefore
                   || server.counters.upload > uploadsBefore;
        if (!moved) return false;
        if (armed === 0) armed = Date.now() + Math.floor(Math.random() * 120);
        return Date.now() >= armed;
      },
    });
    // The code is retained deliberately: a Bridge killed mid-enrollment must
    // still be able to enroll, and passing the code again is exactly what an
    // operator would do. Enrollment is idempotent on the device public key.
  }

  // Guard against a vacuous run: if every kill landed before the Bridge did
  // any real work, the clean finishing round would carry the whole test and
  // prove nothing about crash safety.
  const midway = server.captureCount();
  assert.ok(midway > 0,
    'the kills interleaved with real work (captures created before the clean run)');
  assert.ok(server.counters.announce > 14,
    'the Bridge got past startup repeatedly, not just once per round');

  // Now let it finish in peace.
  server.faults = { announce5xx: 0, upload5xx: 0, confirm5xx: 0, dropAckAfterCommit: 0, corruptUpload: 0, networkDead: false };
  const final = await runWorker(env);
  assert.equal(final.code, 0, 'the Bridge completes cleanly once left alone');

  // --- the invariants ------------------------------------------------------

  const captures = server.allCaptures();
  assert.equal(captures.length, SHOTS,
    `exactly one capture per photograph (got ${captures.length} for ${SHOTS})`);

  const seenKeys = new Set(captures.map((c) => c.idempotency_key));
  assert.equal(seenKeys.size, SHOTS, 'no capture was announced twice under different keys');

  const seq = captures.map((c) => c.device_sequence);
  assert.equal(new Set(seq).size, seq.length, 'no device sequence was reused');

  const confirmed = captures.filter((c) => c.assets.master);
  assert.equal(confirmed.length, SHOTS, 'every master is confirmed');

  const storedDigests = new Set(confirmed.map((c) => c.assets.master.sha256));
  for (const [name, digest] of expected) {
    assert.ok(storedDigests.has(digest), `${name} arrived byte-exact`);
  }
});

test('a kill between server commit and our acknowledgement still yields one capture',
  { timeout: 120_000 }, async (t) => {
  const server = new FakeServer();
  await server.listen();
  const home = tempDir('ack-home-');
  const card = tempDir('ack-card-');
  t.after(async () => {
    await server.close();
    rmSync(home, { recursive: true, force: true });
    rmSync(card, { recursive: true, force: true });
  });

  // The single nastiest ordering: the server creates the capture, then the
  // response never arrives. Without an idempotency key written before the
  // request, the retry makes a second photograph.
  const SHOTS = 8;
  for (let i = 0; i < SHOTS; i++) {
    writeFileSync(join(card, `DSC${i}.JPG`), Buffer.from(`ack-test-${i}`.padEnd(2000, 'y')));
  }
  server.faults.dropAckAfterCommit = SHOTS;

  const env = {
    BRIDGE_DB: join(home, 'spool.db'),
    BRIDGE_CARD: card,
    BRIDGE_URL: server.baseUrl,
    BRIDGE_EVENT: 'event-a',
    BRIDGE_ENROLL_CODE: server.enrollDevice(),
  };

  await runWorker(env);

  assert.equal(server.captureCount(), SHOTS,
    `one capture each despite every announce losing its response (got ${server.captureCount()})`);
  assert.equal(server.confirmedMasters(), SHOTS);
});

test('the spool survives a kill with no torn or unreadable rows',
  { timeout: 120_000 }, async (t) => {
  const server = new FakeServer();
  await server.listen();
  const home = tempDir('torn-home-');
  const card = tempDir('torn-card-');
  t.after(async () => {
    await server.close();
    rmSync(home, { recursive: true, force: true });
    rmSync(card, { recursive: true, force: true });
  });

  for (let i = 0; i < 25; i++) {
    writeFileSync(join(card, `T${i}.JPG`), Buffer.from(`torn-${i}`.padEnd(4000, 'z')));
  }

  const env = {
    BRIDGE_DB: join(home, 'spool.db'),
    BRIDGE_CARD: card,
    BRIDGE_URL: server.baseUrl,
    BRIDGE_EVENT: 'event-a',
    BRIDGE_ENROLL_CODE: server.enrollDevice(),
  };

  for (let round = 0; round < 8; round++) {
    await runWorker(env, { killAfterMs: 30 + Math.floor(Math.random() * 150) });

    // Reopen the database the way a restart does and check it is coherent.
    const { openDb } = await import('../src/db.js');
    const db = openDb(env.BRIDGE_DB);
    const rows = db.prepare('select * from captures').all();
    for (const r of rows) {
      assert.ok(r.idempotency_key, 'every row has its idempotency key');
      assert.ok(r.group_key && r.master_path, 'every row knows what file it is');
      assert.ok(r.device_sequence > 0, 'every row holds a sequence number');
      if (['preview_confirmed', 'uploading_master', 'master_confirmed', 'complete'].includes(r.state)) {
        assert.ok(r.server_capture_id, `${r.state} implies the server acknowledged a capture id`);
      }
      if (r.state === 'master_confirmed' || r.state === 'complete') {
        assert.ok(r.master_asset_id, 'a confirmed master names the asset the server stored');
      }
    }
    db.close();
  }

  const final = await runWorker(env);
  assert.equal(final.code, 0);
  assert.equal(server.captureCount(), 25);
  assert.equal(server.confirmedMasters(), 25);
});

test('a kill during enrollment does not brick the device', { timeout: 60_000 }, async (t) => {
  const server = new FakeServer();
  await server.listen();
  const home = tempDir('enroll-home-');
  const card = tempDir('enroll-card-');
  t.after(async () => {
    await server.close();
    rmSync(home, { recursive: true, force: true });
    rmSync(card, { recursive: true, force: true });
  });

  writeFileSync(join(card, 'DSC0001.JPG'), Buffer.from('after-enrollment'.padEnd(2000, 'q')));

  const env = {
    BRIDGE_DB: join(home, 'spool.db'),
    BRIDGE_CARD: card,
    BRIDGE_URL: server.baseUrl,
    BRIDGE_EVENT: 'event-a',
    BRIDGE_ENROLL_CODE: server.enrollDevice(),
  };

  // Die repeatedly in the window where enrollment happens. The code is spent
  // the first time the server sees it, so anything less than idempotent
  // enrollment leaves this laptop permanently unable to shoot.
  for (let i = 0; i < 6; i++) await runWorker(env, { killAfterMs: 8 + i * 4 });

  const final = await runWorker(env);
  assert.equal(final.code, 0, 'the Bridge still enrolls and runs after a mid-enrollment crash');
  assert.equal(server.devices.size, 1, 'and exactly one device exists, not six');
  assert.equal(server.captureCount(), 1);
});
