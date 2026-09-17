// Restart recovery at every transition.
//
// The random-kill suite proves crash safety in aggregate. This proves it one
// transition at a time: for each state a capture can occupy, the process is
// killed the instant a capture first reaches it, restarted, and required to
// converge — exactly one capture, byte-exact, with no operator repair and no
// state machine ping-pong.

import test from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { createHash } from 'node:crypto';
import { rmSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FakeServer } from './fake-server.js';
import { tempDir } from './helpers.js';
import { openDb } from '../src/db.js';

const WORKER = fileURLToPath(new URL('./worker.js', import.meta.url));

function runWorker(env, timeoutMs = 20_000) {
  return new Promise((resolve) => {
    const child = fork(WORKER, [], {
      env: { ...process.env, ...env }, stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    const killer = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, timeoutMs);
    child.on('exit', (code, signal) => { clearTimeout(killer); resolve({ code, signal }); });
  });
}

const STATES = [
  'discovered', 'hashed', 'queued', 'uploading_preview',
  'preview_confirmed', 'uploading_master', 'master_confirmed',
];

for (const state of STATES) {
  test(`RESTART: killed at ${state}, converges without repair`, { timeout: 90_000 }, async (t) => {
    const server = new FakeServer();
    await server.listen();
    const home = tempDir(`rs-${state}-home-`);
    const card = tempDir(`rs-${state}-card-`);
    t.after(async () => {
      await server.close();
      rmSync(home, { recursive: true, force: true });
      rmSync(card, { recursive: true, force: true });
    });

    const body = Buffer.from(`restart-at-${state}-`.padEnd(6000, 'z'));
    writeFileSync(join(card, 'RS0001.JPG'), body);
    const digest = createHash('sha256').update(body).digest('hex');

    const env = {
      BRIDGE_DB: join(home, 'spool.db'), BRIDGE_CARD: card,
      BRIDGE_URL: server.baseUrl, BRIDGE_EVENT: 'event-a',
      BRIDGE_ENROLL_CODE: server.enrollDevice(),
    };

    // Die exactly at the transition under test.
    const killed = await runWorker({ ...env, BRIDGE_STOP_AT: state });
    assert.equal(killed.signal, 'SIGKILL',
      `the process must actually have been killed at ${state}, not have exited normally`);

    // The spool must be readable and coherent immediately after the kill.
    const db = openDb(env.BRIDGE_DB);
    const rows = db.prepare('select * from captures').all();
    assert.equal(rows.length, 1, 'exactly one capture row survived the kill');
    assert.ok(rows[0].idempotency_key, 'with its idempotency key intact');
    db.close();

    // Restart, unaided.
    delete env.BRIDGE_ENROLL_CODE;
    const finished = await runWorker(env);
    assert.equal(finished.code, 0, 'the restarted Bridge completes on its own');

    assert.equal(server.captureCount(), 1, `exactly one capture after a kill at ${state}`);
    assert.equal(server.confirmedMasters(), 1, 'and the master is confirmed');
    assert.equal(server.allCaptures()[0].assets.master.sha256, digest, 'byte-exact');

    const after = openDb(env.BRIDGE_DB);
    const final = after.prepare('select * from captures').all();
    assert.equal(final.length, 1, 'no duplicate row was created by the restart');
    assert.equal(final[0].state, 'complete', 'and it converged to one deterministic state');
    after.close();
  });
}

test('RESTART: killed with the enrollment unrecorded, recovers and runs', { timeout: 60_000 }, async (t) => {
  const server = new FakeServer();
  await server.listen();
  const home = tempDir('rs-enroll-home-');
  const card = tempDir('rs-enroll-card-');
  t.after(async () => {
    await server.close();
    rmSync(home, { recursive: true, force: true });
    rmSync(card, { recursive: true, force: true });
  });

  writeFileSync(join(card, 'EN0001.JPG'), Buffer.from('enrolment-window'.padEnd(4000, 'e')));
  const code = server.enrollDevice();
  const env = {
    BRIDGE_DB: join(home, 'spool.db'), BRIDGE_CARD: card,
    BRIDGE_URL: server.baseUrl, BRIDGE_EVENT: 'event-a', BRIDGE_ENROLL_CODE: code,
  };

  const died = await runWorker({ ...env, BRIDGE_STOP_BEFORE_ENROLL: '1' });
  assert.equal(died.signal, 'SIGKILL', 'died with a keypair on disk and no enrollment');

  const finished = await runWorker(env);
  assert.equal(finished.code, 0);
  assert.equal(server.devices.size, 1, 'one device, not two');
  assert.equal(server.confirmedMasters(), 1);
});

test('RESTART: a pending retry survives a restart and is not restarted from zero',
  { timeout: 60_000 }, async (t) => {
  const server = new FakeServer();
  await server.listen();
  const home = tempDir('rs-retry-home-');
  const card = tempDir('rs-retry-card-');
  t.after(async () => {
    await server.close();
    rmSync(home, { recursive: true, force: true });
    rmSync(card, { recursive: true, force: true });
  });

  writeFileSync(join(card, 'RT0001.JPG'), Buffer.from('retry-state'.padEnd(4000, 'r')));
  const env = {
    BRIDGE_DB: join(home, 'spool.db'), BRIDGE_CARD: card,
    BRIDGE_URL: server.baseUrl, BRIDGE_EVENT: 'event-a',
    BRIDGE_ENROLL_CODE: server.enrollDevice(),
  };

  server.faults.announce5xx = 40;          // keep it failing while we kill it
  await runWorker({ ...env, BRIDGE_STOP_AT: 'hashed' }, 8000);

  const db = openDb(env.BRIDGE_DB);
  const row = db.prepare('select * from captures').get();
  assert.ok(row, 'the capture is on disk');
  db.close();

  server.faults.announce5xx = 0;
  delete env.BRIDGE_ENROLL_CODE;
  const finished = await runWorker(env);
  assert.equal(finished.code, 0);
  assert.equal(server.captureCount(), 1, 'the retry resumed rather than starting a new capture');
});

test('RESTART: a half-discovered pair converges to one capture', { timeout: 60_000 }, async (t) => {
  const server = new FakeServer();
  await server.listen();
  const home = tempDir('rs-pair-home-');
  const card = tempDir('rs-pair-card-');
  t.after(async () => {
    await server.close();
    rmSync(home, { recursive: true, force: true });
    rmSync(card, { recursive: true, force: true });
  });

  const env = {
    BRIDGE_DB: join(home, 'spool.db'), BRIDGE_CARD: card,
    BRIDGE_URL: server.baseUrl, BRIDGE_EVENT: 'event-a',
    BRIDGE_ENROLL_CODE: server.enrollDevice(),
    BRIDGE_PAIR_GRACE_MS: '300',
  };

  // The JPEG is on the card when the Bridge dies; the RAW lands while it is
  // down. The restarted process must see one shutter press, not two.
  writeFileSync(join(card, 'PR0001.JPG'), Buffer.from('pair-jpeg'.padEnd(4000, 'j')));
  await runWorker({ ...env, BRIDGE_STOP_AT: 'discovered' }, 8000);

  const rawBody = Buffer.from('pair-raw'.padEnd(20000, 'w'));
  writeFileSync(join(card, 'PR0001.CR3'), rawBody);

  delete env.BRIDGE_ENROLL_CODE;
  const finished = await runWorker(env);
  assert.equal(finished.code, 0);

  assert.equal(server.captureCount(), 1, 'one shutter press');
  const cap = server.allCaptures()[0];
  const rawDigest = createHash('sha256').update(rawBody).digest('hex');
  assert.equal(cap.assets.master.sha256, rawDigest, 'with the RAW as its master');
  assert.ok(cap.assets.preview, 'and the JPEG as its preview');
});

test('RESTART: no capture ping-pongs between states across repeated restarts',
  { timeout: 120_000 }, async (t) => {
  const server = new FakeServer();
  await server.listen();
  const home = tempDir('rs-pp-home-');
  const card = tempDir('rs-pp-card-');
  t.after(async () => {
    await server.close();
    rmSync(home, { recursive: true, force: true });
    rmSync(card, { recursive: true, force: true });
  });

  for (let i = 0; i < 6; i++) {
    writeFileSync(join(card, `PP${i}.JPG`), Buffer.from(`pingpong-${i}`.padEnd(5000, 'p')));
  }
  const env = {
    BRIDGE_DB: join(home, 'spool.db'), BRIDGE_CARD: card,
    BRIDGE_URL: server.baseUrl, BRIDGE_EVENT: 'event-a',
    BRIDGE_ENROLL_CODE: server.enrollDevice(),
  };

  // Restart at each transition in turn, then let it finish. Attempt counts
  // are the tell: a capture that rewinds and redoes work forever accumulates
  // attempts without ever reaching a terminal state.
  for (const state of STATES) {
    await runWorker({ ...env, BRIDGE_STOP_AT: state }, 8000);
    delete env.BRIDGE_ENROLL_CODE;
  }
  const finished = await runWorker(env);
  assert.equal(finished.code, 0);

  const db = openDb(env.BRIDGE_DB);
  const rows = db.prepare('select * from captures').all();
  db.close();

  assert.equal(rows.length, 6, 'six shutter presses, six rows');
  for (const r of rows) {
    assert.ok(['complete', 'rejected'].includes(r.state),
      `capture ${r.device_sequence} settled (got ${r.state})`);
    assert.ok(r.attempts < 12,
      `capture ${r.device_sequence} did not churn (attempts=${r.attempts})`);
  }
  assert.equal(server.captureCount(), 6);
  assert.equal(server.confirmedMasters(), 6);
});
