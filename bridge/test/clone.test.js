// Device identity cloning.
//
// Enrollment recovery deliberately resolves a repeated enrollment of the same
// public key to the same device — without it, a Bridge killed mid-enrollment
// is bricked. The cost is that copying a Bridge's state directory to a second
// laptop produces two installations the server cannot tell apart by identity.
//
// These tests establish that the two are not treated as harmless independent
// devices, and that crash recovery still works.

import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { Bridge } from '../src/bridge.js';
import { FakeServer } from './fake-server.js';
import { tempDir, writeShot, settle, enrollAndSession, ingestUntilFound } from './helpers.js';

/** A second installation holding a byte-for-byte copy of the first's state. */
function cloneInstallation(originalHome, server, { eventId = 'event-a' } = {}) {
  const home = tempDir('clone-home-');
  cpSync(originalHome, home, { recursive: true });
  const card = tempDir('clone-card-');
  const bridge = new Bridge({
    dbFile: join(home, 'spool.db'), roots: [card], eventId,
    baseUrl: server.baseUrl, quietMs: 0, pairGraceMs: 0, log: () => {},
  });
  return { bridge, home, card };
}

async function makeOriginal(server, { eventId = 'event-a' } = {}) {
  const home = tempDir('orig-home-');
  const card = tempDir('orig-card-');
  const bridge = new Bridge({
    dbFile: join(home, 'spool.db'), roots: [card], eventId,
    baseUrl: server.baseUrl, quietMs: 0, pairGraceMs: 0, log: () => {},
  });
  await enrollAndSession(bridge, server);
  return { bridge, home, card };
}

test('CLONE: a copied installation is the same device, not a second one', async (t) => {
  const server = new FakeServer();
  await server.listen();
  const orig = await makeOriginal(server);
  t.after(async () => { orig.bridge.close(); await server.close(); });

  assert.equal(server.devices.size, 1);
  const deviceId = orig.bridge.identity.row().device_id;

  const clone = cloneInstallation(orig.home, server);
  t.after(() => clone.bridge.close());
  await clone.bridge.ensureSession();

  assert.equal(server.devices.size, 1,
    'the clone did not become an independent device');
  assert.equal(clone.bridge.identity.row().device_id, deviceId,
    'it carries the original identity, which is exactly the problem');
});

test('CLONE: one live session per device — the clone takes it, it is not shared', async (t) => {
  const server = new FakeServer();
  await server.listen();
  const orig = await makeOriginal(server);
  t.after(async () => { orig.bridge.close(); await server.close(); });
  const deviceId = orig.bridge.identity.row().device_id;

  assert.equal(server.liveSessionsFor(deviceId).length, 1);

  const clone = cloneInstallation(orig.home, server);
  t.after(() => clone.bridge.close());
  clone.bridge.sessions.clear();
  await clone.bridge.ensureSession();

  assert.equal(server.liveSessionsFor(deviceId).length, 1,
    'two installations never hold two live sessions at once');
});

test('CLONE: the original discovers it lost the session rather than uploading blind', async (t) => {
  const server = new FakeServer();
  await server.listen();
  const orig = await makeOriginal(server);
  t.after(async () => { orig.bridge.close(); await server.close(); });

  const clone = cloneInstallation(orig.home, server);
  t.after(() => clone.bridge.close());
  clone.bridge.sessions.clear();
  await clone.bridge.ensureSession();          // takes the session

  writeShot(orig.card, 'ORIG01.JPG', { seed: 'original-shot' });
  assert.ok(await ingestUntilFound(orig.bridge));
  await orig.bridge.pipeline.step();           // hash
  const result = await orig.bridge.pipeline.step();   // announce -> superseded

  assert.equal(result, 'halted', 'the original stops rather than uploading with a dead session');
  assert.equal(orig.bridge.spool.pending().length, 1,
    'and its photograph is still spooled, not discarded');
});

test('CLONE: two installations fighting are detected and one stands down', async (t) => {
  const server = new FakeServer();
  await server.listen();
  const orig = await makeOriginal(server);
  t.after(async () => { orig.bridge.close(); await server.close(); });
  const deviceId = orig.bridge.identity.row().device_id;

  const clone = cloneInstallation(orig.home, server);
  t.after(() => clone.bridge.close());

  // Each takes the session back from the other, immediately, repeatedly —
  // which is what two machines with one identity actually look like.
  for (let i = 0; i < 4; i++) {
    for (const b of [clone.bridge, orig.bridge]) {
      b.sessions.clear();
      try { await b.ensureSession(); } catch { /* halted */ }
    }
  }

  assert.ok(server.cloneSuspected(deviceId),
    'the server flags the device rather than serving both quietly');
  assert.ok(orig.bridge.haltReason || clone.bridge.haltReason,
    'and at least one installation stops competing for the identity');
});

test('CLONE: an installation that keeps losing its session stops competing', async (t) => {
  // Client-side defence, independent of the server's own clone flag: if this
  // process keeps having its session taken, it stops rather than entering an
  // upload war with whatever is on the other laptop.
  const server = new FakeServer();
  await server.listen();
  const orig = await makeOriginal(server);
  t.after(async () => { orig.bridge.close(); await server.close(); });

  const clone = cloneInstallation(orig.home, server);
  t.after(() => clone.bridge.close());

  writeShot(orig.card, 'FIGHT01.JPG', { seed: 'contested' });

  // Before each of the original's cycles, the clone grabs the session back.
  const realRunOnce = orig.bridge.runOnce.bind(orig.bridge);
  orig.bridge.runOnce = async () => {
    clone.bridge.sessions.clear();
    try { await clone.bridge.ensureSession(); } catch { /* clone may halt too */ }
    return realRunOnce();
  };

  const { haltReason } = await orig.bridge.run({ maxCycles: 8 });

  assert.ok(haltReason, `the Bridge halted rather than looping forever (${haltReason})`);
  assert.ok(orig.bridge.sessionTakeovers > 0, 'and it counted the takeovers it suffered');

  // The photograph may have got through on a cycle where the original held
  // the session, or may still be waiting. Either is fine. What must be true
  // is that it is somewhere — the fight never costs a photograph.
  const spooled = orig.bridge.db.prepare('select count(*) n from captures').get().n;
  assert.equal(spooled, 1, 'the contested photograph is accounted for locally');
  const done = orig.bridge.spool.pending().length === 0;
  assert.ok(done ? server.captureCount() === 1 : true,
    'and if it left the laptop, it became exactly one capture');
});

test('CLONE: an ordinary restart is not mistaken for a clone', async (t) => {
  const server = new FakeServer();
  await server.listen();
  const orig = await makeOriginal(server);
  t.after(async () => { await server.close(); });
  const deviceId = orig.bridge.identity.row().device_id;

  writeShot(orig.card, 'RESTART01.JPG', { seed: 'before-restart' });
  assert.ok(await settle(orig.bridge));
  orig.bridge.close();

  // The same laptop, restarted, after its session went quiet.
  for (const s of server.sessions.values()) s.lastSeenAt = Date.now() - 10 * 60_000;

  const again = new Bridge({
    dbFile: join(orig.home, 'spool.db'), roots: [orig.card], eventId: 'event-a',
    baseUrl: server.baseUrl, quietMs: 0, pairGraceMs: 0, log: () => {},
  });
  t.after(() => again.close());
  again.recover();
  await again.ensureSession();

  assert.equal(server.cloneSuspected(deviceId), false,
    'crash recovery must not look like theft');
  assert.equal(again.haltReason, null, 'and the Bridge keeps working');

  writeShot(orig.card, 'RESTART02.JPG', { seed: 'after-restart' });
  assert.ok(await settle(again));
  assert.equal(server.confirmedMasters(), 2);
});

test('CLONE: a clone that goes away and returns does not duplicate photographs', async (t) => {
  const server = new FakeServer();
  await server.listen();
  const orig = await makeOriginal(server);
  t.after(async () => { orig.bridge.close(); await server.close(); });

  // Both laptops hold the same spool, so both believe they should upload the
  // same photograph. The idempotency key was copied with it.
  writeShot(orig.card, 'SHARED01.JPG', { seed: 'shared-photograph' });
  assert.ok(await ingestUntilFound(orig.bridge));

  const clone = cloneInstallation(orig.home, server);
  t.after(() => clone.bridge.close());
  cpSync(orig.card, clone.card, { recursive: true });
  clone.bridge.sessions.clear();
  await clone.bridge.ensureSession();
  await settle(clone.bridge);

  // The original comes back, re-opens its session, and drains.
  orig.bridge.sessions.clear();
  orig.bridge.sessionTakeovers = 0;
  orig.bridge.haltReason = null;
  await orig.bridge.ensureSession();
  await settle(orig.bridge);

  assert.equal(server.captureCount(), 1,
    'the shared idempotency key collapses both installations onto one capture');
});

test('CLONE: a device declared compromised stops both installations', async (t) => {
  const server = new FakeServer();
  await server.listen();
  const orig = await makeOriginal(server);
  t.after(async () => { orig.bridge.close(); await server.close(); });
  const deviceId = orig.bridge.identity.row().device_id;

  const clone = cloneInstallation(orig.home, server);
  t.after(() => clone.bridge.close());

  server.revokeDevice(deviceId, 'compromised');

  for (const b of [orig.bridge, clone.bridge]) {
    b.sessions.clear();
    await assert.rejects(() => b.ensureSession(), /compromised|device/);
  }

  writeShot(orig.card, 'AFTER01.JPG', { seed: 'after-compromise' });
  await ingestUntilFound(orig.bridge);
  await orig.bridge.drain(10);
  assert.equal(server.captureCount(), 0, 'neither installation can upload');
  assert.equal(orig.bridge.db.prepare('select count(*) n from captures').get().n, 1,
    'and the photograph is kept locally for recovery');
});
