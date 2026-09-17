// Two Bridges at one event, and two organizations at once.
//
// A wedding is routinely shot by two photographers with two laptops. That must
// produce two independent devices whose work lands in one event without
// colliding — and, when the laptops belong to different studios, without one
// studio's photographs ever reaching the other.

import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { Bridge } from '../src/bridge.js';
import { FakeServer } from './fake-server.js';
import { tempDir, settle } from './helpers.js';

async function makeBridgeOn(server, { eventId = 'event-a', organizationId = null } = {}) {
  const home = tempDir('mb-home-');
  const card = tempDir('mb-card-');
  const bridge = new Bridge({
    dbFile: join(home, 'spool.db'), roots: [card], eventId,
    baseUrl: server.baseUrl, quietMs: 0, pairGraceMs: 0, log: () => {},
  });
  const code = server.enrollDevice({ organizationId });
  await bridge.enrollIfNeeded(code);
  // Opening the session here rather than leaving it to the first drain, so a
  // failure to authenticate shows up as a failure to authenticate rather than
  // as a spool that mysteriously will not settle.
  try { await bridge.ensureSession(); } catch { /* the cross-tenant tests expect this */ }
  return { bridge, home, card, cleanup() {
    bridge.close();
    rmSync(home, { recursive: true, force: true });
    rmSync(card, { recursive: true, force: true });
  } };
}

test('MULTI: two Bridges at one event are independent devices', async (t) => {
  const server = new FakeServer();
  await server.listen();
  const a = await makeBridgeOn(server);
  const b = await makeBridgeOn(server);
  t.after(async () => { a.cleanup(); b.cleanup(); await server.close(); });

  assert.equal(server.devices.size, 2, 'two enrollments, two devices');
  assert.notEqual(a.bridge.identity.row().device_id, b.bridge.identity.row().device_id);

  await a.bridge.ensureSession();
  await b.bridge.ensureSession();
  assert.equal(server.liveSessionsFor(a.bridge.identity.row().device_id).length, 1);
  assert.equal(server.liveSessionsFor(b.bridge.identity.row().device_id).length, 1,
    'each holds its own session; neither supersedes the other');
  assert.equal(server.cloneSuspected(a.bridge.identity.row().device_id), false,
    'two legitimate photographers are not mistaken for a clone');
});

test('MULTI: both cameras writing DSC0001.JPG produce two photographs', async (t) => {
  const server = new FakeServer();
  await server.listen();
  const a = await makeBridgeOn(server);
  const b = await makeBridgeOn(server);
  t.after(async () => { a.cleanup(); b.cleanup(); await server.close(); });

  // The single most likely collision at a two-photographer wedding: both
  // bodies are on their first card and both are numbering from 1.
  const bodyA = Buffer.from('shot-by-photographer-a'.padEnd(4000, 'a'));
  const bodyB = Buffer.from('shot-by-photographer-b'.padEnd(4000, 'b'));
  writeFileSync(join(a.card, 'DSC0001.JPG'), bodyA);
  writeFileSync(join(b.card, 'DSC0001.JPG'), bodyB);

  assert.ok(await settle(a.bridge));
  assert.ok(await settle(b.bridge));

  assert.equal(server.captureCount(), 2, 'two shutter presses, two captures');
  const digests = server.allCaptures().map((c) => c.assets.master.sha256).sort();
  const expected = [bodyA, bodyB].map((x) => createHash('sha256').update(x).digest('hex')).sort();
  assert.deepEqual(digests, expected, 'and each photographer got their own photograph');
});

test('MULTI: sequence numbers from two devices do not collide', async (t) => {
  const server = new FakeServer();
  await server.listen();
  const a = await makeBridgeOn(server);
  const b = await makeBridgeOn(server);
  t.after(async () => { a.cleanup(); b.cleanup(); await server.close(); });

  // Both spools start at sequence 1. Uniqueness is per device, not global.
  for (let i = 0; i < 5; i++) {
    writeFileSync(join(a.card, `A${i}.JPG`), Buffer.from(`a-${i}`.padEnd(3000, 'a')));
    writeFileSync(join(b.card, `B${i}.JPG`), Buffer.from(`b-${i}`.padEnd(3000, 'b')));
  }
  assert.ok(await settle(a.bridge));
  assert.ok(await settle(b.bridge));

  assert.equal(server.captureCount(), 10);
  const byDevice = new Map();
  for (const c of server.allCaptures()) {
    const seen = byDevice.get(c.device_id) ?? new Set();
    assert.ok(!seen.has(c.device_sequence), 'no device reused a sequence number');
    seen.add(c.device_sequence);
    byDevice.set(c.device_id, seen);
  }
  assert.equal(byDevice.size, 2, 'the work is attributed to the right two devices');
});

test('MULTI: a device cannot shoot another organization\'s event', async (t) => {
  const server = new FakeServer({
    organizationId: 'org-a',
    liveEvents: ['event-a', 'event-b'],
    events: { 'event-a': 'org-a', 'event-b': 'org-b' },
  });
  await server.listen();

  // Studio A's device, pointed at Studio B's event.
  const a = await makeBridgeOn(server, { eventId: 'event-b', organizationId: 'org-a' });
  t.after(async () => { a.cleanup(); await server.close(); });

  await assert.rejects(() => a.bridge.ensureSession(), /wrong_organization|organization/);

  writeFileSync(join(a.card, 'X1.JPG'), Buffer.from('should-not-land'.padEnd(3000, 'x')));
  await a.bridge.ingestOnce();
  await a.bridge.ingestOnce();
  await a.bridge.drain(20);

  assert.equal(server.captureCount(), 0, 'nothing crossed the tenant boundary');
  assert.equal(a.bridge.db.prepare('select count(*) n from captures').get().n, 1,
    'and the photograph is held locally rather than discarded');
});

test('MULTI: two organizations shooting simultaneously stay separate', async (t) => {
  const server = new FakeServer({
    organizationId: 'org-a',
    liveEvents: ['event-a', 'event-b'],
    events: { 'event-a': 'org-a', 'event-b': 'org-b' },
  });
  await server.listen();
  const a = await makeBridgeOn(server, { eventId: 'event-a', organizationId: 'org-a' });
  const b = await makeBridgeOn(server, { eventId: 'event-b', organizationId: 'org-b' });
  t.after(async () => { a.cleanup(); b.cleanup(); await server.close(); });

  for (let i = 0; i < 4; i++) {
    writeFileSync(join(a.card, `OA${i}.JPG`), Buffer.from(`org-a-${i}`.padEnd(3000, 'a')));
    writeFileSync(join(b.card, `OB${i}.JPG`), Buffer.from(`org-b-${i}`.padEnd(3000, 'b')));
  }
  assert.ok(await settle(a.bridge));
  assert.ok(await settle(b.bridge));

  assert.equal(server.captureCount(), 8);
  for (const c of server.allCaptures()) {
    assert.equal(server.ownerOf(c.event_id), c.organization_id,
      'every capture belongs to the organization that owns its event');
  }
  const orgA = server.allCaptures().filter((c) => c.organization_id === 'org-a');
  const orgB = server.allCaptures().filter((c) => c.organization_id === 'org-b');
  assert.equal(orgA.length, 4);
  assert.equal(orgB.length, 4);
  assert.equal(orgA.every((c) => c.event_id === 'event-a'), true);
  assert.equal(orgB.every((c) => c.event_id === 'event-b'), true);
});

test('MULTI: a stolen session token cannot be used against another tenant', async (t) => {
  const server = new FakeServer({
    organizationId: 'org-a',
    liveEvents: ['event-a', 'event-b'],
    events: { 'event-a': 'org-a', 'event-b': 'org-b' },
  });
  await server.listen();
  const a = await makeBridgeOn(server, { eventId: 'event-a', organizationId: 'org-a' });
  const b = await makeBridgeOn(server, { eventId: 'event-b', organizationId: 'org-b' });
  t.after(async () => { a.cleanup(); b.cleanup(); await server.close(); });

  await a.bridge.ensureSession();
  await b.bridge.ensureSession();

  // Studio B's Bridge, holding Studio A's credential, announcing into A's event.
  const stolen = a.bridge.sessions.current();
  b.bridge.sessions.save({
    sessionId: stolen.session_id, eventId: 'event-a', organizationId: 'org-a',
    token: stolen.token, expiresAt: stolen.expires_at,
  });

  writeFileSync(join(b.card, 'STEAL.JPG'), Buffer.from('stolen-context'.padEnd(3000, 's')));
  await b.bridge.ingestOnce();
  await b.bridge.ingestOnce();
  await b.bridge.drain(20);

  // The token is A's, so anything it creates is attributed to A's device —
  // never to B, and never into B's event. Impersonation is not tenant
  // crossover, and the capture is bound to the token's owner.
  for (const c of server.allCaptures()) {
    assert.equal(c.organization_id, 'org-a');
    assert.equal(c.event_id, 'event-a');
    assert.notEqual(c.device_id, b.bridge.identity.row().device_id,
      'B never acquires authority it did not hold');
  }
});

test('MULTI: an event changing hands mid-session stops the old tenant immediately', async (t) => {
  // The session-open check cannot catch this: the session was legitimate when
  // it was issued. Only the per-request check can, which is why it exists
  // rather than being redundant with the check at session open.
  const server = new FakeServer({
    organizationId: 'org-a',
    liveEvents: ['event-a'],
    events: { 'event-a': 'org-a' },
  });
  await server.listen();
  const a = await makeBridgeOn(server, { eventId: 'event-a', organizationId: 'org-a' });
  t.after(async () => { a.cleanup(); await server.close(); });

  writeFileSync(join(a.card, 'BEFORE.JPG'), Buffer.from('legitimate'.padEnd(3000, 'b')));
  assert.ok(await settle(a.bridge));
  assert.equal(server.confirmedMasters(), 1);

  // The event is reassigned to another studio while this Bridge is still
  // holding a valid, unexpired, unsuperseded session for it.
  server.eventOwners.set('event-a', 'org-b');

  writeFileSync(join(a.card, 'AFTER.JPG'), Buffer.from('no-longer-theirs'.padEnd(3000, 'c')));
  await a.bridge.ingestOnce();
  await a.bridge.ingestOnce();
  await a.bridge.drain(20);

  assert.equal(server.captureCount(), 1,
    'the still-valid session stops working the moment the event is not theirs');
  assert.equal(a.bridge.db.prepare('select count(*) n from captures').get().n, 2,
    'and the photograph is held locally rather than lost');
});
