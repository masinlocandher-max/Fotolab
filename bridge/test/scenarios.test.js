// The Phase 2 non-negotiables: every way a real event tries to lose a photograph.

import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { S } from '../src/spool.js';
import { makeBridge, enrollAndSession, settle, writeShot, tempDir, ingestUntilFound } from './helpers.js';

test('a photograph shot on a good connection becomes exactly one capture', async (t) => {
  const { bridge, server, cleanup } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeShot(bridge.scanner.roots[0], 'DSC0001.JPG', { seed: 'one' });
  assert.ok(await settle(bridge));

  assert.equal(server.captureCount(), 1);
  assert.equal(server.confirmedMasters(), 1);
  const row = bridge.spool.pending().length;
  assert.equal(row, 0);
  assert.equal(bridge.spool.counts()[S.COMPLETE], 1);
});

test('a JPEG+RAW pair is one photograph, not two', async (t) => {
  const { bridge, server, cleanup } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  const card = bridge.scanner.roots[0];
  writeShot(card, 'DSC0007.JPG', { seed: 'jpeg-of-7' });
  writeShot(card, 'DSC0007.CR3', { seed: 'raw-of-7', bytes: 8192 });
  assert.ok(await settle(bridge));

  assert.equal(server.captureCount(), 1, 'one shutter press, one capture');
  const cap = server.allCaptures()[0];
  assert.ok(cap.assets.preview, 'the camera JPEG went up as the preview');
  assert.ok(cap.assets.master, 'the RAW went up as the master');
  assert.notEqual(cap.assets.preview.sha256, cap.assets.master.sha256);
});

test('duplicate camera filenames on different cards stay separate photographs', async (t) => {
  const cardOne = tempDir('card-one-');
  const cardTwo = tempDir('card-two-');
  const { bridge, server, cleanup, cards } = await makeBridge({ roots: [cardOne, cardTwo] });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  // The same filename the camera reuses after a card swap — different content.
  writeShot(cards[0], 'DSC0001.JPG', { seed: 'card-one-image' });
  writeShot(cards[1], 'DSC0001.JPG', { seed: 'card-two-image' });
  assert.ok(await settle(bridge));

  assert.equal(server.captureCount(), 2, 'filename is not an identifier');
});

test('the same bytes arriving twice in one event is one photograph', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  const buf = Buffer.from('identical-content'.padEnd(4096, '.'));
  writeFileSync(join(cards[0], 'DSC0010.JPG'), buf);
  writeFileSync(join(cards[0], 'COPY0010.JPG'), buf);
  assert.ok(await settle(bridge));

  assert.equal(server.captureCount(), 1);
  const counts = bridge.spool.counts();
  assert.equal(counts[S.REJECTED], 1);
  const rejected = bridge.db.prepare("select rejected_reason from captures where state='rejected'").get();
  assert.equal(rejected.rejected_reason, 'duplicate_content');
});

test('repeated scans of an unchanged card create nothing new', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeShot(cards[0], 'DSC0002.JPG', { seed: 'two' });
  for (let i = 0; i < 5; i++) await bridge.ingestOnce();
  assert.equal(bridge.db.prepare('select count(*) n from captures').get().n, 1);
});

test('a file still being written is not spooled until it settles', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge({ quietMs: 50 });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  const p = join(cards[0], 'DSC0003.CR3');
  writeFileSync(p, Buffer.alloc(1000, 1));
  assert.equal(await bridge.ingestOnce(), 0, 'first sighting is never enough');

  writeFileSync(p, Buffer.alloc(9000, 1));            // camera still writing
  assert.equal(await bridge.ingestOnce(), 0, 'growth restarts the quiet period');

  await new Promise((r) => setTimeout(r, 60));
  assert.equal(await bridge.ingestOnce(), 1);
  assert.equal(bridge.spool.byId(1).observed_size, 9000);
});

test('a file replaced while hashing is not uploaded under the old digest', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  const p = join(cards[0], 'DSC0004.JPG');
  writeFileSync(p, Buffer.alloc(4096, 7));
  assert.ok(await ingestUntilFound(bridge));

  await bridge.pipeline.step();                       // DISCOVERED -> HASHED
  const hashed = bridge.spool.byId(1);
  assert.equal(hashed.state, S.HASHED);

  writeFileSync(p, Buffer.alloc(4096, 9));            // different content, same size
  assert.ok(await settle(bridge));

  // Whatever the server ended up with, it must match a digest we computed —
  // never a digest from the version that no longer exists.
  const cap = server.allCaptures()[0];
  if (cap?.assets.master) {
    const onDisk = readFileSync(p);
    const { createHash } = await import('node:crypto');
    assert.equal(cap.assets.master.sha256, createHash('sha256').update(onDisk).digest('hex'));
  }
});

test('an empty or unreadable file is rejected, not retried forever', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeFileSync(join(cards[0], 'DSC0005.JPG'), Buffer.alloc(0));
  assert.ok(await ingestUntilFound(bridge));
  await bridge.pipeline.step();

  const row = bridge.spool.byId(1);
  assert.equal(row.state, S.REJECTED);
  assert.equal(row.rejected_reason, 'empty_file');
  assert.equal(server.captureCount(), 0);
});

test('wifi disappearing mid-event loses nothing and resumes on reconnect', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  server.faults.networkDead = true;
  for (let i = 0; i < 12; i++) writeShot(cards[0], `DSC01${String(i).padStart(2, '0')}.JPG`, { seed: `shot-${i}` });

  for (let i = 0; i < 6; i++) {
    await bridge.ingestOnce();
    await bridge.drain(50);
    bridge.db.prepare('update captures set next_attempt_at_ms = 0').run();
  }
  assert.equal(bridge.db.prepare('select count(*) n from captures').get().n, 12,
    'every shot is spooled while offline');
  assert.equal(server.captureCount(), 0, 'and nothing reached the server');

  server.faults.networkDead = false;
  assert.ok(await settle(bridge), 'spool drains once the venue wifi returns');
  assert.equal(server.captureCount(), 12);
  assert.equal(server.confirmedMasters(), 12);
});

test('server 5xx is retried with growing backoff rather than a retry storm', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  server.faults.announce5xx = 3;
  writeShot(cards[0], 'DSC0020.JPG', { seed: 'flaky' });
  assert.ok(await ingestUntilFound(bridge));
  await bridge.pipeline.step();                       // hash

  const waits = [];
  for (let i = 0; i < 3; i++) {
    const before = Date.now();
    bridge.db.prepare('update captures set next_attempt_at_ms = 0').run();
    await bridge.pipeline.step();
    const row = bridge.spool.byId(1);
    waits.push(row.next_attempt_at_ms - before);
  }
  assert.ok(waits[2] > waits[0], `backoff grows: ${waits.join(', ')}`);

  assert.ok(await settle(bridge));
  assert.equal(server.confirmedMasters(), 1);
});

test('a corrupted upload is never confirmed, and is re-sent until it matches', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  server.faults.corruptUpload = 2;      // storage mangles the first two writes
  writeShot(cards[0], 'DSC0030.JPG', { seed: 'corruptible' });
  assert.ok(await settle(bridge));

  const cap = server.allCaptures()[0];
  assert.ok(cap.assets.master, 'eventually stored');
  assert.equal(cap.assets.master.sha256, bridge.spool.byId(1).content_sha256,
    'and only a byte-exact copy was ever confirmed');
});

test('a revoked device stops uploading immediately and keeps its spool', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeShot(cards[0], 'DSC0040.JPG', { seed: 'before-revoke' });
  assert.ok(await settle(bridge));
  assert.equal(server.confirmedMasters(), 1);

  server.revokeDevice(bridge.identity.row().device_id, 'revoked');
  writeShot(cards[0], 'DSC0041.JPG', { seed: 'after-revoke' });
  assert.ok(await ingestUntilFound(bridge));
  await bridge.drain(20);

  assert.equal(server.captureCount(), 1, 'no new capture after revocation');
  assert.equal(bridge.identity.row().status, 'revoked');
  assert.equal(bridge.db.prepare('select count(*) n from captures').get().n, 2,
    'the unsent photograph is still spooled locally, not discarded');
});

test('a compromised device is recorded distinctly from a revoked one', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  server.revokeDevice(bridge.identity.row().device_id, 'compromised');
  writeShot(cards[0], 'DSC0042.JPG', { seed: 'x' });
  assert.ok(await ingestUntilFound(bridge));
  await bridge.drain(10);

  assert.equal(bridge.identity.row().status, 'compromised');
});

test('an expired session is renewed without losing position', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeShot(cards[0], 'DSC0050.JPG', { seed: 'pre-expiry' });
  assert.ok(await ingestUntilFound(bridge));
  await bridge.pipeline.step();

  // Expire it on both sides, as a real clock would.
  for (const [, s] of server.sessions) s.expiresAt = Date.now() - 1000;
  bridge.db.prepare("update session set expires_at = ? where id = 1")
    .run(new Date(Date.now() - 1000).toISOString());

  await bridge.ensureSession();
  assert.ok(bridge.sessions.isLive(), 'a fresh credential was obtained');
  assert.ok(await settle(bridge));
  assert.equal(server.confirmedMasters(), 1);
});

test('a session cannot be opened for an event this device may not shoot', async (t) => {
  const { bridge, server, cleanup } = await makeBridge({ eventId: 'event-somebody-elses' });
  t.after(() => { cleanup(); return server.close(); });

  const code = server.enrollDevice();
  await bridge.enrollIfNeeded(code);
  await assert.rejects(() => bridge.ensureSession(), /event_not_live|event not live/);
});

test('local files are never deleted before the server confirms the master', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  const p = writeShot(cards[0], 'DSC0060.JPG', { seed: 'keepme' });
  server.faults.confirm5xx = 2;
  await settle(bridge);

  assert.ok(existsSync(p), 'still on disk while unconfirmed');

  // Default retention is "never delete" — the safe default for somebody's
  // only copy of a wedding.
  const noop = await bridge.pipeline.sweepCleanup();
  assert.equal(noop.deleted, 0);

  // With retention explicitly enabled and elapsed, a confirmed master may go.
  assert.equal(server.confirmedMasters(), 1);
  const res = await bridge.pipeline.sweepCleanup({ retentionMs: 0 });
  assert.equal(res.deleted, 1);
  assert.equal(existsSync(p), false);
});

test('cleanup refuses to delete a file whose bytes no longer match', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  const p = writeShot(cards[0], 'DSC0070.JPG', { seed: 'original' });
  assert.ok(await settle(bridge));

  writeFileSync(p, Buffer.from('a completely different photograph'.padEnd(2048, '!')));
  const res = await bridge.pipeline.sweepCleanup({ retentionMs: 0 });

  assert.equal(res.deleted, 0);
  assert.ok(existsSync(p), 'an unrelated file that took the name is not destroyed');
});
