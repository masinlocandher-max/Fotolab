// Disk pressure, against the real filesystem.
//
// The disk cannot be filled inside this container, so pressure is produced by
// moving the thresholds across the volume's actual free space rather than by
// mocking statfs. The readings are real; only the line is moved. That keeps
// the filesystem behaviour genuine — a wrong bsize, a missing bavail or an
// unreadable mount would still fail here.

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { checkDisk, mayIngest, DISK, DEFAULT_THRESHOLDS } from '../src/disk.js';
import { makeBridge, enrollAndSession, settle, writeShot, ingestUntilFound } from './helpers.js';

const HUGE = 2 ** 60;
const critical = { criticalFreeBytes: HUGE, warningFreeBytes: HUGE, criticalFreeRatio: 0.99, warningFreeRatio: 0.99 };
const warning  = { criticalFreeBytes: 0,    warningFreeBytes: HUGE, criticalFreeRatio: 0,    warningFreeRatio: 0.99 };
const healthy  = { criticalFreeBytes: 0,    warningFreeBytes: 0,    criticalFreeRatio: 0,    warningFreeRatio: 0 };

test('DISK: the three states are reported from real filesystem readings', async () => {
  const h = await checkDisk(process.cwd(), healthy);
  const w = await checkDisk(process.cwd(), warning);
  const c = await checkDisk(process.cwd(), critical);

  assert.equal(h.state, DISK.HEALTHY);
  assert.equal(w.state, DISK.WARNING);
  assert.equal(c.state, DISK.CRITICAL);

  assert.ok(h.freeBytes > 0, 'free space is a real number, not a placeholder');
  assert.ok(h.totalBytes >= h.freeBytes);
  assert.ok(h.freeRatio > 0 && h.freeRatio <= 1);
});

test('DISK: the worse of the absolute and proportional readings wins', async () => {
  // Plenty of bytes free, but below the proportional floor.
  const byRatio = await checkDisk(process.cwd(),
    { criticalFreeBytes: 0, warningFreeBytes: 0, criticalFreeRatio: 0.99, warningFreeRatio: 0.99 });
  assert.equal(byRatio.state, DISK.CRITICAL,
    'a nearly-full large volume is critical even with many bytes left');

  // Plenty of proportion free, but below the absolute floor.
  const byBytes = await checkDisk(process.cwd(),
    { criticalFreeBytes: HUGE, warningFreeBytes: HUGE, criticalFreeRatio: 0, warningFreeRatio: 0 });
  assert.equal(byBytes.state, DISK.CRITICAL,
    'a mostly-empty tiny volume is critical when the absolute headroom is gone');
});

test('DISK: an unreadable volume is unknown, and unknown is not safe', async () => {
  const r = await checkDisk('/no/such/volume/anywhere');
  assert.equal(r.state, DISK.UNKNOWN);
  assert.equal(mayIngest(r.state), false,
    'not knowing how much room there is must not read as having room');
});

test('DISK: the shipped defaults are conservative', () => {
  assert.ok(DEFAULT_THRESHOLDS.criticalFreeBytes >= 1024 ** 3, 'at least a GiB of floor');
  assert.ok(DEFAULT_THRESHOLDS.warningFreeBytes > DEFAULT_THRESHOLDS.criticalFreeBytes);
  assert.ok(DEFAULT_THRESHOLDS.warningFreeRatio > DEFAULT_THRESHOLDS.criticalFreeRatio);
});

test('DISK: crossing critical stops new photographs being accepted', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge({ diskThresholds: critical });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeShot(cards[0], 'FULL01.JPG', { seed: 'not-accepted' });
  for (let i = 0; i < 4; i++) await bridge.ingestOnce();

  assert.equal(bridge.db.prepare('select count(*) n from captures').get().n, 0,
    'nothing is taken on that the Bridge cannot durably record');
  assert.equal(bridge.ingestPaused, true, 'and the pause is explicit, not incidental');
  assert.equal(bridge.disk.state, DISK.CRITICAL);
});

test('DISK: a warning state still accepts work', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge({ diskThresholds: warning });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeShot(cards[0], 'WARN01.JPG', { seed: 'still-fine' });
  assert.ok(await settle(bridge));

  assert.equal(bridge.disk.state, DISK.WARNING);
  assert.equal(server.confirmedMasters(), 1,
    'a warning is a warning, not a stoppage — the event does not pause at 5% free');
});

test('DISK: work already in flight keeps draining while ingestion is stopped', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge({ diskThresholds: healthy });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeShot(cards[0], 'INFLIGHT01.JPG', { seed: 'already-mine' });
  assert.ok(await ingestUntilFound(bridge));
  assert.equal(bridge.spool.pending().length, 1);

  // The disk fills while that photograph is mid-flight.
  bridge.diskThresholds = critical;
  await bridge.refreshDisk(true);

  writeShot(cards[0], 'INFLIGHT02.JPG', { seed: 'too-late' });
  for (let i = 0; i < 4; i++) { await bridge.ingestOnce(); await bridge.drain(50); }

  assert.equal(server.confirmedMasters(), 1,
    'the photograph already accepted is still delivered');
  assert.equal(bridge.db.prepare('select count(*) n from captures').get().n, 1,
    'and the one arriving during the outage was not taken on');
});

test('DISK: recovery resumes ingestion without operator action', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge({ diskThresholds: critical });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeShot(cards[0], 'RECOVER01.JPG', { seed: 'waits-on-disk' });
  for (let i = 0; i < 3; i++) await bridge.ingestOnce();
  assert.equal(bridge.db.prepare('select count(*) n from captures').get().n, 0);

  // Space is freed.
  bridge.diskThresholds = healthy;
  await bridge.refreshDisk(true);
  assert.ok(await settle(bridge));

  assert.equal(bridge.ingestPaused, false);
  assert.equal(server.confirmedMasters(), 1,
    'the photograph waiting on the card is picked up once there is room');
});

test('DISK: cleanup still hash-verifies before unlinking, under pressure', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge({ diskThresholds: healthy });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  const keep = writeShot(cards[0], 'PRESSURE01.JPG', { seed: 'genuine' });
  assert.ok(await settle(bridge));
  assert.equal(server.confirmedMasters(), 1);

  // Disk goes critical. Cleanup is not a pressure-release valve that starts
  // deleting things it has not verified.
  bridge.diskThresholds = critical;
  await bridge.refreshDisk(true);

  writeFileSync(keep, Buffer.from('an unrelated file that took the name'.padEnd(2048, '!')));
  const res = await bridge.pipeline.sweepCleanup({ retentionMs: 0 });

  assert.equal(res.deleted, 0);
  assert.ok(existsSync(keep),
    'a photographer file whose name matches is never deleted, however full the disk is');
});

test('DISK: default retention still never deletes, whatever the disk says', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge({ diskThresholds: critical });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  bridge.diskThresholds = healthy;
  await bridge.refreshDisk(true);
  const p = writeShot(cards[0], 'RETAIN01.JPG', { seed: 'keep-me' });
  assert.ok(await settle(bridge));

  bridge.diskThresholds = critical;
  await bridge.refreshDisk(true);
  const res = await bridge.pipeline.sweepCleanup();      // no retention configured

  assert.equal(res.deleted, 0);
  assert.ok(existsSync(p), 'a full disk does not silently enable deletion');
});
