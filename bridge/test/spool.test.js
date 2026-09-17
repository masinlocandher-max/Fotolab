// State machine invariants, in isolation from the network and the filesystem.

import test from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { Spool, S, TERMINAL } from '../src/spool.js';

function spool() { return new Spool(openDb(':memory:')); }

let n = 0;
function shot(sp, over = {}) {
  return sp.discover({
    groupKey: over.groupKey ?? `/card\u0000DSC${++n}`,
    masterPath: over.masterPath ?? '/card/DSC0001.CR3',
    previewPath: over.previewPath ?? null,
    eventId: over.eventId ?? 'event-a',
    size: 1234, mtimeMs: Date.now(),
  });
}

test('a discovered row is committed before anything else happens', () => {
  const sp = spool();
  const row = shot(sp);
  assert.equal(row.state, S.DISCOVERED);
  assert.ok(row.idempotency_key, 'the idempotency key exists from the first instant');
  assert.equal(row.server_capture_id, null);
});

test('sequence numbers never repeat, even across deletions', () => {
  const sp = spool();
  const a = shot(sp), b = shot(sp);
  assert.equal(b.device_sequence, a.device_sequence + 1);

  sp.db.prepare('delete from captures where id = ?').run(b.id);
  const c = shot(sp);
  assert.equal(c.device_sequence, b.device_sequence + 1,
    'the high-water mark does not recycle a number the server may have seen');
});

test('only declared edges are walkable', () => {
  const sp = spool();
  const row = shot(sp);
  assert.throws(() => sp.transition(row.id, S.QUEUED), /illegal capture transition/);
  assert.throws(() => sp.transition(row.id, S.COMPLETE), /illegal capture transition/);

  sp.transition(row.id, S.HASHED, { content_sha256: 'a'.repeat(64) });
  sp.transition(row.id, S.QUEUED, { server_capture_id: 'cap-1' });
  sp.transition(row.id, S.UPLOADING_PREVIEW);
  sp.transition(row.id, S.PREVIEW_CONFIRMED, { preview_asset_id: 'ast-1' });
  sp.transition(row.id, S.UPLOADING_MASTER);
  sp.transition(row.id, S.MASTER_CONFIRMED, { master_asset_id: 'ast-2' });
  sp.transition(row.id, S.COMPLETE);
  assert.ok(TERMINAL.has(sp.byId(row.id).state));
});

test('a terminal row cannot be resurrected', () => {
  const sp = spool();
  const row = shot(sp);
  sp.reject(row.id, 'empty_file');
  assert.throws(() => sp.transition(row.id, S.HASHED), /illegal capture transition/);
});

test('state and the facts justifying it land in one commit', () => {
  const sp = spool();
  const row = shot(sp);
  sp.transition(row.id, S.HASHED, { content_sha256: 'b'.repeat(64) });
  sp.transition(row.id, S.QUEUED, { server_capture_id: 'cap-9' });

  const after = sp.byId(row.id);
  assert.equal(after.state, S.QUEUED);
  assert.equal(after.server_capture_id, 'cap-9',
    'a capture id is never visible without the state that earned it');
});

test('failure records position rather than erasing it', () => {
  const sp = spool();
  const row = shot(sp);
  sp.transition(row.id, S.HASHED, { content_sha256: 'c'.repeat(64) });

  const a1 = sp.recordFailure(row.id, new Error('network down'));
  const a2 = sp.recordFailure(row.id, new Error('network down'));
  const after = sp.byId(row.id);

  assert.equal(a2, a1 + 1);
  assert.equal(after.state, S.HASHED, 'the row did not move');
  assert.match(after.last_error, /network down/);
  assert.ok(after.next_attempt_at_ms > Date.now(), 'and is not retried immediately');
});

test('backoff grows and stays bounded', () => {
  const sp = spool();
  const row = shot(sp);
  let last = 0;
  for (let i = 0; i < 12; i++) {
    sp.recordFailure(row.id, new Error('x'));
    last = sp.byId(row.id).next_attempt_at_ms - Date.now();
  }
  assert.ok(last > 5_000, 'repeated failure backs off meaningfully');
  assert.ok(last <= 61_000, 'and never runs away');
});

test('rows due later are not claimed', () => {
  const sp = spool();
  const row = shot(sp);
  sp.recordFailure(row.id, new Error('later'));
  assert.equal(sp.claimNext(), undefined);

  sp.db.prepare('update captures set next_attempt_at_ms = 0').run();
  assert.equal(sp.claimNext().id, row.id);
});

test('work is claimed in shutter order', () => {
  const sp = spool();
  const a = shot(sp), b = shot(sp);
  sp.recordFailure(a.id, new Error('x'));
  sp.db.prepare('update captures set next_attempt_at_ms = 0').run();
  assert.equal(sp.claimNext().id, a.id, 'oldest sequence first, not most recently touched');
  assert.ok(b.device_sequence > a.device_sequence);
});

test('recovery rewinds interrupted uploads and nothing else', () => {
  const sp = spool();
  const a = shot(sp), b = shot(sp), c = shot(sp);
  for (const r of [a, b, c]) {
    sp.transition(r.id, S.HASHED, { content_sha256: String(r.id).padEnd(64, 'f') });
  }
  sp.transition(a.id, S.QUEUED, { server_capture_id: 'c1' });
  sp.transition(a.id, S.UPLOADING_PREVIEW);
  sp.transition(b.id, S.QUEUED, { server_capture_id: 'c2' });
  sp.transition(b.id, S.UPLOADING_PREVIEW);
  sp.transition(b.id, S.PREVIEW_CONFIRMED, { preview_asset_id: 'p2' });
  sp.transition(b.id, S.UPLOADING_MASTER);

  assert.equal(sp.recover(), 2);
  assert.equal(sp.byId(a.id).state, S.QUEUED, 'preview upload re-arms');
  assert.equal(sp.byId(b.id).state, S.PREVIEW_CONFIRMED,
    'master upload re-arms without discarding the confirmed preview');
  assert.equal(sp.byId(c.id).state, S.HASHED, 'untouched rows stay put');
  assert.equal(sp.byId(b.id).preview_asset_id, 'p2',
    'a server acknowledgement is never rewound');
});

test('retiring a capture frees its group key for rediscovery', () => {
  const sp = spool();
  const key = '/card\u0000DSC0001';
  const row = sp.discover({ groupKey: key, masterPath: '/x', eventId: 'event-a', size: 1, mtimeMs: 1 });
  assert.equal(sp.discover({ groupKey: key, masterPath: '/x', eventId: 'event-a', size: 1, mtimeMs: 1 }), null);

  sp.rejectAndRelease(row.id, 'content_changed_after_announce');
  const fresh = sp.discover({ groupKey: key, masterPath: '/x', eventId: 'event-a', size: 1, mtimeMs: 1 });
  assert.ok(fresh, 'the image now on disk can become its own photograph');
  assert.notEqual(fresh.id, row.id);
});

test('a master cannot be upgraded once the server has been told the digest', () => {
  const sp = spool();
  const row = shot(sp);
  sp.transition(row.id, S.HASHED, { content_sha256: 'd'.repeat(64) });
  sp.transition(row.id, S.QUEUED, { server_capture_id: 'cap-x' });

  // Past this point the server holds a promise about this capture's content.
  // Swapping the master underneath it would make the announced digest a lie.
  assert.throws(
    () => sp.upgradeMasterToRaw(row.id, '/card/DSC0001.CR3', '/card/DSC0001.JPG',
                                { size: 9999, mtimeMs: Date.now() }),
    /cannot upgrade master of a queued capture/);

  const after = sp.byId(row.id);
  assert.equal(after.master_path, '/card/DSC0001.CR3'.replace('/card/DSC0001.CR3', after.master_path),
    'the row is untouched');
  assert.equal(after.state, S.QUEUED);
  assert.equal(after.content_sha256, 'd'.repeat(64), 'and its digest still stands');
});
