// Attacking the capture identity rule.
//
// The rule under test is: a capture is (directory, basename-without-extension).
// These tests exist to find the four ways it can be wrong:
//
//   1. merge two different shutter presses into one capture
//   2. split one shutter press into several captures
//   3. wait forever for a pair that will never arrive
//   4. create duplicate gallery identity
//
// Written to fail first. Anything green here was green before the fix too, and
// is stated as such.

import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, renameSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { S } from '../src/spool.js';
import { makeBridge, enrollAndSession, settle, writeShot, tempDir, ingestUntilFound } from './helpers.js';

// --- 0. the key itself must be readable ------------------------------------

test('IDENTITY: group keys survive storage intact and are greppable', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  mkdirSync(join(cards[0], '100CANON'), { recursive: true });
  writeFileSync(join(cards[0], '100CANON', 'IMG_9001.JPG'), Buffer.from('a'.repeat(3000)));
  writeFileSync(join(cards[0], '100CANON', 'IMG_9002.JPG'), Buffer.from('b'.repeat(3000)));
  assert.ok(await settle(bridge));

  const rows = bridge.db.prepare('select group_key, length(group_key) len from captures').all();
  assert.equal(rows.length, 2);
  for (const r of rows) {
    assert.equal(r.len, r.group_key.length,
      'SQLite reports the same length the application sees — no silent truncation');
    assert.ok(r.group_key.includes('IMG_900'),
      `the key identifies the photograph, not just its folder (got ${r.group_key})`);
  }
  assert.equal(new Set(rows.map((r) => r.group_key)).size, 2, 'and the two keys differ');

  // The operator-facing case: finding one photograph by name must work.
  const found = bridge.db.prepare(
    "select count(*) n from captures where group_key like '%IMG_9001'").get().n;
  assert.equal(found, 1, 'a diagnostic query by filename finds exactly its capture');
});

// --- 1. merging two different shutter presses ------------------------------

test('IDENTITY: extension case difference must not merge two distinct files', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  // On a case-sensitive filesystem these are two separate photographs that
  // happen to share a stem. Merging them silently loses one.
  writeFileSync(join(cards[0], 'IMG_0001.JPG'), Buffer.from('camera-original'.padEnd(3000, 'a')));
  writeFileSync(join(cards[0], 'IMG_0001.jpg'), Buffer.from('a-different-image'.padEnd(3000, 'b')));

  assert.ok(await settle(bridge));
  assert.equal(server.captureCount(), 2,
    'two distinct files must not collapse into one capture');
});

test('IDENTITY: .jpg and .jpeg for one stem must not silently drop one', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeFileSync(join(cards[0], 'SHOT01.jpg'), Buffer.from('first'.padEnd(3000, 'a')));
  writeFileSync(join(cards[0], 'SHOT01.jpeg'), Buffer.from('second'.padEnd(3000, 'b')));

  assert.ok(await settle(bridge));
  assert.equal(server.captureCount(), 2, 'neither file is discarded');
});

test('IDENTITY: a camera filename counter reset must not swallow the new photograph', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  const p = join(cards[0], 'DSC0001.JPG');
  writeFileSync(p, Buffer.from('the-first-DSC0001'.padEnd(3000, 'a')));
  assert.ok(await settle(bridge));
  assert.equal(server.captureCount(), 1);

  // Counter wrapped at 9999, or the card was formatted and reused. Same name,
  // genuinely different photograph.
  await new Promise((r) => setTimeout(r, 10));
  writeFileSync(p, Buffer.from('the-second-DSC0001'.padEnd(4000, 'b')));
  assert.ok(await settle(bridge));

  assert.equal(server.captureCount(), 2,
    'the reused filename holds a new photograph, and it must not be dropped');
});

// --- 2. splitting one shutter press ----------------------------------------

test('IDENTITY: a RAW arriving well after its JPEG must not be lost', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  // Slow card: the JPEG lands and settles, the RAW follows much later. This is
  // ordinary behaviour, not an edge case.
  writeFileSync(join(cards[0], 'PAIR01.JPG'), Buffer.from('jpeg-of-pair'.padEnd(3000, 'j')));
  assert.ok(await settle(bridge));

  writeFileSync(join(cards[0], 'PAIR01.CR3'), Buffer.from('raw-of-pair'.padEnd(20000, 'r')));
  assert.ok(await settle(bridge));

  // The RAW is the master. Losing it is losing the product.
  const rawDigest = (await import('node:crypto')).createHash('sha256')
    .update(Buffer.from('raw-of-pair'.padEnd(20000, 'r'))).digest('hex');
  const stored = server.allCaptures().flatMap((c) => Object.values(c.assets)).map((a) => a.sha256);
  assert.ok(stored.includes(rawDigest), 'the RAW reached the server somehow');
});

test('IDENTITY: a RAW landing before the JPEG capture is announced upgrades the master', async (t) => {
  // Grace disabled, so the lone JPEG commits immediately as a JPEG-master
  // capture. The RAW then arrives while the capture is still un-announced.
  // A single shutter press always meant RAW-as-master, so the capture is
  // upgraded in place rather than left pointing at the JPEG.
  const { bridge, server, cleanup, cards } = await makeBridge({ pairGraceMs: 0 });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeFileSync(join(cards[0], 'UPG01.JPG'), Buffer.from('jpeg-of-upgrade'.padEnd(3000, 'j')));
  assert.ok(await ingestUntilFound(bridge));
  const before = bridge.spool.byId(1);
  assert.ok(before.master_path.endsWith('.JPG'), 'committed with the JPEG as master');
  assert.equal(before.state, S.DISCOVERED, 'and not yet announced');

  const rawBody = Buffer.from('raw-of-upgrade'.padEnd(20000, 'r'));
  writeFileSync(join(cards[0], 'UPG01.CR3'), rawBody);
  await bridge.ingestOnce();
  await bridge.ingestOnce();

  const after = bridge.spool.byId(1);
  assert.ok(after.master_path.endsWith('.CR3'), 'the master was upgraded to the RAW');
  assert.ok(after.preview_path.endsWith('.JPG'), 'and the JPEG became the preview');
  assert.equal(after.content_sha256, null, 'the stale digest was discarded, not reused');

  assert.ok(await settle(bridge));
  assert.equal(server.captureCount(), 1, 'still one shutter press');
  const cap = server.allCaptures()[0];
  const rawDigest = (await import('node:crypto')).createHash('sha256').update(rawBody).digest('hex');
  assert.equal(cap.assets.master.sha256, rawDigest, 'and the RAW is what the server holds');
});

test('IDENTITY: a JPEG arriving before its RAW is announced is attached as the preview', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge({ quietMs: 0 });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeFileSync(join(cards[0], 'PAIR02.CR3'), Buffer.from('raw-first'.padEnd(20000, 'r')));
  assert.ok(await ingestUntilFound(bridge));         // spooled, not yet announced
  writeFileSync(join(cards[0], 'PAIR02.JPG'), Buffer.from('jpeg-second'.padEnd(3000, 'j')));
  await bridge.ingestOnce();                          // first sighting of the JPEG
  await bridge.ingestOnce();                          // now stable: attach it

  assert.ok(await settle(bridge));
  assert.equal(server.captureCount(), 1, 'still one shutter press');
  const cap = server.allCaptures()[0];
  assert.ok(cap.assets.preview, 'the late JPEG was used rather than discarded');
  assert.ok(cap.assets.master, 'and the RAW is still the master');
});

test('IDENTITY: a RAW arriving after the JPEG was announced still reaches the server', async (t) => {
  // The window the in-place upgrade cannot cover: the capture has already been
  // announced with the JPEG's digest, so the server is holding a promise we
  // cannot retract. The RAW goes up as its own capture with the relationship
  // recorded — two rows the server can reconcile beats a master that never
  // left the laptop.
  const { bridge, server, cleanup, cards } = await makeBridge({ pairGraceMs: 0 });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeFileSync(join(cards[0], 'ORPH01.JPG'), Buffer.from('jpeg-announced'.padEnd(3000, 'j')));
  assert.ok(await ingestUntilFound(bridge));
  await bridge.pipeline.step();                       // hash
  await bridge.pipeline.step();                       // announce
  assert.equal(bridge.spool.byId(1).state, S.QUEUED, 'the server already knows this capture');

  const rawBody = Buffer.from('raw-after-announce'.padEnd(20000, 'r'));
  writeFileSync(join(cards[0], 'ORPH01.CR3'), rawBody);
  assert.ok(await settle(bridge));

  const rawDigest = (await import('node:crypto')).createHash('sha256').update(rawBody).digest('hex');
  const stored = server.allCaptures().flatMap((c) => Object.values(c.assets)).map((a) => a.sha256);
  assert.ok(stored.includes(rawDigest), 'the RAW reached the server');

  const orphan = bridge.db.prepare(
    'select * from captures where sibling_group_key is not null').get();
  assert.ok(orphan, 'and its relationship to the JPEG capture is recorded, not lost');
  assert.ok(orphan.master_path.endsWith('.CR3'));
});

test('IDENTITY: a photograph inside the pair grace window is not mistaken for idleness', async (t) => {
  // A caller that asks "is there anything to do?" while a lone JPEG is waiting
  // for its RAW must be told yes. Answering no is how a Bridge shuts down, or
  // a harness declares success, while holding an uncommitted photograph.
  const { bridge, server, cleanup, cards } = await makeBridge({ pairGraceMs: 5000 });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeFileSync(join(cards[0], 'QUIET01.JPG'), Buffer.from('held-back'.padEnd(3000, 'q')));
  await bridge.ingestOnce();
  await bridge.ingestOnce();

  assert.equal(bridge.spool.pending().length, 0, 'nothing is in the spool yet');
  assert.equal(bridge.scanner.waitingGroups(), 1, 'but the scanner is holding one');
  assert.equal(bridge.isQuiescent(), false,
    'so the Bridge must not report itself idle');
});

test('IDENTITY: a JPEG arriving after the capture completed loses nothing that matters', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge({ quietMs: 0 });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  // The documented residual: once a RAW-only capture is finished, a JPEG
  // turning up later cannot be folded into it. The contract that must hold is
  // narrower than "the JPEG is used" — the master is safe, no second
  // photograph is invented, and the missing preview is explicit so the
  // server-side worker derives one from the RAW.
  writeFileSync(join(cards[0], 'PAIR03.CR3'), Buffer.from('raw-alone'.padEnd(20000, 'r')));
  assert.ok(await settle(bridge));
  assert.equal(server.confirmedMasters(), 1);

  writeFileSync(join(cards[0], 'PAIR03.JPG'), Buffer.from('jpeg-too-late'.padEnd(3000, 'j')));
  assert.ok(await settle(bridge));

  assert.equal(server.captureCount(), 1, 'no duplicate photograph was invented');
  const row = bridge.db.prepare("select * from captures where group_key like '%PAIR03'").get();
  assert.equal(row.preview_skipped, 1, 'the absent preview is recorded, not guessed at');
});

test('IDENTITY: the pair grace window catches a RAW that lands moments after its JPEG', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge({ quietMs: 0, pairGraceMs: 400 });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeFileSync(join(cards[0], 'GRACE01.JPG'), Buffer.from('jpeg-of-grace'.padEnd(3000, 'j')));
  for (let i = 0; i < 3; i++) await bridge.ingestOnce();
  assert.equal(bridge.db.prepare('select count(*) n from captures').get().n, 0,
    'a lone JPEG waits briefly rather than committing to JPEG-as-master');

  writeFileSync(join(cards[0], 'GRACE01.CR3'), Buffer.from('raw-of-grace'.padEnd(20000, 'r')));
  await new Promise((r) => setTimeout(r, 450));
  assert.ok(await settle(bridge));

  assert.equal(server.captureCount(), 1, 'one shutter press');
  const cap = server.allCaptures()[0];
  assert.ok(cap.assets.master && cap.assets.preview, 'RAW as master, JPEG as preview');
});

test('IDENTITY: a pair that never completes must not wait forever', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeFileSync(join(cards[0], 'LONELY.JPG'), Buffer.from('no-raw-coming'.padEnd(3000, 'x')));
  assert.ok(await settle(bridge), 'a JPEG-only capture completes without its absent sibling');
  assert.equal(server.confirmedMasters(), 1);
});

// --- 3. moving and renaming -------------------------------------------------

test('IDENTITY: a file moved mid-flight does not wedge the capture forever', async (t) => {
  // A short grace so the test can observe the bounded deadline. Production
  // waits ten minutes, because a card reader pulled for thirty seconds must
  // not cost a photograph.
  const { bridge, server, cleanup, cards } = await makeBridge({ sourceMissingGraceMs: 150 });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  const from = join(cards[0], 'MOVED.JPG');
  writeFileSync(from, Buffer.from('will-be-moved'.padEnd(5000, 'm')));
  assert.ok(await ingestUntilFound(bridge));
  await bridge.pipeline.step();                    // hash
  await bridge.pipeline.step();                    // announce

  const sorted = join(cards[0], 'sorted');
  mkdirSync(sorted, { recursive: true });
  renameSync(from, join(sorted, 'MOVED.JPG'));

  // Within the grace window the capture waits — it does not give up on a card
  // that might come back.
  await bridge.drain(20);
  const waiting = bridge.spool.byId(1);
  assert.ok(waiting.source_missing_since, 'the absence is recorded and timed');
  assert.ok(!['complete', 'rejected'].includes(waiting.state), 'still hoping');

  // Past the deadline it converges, and releases its group key so the file —
  // which merely moved — is picked up where it now lives.
  await new Promise((r) => setTimeout(r, 200));
  assert.ok(await settle(bridge), 'the spool converges without operator repair');

  const rows = bridge.db.prepare('select * from captures').all();
  assert.ok(rows.some((r) => r.rejected_reason === 'source_vanished'),
    'the stranded capture is explicitly given up on, not left in flight');
  assert.equal(bridge.spool.pending().length, 0, 'nothing is permanently wedged');
  assert.ok(existsSync(join(sorted, 'MOVED.JPG')), 'and the photograph is still on disk');
});

test('IDENTITY: a photographer sorting files into folders does not duplicate them', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  const body = Buffer.from('sorted-later'.padEnd(4000, 's'));
  writeFileSync(join(cards[0], 'SORT01.JPG'), body);
  assert.ok(await settle(bridge));
  assert.equal(server.captureCount(), 1);

  const keep = join(cards[0], 'keepers');
  mkdirSync(keep, { recursive: true });
  renameSync(join(cards[0], 'SORT01.JPG'), join(keep, 'SORT01.JPG'));

  assert.ok(await settle(bridge));
  assert.equal(server.captureCount(), 1,
    'the same bytes in a new folder is the same photograph');
});

// --- 4. formats -------------------------------------------------------------

test('IDENTITY: common RAW formats are all recognised as masters', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  const formats = ['CR3', 'NEF', 'ARW', 'RAF', 'ORF', 'RW2', 'DNG'];
  for (const [i, ext] of formats.entries()) {
    writeFileSync(join(cards[0], `FMT${i}.JPG`), Buffer.from(`jpeg-${ext}`.padEnd(3000, 'j')));
    writeFileSync(join(cards[0], `FMT${i}.${ext}`), Buffer.from(`raw-${ext}`.padEnd(9000, 'r')));
  }
  assert.ok(await settle(bridge));

  assert.equal(server.captureCount(), formats.length, 'one capture per shutter press');
  for (const cap of server.allCaptures()) {
    assert.ok(cap.assets.master, 'every RAW became a master');
    assert.ok(cap.assets.preview, 'every JPEG became a preview');
  }
});

test('IDENTITY: lowercase RAW extensions are recognised too', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeFileSync(join(cards[0], 'LOW01.jpg'), Buffer.from('jpeg-low'.padEnd(3000, 'j')));
  writeFileSync(join(cards[0], 'LOW01.cr3'), Buffer.from('raw-low'.padEnd(9000, 'r')));
  assert.ok(await settle(bridge));

  assert.equal(server.captureCount(), 1);
  const cap = server.allCaptures()[0];
  assert.ok(cap.assets.master && cap.assets.preview);
});

test('IDENTITY: HEIC is treated as a capture, not ignored', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeFileSync(join(cards[0], 'HEIF01.HEIC'), Buffer.from('heic-bytes'.padEnd(4000, 'h')));
  assert.ok(await settle(bridge));
  assert.equal(server.captureCount(), 1);
});

test('IDENTITY: sidecars and junk are ignored without affecting the capture', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  writeFileSync(join(cards[0], 'SIDE01.JPG'), Buffer.from('the-photo'.padEnd(3000, 'p')));
  writeFileSync(join(cards[0], 'SIDE01.XMP'), Buffer.from('<x:xmpmeta/>'));
  writeFileSync(join(cards[0], 'SIDE01.THM'), Buffer.from('thumb'));
  writeFileSync(join(cards[0], '.DS_Store'), Buffer.from('junk'));
  writeFileSync(join(cards[0], 'MISC.txt'), Buffer.from('notes'));

  assert.ok(await settle(bridge));
  assert.equal(server.captureCount(), 1, 'exactly the photograph, nothing else');
});

test('IDENTITY: same filename in separate camera directories is two photographs', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  // 100CANON fills up, camera rolls to 101CANON and restarts numbering.
  for (const dir of ['100CANON', '101CANON']) {
    mkdirSync(join(cards[0], dir), { recursive: true });
    writeFileSync(join(cards[0], dir, 'IMG_0001.JPG'),
      Buffer.from(`from-${dir}`.padEnd(3000, 'c')));
  }
  assert.ok(await settle(bridge));
  assert.equal(server.captureCount(), 2);
});

test('IDENTITY: a card that disappears and returns does not lose or duplicate work', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);

  const card = cards[0];
  const p = join(card, 'EJECT01.JPG');
  writeFileSync(p, Buffer.from('on-the-card'.padEnd(4000, 'e')));
  assert.ok(await ingestUntilFound(bridge));

  // Reader yanked before the upload finishes.
  const stash = tempDir('stash-');
  renameSync(p, join(stash, 'EJECT01.JPG'));
  for (let i = 0; i < 3; i++) { await bridge.ingestOnce(); await bridge.drain(20); }

  // Reader plugged back in.
  renameSync(join(stash, 'EJECT01.JPG'), p);
  rmSync(stash, { recursive: true, force: true });
  assert.ok(await settle(bridge));

  assert.equal(server.captureCount(), 1, 'exactly one capture across the round trip');
  assert.equal(server.confirmedMasters(), 1);
});
