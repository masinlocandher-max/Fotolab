// Operator testability.
//
// Two things are being checked: that a photographer standing at a reception
// can answer their own questions from this screen, and that the screen is safe
// to screenshot into a group chat.

import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildStatus, renderStatus, recordHeartbeat, deviceFingerprint } from '../src/status.js';
import { DISK } from '../src/disk.js';
import { makeBridge, enrollAndSession, settle, writeShot, ingestUntilFound } from './helpers.js';

const HUGE = 2 ** 60;
const criticalDisk = { criticalFreeBytes: HUGE, warningFreeBytes: HUGE, criticalFreeRatio: 0.99, warningFreeRatio: 0.99 };

test('STATUS: answers every question a photographer will ask', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);
  await bridge.refreshDisk(true);
  recordHeartbeat(bridge.db);

  writeShot(cards[0], 'ST01.JPG', { seed: 'uploaded' });
  assert.ok(await settle(bridge));

  const s = bridge.status();

  assert.equal(s.running, true, 'Is Bridge running?');
  assert.equal(s.device.enrolled, true, 'Is the device enrolled?');
  assert.ok(s.event.name, 'What event am I connected to?');
  assert.equal(s.event.connected, true);
  assert.equal(s.network.reachable, true, 'Is the network available?');
  assert.equal(s.photographs.waitingToUpload, 0, 'How many captures are pending?');
  assert.equal(s.photographs.uploaded, 1, 'How many have uploaded?');
  assert.equal(s.disk.state, DISK.HEALTHY, 'Is disk space safe?');
  assert.deepEqual(s.needsAttention, [], 'Is anything permanently failing?');
  assert.ok(Array.isArray(s.whatToDo) && s.whatToDo.length > 0, 'What should I do?');
  assert.match(s.summary, /uploaded/i);
});

test('STATUS: leaks no secret, token, key or internal identifier', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);
  await bridge.refreshDisk(true);

  writeShot(cards[0], 'SEC01.JPG', { seed: 'secret-check' });
  assert.ok(await settle(bridge));

  const device = bridge.identity.row();
  const session = bridge.sessions.current();
  const captureRow = bridge.db.prepare('select * from captures limit 1').get();

  const serialised = JSON.stringify(bridge.status()) + '\n' + renderStatus(bridge.status());

  const forbidden = [
    ['session token', session.token],
    ['device id', device.device_id],
    ['organization id', device.organization_id],
    ['server capture id', captureRow.server_capture_id],
    ['idempotency key', captureRow.idempotency_key],
    ['stored private key', device.private_key.slice(0, 40)],
    ['public key PEM body', device.public_key_pem.split('\n')[1]],
    ['absolute file path', captureRow.master_path],
  ];

  for (const [what, value] of forbidden) {
    assert.ok(value, `${what} exists to be checked for`);
    assert.equal(serialised.includes(value), false,
      `the status must not contain the ${what}`);
  }

  // What it does carry instead: a stable, non-secret way to name the device.
  assert.ok(bridge.status().device.fingerprint, 'a fingerprint stands in for the device id');
  assert.equal(bridge.status().device.fingerprint,
    deviceFingerprint(device.public_key_pem), 'derived from the public key, not the private one');
});

test('STATUS: an offline event reads as safe, not as failure', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);
  await bridge.refreshDisk(true);
  recordHeartbeat(bridge.db);

  server.faults.networkDead = true;
  for (let i = 0; i < 8; i++) writeShot(cards[0], `OFF${i}.JPG`, { seed: `offline-${i}` });
  for (let i = 0; i < 4; i++) {
    await bridge.ingestOnce(); await bridge.drain(30);
    bridge.db.prepare('update captures set next_attempt_at_ms = 0').run();
  }

  const s = bridge.status();
  assert.equal(s.photographs.waitingToUpload, 8);
  assert.match(s.summary, /safe on this laptop/i,
    'the photographer is told their work is safe, not that something failed');
  assert.ok(s.whatToDo.some((a) => /keep shooting/i.test(a)),
    'and told to carry on shooting');
});

test('STATUS: a full disk says what is happening and what to do', async (t) => {
  const { bridge, server, cleanup } = await makeBridge({ diskThresholds: criticalDisk });
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);
  await bridge.refreshDisk(true);
  await bridge.ingestOnce();
  recordHeartbeat(bridge.db);

  const s = bridge.status();
  assert.equal(s.disk.state, DISK.CRITICAL);
  assert.equal(s.disk.acceptingNewPhotographs, false);
  assert.match(s.summary, /disk is nearly full/i);
  assert.ok(s.whatToDo.some((a) => /free up disk space/i.test(a)));
  assert.ok(s.whatToDo.some((a) => /nothing already taken on will be lost/i.test(a)),
    'and reassures them about what they already shot');
});

test('STATUS: rejected photographs are explained in plain language', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);
  await bridge.refreshDisk(true);
  recordHeartbeat(bridge.db);

  // An empty file, which on a real card means a failed write.
  writeFileSync(join(cards[0], 'BAD01.JPG'), Buffer.alloc(0));
  assert.ok(await ingestUntilFound(bridge));
  await bridge.pipeline.step();

  const s = bridge.status();
  assert.equal(s.photographs.notUploadable, 1);
  assert.equal(s.needsAttention.length, 1);
  assert.match(s.needsAttention[0].message, /empty on the card/i);
  assert.ok(!/undefined|null|Error:|at Object\./.test(s.needsAttention[0].message),
    'no developer wording leaks into an operator message');
});

test('STATUS: a duplicate is reported as nothing to worry about', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);
  await bridge.refreshDisk(true);
  recordHeartbeat(bridge.db);

  const body = Buffer.from('same-bytes-twice'.padEnd(3000, 'd'));
  writeFileSync(join(cards[0], 'DUP01.JPG'), body);
  writeFileSync(join(cards[0], 'DUP02.JPG'), body);
  assert.ok(await settle(bridge));

  const s = bridge.status();
  assert.match(s.needsAttention[0].message, /already uploaded|nothing is missing/i,
    'a deduplicated photograph must not read as a lost one');
});

test('STATUS: a suspected clone is explained without jargon', async (t) => {
  const { bridge, server, cleanup } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);
  await bridge.refreshDisk(true);
  recordHeartbeat(bridge.db);

  bridge.haltReason = 'clone_suspected';
  const s = bridge.status();

  assert.ok(s.halted);
  assert.match(s.summary, /another copy of this bridge/i);
  assert.ok(s.whatToDo.some((a) => /only one laptop/i.test(a)),
    'the instruction is actionable by a photographer, not a developer');
});

test('STATUS: a retrying photograph is not alarming until it has really stuck', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);
  await bridge.refreshDisk(true);
  recordHeartbeat(bridge.db);

  server.faults.announce5xx = 3;
  writeShot(cards[0], 'RETRY01.JPG', { seed: 'briefly-flaky' });
  assert.ok(await ingestUntilFound(bridge));
  for (let i = 0; i < 3; i++) {
    await bridge.pipeline.step();
    bridge.db.prepare('update captures set next_attempt_at_ms = 0').run();
  }

  assert.deepEqual(bridge.status().needsAttention, [],
    'a few retries during bad wifi is normal and must not be raised as a problem');

  bridge.db.prepare('update captures set attempts = 9').run();
  assert.equal(bridge.status().needsAttention.length, 1,
    'but one that has really stuck is surfaced');
});

test('STATUS: the rendered text mentions no absolute paths or raw errors', async (t) => {
  const { bridge, server, cleanup, cards } = await makeBridge();
  t.after(() => { cleanup(); return server.close(); });
  await enrollAndSession(bridge, server);
  await bridge.refreshDisk(true);
  recordHeartbeat(bridge.db);

  writeFileSync(join(cards[0], 'TXT01.JPG'), Buffer.alloc(0));
  assert.ok(await ingestUntilFound(bridge));
  await bridge.pipeline.step();

  const text = renderStatus(bridge.status());
  assert.ok(!text.includes('/tmp/'), 'no absolute filesystem paths');
  assert.ok(!/\bat \S+ \(/.test(text), 'no stack frames');
  assert.ok(!/Bearer|token|secret|PRIVATE KEY/i.test(text), 'no credential words');
});
