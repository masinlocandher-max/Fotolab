// The Phase 2 milestone, as an executable claim.
//
// 500+ photographs through unstable connectivity, with the process dying
// repeatedly, and not one lost, duplicated, or crossed into the wrong event.
//
// Slow by design. Run it with: npm run test:soak

import test from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { createHash } from 'node:crypto';
import { rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FakeServer } from './fake-server.js';
import { tempDir } from './helpers.js';

const WORKER = fileURLToPath(new URL('./worker.js', import.meta.url));
const SHOTS = Number(process.env.SOAK_SHOTS ?? 500);

function runWorker(env, killAfterMs = null) {
  return new Promise((resolve) => {
    const child = fork(WORKER, [], { env: { ...process.env, ...env }, stdio: ['ignore','ignore','ignore','ipc'] });
    const killer = killAfterMs == null ? null
      : setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, killAfterMs);
    child.on('exit', (code, signal) => { if (killer) clearTimeout(killer); resolve({ code, signal }); });
  });
}

test(`${SHOTS} photographs survive an unstable event`,
  { skip: process.env.SOAK ? false : 'set SOAK=1 to run', timeout: 900_000 },
  async (t) => {
    const server = new FakeServer();
    await server.listen();
    const home = tempDir('soak-home-');
    const card = tempDir('soak-card-');
    t.after(async () => {
      await server.close();
      rmSync(home, { recursive: true, force: true });
      rmSync(card, { recursive: true, force: true });
    });

    const digests = new Set();
    for (let i = 0; i < SHOTS; i++) {
      // Half the event is shot JPEG+RAW, as a real wedding would be.
      const body = Buffer.from(`soak-${i}-`.padEnd(5000 + (i % 37) * 11, 'x'));
      writeFileSync(join(card, `IMG${String(i).padStart(5, '0')}.JPG`), body);
      digests.add(createHash('sha256').update(body).digest('hex'));
      if (i % 2 === 0) {
        const raw = Buffer.from(`soak-raw-${i}-`.padEnd(20000 + (i % 17) * 13, 'r'));
        writeFileSync(join(card, `IMG${String(i).padStart(5, '0')}.CR3`), raw);
        digests.add(createHash('sha256').update(raw).digest('hex'));
      }
    }

    const env = {
      BRIDGE_DB: join(home, 'spool.db'),
      BRIDGE_CARD: card,
      BRIDGE_URL: server.baseUrl,
      BRIDGE_EVENT: 'event-a',
      BRIDGE_ENROLL_CODE: server.enrollDevice(),
    };

    // A venue's worth of bad behaviour: flapping wifi, 5xx, lost acks, kills.
    for (let round = 0; round < 25; round++) {
      server.faults.announce5xx = 2;
      server.faults.upload5xx = 3;
      server.faults.confirm5xx = 1;
      if (round % 3 === 0) server.faults.dropAckAfterCommit = 2;
      if (round % 5 === 4) server.faults.corruptUpload = 1;

      server.faults.networkDead = round % 7 === 6;
      await runWorker(env, 200 + Math.floor(Math.random() * 700));
      server.faults.networkDead = false;
    }

    // Same anti-vacuous guard as the crash suite: if the kills all landed
    // before any real work, the clean finishing rounds would carry the test.
    assert.ok(server.captureCount() > 0,
      'the unstable rounds did real work, not just repeated startup');
    assert.ok(server.counters.upload > SHOTS / 4,
      'a substantial share of the event went up under bad conditions');

    server.faults = { announce5xx: 0, upload5xx: 0, confirm5xx: 0,
                      dropAckAfterCommit: 0, corruptUpload: 0, networkDead: false };
    for (let i = 0; i < 6; i++) {
      const r = await runWorker(env);
      if (r.code === 0) break;
    }

    const captures = server.allCaptures();
    assert.equal(captures.length, SHOTS,
      `exactly one capture per shutter press (got ${captures.length}, expected ${SHOTS})`);
    assert.equal(new Set(captures.map((c) => c.device_sequence)).size, SHOTS,
      'no sequence number reused');
    assert.equal(captures.filter((c) => c.assets.master).length, SHOTS,
      'every master confirmed');
    for (const c of captures) {
      assert.equal(c.event_id, 'event-a', 'nothing crossed into another event');
      assert.equal(c.organization_id, 'org-a', 'nothing crossed into another tenant');
      assert.ok(digests.has(c.assets.master.sha256), 'every stored master is byte-exact');
    }
  });
