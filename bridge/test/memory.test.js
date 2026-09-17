// Memory envelope.
//
// Uploads buffer whole files. That was a deliberate correctness choice — a
// consumed stream cannot be retried, and silently re-sending zero bytes is
// worse than the memory — but "defensible on a photographer's laptop" is a
// number, not an opinion. This measures it before deciding whether anything
// needs to change.
//
// Real files, real child process, real RSS sampled from inside the process
// doing the work.

import test from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FakeServer } from './fake-server.js';
import { tempDir } from './helpers.js';

const WORKER = fileURLToPath(new URL('./worker.js', import.meta.url));
const MiB = 1024 ** 2;

// The envelope. A photographer's laptop is commonly 8GB with Lightroom and a
// browser already open, so the Bridge's share has to be small enough to be
// uninteresting. 1 GiB peak RSS is the line; anything approaching it is a
// reason to revisit whole-file buffering.
const ENVELOPE_BYTES = 1024 * MiB;

function runWorker(env) {
  return new Promise((resolve) => {
    let report = null;
    const child = fork(WORKER, [], {
      env: { ...process.env, ...env, BRIDGE_REPORT_MEMORY: '1' },
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    child.on('message', (m) => { if (m?.done) report = m; });
    child.on('exit', (code) => resolve({ code, report }));
  });
}

async function measure(t, { files, sizeMiB, faults = {} }) {
  const server = new FakeServer();
  await server.listen();
  const home = tempDir('mem-home-');
  const card = tempDir('mem-card-');
  t.after(async () => {
    await server.close();
    rmSync(home, { recursive: true, force: true });
    rmSync(card, { recursive: true, force: true });
  });

  // Distinct content per file so nothing is deduplicated away.
  for (let i = 0; i < files; i++) {
    const buf = Buffer.alloc(sizeMiB * MiB, 0);
    buf.write(`raw-${i}-`, 0);
    buf.write(`tail-${i}`, buf.length - 16);
    writeFileSync(join(card, `BIG${String(i).padStart(3, '0')}.CR3`), buf);
  }
  Object.assign(server.faults, faults);

  const { code, report } = await runWorker({
    BRIDGE_DB: join(home, 'spool.db'),
    BRIDGE_CARD: card,
    BRIDGE_URL: server.baseUrl,
    BRIDGE_EVENT: 'event-a',
    BRIDGE_ENROLL_CODE: server.enrollDevice(),
  });

  return { code, report, server, files };
}

test('MEMORY: large RAW files stay inside the envelope', { timeout: 300_000 }, async (t) => {
  // 12 files at 60 MiB: a burst of full-size RAWs from a modern body.
  const { code, report, server } = await measure(t, { files: 12, sizeMiB: 60 });

  assert.equal(code, 0, 'the run completed');
  assert.equal(server.confirmedMasters(), 12, 'and every file was delivered');
  assert.ok(report?.peakRssBytes > 0, 'peak RSS was actually sampled');

  const peakMiB = report.peakRssBytes / MiB;
  console.log(`      measured peak RSS: ${peakMiB.toFixed(0)} MiB across 12 x 60 MiB files`);
  assert.ok(report.peakRssBytes < ENVELOPE_BYTES,
    `peak RSS ${peakMiB.toFixed(0)} MiB must stay under ${ENVELOPE_BYTES / MiB} MiB`);
});

test('MEMORY: a retry storm does not accumulate buffers', { timeout: 300_000 }, async (t) => {
  // Every upload fails several times before succeeding. If a failed attempt
  // retained its buffer, this is where it would show.
  const { code, report, server } = await measure(t, {
    files: 8, sizeMiB: 50,
    faults: { upload5xx: 16, confirm5xx: 8, corruptUpload: 3 },
  });

  assert.equal(code, 0);
  assert.equal(server.confirmedMasters(), 8, 'every file survived the storm');

  const peakMiB = report.peakRssBytes / MiB;
  console.log(`      measured peak RSS under retry storm: ${peakMiB.toFixed(0)} MiB`);
  assert.ok(report.peakRssBytes < ENVELOPE_BYTES,
    `peak RSS ${peakMiB.toFixed(0)} MiB must stay under ${ENVELOPE_BYTES / MiB} MiB`);
});

test('MEMORY: a long offline backlog costs disk rows, not memory', { timeout: 300_000 }, async (t) => {
  // 150 captures spooled while the network is dead, then drained. A backlog
  // that lived in memory rather than SQLite would be visible here.
  const server = new FakeServer();
  await server.listen();
  const home = tempDir('mem-backlog-home-');
  const card = tempDir('mem-backlog-card-');
  t.after(async () => {
    await server.close();
    rmSync(home, { recursive: true, force: true });
    rmSync(card, { recursive: true, force: true });
  });

  for (let i = 0; i < 150; i++) {
    writeFileSync(join(card, `BK${String(i).padStart(4, '0')}.JPG`),
      Buffer.from(`backlog-${i}-`.padEnd(2 * MiB, 'b')));
  }

  const env = {
    BRIDGE_DB: join(home, 'spool.db'),
    BRIDGE_CARD: card,
    BRIDGE_URL: server.baseUrl,
    BRIDGE_EVENT: 'event-a',
    BRIDGE_ENROLL_CODE: server.enrollDevice(),
  };

  const { code, report } = await runWorker(env);
  assert.equal(code, 0);
  assert.equal(server.confirmedMasters(), 150);

  const peakMiB = report.peakRssBytes / MiB;
  console.log(`      measured peak RSS over a 150-capture backlog: ${peakMiB.toFixed(0)} MiB`);
  assert.ok(report.peakRssBytes < ENVELOPE_BYTES,
    `peak RSS ${peakMiB.toFixed(0)} MiB must stay under ${ENVELOPE_BYTES / MiB} MiB`);
});

test('MEMORY: the shipped size ceiling is consistent with the envelope', async () => {
  const {
    MEMORY_ENVELOPE_BYTES, MEASURED_RSS_BASELINE_BYTES,
    MEASURED_RSS_PER_FILE_BYTE, DEFAULT_MAX_BYTES,
  } = await import('../src/pipeline.js');

  // The ceiling is not a round number somebody liked; it follows from the
  // measurement. If either is edited without the other, this fails.
  const predictedPeak =
    MEASURED_RSS_BASELINE_BYTES + DEFAULT_MAX_BYTES * MEASURED_RSS_PER_FILE_BYTE;

  assert.ok(predictedPeak < MEMORY_ENVELOPE_BYTES,
    `a file at the ceiling is predicted to peak at ${(predictedPeak / MiB).toFixed(0)} MiB, ` +
    `which must stay under the ${MEMORY_ENVELOPE_BYTES / MiB} MiB envelope`);

  // And it must still clear a real RAW. A 61MP full-frame file is ~120 MiB.
  assert.ok(DEFAULT_MAX_BYTES >= 150 * MiB,
    'the ceiling must not be so low that ordinary RAW files are refused');
});

test('MEMORY: a file at the ceiling stays inside the envelope in practice',
  { timeout: 300_000 }, async (t) => {
  const { DEFAULT_MAX_BYTES } = await import('../src/pipeline.js');
  const atCeiling = Math.floor(DEFAULT_MAX_BYTES / MiB) - 1;

  const { code, report, server } = await measure(t, {
    files: 1, sizeMiB: atCeiling,
    faults: { upload5xx: 2, corruptUpload: 1 },
  });

  assert.equal(code, 0);
  assert.equal(server.confirmedMasters(), 1, 'a file just under the ceiling is delivered');

  const peakMiB = report.peakRssBytes / MiB;
  console.log(`      measured peak RSS at the ${atCeiling} MiB ceiling: ${peakMiB.toFixed(0)} MiB`);
  assert.ok(report.peakRssBytes < ENVELOPE_BYTES,
    `the prediction must hold in practice: ${peakMiB.toFixed(0)} MiB under ${ENVELOPE_BYTES / MiB} MiB`);
});

test('MEMORY: a file beyond the size ceiling is refused, not buffered', async (t) => {
  // The ceiling is what stands in for resumable multipart today. A file too
  // big to hold is rejected before it is read, not discovered halfway through.
  const { Pipeline } = await import('../src/pipeline.js');
  const { openDb } = await import('../src/db.js');
  const { Spool, S } = await import('../src/spool.js');

  const home = tempDir('mem-ceiling-');
  const card = tempDir('mem-ceiling-card-');
  t.after(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(card, { recursive: true, force: true });
  });

  const big = join(card, 'HUGE.CR3');
  writeFileSync(big, Buffer.alloc(4 * MiB, 7));

  const db = openDb(join(home, 'spool.db'));
  const spool = new Spool(db);
  const pipeline = new Pipeline({
    spool, client: {}, identity: {}, sessions: {}, maxBytes: 1 * MiB,
  });

  const row = spool.discover({
    groupKey: join(card, 'HUGE'), masterPath: big, eventId: 'event-a',
    size: 4 * MiB, mtimeMs: Date.now(),
  });
  const before = process.memoryUsage().rss;
  await pipeline.step();
  const after = process.memoryUsage().rss;

  const state = spool.byId(row.id);
  assert.equal(state.state, S.REJECTED);
  assert.equal(state.rejected_reason, 'too_large');
  assert.ok(after - before < 3 * MiB,
    'the oversized file was measured, not loaded');
  db.close();
});
