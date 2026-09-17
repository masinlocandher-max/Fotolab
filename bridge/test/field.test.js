// The field qualification run.
//
//   npm run qualify              1200 shutter presses, the full gate
//   FQ_PRESSES=150 npm run qualify   a short run, for iterating
//
// A trimmed version runs in the normal suite so the harness itself cannot rot;
// the gate is the full run.

import test from 'node:test';
import assert from 'node:assert/strict';
import { FieldHarness, FAULTS } from './field-harness.js';

const FULL = !!process.env.FQ_FULL;
const PRESSES = Number(process.env.FQ_PRESSES ?? (FULL ? 1200 : 90));
const BATCHES = Number(process.env.FQ_BATCHES ?? (FULL ? 30 : 10));
// File sizes are realistic for the gate and scaled down for the routine run,
// so the harness stays exercised without spending the suite's time on I/O.
const SIZE_SCALE = Number(process.env.FQ_SIZE_SCALE ?? (FULL ? 1 : 0.02));

test(`FIELD: ${PRESSES} shutter presses through a hostile event`,
  { timeout: 3 * 60 * 60_000 }, async (t) => {
  const h = new FieldHarness({
    shutterPresses: PRESSES, batches: BATCHES, sizeScale: SIZE_SCALE,
    verbose: !!process.env.FQ_VERBOSE,
  });
  await h.start();
  t.after(() => h.stop());

  const started = Date.now();
  await h.run();
  const minutes = ((Date.now() - started) / 60_000).toFixed(1);

  const audit = h.auditFaults();
  const result = h.verify();

  console.log('');
  console.log(`   Field qualification: ${PRESSES} presses over ${BATCHES} worker lifetimes, ${minutes} min` +
              `${FULL ? '' : ` (short run, file sizes x${SIZE_SCALE})`}`);
  console.log(`   shutter presses        ${result.shutterPresses}`);
  console.log(`   files on card          ${result.filesOnCard}`);
  console.log(`   arrived byte-exact     ${result.filesArrivedByteExact}`);
  console.log(`   server captures        ${result.serverCaptures}`);
  console.log(`   spool rows             ${result.spoolRows} (${result.completed} complete, ${result.rejected} rejected)`);
  console.log(`   rejection reasons      ${JSON.stringify(result.rejectionReasons)}`);
  console.log(`   peak RSS               ${result.peakRssMiB} MiB`);
  if (result.missing?.length) {
    console.log('   files that did NOT arrive byte-exact:');
    for (const m of result.missing) console.log(`     ${JSON.stringify(m)}`);
  }
  console.log('   faults injected:');
  for (const [fault, n] of Object.entries(audit.byType)) {
    console.log(`     ${fault.padEnd(20)} ${String(n.total).padStart(4)}  (${n.onLiveWork} while work in flight)`);
  }
  console.log('');

  // Anti-vacuous: the run only counts if every fault actually landed on live
  // work. A clean sheet here would mean the event was never really hostile.
  assert.deepEqual(audit.problems, [],
    `every fault type must have been injected while work was in flight:\n  ${audit.problems.join('\n  ')}`);

  // And then the claims themselves.
  assert.deepEqual(result.failures, [],
    `field qualification failures:\n  ${result.failures.join('\n  ')}`);

  assert.ok(result.filesArrivedByteExact === result.filesOnCard,
    'every file still on the card arrived byte-exact');
  assert.ok(result.peakRssMiB < 1024, `peak RSS ${result.peakRssMiB} MiB inside the envelope`);
});
