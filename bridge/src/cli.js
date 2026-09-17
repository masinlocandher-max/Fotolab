#!/usr/bin/env node
// fotolab-bridge — run a capture device.

import { join } from 'node:path';
import { homedir } from 'node:os';
import { Bridge } from './bridge.js';
import { renderStatus } from './status.js';

function arg(name, fallback = undefined) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1 || i === process.argv.length - 1) return fallback;
  return process.argv[i + 1];
}
const has = (name) => process.argv.includes(`--${name}`);

const command = process.argv[2];
const home = arg('home', join(homedir(), '.fotolab-bridge'));
const dbFile = join(home, 'spool.db');
const log = (kind, data) => console.log(`[${new Date().toISOString()}] ${kind}`, data ?? '');

if (!command || has('help')) {
  console.log(`fotolab-bridge

  enroll --url URL --code CODE            register this installation
  run    --url URL --event ID --card DIR  shoot an event
  status [--json]                         what is happening on this laptop

  --home DIR              where the spool lives (default ~/.fotolab-bridge)
  --retention-hours N     delete local originals N hours after the server
                          confirms them. Omit this and nothing is ever deleted,
                          which is the right default for somebody's only copy.`);
  process.exit(0);
}

if (command === 'enroll') {
  const bridge = new Bridge({ dbFile, roots: [], eventId: '', baseUrl: arg('url'), log });
  const device = await bridge.enrollIfNeeded(arg('code'));
  console.log(`enrolled as ${device.device_id} in organization ${device.organization_id}`);
  bridge.close();
  process.exit(0);
}

if (command === 'status') {
  const bridge = new Bridge({ dbFile, roots: [], eventId: '', baseUrl: 'http://unused', log: () => {} });
  await bridge.refreshDisk(true);
  const status = bridge.status();
  console.log(has('json') ? JSON.stringify(status, null, 2) : renderStatus(status));
  bridge.close();
  process.exit(status.running && !status.halted ? 0 : 1);
}

if (command === 'run') {
  const retentionHours = arg('retention-hours');
  const bridge = new Bridge({
    dbFile, roots: [arg('card')], eventId: arg('event'), baseUrl: arg('url'), log,
  });

  // Ctrl-C is safe at any moment: there is no in-memory progress to flush.
  const shutdown = () => { log('stopping', 'finishing the current step'); bridge.stop(); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  if (retentionHours) {
    const ms = Number(retentionHours) * 3600_000;
    setInterval(() => {
      bridge.pipeline.sweepCleanup({ retentionMs: ms })
        .then((r) => { if (r.deleted) log('cleanup', r); })
        .catch((e) => log('cleanup-error', e.message));
    }, 60_000).unref();
  }

  await bridge.run();
  log('stopped', JSON.stringify(bridge.spool.counts()));
  bridge.close();
}
