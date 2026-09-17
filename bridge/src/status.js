// What the photographer needs to know, and nothing they should not see.
//
// The audience is someone standing at a reception with a laptop, not a
// developer with a debugger. Every field here exists to answer one of the
// questions they will actually ask, and the answers are plain language with a
// next step attached.
//
// Equally deliberate is what is absent: no session token, no private key, no
// enrollment code, no internal database id, no stack trace. A status screen is
// the thing most likely to be screenshotted into a group chat.

import { createHash } from 'node:crypto';
import { S } from './spool.js';
import { DISK, gib, pct } from './disk.js';

/** Stable, non-secret way to name a device out loud. */
export function deviceFingerprint(publicKeyPem) {
  if (!publicKeyPem) return null;
  return createHash('sha256').update(publicKeyPem).digest('hex').slice(0, 12)
    .replace(/(.{4})(?=.)/g, '$1-');
}

const HEARTBEAT_KEY = 'last_heartbeat_ms';
const CONTACT_KEY = 'last_server_contact_ms';
const FAILURES_KEY = 'consecutive_network_failures';
export const RUNNING_WITHIN_MS = 30_000;
// Two failures in a row is the venue wifi, not a blip. The photographer wants
// to know whether it is working now, not whether it worked two minutes ago.
export const OFFLINE_AFTER_FAILURES = 2;

export function recordHeartbeat(db, now = Date.now()) {
  db.prepare(`insert into meta(key, value) values(?, ?)
              on conflict(key) do update set value = excluded.value`)
    .run(HEARTBEAT_KEY, String(now));
}

export function recordServerContact(db, now = Date.now()) {
  db.prepare(`insert into meta(key, value) values(?, ?)
              on conflict(key) do update set value = excluded.value`)
    .run(CONTACT_KEY, String(now));
  db.prepare(`insert into meta(key, value) values(?, '0')
              on conflict(key) do update set value = '0'`).run(FAILURES_KEY);
}

/** A network attempt that did not reach the server. */
export function recordNetworkFailure(db) {
  const cur = Number(db.prepare('select value from meta where key = ?').get(FAILURES_KEY)?.value ?? 0);
  db.prepare(`insert into meta(key, value) values(?, ?)
              on conflict(key) do update set value = excluded.value`)
    .run(FAILURES_KEY, String(cur + 1));
  return cur + 1;
}

/**
 * Build the operator-facing status.
 * @param {object} bridge
 * @param {object} [opts]
 * @param {number} [opts.now]
 */
export function buildStatus(bridge, { now = Date.now() } = {}) {
  const db = bridge.db;
  const device = bridge.identity.row();
  const session = bridge.sessions.current();
  const counts = bridge.spool.counts();

  const heartbeat = Number(db.prepare('select value from meta where key = ?').get(HEARTBEAT_KEY)?.value ?? 0);
  const contact = Number(db.prepare('select value from meta where key = ?').get(CONTACT_KEY)?.value ?? 0);
  const failures = Number(db.prepare('select value from meta where key = ?').get(FAILURES_KEY)?.value ?? 0);

  const uploaded = counts[S.COMPLETE] ?? 0;
  const pending = bridge.spool.pending().length;

  // "Needs attention" is narrower than "failed". A capture retrying because
  // the venue wifi is down is working as designed and is not worth alarming
  // anybody about; one that has been given up on, or has been retrying long
  // enough that it is not going to fix itself, is.
  const rejected = db.prepare(
    `select rejected_reason, count(*) n from captures where state = ? group by rejected_reason`
  ).all(S.REJECTED);
  const stuck = db.prepare(
    `select device_sequence, state, attempts, last_error from captures
      where state not in (?, ?) and attempts >= 8 order by attempts desc limit 10`
  ).all(S.COMPLETE, S.REJECTED);

  const status = {
    running: now - heartbeat < RUNNING_WITHIN_MS,
    lastActiveAt: heartbeat ? new Date(heartbeat).toISOString() : null,

    device: {
      enrolled: !!device?.device_id,
      state: device?.status ?? 'not set up',
      name: device?.label ?? null,
      fingerprint: deviceFingerprint(device?.public_key_pem),
    },

    event: {
      connected: !!session?.token && Date.parse(session.expires_at) > now,
      name: session?.event_label ?? bridge.eventLabel ?? null,
      reference: session?.event_id ? shortRef(session.event_id) : null,
    },

    network: {
      reachable: contact > 0 && failures < OFFLINE_AFTER_FAILURES,
      lastContactAt: contact ? new Date(contact).toISOString() : null,
      failedAttempts: failures,
    },

    photographs: {
      uploaded,
      waitingToUpload: pending,
      notUploadable: rejected.reduce((a, r) => a + r.n, 0),
    },

    disk: {
      state: bridge.disk?.state ?? DISK.UNKNOWN,
      free: gib(bridge.disk?.freeBytes),
      freePercent: pct(bridge.disk?.freeRatio),
      acceptingNewPhotographs: !bridge.ingestPaused,
    },

    needsAttention: [
      ...rejected.map((r) => ({
        kind: r.rejected_reason,
        count: r.n,
        message: explainRejection(r.rejected_reason, r.n),
      })),
      ...stuck.map((r) => ({
        kind: 'retrying',
        count: 1,
        message: `Photograph #${r.device_sequence} has retried ${r.attempts} times (${friendlyError(r.last_error)}).`,
      })),
    ],

    halted: bridge.haltReason ? { reason: bridge.haltReason, message: explainHalt(bridge.haltReason) } : null,
  };

  status.summary = summarise(status);
  status.whatToDo = advise(status);
  return status;
}

/** A short, non-guessable-from reference for support, not the id itself. */
function shortRef(id) {
  return createHash('sha256').update(String(id)).digest('hex').slice(0, 8);
}

function explainRejection(reason, n) {
  const one = n === 1 ? 'A photograph' : `${n} photographs`;
  switch (reason) {
    case 'duplicate_content':
      return `${one} was already uploaded from this card. Nothing is missing.`;
    case 'too_large':
      return `${one} is larger than this version can upload. Copy the file across by hand and tell support.`;
    case 'empty_file':
      return `${one} is empty on the card, which usually means a write failed. Check the card.`;
    case 'source_vanished':
      return `${one} was moved or deleted before it finished uploading. If you moved files, move them back or re-add the folder.`;
    case 'content_changed_after_announce':
      return `${one} changed on the card while it was uploading. The new version will be picked up on its own.`;
    case 'checksum_mismatch_persistent':
      return `${one} would not transfer intact after several tries. Worth checking the card and the connection.`;
    default:
      return `${one} could not be uploaded (${reason}).`;
  }
}

function explainHalt(reason) {
  switch (reason) {
    case 'clone_suspected':
    case 'session_contended':
      return 'Another copy of this Bridge is using the same identity. Only one laptop can use one Bridge installation. Stop the other one, or set this laptop up as its own device.';
    default:
      return 'The Bridge has stopped and needs attention.';
  }
}

function friendlyError(err) {
  if (!err) return 'no detail';
  // Never a stack trace, never a URL that might carry a token.
  const first = String(err).split('\n')[0].replace(/https?:\/\/\S+/g, 'the server');
  return first.length > 80 ? `${first.slice(0, 77)}...` : first;
}

function summarise(s) {
  if (!s.running) return 'Bridge is not running.';
  if (s.halted) return s.halted.message;
  if (!s.device.enrolled) return 'Bridge is running but this laptop is not set up yet.';
  if (!s.event.connected) return 'Bridge is running but not connected to an event.';
  if (s.disk.state === DISK.CRITICAL) return 'Disk is nearly full. New photographs are not being taken on.';
  if (!s.network.reachable && s.photographs.waitingToUpload > 0) {
    return `No connection. ${s.photographs.waitingToUpload} photograph(s) are safe on this laptop and will upload when the connection returns.`;
  }
  if (s.photographs.waitingToUpload > 0) {
    return `Uploading. ${s.photographs.uploaded} done, ${s.photographs.waitingToUpload} to go.`;
  }
  return `Everything shot on this laptop is uploaded (${s.photographs.uploaded}).`;
}

function advise(s) {
  const out = [];
  if (!s.running) out.push('Start the Bridge, then check this screen again.');
  if (s.halted) out.push(s.halted.message);
  if (!s.device.enrolled) out.push('Run setup with the enrolment code from your Fotolab account.');
  else if (s.device.state === 'revoked' || s.device.state === 'compromised') {
    out.push('This laptop has been blocked from uploading. Contact whoever manages your Fotolab account.');
  }
  if (s.disk.state === DISK.CRITICAL) {
    out.push('Free up disk space. Nothing already taken on will be lost, and uploading continues.');
  } else if (s.disk.state === DISK.WARNING) {
    out.push(`Disk is getting full (${s.disk.free} left). Worth clearing space before the next event.`);
  } else if (s.disk.state === DISK.UNKNOWN) {
    out.push('Cannot read how much disk space is left, so new photographs are not being taken on.');
  }
  if (!s.network.reachable) {
    out.push('Check the venue wifi. Keep shooting — nothing is lost while offline.');
  }
  for (const a of s.needsAttention) out.push(a.message);
  if (out.length === 0) out.push('Nothing to do.');
  return out;
}

/** The same information as plain text, for the terminal. */
export function renderStatus(s) {
  const tick = (ok) => (ok ? 'yes' : 'no');
  const lines = [
    s.summary,
    '',
    `  Running                ${tick(s.running)}`,
    `  This laptop set up     ${tick(s.device.enrolled)}${s.device.fingerprint ? `  (${s.device.fingerprint})` : ''}`,
    `  Connected to an event  ${tick(s.event.connected)}${s.event.name ? `  (${s.event.name})` : ''}`,
    `  Connection to Fotolab  ${tick(s.network.reachable)}`,
    `  Photographs uploaded   ${s.photographs.uploaded}`,
    `  Waiting to upload      ${s.photographs.waitingToUpload}`,
    `  Disk space             ${s.disk.state} (${s.disk.free} free)`,
    `  Taking new photographs ${tick(s.disk.acceptingNewPhotographs)}`,
  ];
  if (s.needsAttention.length) {
    lines.push('', 'Needs attention:');
    for (const a of s.needsAttention) lines.push(`  - ${a.message}`);
  }
  lines.push('', 'What to do:');
  for (const a of s.whatToDo) lines.push(`  - ${a}`);
  return lines.join('\n');
}
