// Wiring: watch, spool, authenticate, upload. The run loop owns no state that
// is not in the database, so stopping it is always safe and starting it always
// resumes.

import { openDb } from './db.js';
import { Spool } from './spool.js';
import { Identity, SessionStore } from './identity.js';
import { Scanner } from './scanner.js';
import { HttpClient, AuthorityError } from './client.js';
import { Pipeline } from './pipeline.js';

export class Bridge {
  constructor({
    dbFile, roots, eventId, baseUrl, passphrase = null,
    quietMs = 1500, pairGraceMs = 2500, pollMs = 500,
    sourceMissingGraceMs, fetchImpl, log = () => {},
  }) {
    this.db = openDb(dbFile);
    this.spool = new Spool(this.db);
    this.identity = new Identity(this.db, { passphrase });
    this.sessions = new SessionStore(this.db);
    this.scanner = new Scanner({ roots, quietMs, pairGraceMs });
    this.client = new HttpClient({ baseUrl, sessionStore: this.sessions, fetchImpl });
    this.pipeline = new Pipeline({
      spool: this.spool, client: this.client,
      identity: this.identity, sessions: this.sessions, log,
      ...(sourceMissingGraceMs != null ? { sourceMissingGraceMs } : {}),
    });
    this.eventId = eventId;
    this.pollMs = pollMs;
    this.log = log;
    this.stopped = false;
  }

  /** Called once at startup: rewind rows that a crash caught mid-flight. */
  recover() {
    const n = this.spool.recover();
    if (n) this.log('recovered', { interrupted: n });
    return n;
  }

  /**
   * Enroll this installation, or confirm it is already enrolled.
   *
   * Safe to call on every start and safe to interrupt. The keypair is written
   * to disk before the first request, and the server resolves a repeat
   * enrollment of the same public key to the same device — so a crash between
   * the server creating the device and us recording its id costs nothing.
   * Without that, the enrollment code is spent and the laptop cannot enroll.
   */
  async enrollIfNeeded(enrollmentCode) {
    this.identity.ensureKeypair();
    if (this.identity.isUsable()) return this.identity.row();

    const res = await this.client.enroll({
      enrollmentCode,
      publicKeyPem: this.identity.publicKeyPem(),
      label: 'bridge',
    });
    // device_id and organization_id are whatever the server says they are.
    this.identity.recordEnrollment({
      deviceId: res.device_id, organizationId: res.organization_id,
    });
    this.log('enrolled', { deviceId: res.device_id });
    return this.identity.row();
  }

  async ensureSession() {
    if (this.sessions.isLive()) return true;

    const device = this.identity.row();
    if (!device?.device_id) throw new AuthorityError('device not enrolled', { code: 'device_revoked' });
    if (device.status !== 'active') {
      throw new AuthorityError(`device is ${device.status}`, { code: `device_${device.status}` });
    }

    const ch = await this.client.challenge({ deviceId: device.device_id });
    const signature = this.identity.signChallenge(ch.challenge);
    const s = await this.client.openSession({
      deviceId: device.device_id, eventId: this.eventId,
      challengeId: ch.challenge_id, signature,
    });

    this.sessions.save({
      sessionId: s.session_id, eventId: s.event_id,
      organizationId: s.organization_id, token: s.token, expiresAt: s.expires_at,
    });
    this.log('session', { eventId: s.event_id, expiresAt: s.expires_at });
    return true;
  }

  /** One scan pass: commit every settled capture group to the spool first. */
  async ingestOnce() {
    const groups = await this.scanner.scan();
    let n = 0;
    for (const g of groups) {
      const row = this.spool.discover({ ...g, eventId: this.eventId });
      if (row) { n++; this.log('discovered', { id: row.id, master: g.masterPath }); }
    }
    return n;
  }

  /** Drain the spool until nothing is due. Returns steps taken. */
  async drain(maxSteps = 10_000) {
    let steps = 0;
    for (; steps < maxSteps; steps++) {
      const r = await this.pipeline.step();
      if (r === 'idle') break;
      if (r === 'halted') { this.log('halted', {}); break; }
    }
    return steps;
  }

  async runOnce() {
    await this.ensureSession();
    await this.ingestOnce();
    return this.drain();
  }

  async run() {
    this.recover();
    while (!this.stopped) {
      try {
        await this.runOnce();
      } catch (err) {
        // Nothing here may lose spool state: an outage is a pause, not a loss.
        this.log('cycle-error', { error: err.message });
      }
      await new Promise((r) => setTimeout(r, this.pollMs));
    }
  }

  /**
   * Nothing to do, and nothing about to become something to do. The scanner
   * check is not decoration: a lone JPEG inside the pair grace window is a
   * photograph this Bridge has seen and not yet committed.
   */
  isQuiescent() {
    return this.spool.pending().length === 0 && this.scanner.waitingGroups() === 0;
  }

  stop() { this.stopped = true; }
  close() { try { this.db.close(); } catch { /* already closed */ } }
}
