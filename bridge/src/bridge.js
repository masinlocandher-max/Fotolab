// Wiring: watch, spool, authenticate, upload. The run loop owns no state that
// is not in the database, so stopping it is always safe and starting it always
// resumes.

import { openDb } from './db.js';
import { Spool } from './spool.js';
import { Identity, SessionStore } from './identity.js';
import { Scanner } from './scanner.js';
import { HttpClient, AuthorityError } from './client.js';
import { Pipeline } from './pipeline.js';
import { checkDisk, DISK, DEFAULT_THRESHOLDS, mayIngest } from './disk.js';
import { dirname } from 'node:path';

export class Bridge {
  constructor({
    dbFile, roots, eventId, baseUrl, passphrase = null,
    quietMs = 1500, pairGraceMs = 2500, pollMs = 500,
    sourceMissingGraceMs, diskThresholds = DEFAULT_THRESHOLDS, diskCheckMs = 15_000,
    fetchImpl, log = () => {},
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

    // How many times this process will re-open a session that something else
    // took from it. One is an ordinary restart race. Repeatedly losing the
    // session to another installation is two machines holding one identity,
    // and the correct response is to stop and say so — not to win the fight,
    // which would just produce an upload storm and corrupt nobody's benefit.
    this.maxSessionTakeovers = 2;
    this.sessionTakeovers = 0;
    this.haltReason = null;

    // The volume that matters is the one holding the spool: if that fills,
    // the Bridge cannot record that a photograph exists.
    this.spoolVolume = dirname(dbFile);
    this.diskThresholds = diskThresholds;
    this.diskCheckMs = diskCheckMs;
    this.disk = { state: DISK.UNKNOWN, reason: 'not checked yet', checkedAt: 0 };
  }

  /** Cached so a fast poll loop does not statfs on every pass. */
  async refreshDisk(force = false) {
    if (!force && Date.now() - this.disk.checkedAt < this.diskCheckMs) return this.disk;
    const result = await checkDisk(this.spoolVolume, this.diskThresholds);
    const changed = result.state !== this.disk.state;
    this.disk = { ...result, checkedAt: Date.now() };
    if (changed) this.log('disk', { state: result.state, reason: result.reason });
    return this.disk;
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
    if (this.haltReason) throw new AuthorityError(this.haltReason, { code: this.haltReason });
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
    if (s.clone_suspected) {
      this.haltReason = 'clone_suspected';
      this.log('clone-suspected', {
        message: 'the server reports another installation using this device identity',
      });
    }
    this.log('session', { eventId: s.event_id, expiresAt: s.expires_at });
    return true;
  }

  /**
   * Another installation took this device's session. Called from the run loop
   * rather than handled silently, because the honest outcomes are "a laptop
   * restarted" (retry once) and "somebody copied the Bridge" (stop).
   */
  noteSessionTakeover() {
    this.sessions.clear();
    this.sessionTakeovers += 1;
    if (this.sessionTakeovers > this.maxSessionTakeovers) {
      this.haltReason = 'session_contended';
      this.log('halted', {
        reason: 'session_contended',
        message: 'this device identity is in use by another installation; not competing for it',
      });
    }
    return this.haltReason;
  }

  /**
   * One scan pass: commit every settled capture group to the spool first.
   *
   * Refuses to take on new photographs when the spool volume cannot be
   * trusted to hold them. Discovering a capture we cannot durably record is
   * worse than not discovering it: the file stays safely on the card either
   * way, but a half-recorded capture is a lie about what we are responsible
   * for. Draining continues regardless — that is how the backlog shrinks.
   */
  async ingestOnce() {
    const disk = await this.refreshDisk();
    if (!mayIngest(disk.state)) {
      if (!this.ingestPaused) {
        this.ingestPaused = true;
        this.log('ingest-paused', {
          state: disk.state, reason: disk.reason,
          message: 'not accepting new photographs; already-spooled work continues',
        });
      }
      return 0;
    }
    if (this.ingestPaused) {
      this.ingestPaused = false;
      this.log('ingest-resumed', { state: disk.state, reason: disk.reason });
    }

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
    const steps = await this.drain();
    // drain() swallows an authority failure into 'halted' so the spool is left
    // alone; the loop still needs to know which authority failed.
    const code = this.pipeline.lastAuthorityCode;
    if (code) {
      this.pipeline.lastAuthorityCode = null;
      const err = new Error(code);
      err.code = code;
      throw err;
    }
    return steps;
  }

  /**
   * @param {object} [opts]
   * @param {number} [opts.maxCycles] stop after this many passes. Exists so the
   *   loop's own error handling — which is where session contention is
   *   resolved — can be tested rather than only the pieces it calls.
   */
  async run({ maxCycles = Infinity } = {}) {
    this.recover();
    let cycles = 0;
    while (!this.stopped && cycles < maxCycles) {
      cycles++;
      try {
        await this.runOnce();
      } catch (err) {
        if (err?.code === 'session_superseded') this.noteSessionTakeover();
        // Nothing here may lose spool state: an outage is a pause, not a loss.
        this.log('cycle-error', { error: err.message });
      }
      if (this.haltReason) break;
      await new Promise((r) => setTimeout(r, this.pollMs));
    }
    return { cycles, haltReason: this.haltReason };
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
