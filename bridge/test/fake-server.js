// A server that behaves like the real one, including badly.
//
// It is deliberately strict about the things the Bridge must get right:
// idempotency, tenancy, sequence uniqueness, and checksum agreement. If the
// Bridge can satisfy this, the failures left are the real server's.

import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { randomUUID } from 'node:crypto';

export class FakeServer {
  constructor({ organizationId = 'org-a', liveEvents = ['event-a'], events = null } = {}) {
    this.organizationId = organizationId;
    this.liveEvents = new Set(liveEvents);
    // event id -> owning organization. Anything not listed belongs to the
    // default organization, which keeps the single-tenant tests unchanged.
    this.eventOwners = new Map(Object.entries(events ?? {}));

    this.devices = new Map();          // device_id -> {publicKey, status, organizationId}
    this.challenges = new Map();
    this.sessions = new Map();         // token -> {deviceId, eventId, expiresAt, ...}
    this.cloneSignals = new Map();     // deviceId -> count of active-session takeovers
    this.capturesByKey = new Map();    // idempotency_key -> capture
    this.captures = new Map();         // capture_id -> capture
    this.sequences = new Set();        // `${deviceId}:${seq}`
    this.objects = new Map();          // storage key -> {sha256, size}

    // Fault injection
    this.faults = {
      announce5xx: 0, upload5xx: 0, confirm5xx: 0,
      dropAckAfterCommit: 0,   // commit, then fail the response — the nastiest case
      corruptUpload: 0,
      networkDead: false,
    };
    this.counters = { announce: 0, upload: 0, confirm: 0 };
  }

  #take(name) {
    if (this.faults[name] > 0) { this.faults[name]--; return true; }
    return false;
  }

  enrollDevice({ label = 'bridge', organizationId = null } = {}) {
    const code = randomUUID();
    this.pendingEnrollments ??= new Map();
    this.pendingEnrollments.set(code, { label, organizationId: organizationId ?? this.organizationId });
    return code;
  }

  ownerOf(eventId) { return this.eventOwners.get(eventId) ?? this.organizationId; }

  revokeDevice(deviceId, status = 'revoked') {
    const d = this.devices.get(deviceId);
    if (d) d.status = status;
  }

  async listen() {
    this.server = createServer((req, res) => this.#handle(req, res));
    await new Promise((r) => this.server.listen(0, '127.0.0.1', r));
    this.port = this.server.address().port;
    this.baseUrl = `http://127.0.0.1:${this.port}`;
    return this.baseUrl;
  }

  async close() {
    if (this.server) await new Promise((r) => this.server.close(r));
  }

  #json(res, status, body) {
    const b = JSON.stringify(body ?? {});
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(b) });
    res.end(b);
  }

  async #body(req) {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    return Buffer.concat(chunks);
  }

  #auth(req) {
    const h = req.headers.authorization ?? '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    const s = token ? this.sessions.get(token) : null;
    if (!s) return { error: { status: 401, code: 'session_expired', message: 'no session' } };
    // A session another installation took over. Distinct from expiry: nothing
    // timed out, somebody else claimed this device's identity.
    if (s.supersededAt) {
      return { error: { status: 409, code: 'session_superseded',
                        message: 'another installation opened a session for this device' } };
    }
    if (s.expiresAt <= Date.now()) return { error: { status: 401, code: 'session_expired', message: 'expired' } };
    const d = this.devices.get(s.deviceId);
    if (!d || d.status !== 'active') {
      return { error: { status: 403, code: d?.status === 'compromised' ? 'device_compromised' : 'device_revoked', message: 'device not active' } };
    }
    if (!this.liveEvents.has(s.eventId)) {
      return { error: { status: 403, code: 'event_not_live', message: 'event not live' } };
    }
    if (this.ownerOf(s.eventId) !== d.organizationId) {
      return { error: { status: 403, code: 'wrong_organization', message: 'cross-tenant session' } };
    }
    s.lastSeenAt = Date.now();
    return { session: s, device: d };
  }

  async #handle(req, res) {
    if (this.faults.networkDead) { req.socket.destroy(); return; }
    const url = new URL(req.url, 'http://x');
    const path = url.pathname;

    try {
      if (path === '/v1/devices/enroll')    return await this.#enroll(req, res);
      if (path === '/v1/devices/challenge') return await this.#challenge(req, res);
      if (path === '/v1/devices/session')   return await this.#session(req, res);
      if (path === '/v1/captures')          return await this.#announce(req, res);
      if (path.startsWith('/upload/'))      return await this.#upload(req, res, path);
      const m = path.match(/^\/v1\/captures\/([^/]+)\/assets\/([^/]+)\/confirm$/);
      if (m)                                 return await this.#confirm(req, res, m[1], m[2]);
      return this.#json(res, 404, { code: 'not_found' });
    } catch (err) {
      return this.#json(res, 500, { code: 'server_error', message: err.message });
    }
  }

  async #enroll(req, res) {
    const body = JSON.parse((await this.#body(req)).toString() || '{}');

    // Idempotent on the public key, and checked BEFORE the enrollment code.
    // A Bridge killed after the server created the device but before it stored
    // the device id has already spent its code; without this it could never
    // enroll again and the laptop is bricked before the event starts. The
    // keypair is committed to disk before the first request, so the retry
    // presents the same key — the same mechanism as capture idempotency.
    for (const [deviceId, d] of this.devices) {
      if (d.publicKey === body.public_key) {
        return this.#json(res, 200, { device_id: deviceId, organization_id: d.organizationId });
      }
    }

    if (!this.pendingEnrollments?.has(body.enrollment_code)) {
      return this.#json(res, 403, { code: 'bad_enrollment_code' });
    }
    const pending = this.pendingEnrollments.get(body.enrollment_code);
    this.pendingEnrollments.delete(body.enrollment_code);
    const deviceId = `dev-${randomUUID().slice(0, 8)}`;
    this.devices.set(deviceId, {
      publicKey: body.public_key, status: 'active', organizationId: pending.organizationId,
    });
    // Server-authoritative: the Bridge gets told who it is.
    return this.#json(res, 200, { device_id: deviceId, organization_id: pending.organizationId });
  }

  async #challenge(req, res) {
    const body = JSON.parse((await this.#body(req)).toString() || '{}');
    if (!this.devices.has(body.device_id)) return this.#json(res, 403, { code: 'device_revoked' });
    const id = randomUUID();
    const challenge = randomUUID();
    this.challenges.set(id, { challenge, deviceId: body.device_id, at: Date.now() });
    return this.#json(res, 200, { challenge_id: id, challenge });
  }

  async #session(req, res) {
    const body = JSON.parse((await this.#body(req)).toString() || '{}');
    const ch = this.challenges.get(body.challenge_id);
    if (!ch || ch.deviceId !== body.device_id) return this.#json(res, 403, { code: 'session_revoked' });
    this.challenges.delete(body.challenge_id);

    const d = this.devices.get(body.device_id);
    if (!d || d.status !== 'active') {
      return this.#json(res, 403, {
        code: d?.status === 'compromised' ? 'device_compromised' : 'device_revoked',
      });
    }

    const { verify, createPublicKey } = await import('node:crypto');
    const ok = verify(null, Buffer.from(ch.challenge), createPublicKey(d.publicKey),
                      Buffer.from(body.signature, 'base64'));
    if (!ok) return this.#json(res, 403, { code: 'bad_signature' });

    if (!this.liveEvents.has(body.event_id)) return this.#json(res, 403, { code: 'event_not_live' });
    // Tenancy: a device may only shoot events its own organization owns. The
    // database enforces this too, via the composite foreign key on
    // device_sessions; this is the application layer saying the same thing.
    if (this.ownerOf(body.event_id) !== d.organizationId) {
      return this.#json(res, 403, { code: 'wrong_organization' });
    }

    // One live session per device, matching the database invariant in
    // migration 0007. Two clones cannot upload concurrently; each takes the
    // session from the other, and taking it from an installation that was
    // working moments ago is what distinguishes a clone from a restart.
    const ACTIVITY_WINDOW_MS = 90_000;
    let signalled = false;
    for (const [tok, prior] of this.sessions) {
      if (prior.deviceId !== body.device_id || prior.supersededAt) continue;
      const lastActive = prior.lastSeenAt ?? prior.issuedAt;
      if (Date.now() - lastActive < ACTIVITY_WINDOW_MS) signalled = true;
      prior.supersededAt = Date.now();
      this.sessions.set(tok, prior);
    }
    if (signalled) {
      const n = (this.cloneSignals.get(body.device_id) ?? 0) + 1;
      this.cloneSignals.set(body.device_id, n);
      if (n >= 3) d.cloneSuspected = true;
    }

    const token = randomUUID();
    const expiresAt = Date.now() + 8 * 3600_000;
    this.sessions.set(token, {
      deviceId: body.device_id, eventId: body.event_id, expiresAt,
      sessionId: randomUUID(), issuedAt: Date.now(), lastSeenAt: Date.now(),
      supersededAt: null,
    });
    return this.#json(res, 200, {
      session_id: randomUUID(), token, event_id: body.event_id,
      organization_id: d.organizationId, expires_at: new Date(expiresAt).toISOString(),
      clone_suspected: !!d.cloneSuspected,
    });
  }

  async #announce(req, res) {
    const a = this.#auth(req);
    if (a.error) return this.#json(res, a.error.status, a.error);
    this.counters.announce++;
    if (this.#take('announce5xx')) return this.#json(res, 503, { code: 'unavailable' });

    const body = JSON.parse((await this.#body(req)).toString() || '{}');

    // Idempotency. This is the mechanism the Bridge relies on for exactly-once.
    const existing = this.capturesByKey.get(body.idempotency_key);
    if (existing) return this.#json(res, 200, this.#targets(existing));

    if (body.event_id !== a.session.eventId) {
      return this.#json(res, 403, { code: 'wrong_event', message: 'session is scoped to another event' });
    }
    const seqKey = `${a.session.deviceId}:${body.device_sequence}`;
    if (this.sequences.has(seqKey)) {
      return this.#json(res, 409, { code: 'sequence_conflict' });
    }
    this.sequences.add(seqKey);

    const capture = {
      capture_id: `cap-${randomUUID().slice(0, 8)}`,
      idempotency_key: body.idempotency_key,
      event_id: body.event_id,
      device_id: a.session.deviceId,
      organization_id: a.device.organizationId,
      device_sequence: body.device_sequence,
      expected: { master: body.content_sha256, preview: body.preview_sha256 },
      assets: {},
    };
    this.capturesByKey.set(body.idempotency_key, capture);
    this.captures.set(capture.capture_id, capture);

    // The nastiest realistic failure: the server committed, then the response
    // never arrived. The Bridge must resolve this to one capture, not two.
    if (this.#take('dropAckAfterCommit')) { req.socket.destroy(); return; }

    return this.#json(res, 200, this.#targets(capture));
  }

  #targets(capture) {
    const base = `/upload/${capture.organization_id}/${capture.event_id}/${capture.capture_id}`;
    return {
      capture_id: capture.capture_id,
      preview_upload: { url: `${this.baseUrl}${base}/preview`, method: 'PUT', headers: {} },
      master_upload:  { url: `${this.baseUrl}${base}/master`,  method: 'PUT', headers: {} },
    };
  }

  async #upload(req, res, path) {
    this.counters.upload++;
    if (this.#take('upload5xx')) { await this.#body(req); return this.#json(res, 503, { code: 'unavailable' }); }

    const body = await this.#body(req);
    const stored = this.#take('corruptUpload') ? Buffer.concat([body, Buffer.from('x')]) : body;
    this.objects.set(path, {
      sha256: createHash('sha256').update(stored).digest('hex'),
      size: stored.length,
    });
    return this.#json(res, 200, { ok: true });
  }

  async #confirm(req, res, captureId, kind) {
    const a = this.#auth(req);
    if (a.error) return this.#json(res, a.error.status, a.error);
    this.counters.confirm++;
    if (this.#take('confirm5xx')) return this.#json(res, 503, { code: 'unavailable' });

    const capture = this.captures.get(captureId);
    if (!capture) return this.#json(res, 404, { code: 'no_such_capture' });
    if (capture.device_id !== a.session.deviceId) {
      return this.#json(res, 403, { code: 'wrong_organization' });
    }

    const body = JSON.parse((await this.#body(req)).toString() || '{}');
    const key = `/upload/${capture.organization_id}/${capture.event_id}/${captureId}/${kind}`;
    const obj = this.objects.get(key);
    if (!obj) return this.#json(res, 409, { code: 'not_uploaded', message: 'no object at that key' });

    // The server verifies what it actually holds, and refuses to confirm bytes
    // that do not match what the Bridge announced.
    if (obj.sha256 !== body.sha256) {
      return this.#json(res, 422, { code: 'checksum_mismatch', message: 'stored bytes differ' });
    }
    const expected = capture.expected[kind];
    if (expected && expected !== body.sha256) {
      return this.#json(res, 422, { code: 'checksum_mismatch', message: 'differs from announced digest' });
    }

    capture.assets[kind] = { asset_id: `ast-${randomUUID().slice(0, 8)}`, sha256: obj.sha256 };
    return this.#json(res, 200, {
      status: 'confirmed', asset_id: capture.assets[kind].asset_id, sha256: obj.sha256,
    });
  }

  // --- assertions for tests -------------------------------------------------

  liveSessionsFor(deviceId) {
    return [...this.sessions.values()].filter(
      (s) => s.deviceId === deviceId && !s.supersededAt && s.expiresAt > Date.now());
  }
  cloneSuspected(deviceId) { return !!this.devices.get(deviceId)?.cloneSuspected; }

  allCaptures() { return [...this.captures.values()]; }
  captureCount() { return this.captures.size; }
  confirmedMasters() { return this.allCaptures().filter((c) => c.assets.master).length; }
}
