// The server contract, and the difference between "try again" and "stop".
//
// Every call here is safe to repeat. announceCapture carries an idempotency key
// so a retry after a lost response returns the capture the server already
// created rather than creating a second one — which is the whole mechanism
// behind "every accepted photograph becomes exactly one capture".

export class TransientError extends Error {
  /**
   * @param {object} [opts]
   * @param {boolean} [opts.bounded] retry, but give up eventually. Used for a
   *   checksum mismatch: the transfer or the store corrupted the bytes and a
   *   re-send may well fix it, so rejecting on the first mismatch would lose a
   *   photograph to one bad packet — but retrying forever would spin on a file
   *   that genuinely cannot be transferred.
   */
  constructor(message, { status, bounded = false } = {}) {
    super(message); this.name = 'TransientError'; this.status = status; this.bounded = bounded;
  }
}

/** A failure that retrying cannot fix: the file, the event, or this device is wrong. */
export class PermanentError extends Error {
  constructor(message, { status, code } = {}) {
    super(message); this.name = 'PermanentError'; this.status = status; this.code = code;
  }
}

/** Authority was withdrawn. Stop all work now; do not touch the spool. */
export class AuthorityError extends Error {
  constructor(message, { code } = {}) { super(message); this.name = 'AuthorityError'; this.code = code; }
}

const AUTHORITY_CODES = new Set([
  'device_revoked', 'device_compromised', 'session_expired',
  'session_revoked', 'event_not_live', 'wrong_organization', 'wrong_event',
]);

export function classify(status, code, message) {
  if (AUTHORITY_CODES.has(code)) return new AuthorityError(message ?? code, { code });
  if (status === 408 || status === 429 || status >= 500) {
    return new TransientError(message ?? `server returned ${status}`, { status });
  }
  if (code === 'checksum_mismatch' || code === 'not_uploaded') {
    return new TransientError(message ?? code, { status, bounded: true });
  }
  if (status >= 400) return new PermanentError(message ?? `server rejected: ${status}`, { status, code });
  return null;
}

export class HttpClient {
  constructor({ baseUrl, sessionStore, fetchImpl = globalThis.fetch, timeoutMs = 30_000 }) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.sessions = sessionStore;
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  async #request(path, { method = 'POST', body, auth = true, raw = null, headers = {} } = {}) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.timeoutMs);
    const h = { ...headers };

    if (auth) {
      const s = this.sessions.current();
      if (!s?.token) throw new AuthorityError('no event session', { code: 'session_expired' });
      h['authorization'] = `Bearer ${s.token}`;
    }
    if (body !== undefined) h['content-type'] = 'application/json';

    let res;
    try {
      res = await this.fetch(`${this.baseUrl}${path}`, {
        method, headers: h, signal: ac.signal,
        body: raw ?? (body === undefined ? undefined : JSON.stringify(body)),
      });
    } catch (err) {
      // A network failure is indistinguishable from a response we never saw.
      // It is transient, and it is why every call must be idempotent.
      throw new TransientError(`network: ${err.message}`);
    } finally {
      clearTimeout(timer);
    }

    const text = await res.text();
    let payload = null;
    try { payload = text ? JSON.parse(text) : null; } catch { /* non-JSON body */ }

    if (!res.ok) {
      const err = classify(res.status, payload?.code, payload?.message ?? text?.slice(0, 200));
      if (err) throw err;
    }
    return payload;
  }

  // --- enrollment -----------------------------------------------------------

  /** Trade an operator-issued enrollment code for a server-assigned identity. */
  enroll({ enrollmentCode, publicKeyPem, label }) {
    return this.#request('/v1/devices/enroll', {
      auth: false, body: { enrollment_code: enrollmentCode, public_key: publicKeyPem, label },
    });
  }

  challenge({ deviceId }) {
    return this.#request('/v1/devices/challenge', { auth: false, body: { device_id: deviceId } });
  }

  /** Exchange a signed challenge for a short-lived, event-scoped credential. */
  openSession({ deviceId, eventId, challengeId, signature }) {
    return this.#request('/v1/devices/session', {
      auth: false,
      body: { device_id: deviceId, event_id: eventId, challenge_id: challengeId, signature },
    });
  }

  // --- captures -------------------------------------------------------------

  /**
   * Announce a capture and receive upload authorizations.
   * Idempotent on idempotency_key: repeat calls return the same capture_id.
   */
  announceCapture(req) {
    return this.#request('/v1/captures', { body: req });
  }

  /** Upload bytes to the storage target the server nominated. */
  async uploadAsset({ target, body }) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.timeoutMs * 10);
    let res;
    try {
      res = await this.fetch(target.url, {
        method: target.method ?? 'PUT',
        headers: target.headers ?? {},
        body, signal: ac.signal, duplex: 'half',
      });
    } catch (err) {
      throw new TransientError(`upload network: ${err.message}`);
    } finally { clearTimeout(timer); }

    if (!res.ok) {
      const err = classify(res.status, null, `upload failed: ${res.status}`);
      if (err) throw err;
    }
    // Note what this does NOT do: return success to the caller as proof. The
    // only proof is confirmAsset below.
    return true;
  }

  /**
   * Ask the server what it durably holds. This is the only thing that may
   * advance a capture to a *_CONFIRMED state.
   */
  confirmAsset({ captureId, kind, sha256, byteSize }) {
    return this.#request(`/v1/captures/${captureId}/assets/${kind}/confirm`, {
      body: { sha256, byte_size: byteSize },
    });
  }
}
