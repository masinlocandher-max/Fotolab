// Device identity.
//
// The Bridge holds exactly one secret: an Ed25519 private key that identifies
// this installation. It holds no service_role key, no database password, no
// storage master key and no payment secret — a full filesystem dump of a
// Bridge should yield a device key and nothing else of platform value.
//
// The key is encrypted at rest with a passphrase (scrypt + AES-256-GCM) when
// one is configured. The honest caveat: an unattended Bridge that restarts
// without a human needs the passphrase available to it, at which point at-rest
// encryption protects against a stolen disk read offline, not against someone
// with the running machine. Full-disk encryption (FileVault / BitLocker) is the
// real control for the spooled photographs themselves, and OS keychain storage
// for this key is Phase 6.

import {
  generateKeyPairSync, createPrivateKey, createPublicKey, sign,
  randomBytes, scryptSync, createCipheriv, createDecipheriv,
} from 'node:crypto';
import { tx } from './db.js';

// N=2^15 costs ~32MB per derivation, which is above Node's default scrypt
// memory cap, so maxmem is raised to match rather than the cost lowered to fit.
const KDF = { N: 2 ** 15, r: 8, p: 1, keylen: 32, maxmem: 128 * (2 ** 15) * 8 * 2 };

function encryptKey(pem, passphrase) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, KDF.keylen, KDF);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(pem, 'utf8'), c.final()]);
  return JSON.stringify({
    v: 1, salt: salt.toString('base64'), iv: iv.toString('base64'),
    tag: c.getAuthTag().toString('base64'), ct: ct.toString('base64'),
  });
}

function decryptKey(envelope, passphrase) {
  const e = JSON.parse(envelope);
  const key = scryptSync(passphrase, Buffer.from(e.salt, 'base64'), KDF.keylen, KDF);
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(e.iv, 'base64'));
  d.setAuthTag(Buffer.from(e.tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(e.ct, 'base64')), d.final()]).toString('utf8');
}

export class Identity {
  constructor(db, { passphrase = null } = {}) {
    this.db = db;
    this.passphrase = passphrase;
  }

  row() { return this.db.prepare('select * from device where id = 1').get(); }

  /** Generate this installation's keypair. Idempotent: never replaces one. */
  ensureKeypair({ label = 'bridge' } = {}) {
    return tx(this.db, () => {
      const existing = this.db.prepare('select * from device where id = 1').get();
      if (existing) return existing;

      const { publicKey, privateKey } = generateKeyPairSync('ed25519');
      const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
      const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

      const stored = this.passphrase ? encryptKey(privPem, this.passphrase) : privPem;
      this.db.prepare(`
        insert into device (id, public_key_pem, private_key, key_encrypted, label, status)
        values (1, ?, ?, ?, ?, 'pending')
      `).run(pubPem, stored, this.passphrase ? 1 : 0, label);
      return this.db.prepare('select * from device where id = 1').get();
    });
  }

  #privateKey() {
    const row = this.row();
    if (!row) throw new Error('no device keypair; run enrollment first');
    const pem = row.key_encrypted ? decryptKey(row.private_key, this.passphrase) : row.private_key;
    return createPrivateKey(pem);
  }

  publicKeyPem() {
    const row = this.row();
    if (!row) throw new Error('no device keypair');
    return row.public_key_pem;
  }

  /** Sign a server-issued challenge. Ed25519 signs the message directly. */
  signChallenge(challenge) {
    return sign(null, Buffer.from(challenge, 'utf8'), this.#privateKey()).toString('base64');
  }

  /**
   * Record the identity the server assigned. device_id and organization_id are
   * server-authoritative: the Bridge never invents or asserts either.
   */
  recordEnrollment({ deviceId, organizationId }) {
    tx(this.db, () => {
      this.db.prepare(`
        update device set device_id = ?, organization_id = ?, status = 'active', enrolled_at = ?
         where id = 1
      `).run(deviceId, organizationId, new Date().toISOString());
    });
  }

  markRevoked(reason) {
    tx(this.db, () => {
      this.db.prepare(
        `update device set status = ?, revoked_noticed_at = ? where id = 1`
      ).run(reason === 'compromised' ? 'compromised' : 'revoked', new Date().toISOString());
    });
  }

  isUsable() {
    const r = this.row();
    return !!r && r.status === 'active' && !!r.device_id;
  }
}

export class SessionStore {
  constructor(db) { this.db = db; }

  current() { return this.db.prepare('select * from session where id = 1').get(); }

  save({ sessionId, eventId, organizationId, token, expiresAt }) {
    tx(this.db, () => {
      this.db.prepare(`
        insert into session (id, session_id, event_id, organization_id, token, expires_at, obtained_at)
        values (1, ?, ?, ?, ?, ?, ?)
        on conflict(id) do update set
          session_id = excluded.session_id, event_id = excluded.event_id,
          organization_id = excluded.organization_id, token = excluded.token,
          expires_at = excluded.expires_at, obtained_at = excluded.obtained_at
      `).run(sessionId, eventId, organizationId, token, expiresAt, new Date().toISOString());
    });
  }

  clear() { this.db.prepare('delete from session where id = 1').run(); }

  /** Live with a margin, so we renew before an upload fails mid-flight. */
  isLive(marginMs = 120_000) {
    const s = this.current();
    if (!s?.token) return false;
    return Date.parse(s.expires_at) - Date.now() > marginMs;
  }
}
