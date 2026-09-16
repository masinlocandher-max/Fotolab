// Content hashing, and the check that the file did not change under us.

import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';

export async function sha256File(path) {
  const h = createHash('sha256');
  await new Promise((resolve, reject) => {
    const s = createReadStream(path);
    s.on('data', (c) => h.update(c));
    s.on('error', reject);
    s.on('end', resolve);
  });
  return h.digest('hex');
}

/**
 * Hash a file and prove it was not replaced while we read it.
 *
 * A camera writing over a filename we are mid-hash produces a digest that
 * belongs to neither version. Comparing size and mtime either side of the read
 * catches that; the caller rewinds the row to DISCOVERED and lets it
 * re-stabilise rather than uploading a hash that matches nothing on disk.
 *
 * @returns {{sha256: string, size: number, mtimeMs: number} | {changed: true}}
 */
export async function hashStable(path) {
  const before = await stat(path);
  const sha256 = await sha256File(path);
  const after = await stat(path);

  if (before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
    return { changed: true };
  }
  return { sha256, size: after.size, mtimeMs: after.mtimeMs };
}

export function sha256Buffer(buf) {
  return createHash('sha256').update(buf).digest('hex');
}
