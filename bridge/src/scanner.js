// Watching the card / tethered folder for new photographs.
//
// This polls rather than using fs.watch. That is a deliberate downgrade:
// fs.watch silently drops events under load, behaves differently on every
// platform, and misses files that appear while the process was dead. A scan
// that re-derives truth from the filesystem every tick cannot miss a file, and
// "I already know about this path" is a unique index rather than a guess.

import { readdir, stat } from 'node:fs/promises';
import { join, extname, dirname, basename } from 'node:path';

const PREVIEW_EXTENSIONS = new Set(['.jpg', '.jpeg', '.heic']);
const RAW_EXTENSIONS = new Set(['.cr2', '.cr3', '.nef', '.arw', '.raf', '.orf', '.rw2', '.dng']);
const DEFAULT_EXTENSIONS = new Set([...PREVIEW_EXTENSIONS, ...RAW_EXTENSIONS]);

/** (directory, basename without extension) — one press of the shutter. */
export function groupKeyFor(path) {
  const dir = dirname(path);
  const base = basename(path, extname(path));
  return `${dir}\u0000${base}`;
}

export class Scanner {
  /**
   * @param {object} opts
   * @param {string[]} opts.roots directories to watch
   * @param {number} opts.quietMs a file must be unchanged this long to count as
   *   finished. A camera still writing a 60MB raw must not be hashed mid-write.
   */
  constructor({ roots, quietMs = 1500, extensions = DEFAULT_EXTENSIONS, now = () => Date.now() }) {
    this.roots = roots;
    this.quietMs = quietMs;
    this.extensions = extensions;
    this.now = now;
    /** @type {Map<string, {size:number, mtimeMs:number, seenAt:number}>} */
    this.observations = new Map();
  }

  async #walk(dir, out) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return out;   // card ejected mid-scan; next tick will see it again
    }
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory()) await this.#walk(p, out);
      else if (e.isFile() && this.extensions.has(extname(e.name).toLowerCase())) out.push(p);
    }
    return out;
  }

  /**
   * One pass. Returns the files that have been stable long enough to be worth
   * committing to the spool.
   *
   * A file whose size or mtime changed since the last tick restarts its quiet
   * period, so a slow write over bad USB never produces a truncated capture.
   */
  async scan() {
    const files = [];
    for (const root of this.roots) await this.#walk(root, files);

    const seen = new Set();
    /** @type {Map<string, {stable: any[], pending: number}>} */
    const groups = new Map();

    for (const path of files) {
      seen.add(path);
      let st;
      try { st = await stat(path); } catch { continue; }

      const key = groupKeyFor(path);
      if (!groups.has(key)) groups.set(key, { stable: [], pending: 0 });
      const g = groups.get(key);

      const prev = this.observations.get(path);
      if (!prev || prev.size !== st.size || prev.mtimeMs !== st.mtimeMs) {
        this.observations.set(path, { size: st.size, mtimeMs: st.mtimeMs, seenAt: this.now() });
        g.pending++;                    // changed this tick: not stable yet
        continue;
      }

      if (this.now() - prev.seenAt >= this.quietMs) {
        g.stable.push({ path, size: st.size, mtimeMs: st.mtimeMs, ext: extname(path).toLowerCase() });
      } else {
        g.pending++;
      }
    }

    // A group is emitted only when every file currently present for it has
    // settled. Emitting a JPEG while its RAW sibling is still being written
    // would spool the pair as two photographs.
    const ready = [];
    for (const [groupKey, g] of groups) {
      if (g.pending > 0 || g.stable.length === 0) continue;

      const raw = g.stable.find((f) => RAW_EXTENSIONS.has(f.ext));
      const jpeg = g.stable.find((f) => PREVIEW_EXTENSIONS.has(f.ext));

      // The master is the highest-fidelity file present; the preview source is
      // the camera JPEG when there is one. A RAW-only capture has no preview
      // until the server-side worker derives one, which is the right place for
      // it — the Bridge is not trusted to produce customer-facing pixels.
      const master = raw ?? jpeg;
      ready.push({
        groupKey,
        masterPath: master.path,
        previewPath: jpeg ? jpeg.path : null,
        size: master.size,
        mtimeMs: master.mtimeMs,
        files: g.stable.map((f) => f.path),
      });
    }

    for (const path of this.observations.keys()) {
      if (!seen.has(path)) this.observations.delete(path);
    }

    return ready;
  }
}
