// Watching the card / tethered folder for new photographs.
//
// This polls rather than using fs.watch. That is a deliberate downgrade:
// fs.watch silently drops events under load, behaves differently on every
// platform, and misses files that appear while the process was dead. A scan
// that re-derives truth from the filesystem every tick cannot miss a file, and
// "I already know about this path" is a unique index rather than a guess.

import { readdir, stat } from 'node:fs/promises';
import { join, extname, dirname, basename } from 'node:path';

export const PREVIEW_EXTENSIONS = new Set(['.jpg', '.jpeg', '.heic']);
export const RAW_EXTENSIONS = new Set(['.cr2', '.cr3', '.nef', '.arw', '.raf', '.orf', '.rw2', '.dng']);
const DEFAULT_EXTENSIONS = new Set([...PREVIEW_EXTENSIONS, ...RAW_EXTENSIONS]);

/**
 * (directory, basename without extension) — one press of the shutter,
 * expressed as the file path with its extension removed.
 *
 * The separator is the path separator, not a NUL byte. A NUL looks like a
 * tidy unambiguous delimiter and is not: SQLite stores the text but truncates
 * it at the NUL for length(), LIKE, substr and concatenation, so every key in
 * a directory reads back as the directory itself. Exact lookups still worked
 * by accident, which is the worst kind of working — every diagnostic query,
 * status listing and log line would have been wrong at the exact moment
 * somebody needed one. A basename can never contain '/', so joining with it
 * is unambiguous and stays readable.
 */
export function groupKeyFor(path) {
  return join(dirname(path), basename(path, extname(path)));
}

export class Scanner {
  /**
   * @param {object} opts
   * @param {string[]} opts.roots directories to watch
   * @param {number} opts.quietMs a file must be unchanged this long to count as
   *   finished. A camera still writing a 60MB raw must not be hashed mid-write.
   */
  /**
   * @param {object} opts
   * @param {number} [opts.pairGraceMs] how long a lone JPEG waits for the RAW
   *   its camera is probably still writing. A shutter press that produced both
   *   should become one capture, and on a slow card the two files can be
   *   seconds apart. Bounded, so a JPEG-only camera never waits forever.
   */
  constructor({
    roots, quietMs = 1500, pairGraceMs = 8000,
    extensions = DEFAULT_EXTENSIONS, now = () => Date.now(),
  }) {
    this.roots = roots;
    this.quietMs = quietMs;
    this.pairGraceMs = pairGraceMs;
    this.extensions = extensions;
    this.now = now;
    /** @type {Map<string, {size:number, mtimeMs:number, seenAt:number}>} */
    this.observations = new Map();
    /** @type {Map<string, number>} when each group first had everything settled */
    this.groupSettledAt = new Map();
  }

  /**
   * Groups held back waiting for a possible RAW sibling. A caller deciding
   * whether there is nothing left to do must ask this as well as the spool —
   * otherwise it concludes "idle" while a photograph is still in the grace
   * window and walks away from it.
   */
  waitingGroups() {
    let n = 0;
    for (const settledAt of this.groupSettledAt.values()) {
      if (this.now() - settledAt < this.pairGraceMs) n++;
    }
    return n;
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

      const raws = g.stable.filter((f) => RAW_EXTENSIONS.has(f.ext));
      const jpegs = g.stable.filter((f) => PREVIEW_EXTENSIONS.has(f.ext));

      // Two files competing for the same role — IMG_0001.JPG beside
      // IMG_0001.jpg, or a .jpg beside a .jpeg. They share a stem but they are
      // different photographs, and picking one silently loses the other. Break
      // the group apart and let each file be its own capture, keyed by its own
      // path. Visibly two, rather than invisibly one.
      if (raws.length > 1 || jpegs.length > 1) {
        for (const f of g.stable) {
          ready.push({
            groupKey: f.path, masterPath: f.path,
            previewPath: PREVIEW_EXTENSIONS.has(f.ext) ? f.path : null,
            size: f.size, mtimeMs: f.mtimeMs, files: [f.path], roleCollision: true,
          });
        }
        continue;
      }

      const raw = raws[0], jpeg = jpegs[0];

      // A lone JPEG may be half of a pair whose RAW is still being written.
      // Give the card a bounded moment before committing to JPEG-as-master.
      if (!raw && jpeg && this.pairGraceMs > 0) {
        const settledAt = this.groupSettledAt.get(groupKey) ?? this.now();
        this.groupSettledAt.set(groupKey, settledAt);
        if (this.now() - settledAt < this.pairGraceMs) continue;
      }

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
        hasRaw: !!raw,
      });
    }

    for (const path of this.observations.keys()) {
      if (!seen.has(path)) this.observations.delete(path);
    }
    for (const key of this.groupSettledAt.keys()) {
      if (!groups.has(key)) this.groupSettledAt.delete(key);
    }

    return ready;
  }
}
