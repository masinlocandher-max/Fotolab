// Disk pressure.
//
// The Bridge never copies a photograph — it reads from the card in place and
// uploads. Its own footprint is the spool database, which is small. So the
// disk risk is not "the Bridge fills the disk"; it is that the volume holding
// the spool runs out and the Bridge can no longer commit the row that says a
// photograph exists.
//
// That is the line that must not be crossed silently. A Bridge that cannot
// durably record a capture must stop accepting new ones and say so, not keep
// discovering photographs it has no way to remember.

import { statfs } from 'node:fs/promises';

export const DISK = {
  HEALTHY:  'healthy',
  WARNING:  'warning',
  CRITICAL: 'critical',
  UNKNOWN:  'unknown',
};

/**
 * Thresholds, in one place and deliberately conservative.
 *
 * Both an absolute floor and a proportion, because neither alone is right: 2%
 * of a 4TB array is 80GB of headroom nobody needs, and 2GB free on a 64GB
 * laptop SSD is genuinely nearly full. A volume is as bad as the worse of the
 * two readings.
 */
export const DEFAULT_THRESHOLDS = {
  criticalFreeBytes: 1 * 1024 ** 3,     // 1 GiB
  warningFreeBytes:  5 * 1024 ** 3,     // 5 GiB
  criticalFreeRatio: 0.02,              // 2%
  warningFreeRatio:  0.05,              // 5%
};

/**
 * Inspect the filesystem holding `path`.
 * @returns {Promise<{state: string, freeBytes: number|null, totalBytes: number|null,
 *                    freeRatio: number|null, reason: string}>}
 */
export async function checkDisk(path, thresholds = DEFAULT_THRESHOLDS) {
  let st;
  try {
    st = await statfs(path);
  } catch (err) {
    // Not knowing is not the same as being fine. An unreadable volume is
    // reported as unknown and treated by callers as unsafe to ingest into.
    return { state: DISK.UNKNOWN, freeBytes: null, totalBytes: null, freeRatio: null,
             reason: `could not stat ${path}: ${err.message}` };
  }

  const freeBytes = st.bavail * st.bsize;      // bavail: usable by non-root
  const totalBytes = st.blocks * st.bsize;
  const freeRatio = totalBytes > 0 ? freeBytes / totalBytes : 0;

  const byBytes =
    freeBytes <= thresholds.criticalFreeBytes ? DISK.CRITICAL :
    freeBytes <= thresholds.warningFreeBytes ? DISK.WARNING : DISK.HEALTHY;
  const byRatio =
    freeRatio <= thresholds.criticalFreeRatio ? DISK.CRITICAL :
    freeRatio <= thresholds.warningFreeRatio ? DISK.WARNING : DISK.HEALTHY;

  const rank = { [DISK.HEALTHY]: 0, [DISK.WARNING]: 1, [DISK.CRITICAL]: 2 };
  const state = rank[byBytes] >= rank[byRatio] ? byBytes : byRatio;

  return {
    state, freeBytes, totalBytes, freeRatio,
    reason: state === DISK.HEALTHY
      ? `${gib(freeBytes)} free (${pct(freeRatio)})`
      : `only ${gib(freeBytes)} free (${pct(freeRatio)}) on the volume holding the spool`,
  };
}

export function gib(bytes) {
  if (bytes == null) return 'unknown';
  return `${(bytes / 1024 ** 3).toFixed(1)} GiB`;
}
export function pct(ratio) {
  if (ratio == null) return 'unknown';
  return `${(ratio * 100).toFixed(1)}%`;
}

/**
 * Whether it is safe to take responsibility for more photographs.
 *
 * Draining is always allowed — finishing work in progress is how the backlog
 * shrinks, and an upload needs no disk. Only *accepting* new work stops.
 */
export function mayIngest(state) {
  return state === DISK.HEALTHY || state === DISK.WARNING;
}
