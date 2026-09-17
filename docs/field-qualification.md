# Field Qualification (Phase 2.5)

Phase 2 proved the Bridge is correct under fault injection. Phase 2.5 asks a
different question: will it survive a real photographer's day, on their laptop,
on a venue's wifi, without anybody who understands the code being in the room?

This document records what was tested, what was measured, what was found, and
what a shadow event has to demonstrate before the Bridge carries anything real.

---

## Running it

```bash
cd bridge
npm test                # the full suite, including a short field run
npm run qualify         # the gate: 1200 shutter presses, realistic file sizes
npm run test:soak       # 500 presses through repeated SIGKILL
```

```bash
# the database side
./tests/security/run.sh
```

The qualification run takes a while by design — it spans many worker lifetimes
with real file sizes. `FQ_PRESSES`, `FQ_BATCHES` and `FQ_SIZE_SCALE` shorten it
for iteration; the gate is the unscaled run.

---

## What the harness simulates

A camera shooting into folders that roll over every 999 frames and restart
numbering, producing a realistic mix: JPEG+RAW pairs, JPEG-only, RAW-only,
occasional large RAWs, bursts, slow writes that grow between scans, and writes
interrupted partway and completed later.

Around that, everything a venue does: the Bridge process dying, the machine
restarting, the network disappearing and returning, requests timing out,
acknowledgements lost after the server has already committed, 5xx storms,
transfers corrupted in flight, the card reader pulled out and plugged back in,
the disk going critical, the photographer renaming and moving files mid-event,
and the same unchanged card being rescanned repeatedly.

### The harness audits itself

A fault that never fired, or only ever fired against an empty spool, proves
nothing. Every injection is recorded and scored against the **peak spool depth
observed while that fault was in force**, and the run fails if any fault type
never landed on live work.

Two things were corrected because that audit failed honestly:

- In-flight was first measured when a fault was *scheduled*, which is before
  the worker starts and usually when the spool is empty. Every fault scored
  zero. It is now measured by sampling the spool while the worker runs.
- Random rolls left whole fault types uninjected on shorter runs. Each batch
  now deterministically takes the next fault in rotation on top of the dice, so
  coverage is scheduled rather than hoped for.

---

## Defects found in Phase 2.5

Seven in capture identity, one in privilege, one in memory, one in restart.

| # | Defect | Root cause | Consequence |
|---|---|---|---|
| 1 | `IMG_0001.JPG` and `IMG_0001.jpg` merged | a capture group assumed at most one file per role | one photograph silently dropped |
| 2 | `.jpg` beside `.jpeg` merged | same | one photograph silently dropped |
| 3 | Camera counter reset swallowed the new frame | `discover()` read "key exists" as "same file" | photograph never spooled |
| 4 | RAW arriving after its JPEG never uploaded | the group froze at emit; no path for a late master | **the master lost on any slow card** |
| 5 | JPEG arriving after its RAW discarded | attach window too narrow | no fast preview |
| 6 | A file moved mid-flight retried ENOENT forever | ENOENT classed as retry-forever | capture wedged permanently |
| 7 | Group keys truncated in storage | a NUL byte as separator; SQLite truncates text at NUL | every diagnostic query silently wrong |
| 8 | `anon` held EXECUTE on every `app` function | `revoke ... from anon` does not remove PUBLIC's default grant | defence in depth absent |
| 9 | Size ceiling inconsistent with the memory envelope | 512 MiB ceiling predicted ~1.8 GiB peak RSS | OOM kill, then a restart that meets the same file |
| 10 | A carried-over JPEG capture completed before its RAW was noticed | the drain outran the scanner's second tick | one shutter press split into two captures |
| 11 | A card pulled between hashing and announcing discarded the capture instantly | `vanished_before_announce` rejected with no grace and kept the group key | **photographs lost by unplugging a cable for two seconds**, and never rediscovered when it came back |

Defect 7 is the one worth dwelling on. It broke nothing any test could see —
exact lookups worked because the index compares full bytes — while making
`length()`, `LIKE`, `substr`, concatenation, logs and every operator diagnostic
return a truncated, ambiguous value. It would have been discovered by a
photographer at an event, by someone trying to find one photograph by name.

Defect 8 was confirmed by direct experiment rather than inference: a function
revoked from `anon` still reported `has_function_privilege(anon, ...) = true`,
and only revoking from `PUBLIC` changed it.

Defect 11 was found by the field harness and by nothing else. The unit tests
covered a card removed during *upload*, where the grace period applies. They did
not cover the narrower window between hashing and announcing, which had a
separate code path that rejected on the spot — and because the rejection kept
the group key, the returning file was never rediscovered. Every photograph in
flight at the moment a reader was bumped was lost, silently.

### Two test defects, found by the harness auditing itself

Not Bridge defects, but worth recording because both would have produced a
green run that proved nothing:

- **Faults were scored against the wrong moment.** In-flight depth was
  measured when a fault was *scheduled*, which is before the worker starts and
  usually when the spool is empty. Every fault scored zero. It is now the peak
  spool depth observed while the fault was in force, over a window covering the
  injecting batch and the next — because a renamed file is not discovered until
  the next scan and an armed server fault sits until a request consumes it.
- **Rotation coverage was a claim, not a fact.** A random roll could pre-empt
  the scheduled fault, so whole fault types went uninjected. The scheduled
  fault now takes precedence, and a run cannot be shorter than the rotation.

### One test defect in the Phase 2 suite

`every photograph survives repeated kill -9` failed roughly one run in four,
but only when the whole suite ran. Test files execute concurrently and these
tests fork heavily, so a worker could sit unscheduled through its fixed
40–300ms kill window and be killed having done nothing — tripping its own
anti-vacuous guard. Kills are now triggered by observed progress rather than by
wall-clock delay, which makes the crash land on live work by construction.
Verified stable across repeated full-suite runs.

---

## Measurements

### Memory

Sampled from inside the process doing the work, on real files.

| Scenario | Peak RSS |
|---|---|
| 12 × 60 MiB RAW | 297 MiB |
| 8 × 50 MiB under a retry storm | 430 MiB |
| 150-capture offline backlog | 144 MiB |
| One file at the 191 MiB ceiling, with retries | 679 MiB |

Scaling, measured across three file sizes:

```
peak RSS  ~=  150 MiB  +  3.6 x file size
```

**Envelope: 1 GiB.** A photographer's laptop is commonly 8 GB with Lightroom and
a browser already open; the Bridge's share has to be uninteresting.

Whole-file buffering is kept — a consumed stream cannot be retried, and
silently sending an empty body is worse than the memory. The ceiling is derived
from the measurement at **192 MiB**, and a test fails if the ceiling and the
measured constants are ever edited apart. Resumable multipart upload is the
named follow-up that lifts it properly.

### Disk

Three states with thresholds in one place, evaluated as the worse of an
absolute floor and a proportion:

| State | Free bytes | Free proportion |
|---|---|---|
| healthy | > 5 GiB | > 5% |
| warning | ≤ 5 GiB | ≤ 5% |
| critical | ≤ 1 GiB | ≤ 2% |

Critical stops the Bridge **accepting** new photographs; work already accepted
continues to drain, because draining needs no disk and is how the backlog
shrinks. An unreadable volume reports `unknown` and is treated as unsafe — not
knowing how much room there is must not read as having room. Recovery resumes
ingestion with no operator action.

Cleanup is unchanged: it defaults to never deleting, and when enabled it
re-hashes the file and compares against what the server acknowledged before
unlinking. A full disk does not turn it into a pressure-release valve.

### Device cloning

Enrollment recovery resolves a repeated enrollment of the same public key to
the same device, which is required — without it a Bridge killed mid-enrollment
has spent its code and is bricked. The consequence is that a copied state
directory is the same device to the server.

The invariant that makes that visible is enforced in the database: **a device
has at most one live session**, by partial unique index. Two clones cannot
upload concurrently; each takes the session from the other. Taking a session
from an installation that was uploading seconds ago is what distinguishes a
clone from a restart — a crashed Bridge stops touching its heartbeat
immediately, a working one does not. Three such takeovers flag the device, and
an operator either clears the suspicion or declares it compromised, which
revokes every session at once.

Client side, the losing installation stops competing rather than starting an
upload war, and its spool is left completely intact.

---

## Shadow-event acceptance gate

The Bridge runs in parallel with the photographer's existing workflow. They
shoot and deliver exactly as they do today. **No customer depends on the Bridge,
and nothing it produces is sold or shown.** It is a passenger.

### Before the event

1. `npm run qualify` passes on the laptop that will be used, not just in CI.
2. `./tests/security/run.sh` passes against a scratch database.
3. The Bridge is enrolled on that laptop and `node src/cli.js status` reads
   *set up* and *connected to an event*.
4. Retention is left at the default. **Nothing is deleted from any card.**
5. The photographer is shown the status screen once and told the only two
   things they need to know: shooting never stops for the Bridge, and nothing
   is lost while it is offline.

### During the event

The photographer works normally. Nobody debugs anything. If the Bridge stops,
it stops — that is data, not an emergency.

### After the event

| # | Criterion | How it is checked |
|---|---|---|
| 1 | Every valid shutter press became exactly one capture | count frames on the card against server captures; no idempotency key used twice, no device sequence reused |
| 2 | Every accepted source file is byte-verifiable | re-hash each file on the card and compare against the digest the server confirmed |
| 3 | JPEG+RAW pairing stayed correct | every pair is one capture with the RAW as master and the JPEG as preview |
| 4 | Nothing crossed a tenant or event boundary | every capture carries the right organization and event |
| 5 | No capture is permanently stuck | no spool row outside `complete` or `rejected`, and every rejection has a reason a person can act on |
| 6 | Restart recovery needed no database intervention | no manual SQL was run; `status` was the only tool used |
| 7 | Disk pressure was visible before ingestion became unsafe | if the disk crossed warning, the status screen said so before critical |
| 8 | Memory stayed inside the envelope | peak RSS below 1 GiB |
| 9 | The photographer's workflow was not materially disrupted | their own account, in their own words |
| 10 | Faults were diagnosable from status and logs, with no secrets | a reviewer reads the status output and the log and can say what happened; no token, key, or internal identifier appears |

A single failure of 1, 2, 3, 4 or 5 fails the gate outright. Failures of 6–10
are recorded and judged.

### What would fail the gate quietly, and so is checked explicitly

- A photograph on the card that is on the server under a *different* digest.
  Checked by re-hashing, not by counting.
- A capture that completed but whose master is the JPEG of a pair whose RAW is
  still on the card. Checked by pairing, not by totals.
- A rejection reason nobody can act on.

---

## Known limits

Stated rather than discovered later.

- **Files above 192 MiB are refused.** The ceiling follows from the memory
  envelope. Medium-format and multi-shot files will hit it. Resumable multipart
  upload is the fix and is not attempted here.
- **A RAW landing after its JPEG capture was announced becomes its own capture**
  with the relationship recorded, rather than being folded in. The pair grace
  window and the direct sibling check make this rare; it is not impossible.
- **A JPEG arriving after a RAW-only capture has completed is not attached.**
  The master is safe and the missing preview is explicit, so the server-side
  worker derives one. No photograph is lost.
- **Clone detection is a signal, not a proof.** A laptop force-restarted three
  times while uploading can be flagged. The remedy is an operator decision, not
  an automatic lockout, precisely because of that.
- **`node:sqlite` is flagged experimental by Node.** The durability is SQLite's;
  the exposure is API churn on upgrade.
- **At-rest key encryption protects a stolen disk, not a running laptop.**
  Full-disk encryption is the real control for the spooled photographs. OS
  keychain storage for the device key is still Phase 6 work.
- **The Bridge has never run on macOS or Windows here.** Everything in this
  document was executed on Linux. Path handling, `statfs` semantics and
  filesystem case sensitivity all differ, and case sensitivity is directly
  load-bearing for capture identity. **A shadow event on the photographer's
  actual operating system is required before any of this transfers.**

---

## Field harness: observed results

Eleven short runs (45 shutter presses, scaled file sizes) were executed after
the vanished-source fix. Ten delivered **every file on the card byte-exact**.
One delivered 74 of 76, alongside a `content_changed_after_announce` rejection.

Of the five runs after the final harness correction: four passed outright, one
was the 74-of-76 run. **That residual was not isolated.** The suspected
mechanism is a slow write completing while its capture is between announce and
upload, near the end of the run, leaving too little time for the retired
capture's replacement to be rediscovered and uploaded — but that is a
hypothesis, not a finding, and it is recorded as an open item rather than
explained away.

Two earlier runs failed the coverage audit rather than the delivery check, and
each produced a harness correction (idle-batch deferral, rotation
displacement). Those are described above.

**The full 1200-press gate at realistic file sizes has not been executed.** A
45-press scaled run takes roughly sixteen minutes here; the gate is hours. It
is wired as `npm run qualify` and in CI on the default branch, and it has not
been run to completion in this environment.

## Qualification status

The honest label as of this document:

- **Engineering-qualified** — yes. The database and Bridge suites pass
  repeatedly and stably, every new safety invariant has been mutation-tested,
  and all eleven defects above were found by execution rather than review.
- **Field-qualified** — **no.** Two things block it, and neither is a
  formality: the field gate is not consistently green (one run in five lost
  two files, unexplained), and the full-scale gate has never been executed.
- **Shadow-event-qualified** — no. No real event has been shot, and nothing
  here has ever run on macOS or Windows, where filesystem case sensitivity —
  which capture identity depends on directly — differs.

The next step is to isolate the remaining delivery failure and run the gate at
full scale. Only then does a shadow event become worth a photographer's day.
