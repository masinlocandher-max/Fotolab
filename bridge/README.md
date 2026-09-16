# Capture Bridge

The program that sits on a photographer's laptop, watches the card or tether
folder, and gets every photograph to the cloud — through bad venue wifi, a
closed lid, a yanked cable, and a process that dies without warning.

```
camera writes file
  → Bridge notices it and commits a spool row      (durable, before anything else)
  → hashes it, proving the bytes did not move
  → announces it and receives upload authorizations
  → sends the preview, waits for the server to say it has it
  → sends the master, waits for the server to say it has it
  → marks it complete; the local file becomes *eligible* for cleanup
```

## The two rules

**A photograph is recorded before it is processed.** The spool row is committed
to SQLite — WAL, `synchronous=FULL` — before the Bridge hashes a byte or opens a
socket. Losing power one millisecond after the camera writes still leaves
evidence that the photograph exists.

**Only the server may say a photograph arrived.** An upload returning `200`
means our socket closed cleanly. It does not mean the bytes are durable, that
they were not corrupted in flight, or that they are the bytes we meant to send.
A capture reaches `PREVIEW_CONFIRMED` or `MASTER_CONFIRMED` only when the server
returns an asset id *and* a digest matching what we computed locally.

## Exactly once, across crashes

The nastiest realistic failure is not a network outage. It is the server
committing a capture and the response never arriving: retry naively and the
event has two of the same photograph, priced twice and shown twice.

The `idempotency_key` is generated and committed at discovery, before the first
request. Every announce carries it, and the server returns the capture it
already created. A crash anywhere in that window resolves to one photograph.

`tests/crash.test.js` proves this by killing the process with `SIGKILL` at
random points, fourteen rounds, with the fake server dropping acknowledgements
after committing — then asserting exactly one capture per file, byte-exact.

Enrollment gets the same treatment. The keypair is written to disk before the
first request, and the server resolves a repeat enrollment of the same public
key to the same device. Without that, a Bridge killed after the server created
the device but before it recorded the id has spent its enrollment code and can
never enroll — a laptop bricked before the event starts. `tests/crash.test.js`
kills the process six times inside that window and demands one device and a
working Bridge at the end.

## State machine

```
DISCOVERED → HASHED → QUEUED → UPLOADING_PREVIEW → PREVIEW_CONFIRMED
           → UPLOADING_MASTER → MASTER_CONFIRMED → COMPLETE
                                                 ↘ REJECTED
```

Failure is not a state. A failed attempt records an error and a backoff on the
row it failed in; it never rewinds past a confirmation the server gave us.
Restarting resumes every non-terminal row where it stopped — `recover()` rewinds
only the two in-flight upload states, because those are the only ones where the
process could have died mid-request.

`REJECTED` is for things retrying cannot fix: an empty file, a file larger than
the ceiling, bytes already present in this event, or content that changed after
the capture was announced.

## What the Bridge holds

One Ed25519 private key, encrypted at rest with scrypt + AES-256-GCM when a
passphrase is configured. Nothing else.

No `service_role` key. No database password. No storage master key. No payment
secret. No platform admin token. A full filesystem dump of a Bridge install
yields a device key and the photographs already on that laptop.

`device_id`, `organization_id`, `event_id` and every capture id are
**server-authoritative** — the Bridge is told who it is and never asserts it.
Event credentials are short-lived and scoped to one organization, one event, one
device. Revoking or marking a device compromised stops new work immediately
rather than at token expiry, and the spool is left completely intact: losing
permission must never look like losing photographs.

## One shutter press, one capture

A camera shooting JPEG+RAW writes `DSC0123.JPG` and `DSC0123.CR3` for a single
press. Keying the spool on the file path would make that two photographs — two
gallery tiles, two prices. Captures are keyed on `(directory, basename)`, the
camera JPEG goes up as the preview source, and the RAW is the master.

Filenames are never identifiers. The same `DSC0001.JPG` from two different cards
is two photographs; the same bytes in two places is one.

## Honest limits

- **The Bridge does not make customer-facing pixels.** It uploads a source
  preview; watermarking, downscaling and metadata stripping happen in the
  sandboxed server-side worker. A laptop at a venue is not a trusted renderer.
- **A RAW-only capture has no preview** until the server derives one. Extracting
  the embedded JPEG from RAW needs a parser the Bridge deliberately does not
  carry.
- **Uploads are whole-file, buffered.** Retry correctness came first: a consumed
  stream cannot be re-sent, and silently uploading zero bytes on retry is worse
  than the memory cost. Resumable multipart is the next piece of work, and is
  what the `maxBytes` ceiling stands in for today.
- **`node:sqlite` is flagged experimental by Node.** The durability is SQLite's,
  not Node's, so the exposure is API churn on upgrade rather than data loss. The
  surface used here is deliberately tiny.
- **At-rest key encryption protects a stolen disk, not a running laptop.**
  Full-disk encryption is the real control for the spooled photographs; OS
  keychain storage for the device key is Phase 6.
- **A sibling file that lands long after its group was spooled** (a RAW arriving
  minutes after its JPEG on a failing card) is not merged into that capture.
  It is visible in `status` rather than silently dropped or silently duplicated.

## Running it

```bash
node src/cli.js enroll --url https://ingest.example.com --code ENROLLMENT_CODE
node src/cli.js run    --url https://ingest.example.com --event EVENT_ID --card /Volumes/EOS_DIGITAL
node src/cli.js status
```

Nothing is ever deleted from the card unless `--retention-hours` is passed, and
even then only when the server has confirmed the master, the window has elapsed,
and the bytes on disk still hash to what the server acknowledged. The default is
to keep everything, because the correct default for somebody's only copy of a
wedding is to keep it.

Ctrl-C is safe at any moment. So is pulling the power.

## Tests

```bash
npm test              # state machine, scenarios, crash safety
npm run test:soak     # the Phase 2 milestone: 500+ photographs, unstable event
```

`test/fake-server.js` is strict about the things the Bridge must get right —
idempotency, tenancy, sequence uniqueness, checksum agreement — and can be told
to fail in specific ways, including committing a capture and then dropping the
response.

## Server contract

| Endpoint | Purpose |
|---|---|
| `POST /v1/devices/enroll` | trade an operator-issued code for a server-assigned device identity |
| `POST /v1/devices/challenge` | get a nonce to sign |
| `POST /v1/devices/session` | exchange a signed nonce for a short-lived, event-scoped credential |
| `POST /v1/captures` | announce a capture; **idempotent on `idempotency_key`**; returns upload targets |
| `PUT <upload target>` | send bytes to storage |
| `POST /v1/captures/:id/assets/:kind/confirm` | the server states what it durably holds; the only thing that advances a capture |

Error codes the Bridge treats as loss of authority, stopping work without
touching the spool: `device_revoked`, `device_compromised`, `session_expired`,
`session_revoked`, `event_not_live`, `wrong_organization`, `wrong_event`.

`checksum_mismatch` is retried a bounded number of times and then rejected —
one corrupted transfer must not lose a photograph, and a file that genuinely
cannot be transferred must not spin forever.
