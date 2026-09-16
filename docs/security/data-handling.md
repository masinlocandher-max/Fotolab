# Data Handling

## Buckets

Four buckets, none of them public, none of them eligible to become public.

| Bucket | Contents | Reachability |
|---|---|---|
| `quarantine` | Untrusted bytes on arrival | Sandboxed processor only. Nothing else reads it |
| `master` | Write-once originals — the business asset | Photographer's own org via RLS; workers via server credential |
| `preview` | Derived, watermarked, downscaled, metadata-stripped | Served through an access-checked, cacheable route |
| `deliverable` | The thing the customer paid for | Short-lived signed URL, minted only after `app.authorize_download()` returns a row |

A trigger on `storage.buckets` rejects `public = true` for all four. This exists
because the failure mode is predictable: the gallery feels slow, someone opens
the bucket, and every original is permanently public to anyone who has ever seen
a URL. **If you are here because the gallery is slow, cache the preview route.**

The `service_role` key bypasses RLS and every policy above. It belongs in server
processes only — never in a browser bundle, never in the Capture Bridge, never in
a mobile app, never in a repository.

## Signed URLs

Treat one as a bearer capability: whoever holds it gets the bytes until it
expires, regardless of who requested it.

- Check entitlement **at request time**, then mint. Never pre-mint, never cache.
- Lifetime 60–120 seconds. Not 24 hours.
- `Referrer-Policy: no-referrer` on the page that redirects.
- `Cache-Control: private, no-store` on the response.
- A signed URL must never reach: application logs, analytics, error reporting,
  support screenshots, email bodies, email link-tracking, or any third-party
  script.

## Upload pipeline

Declared `Content-Type` is a claim by the uploader. It is evidence of nothing.

```
upload
  → QUARANTINE bucket
  → extension allowlist
  → magic-byte check
  → real decoder probe (does a decoder actually accept this?)
  → byte-size limit
  → pixel-dimension limit
  → decompression-ratio limit        (decompression bombs)
  → metadata size limit
  → SANDBOX: decode
  → re-encode from pixels
  → SAFE ASSET
```

Sandbox properties, non-negotiable: non-root user, read-only filesystem where
possible, no cloud credentials, no database credentials, no outbound network by
default, CPU limit, memory limit, execution timeout, disposable workspace.

If a decoder is compromised, the blast radius is one throwaway worker — not the
platform.

## Metadata

Customer-facing images are **reconstructed from pixels**, never copied with
metadata stripped as an afterthought. Originals routinely carry GPS coordinates,
camera serial numbers, registered owner names, capture software, device
identifiers, precise timestamps, and embedded thumbnails that may show a
different frame than the one being sold.

Masters keep their metadata. Previews and deliverables ship clean.

## Cost as a security perimeter

An attacker who cannot steal a photo can still bankrupt the account. Every layer
gets a ceiling:

| Layer | Ceiling |
|---|---|
| Device | uploads per minute (`devices.uploads_per_minute`) |
| Event | captures per hour (`events.capture_quota_per_hour`), storage ceiling |
| Organization | monthly storage (`organizations.storage_quota_bytes`), processing credits |
| IP | anonymous requests per window |
| Customer session | checkout attempts, download rate |
| Processor | max concurrent jobs |
| AI features | daily monetary budget |
| Platform | global circuit breaker |

The columns exist. **Enforcement does not yet** — this is launch gate 8.

## Blast radius

Assume the production database is stolen tomorrow. It must not by itself yield:

- RAW files or HD deliverables — storage credentials live elsewhere
- payment credentials — provider secrets live elsewhere
- device private keys — never leave the device

A database compromise should require serious incident response. It should not
automatically be total media compromise.
