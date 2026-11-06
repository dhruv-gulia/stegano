# Security policy

## Supported version

The `main` branch and the live demo at https://stegano-two.vercel.app are supported.
This is a minor-project demonstration, not a production secrets service.

## Reporting a vulnerability

Please email the repository owner instead of opening a public issue for an active
vulnerability. Include the affected route or module, reproduction steps, and the impact
you observed. Do not include real secrets, private images, or other people's data.

## Threat model

Stegano protects message **confidentiality and integrity in transit inside an image**
with scrypt, HKDF, AES-256-GCM, and optional Reed–Solomon ECC. It does **not** promise
undetectability. Anyone who can inspect the image can run statistical tests.

- **Cover image:** a malicious image is parsed by Pillow after an upload-size check.
  Malformed files return a 400 instead of a traceback.
- **Payload:** the header is password-located. A wrong password fails the GCM tag. ECC
  repairs limited bit damage before GCM verification, so invalid ciphertext is not
  returned.
- **Admin:** the password comes from `ADMIN_PASSWORD`; the session cookie stores a
  SHA-256 hash, is HttpOnly, and uses SameSite=Lax. Five failures per 60 seconds per IP
  trigger a temporary lock. The process-local rate limiter is not shared across Vercel
  instances.
- **Audit log:** `data/audit.jsonl` records logins, flag changes, encodes, and lab runs
  with an IP and no message text or passwords. On Vercel it lives in `/tmp` and resets on
  a cold start.
- **Serverless storage:** Vercel instances do not share files. Feature flags, history,
  and audit entries are per-instance. Downloads are inlined as data URLs.

## Known limitations

- LSB payloads are destroyed by JPEG, resizing, cropping, screenshots, and most image
  editors. Reed–Solomon ECC only repairs a bounded number of bit errors inside keyed
  payload positions; it does not make the embedding robust to image transforms.
- Noise fill lowers PSNR and can be detected by RS analysis even when chi-square does
  not flag the image. Detection results are screening evidence, not proof.
- A weak admin password or a weak message password remains weak. Set a long random
  `ADMIN_PASSWORD` before exposing the app.
- The app processes untrusted images in the same process as the web server. Run it in a
  constrained container if you expose it beyond a trusted demo audience.
