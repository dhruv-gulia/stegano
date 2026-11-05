# Stegno — Image Steganography with AES-GCM

Minor project: hide an encrypted message inside the pixels of a PNG image, extract it
again with the right password, measure how invisible the change is, and control the
web features from an admin panel.

## What it does

- **LSB embedding** — each bit of the payload replaces the least significant bit of one
  RGB channel. A 1200x800 image holds about 360 KB of raw payload.
- **Encryption** — AES-256-GCM with a PBKDF2-SHA256 key (390,000 iterations, random
  salt and nonce per encode). Wrong passwords fail authentication instead of printing
  garbage.
- **Three interfaces** — Python library, CLI, and a server-rendered web app.
- **Metrics** — MSE, PSNR, capacity used, message size; recorded per encode and shown
  on a research dashboard.
- **Admin panel** — log in with a token and turn the encoder, decoder, metrics, and
  research dashboard on or off, and set the upload limit. Flags persist in
  `data/features.json`.

## Project layout

```
stegno-minor/
├── steg/
│   ├── core.py        LSB embed/extract + AES-GCM payload format
│   ├── metrics.py     MSE and PSNR
│   ├── features.py    persistent feature flags
│   ├── cli.py         encode / decode / metrics commands
│   └── web.py         FastAPI app, admin panel, research dashboard
├── tests/             core, flags, and web tests
├── requirements.txt
├── run.ps1            one-command Windows start
└── README.md
```

## Setup (Windows)

```powershell
cd C:\Users\dhruv\stegno-minor
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Python 3.11+ is required (tested on 3.15).

## Web app

```powershell
.\run.ps1
# if PowerShell blocks the script:
powershell -ExecutionPolicy Bypass -File .\run.ps1
# or
.\.venv\Scripts\python -m uvicorn steg.web:app --reload
```

Open http://127.0.0.1:8000.

If `ADMIN_TOKEN` is not set, the server prints a random admin token at startup. To use
a fixed one:

```powershell
$env:ADMIN_TOKEN = "choose-a-long-random-string"
```

- `/` — upload a cover image, type a message and password, download the stego PNG.
- `/decode` — upload the stego PNG and password to read the message.
- `/research` — KPIs, capacity chart, and table of recent encodes with PSNR.
- `/admin` — token login, feature toggles, upload limit.

**Do not resize, screenshot, or convert the output to JPEG** — all of those destroy
the least significant bits. Download the PNG and upload that exact file.

## CLI

```powershell
# Encode (password is prompted, not echoed)
python -m steg.cli encode cover.png -m "meet me at 5" -o stego.png

# Decode to stdout
python -m steg.cli decode stego.png

# Binary payloads / saving to a file
python -m steg.cli encode cover.png -f secret.zip -p "password" -o stego.png
python -m steg.cli decode stego.png -p "password" -o secret.zip

# Compare cover and stego (MSE, PSNR, capacity)
python -m steg.cli metrics cover.png stego.png
```

## Payload format

Written MSB-first into consecutive RGB channels:

| Field | Size | Purpose |
|---|---|---|
| Magic `STEG1` | 5 B | Identifies a Stegno payload |
| Salt | 16 B | PBKDF2 salt |
| Nonce | 12 B | AES-GCM nonce |
| Plaintext length | 4 B | Big-endian message size |
| Ciphertext + tag | length + 16 B | Encrypted message and GCM authentication tag |

The 53-byte fixed overhead means an image with `capacity_bytes` raw LSB capacity fits
`capacity_bytes - 53` message bytes. The web app and CLI report this before you hit it.

## Research metrics

- **MSE** — mean squared error per RGB channel between cover and stego.
- **PSNR** — `10 * log10(255² / MSE)`, in dB. Higher is better; above ~40 dB is
  generally considered visually indistinguishable.
- **Capacity used** — payload bytes / raw LSB capacity. More payload means more
  modified pixels and a lower PSNR.

Measure your own files with `python -m steg.cli metrics cover.png stego.png`, or use
the values the web app records in `data/history.jsonl` (shown at `/research`).

### Technique comparison

The table below is **literature context, not measurements from this project**. LSB
numbers in your report should come from your own `metrics` runs and dashboard history.

| Technique | Capacity | Robustness | Typical visual quality | Complexity |
|---|---|---|---|---|
| LSB (this project) | High (~12.5% of raw bytes) | Very low — destroyed by JPEG/resize | High (> 50 dB at low fill) | Low |
| DCT / JPEG coefficients | Medium | Medium — survives JPEG to a degree | ~40–45 dB | High |
| Spread spectrum | Low | High — survives noise/cropping | ~40–45 dB | High |

Typical ranges adapted from Cheddad et al., *Digital image steganography: Survey and
analysis of current methods* (Signal Processing, 2010). Cite the original paper in your
report, not this README.

### Suggested results table for the report

Run 5–10 encodes with different message sizes and image sizes, then fill in:

| Cover size | Message bytes | Capacity used | MSE | PSNR (dB) | Decode OK |
|---|---|---|---|---|---|
| 1200x800 | 100 | 0.03% | … | … | yes |
| 1200x800 | 10,000 | 3.5% | … | … | yes |

## Security and limitations

- **Encryption is real, steganography is not stealthy against analysis.** The `STEG1`
  magic and the length field make the presence of a payload detectable. LSB embedding
  is also visible to chi-square/RS steganalysis. This project protects message
  *content*, not the fact that a message exists.
- **Fragile by design.** Any lossy transform destroys the payload. This is the main
  trade-off versus DCT-based methods.
- **Password strength matters.** PBKDF2 slows guessing, but a weak password is still
  weak. Use a long passphrase.
- **Admin token** is compared in constant time and stored in an HttpOnly, SameSite=Lax
  cookie. For anything beyond a local demo, set a strong `ADMIN_TOKEN`, serve over
  HTTPS, and add rate limiting to `/admin/login`.
- **Uploads** are capped (default 10 MB, configurable 1–50 MB) and parsed by Pillow;
  malformed files return a 400 instead of a traceback.
- Alpha channels are dropped (images are converted to RGB) and output is always PNG.

## Tests

```powershell
.\.venv\Scripts\python -m pytest -q
```

Covers round trips (text and binary), wrong passwords, capacity overflow, corrupt
files, flag validation/persistence, web encode/decode, upload limits, admin
authentication, feature gating, research history, and path-traversal-safe downloads.

## What to demonstrate in a viva

1. Encode a message, download the PNG, decode it, then show a wrong password failing.
2. Show PSNR dropping as the message grows (more capacity used).
3. Turn off the decode feature in `/admin` and show `/decode` blocked.
4. Try opening the stego PNG in an editor and re-saving as JPEG — decoding then fails,
   which motivates the robustness discussion.
5. Point at the payload format table and explain why AES-GCM gives confidentiality and
   integrity, and what LSB does not protect.
