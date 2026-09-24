# BeatStamp

A Windows desktop client for the public **proof-of-existence** log run at
[beattime.live](https://beattime.live). It gives a file a timestamp you can
later use to show that the document existed at a given moment and has not
changed since.

**Your file never leaves the computer.** The only thing that goes out is the
64-character SHA-256 hash computed locally — not the name, not the contents,
not the size.

---

## What a timestamp here proves — and what it does not

It proves **existence at a point in time** and **integrity**: this exact
sequence of bytes existed by then, and it is unchanged. That is all, and the
app says so in the same words.

It does **not** prove authorship, ownership, or that anything in the document
is true. It is not a qualified electronic timestamp under eIDAS.

## How a proof matures

A fresh stamp is not yet worth much; it becomes evidence over about a week,
in three steps the app shows honestly rather than rounding up to "verified":

1. **Recorded** — the hash is in the public append-only log with its @beat and
   UTC time, in a hash chain with its neighbours.
2. **Sealed** — at the end of the ISO week every hash of that week is combined
   into a Merkle root, which is signed with an Ed25519 key.
3. **Anchored** — that weekly root is published into Bitcoin through
   [OpenTimestamps](https://opentimestamps.org) and against an independent bank
   reference. From then on the timestamp no longer rests on anyone's word.

## Verifying without trusting the server

This is the point of the program, so it does the checking itself rather than
asking the server whether everything is fine:

- **It recomputes the inclusion path.** From your file's hash and the sibling
  hashes it walks up the Merkle tree (RFC 6962) and compares the result with
  the published weekly root. A proof that does not recompute is rejected.
- **It verifies the Ed25519 signature offline**, against a list of public keys
  compiled into the program — not against whatever key the server sends. A
  signature made with a **retired** key can never raise a proof above
  "recorded", and the app says why.
- **It checks the time.** A stamp whose timestamp falls outside the week its
  root covers is refused, however well-formed the rest is.
- **It reads `.beatproof` files offline.** Everything needed to check a proof
  fits in one file; verification needs no network and no account.

The server that issues these proofs is not open source. That is precisely why
the client is: the proof is designed so that you do not have to believe either
of them. Everything above can be recomputed from public data — the weekly
roots are on [beattime.live/proof](https://beattime.live/proof/), and the
format is specified at [beattime.live/spec](https://beattime.live/spec/).

## Privacy

No account, no telemetry, no analytics, no advertising identifiers. The app
talks to one host, and only to send a hash and read back a proof. Your history
is a local file you can read, copy or delete.

## Install

Windows 10 or 11, 64-bit. Download the release, unpack it, run `BeatStamp.exe`
— there is no installer and nothing is written outside your user profile.

Your data lives in `%USERPROFILE%\BeatStamp` (history, settings, log). That
location is deliberate: `Documents` is protected by Windows ransomware
protection, which blocks unknown programs from writing there, and a program
that stores evidence cannot depend on whether Windows feels like trusting the
build you downloaded today.

## Run and build from source

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python beatstamp_main.py
```

Build a standalone package (PyInstaller, one directory):

```powershell
pip install -r requirements-dev.txt
.\build.ps1
```

Tests (465 of them, no network required):

```powershell
python -m unittest discover -s tests
```

A built copy can check itself:

```
BeatStamp.exe --selftest --offline
```

Earlier versions used Polish flag names. `--samokontrola` and `--bez-sieci`
still work and always will: once a program is published, its command-line
flags are a public interface, and quietly dropping one breaks somebody's
script for no good reason.

## Interface languages

English, Polish and German. The app follows the system language and can be
switched in Settings.

## Coming from TimeVaultSecure?

TimeVaultSecure (timevaultsecure.com) is an earlier product by the same
author, and BeatStamp takes over the history it left behind. Your old entries
are imported and kept, but they are labelled **TVS archive** and they stay at
that level — they are not silently promoted to look like the new proofs.

The reason is in the old design: that client's proof rested on trusting the
server's answer, and its `signature` field was a concatenation that nothing
could verify. Those records still say what you stamped and when you stamped
it, which is worth keeping; what they cannot do is prove it to a third party.
New stamps can, which is the whole difference.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE).

The program bundles Qt via **PySide6 under LGPLv3**, plus OpenSSL, CPython,
reportlab and others. [NOTICE](NOTICE) lists every component with its licence
and tells you where to get the sources of the LGPL libraries; the full licence
texts are in [`licenses/`](licenses/). The notices are generated from the built
package, not from a dependency list, so a library that ships is a library that
is listed.

One module was deliberately left out: **Qt Virtual Keyboard**, which is
available only commercially or under GPLv3. An on-screen keyboard was not
worth changing the licence of the whole program, and a test fails the build if
it ever reappears in a package.

## Reporting a problem

Security issues: see
[beattime.live/.well-known/security.txt](https://beattime.live/.well-known/security.txt).
Anything else: open an issue here.

---

BeatStamp is the desktop side of [BeatTime](https://beattime.live) — universal
`.beat` time, 1000 beats a day, anchored to UTC, with no timezones.
