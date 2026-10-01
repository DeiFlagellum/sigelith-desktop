> Published with Sigelith Desktop from the Sigelith monorepo
> (`apps/tsa/HANDOVER_SPEC.md`). Paths in this document are relative to that monorepo:
> `desktop/` is the root of this repository, and the web verifier
> (`apps/web/static/web/handover/verify.js`) runs at
> <https://sigelith.org/handover/verify/>.

# sigelith-handover-v1 — proof of delivery completed by a public stamp

**Status: DRAFT 0.3 (2026-09-28) — accepted by the owner; reference
implementation in progress. Frozen together with its test vectors.**
0.3 hardens 0.2 after a threat review and removes every server-side store:
Sigelith's server only stamps, exactly as it does today (§0.3). Decisions
behind this draft: `HANDOVER.md` sections 8–9 (in Polish). Once frozen,
identifiers and byte layouts in this document MUST NOT change; a new version
gets a new identifier.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in
RFC 2119.

---

## 0. What this is

A sender **S** gives a package (one or more files) to a recipient **R**.

- R can open the package only after signing an answer that accepts it.
- S's proof takes effect only at the moment R becomes able to open the
  package.
- That moment is public: an ordinary Sigelith stamp of the last key part.

Everything travels between the parties — by e-mail, a shared folder, a USB
stick. Sigelith's server does what it already does for everyone: it stamps
32-byte values in a public log. It never stores, forwards or sees a package,
an offer or an answer, and it cannot tell that a handover took place.

### 0.1 The flow

1. **Send.** S's application encrypts the package with a key made of two
   parts, **A** and **B**. Part A goes into the offer, sealed to R's key;
   part B stays with S. S signs the offer, stamps its digest and sends the
   package file to R by any channel.
2. **Check.** R's application opens the package file and checks everything it
   can — both cards, S's signature, the ciphertext hash, part A, the preview —
   before it asks the person anything.
3. **Answer.** R accepts (a signature approved with Windows Hello) or refuses.
   R's application stamps the answer's digest and gives R an answer file for
   S.
4. **Complete.** S's application reads the answer file and stamps part B in
   the Sigelith log. This stamp is the moment of delivery.
5. **Open.** R's application finds B in the public log by itself, assembles
   the key, decrypts and checks every hash.
6. **Prove.** Both applications keep an evidence package that anyone can
   verify without Sigelith.

With an exchange folder (§10.3) steps 1–5 run without anybody handling a
file.

### 0.2 Why it is fair

- **S hands no secret to anybody.** Only S holds B until it publishes it, and
  S's application publishes it only against R's signed acceptance.
- **R does not have to trust S.** The acceptance says it takes effect only
  when B is in the public log by a deadline. From that moment R can open the
  package: the log publishes every entry in real time and independent
  witnesses mirror it (§8). If S never publishes B, the acceptance never takes
  effect.
- **Everything else is arithmetic.** A wrong part A is caught before R
  answers; a wrong ciphertext, content or preview is provable afterwards by
  anyone, by recomputation (§11.3).

Fair exchange needs a third party. Here that party is only a public log with
time: it holds no secret, decides nothing and does not know it is being used.

### 0.3 Changes

| draft 0.2 | draft 0.3 | why |
|---|---|---|
| relay for ciphertext on Sigelith's server | none; the package travels between the parties | no user files on the server: no hosting of content, no abuse surface, no disk growth |
| mailbox and inbox on the server | none; answer file by any channel, or an exchange folder | the server carries no messages between users |
| encryption key P-256 (HPKE DHKEM) | hybrid ML-KEM-768 + X25519 | packages recorded today stay closed against a future quantum computer |
| one signature encoding | raw ECDSA or a WebAuthn assertion (§2.1) | Windows Hello and passkeys sign in WebAuthn form |
| answers could conflict | one answer per offer; an acceptance that took effect governs | R cannot void a delivery after reading it |
| any `valid_until` | bounded by the offer | no open-ended acceptances |
| answer stamp optional | R stamps it before releasing the answer (MUST) | a lower bound for the delivery time; long-term validity of signatures |
| binding shown by the application | binding record, signed and stamped (§3.4) | the binding claim demonstrably predates any dispute |
| plain file names | Unicode and file-type rules, Mark of the Web (§4.1) | spoofed names and malicious files |
| offer readable by the transport | sealed envelopes (§10.1) | e-mail and cloud providers see sizes only |

Draft 0.1 (key release by beat-key operators with IBE) was replaced by 0.2 on
the same day; see `HANDOVER.md` section 8.

### 0.4 Claims discipline

What a completed handover proves:

1. S's key signed an offer to R's key that commits to a package with
   container hash `H`; the stamp of the offer shows it existed at time T0.
2. R's key signed an acceptance of that offer, stating that R holds the
   ciphertext with the committed hash; the stamp of the acceptance shows it
   existed at time T1.
3. Part B was recorded in the Sigelith log at time T, after T1 and no later
   than the deadline in the acceptance. From T, R had everything needed to
   open the package: **T is the time of delivery**.
4. With the disclosed container, anyone can check which files the package
   held.

What it does NOT prove: that a person read or understood the content; who
stands behind a key (binding, §3.3, is a precondition, not a feature); that
the offer was sent or when it arrived; legal "delivery" in any jurisdiction
(§14). Silence proves nothing: an unanswered offer is a status, not evidence.
Copy MUST NOT use the name of any postal service ("Einschreiben", "list
polecony" etc.) nor the words "qualified" or "registered delivery".
Description: "proof of delivery signed with the recipient's key and completed
by a public stamp".

### 0.5 Privacy

- Sigelith's server receives only stamps: the offer digest, the answer
  digest, part B, the binding record digest and file hashes — 32-byte values
  indistinguishable from any other stamp.
- Transport channels (e-mail, cloud folders) see sealed envelopes and the
  ciphertext: sizes, never cards, names or content.
- After delivery, B is public forever. The content stays protected by part A
  (sealed to R's key with a post-quantum hybrid) and by the ciphertext staying
  with the parties.

---

## 1. Identifiers (new, `sigelith-` prefix)

| identifier | used for |
|---|---|
| `sigelith-handover-v1` | the `v` field of every object in this document |
| `sigelith-handover-v1\|card` | card signature and fingerprint |
| `sigelith-handover-v1\|binding` | binding record signature and digest |
| `sigelith-handover-v1\|offer` | offer signature and offer digest |
| `sigelith-handover-v1\|answer` | answer signature and answer digest |
| `sigelith-handover-v1\|part-a` | commitment to A |
| `sigelith-handover-v1\|seal-a` | HPKE `info` prefix when sealing A |
| `sigelith-handover-v1\|part-b` | commitment to B; search rule of §8 |
| `sigelith-handover-v1\|content-key` | HKDF `info`: content key |
| `sigelith-handover-v1\|container` | content `aad` |
| `sigelith-handover-v1\|preview-key` | HKDF `info`: preview key |
| `sigelith-handover-v1\|preview` | preview `aad` |
| `sigelith-handover-v1\|envelope` | HPKE `info` for transport envelopes |
| `sigelith-handover-evidence-v1` | evidence package (§11) |
| `sigelith-handover-defect-v1` | defect proof file (§11.3) |
| `sigelith-receipt-v1` | signed stamp receipt (§9.2), usable outside Handover |

Rules:

- Every domain string used in a hash or signature ends with `|`, and none is
  a prefix of another.
- The **digest** of a signed object is SHA-256 of exactly the bytes its
  signature covers, `domain ‖ JCS(object without sig)`. A digest never covers
  a signature, so signature malleability cannot change it.

The existing log identifiers (`beattime-entry-v1`, `beattime-checkpoint-v1`,
`beattime-proof-v1`) and the seal identifiers (`beattime-seal-v1`,
`beattime-beat-v1`) are untouched. Handover adds, it changes nothing.

## 2. Primitives

| primitive | specification |
|---|---|
| hash | SHA-256 |
| key derivation | HKDF-SHA256 (RFC 5869) |
| canonical JSON | JCS subset (RFC 8785) as in checkpoints (`apps/tsa/checkpoint.py`): sorted ASCII keys, no whitespace, integers only (|n| < 2^53), UTF-8. Parsers MUST reject duplicate keys, floats, NaN/Infinity, invalid UTF-8, lone surrogates, and input that is not already canonical; protocol objects are limited to 64 KiB and nesting depth 8. |
| signatures of S and R | ECDSA P-256 with SHA-256 (ES256); public keys validated (on the curve, not the point at infinity); encodings in §2.1 |
| encryption to a party | HPKE (RFC 9180), mode base, single-shot, KEM **ML-KEM-768 + X25519** hybrid (as in the IETF HPKE post-quantum draft and `cryptography` ≥ 50; code point frozen with the test vectors), KDF HKDF-SHA256, AEAD AES-256-GCM. Context is bound through `info` only (common libraries expose no `aad` for single-shot HPKE). Public key = ML-KEM-768 encapsulation key (1184 B) ‖ X25519 public key (32 B); ciphertext = `enc` (1120 B) ‖ AEAD output. |
| content | AES-256-GCM-STREAM exactly as `beattime-seal-v1` §5 (`SEAL.md`): 65536-byte segments, nonce = 7-byte prefix ‖ 4-byte big-endian counter ‖ 1-byte `last` flag, one 32-byte `aad` for all segments |
| preview | AES-256-GCM, 12-byte all-zero nonce (the key is used once) |
| binary fields | base64 standard with padding (as `beattime-seal-v1`), canonical only (decoding and re-encoding gives the same text); digests as lowercase hex |
| fingerprint text | Crockford Base32 |

### 2.1 Signature encodings

- **`es256`** — `sig` = 64-byte `r‖s` (IEEE P1363), base64, over the message
  `domain ‖ JCS(object without sig)`. `s` MUST be ≤ n/2 (low-S); software
  keys MUST use RFC 6979 (or hedged) nonces.
- **`es256-webauthn`** — for Windows Hello and passkeys, which sign only in
  WebAuthn form. `sig` = `{"authenticator_data": b64, "client_data_json": b64,
  "signature": b64 (DER, as produced)}`. The verifier checks: `type` in the
  client data is `webauthn.get`; `challenge` equals base64url(SHA-256(message));
  the rpIdHash equals SHA-256(`"sigelith.org"`); the flags show user presence
  **and user verification**; the ECDSA signature verifies over
  `authenticator_data ‖ SHA-256(client_data_json)`. `origin` is not checked:
  outside a browser it is whatever the calling application writes.

The card states which encoding its key uses. On Windows the application signs
through the WebAuthn platform authenticator (`webauthn.dll`, i.e. Windows
Hello). Tested on 2026-09-28 on Windows 11 (API version 9, Intel PTT TPM) with
`desktop/tools/winhello_probe.py`: a desktop application may create a key for
rpId `sigelith.org`, every signature carries user verification, and a card and
an acceptance signed this way pass these rules unchanged. Where Windows Hello
is unavailable, a software key (`es256`, `sig_storage: software`) is the
fallback, and the application says so.

### 2.2 Why these algorithms

- **Signatures: P-256.** The signing key SHOULD live in secure hardware and
  require user verification. Windows TPM 2.0, Android Keystore/StrongBox, Apple
  Secure Enclave and passkeys all offer P-256; none reliably offers Ed25519 or
  a post-quantum signature. No post-quantum signature is needed here: the
  offer and the answer are stamped, and the stamps are anchored in Bitcoin, so
  a signature forged by a future quantum computer could not be dated back to
  before such a computer existed (§13).
- **Encryption: hybrid ML-KEM-768 + X25519.** An encrypted package recorded
  today (in a mailbox, on a cloud drive) could be opened by a future quantum
  computer if part A were sealed with classical elliptic curves only. The
  hybrid stays closed while either half holds. Its private key cannot live in
  a TPM (TPMs do not do ML-KEM); it is a software key protected by the
  operating system's user profile (DPAPI on Windows). Malware running as the
  user could copy it — but such malware could equally read the decrypted
  files, so the protection lost is small and the protection gained is long.
  Handshake v2 keys (Ed25519, software) stay as they are.

## 3. Identity card ("Sigelith ID")

### 3.1 Object

```json
{
  "v": "sigelith-handover-v1",
  "type": "card",
  "sig_alg": "es256-webauthn",
  "sig_key": "<b64: P-256 public key, SEC1 uncompressed, 65 B>",
  "sig_storage": "hardware-uv",
  "enc_alg": "hpke-mlkem768x25519-hkdfsha256-aes256gcm",
  "enc_key": "<b64: hybrid public key>",
  "created": "2026-10-01T12:00:00Z",
  "sig": "<signature by sig_key over 'sigelith-handover-v1|card|' ‖ JCS(card without sig)>"
}
```

- Two keys, never one key for both jobs. `sig_key` signs with user
  verification (Windows Hello, biometrics) every time — an answer then means
  "a person approved", not "a process signed". `enc_key` has no user
  verification: the applications open envelopes automatically.
- `sig_storage` is `hardware-uv` (secure hardware with user verification) or
  `software`. It is **declared** by the owner's application and proven only
  with a platform attestation (a later version); verifiers show it as
  declared.
- The card carries no name, e-mail, address or label. A label is local to
  each address book.

This is every user's "own seed": the keys are generated on the device and
never leave it. The "code" a person enters is the Windows Hello PIN; what
comes out is a signature — nobody else can produce it, not even Sigelith, and
anybody can check it.

### 3.2 Fingerprint

```
fingerprint = SHA-256("sigelith-handover-v1|card|" ‖ JCS(card without sig))   # 32 B
shown as      Crockford Base32 of the first 20 bytes, 8 groups of 4
              e.g.  7F3A-K5MZ-8PQT-2WXR-9HJD-4NBC-6VYE-1KQM
```

The card itself (about 2 KB) travels as a file or text by any channel. The QR
code shows only the fingerprint, which keeps it small enough to scan from a
screen; the application checks the received card against the scanned
fingerprint.

### 3.3 Binding a card to a person — precondition

A signature proves "somebody holding this key", nothing more, until the card
is bound to a person in a way the person cannot later deny. Accepted
bindings, strongest first:

1. exchanged in person — fingerprint QR scanned face to face (NFC later);
2. named in a document signed by the person (the fingerprint in the text);
3. a Sigelith handshake between the two devices (v3, when available);
4. compared by voice on a phone or video call — at least the first **4
   groups** (80 bits) read aloud;
5. received over a channel the person already controls (e-mail) — weakest.

Why at least 4 groups: an attacker who substitutes a card can generate keys
until the part a person compares matches. Against 80 bits that is out of
reach; against a 6-digit code it takes seconds.

The application MUST show the binding level of every card, MUST NOT present
an unbound card as verified, and MUST show R the binding level of S's card
next to every offer.

### 3.4 Binding record

```json
{
  "v": "sigelith-handover-v1",
  "type": "binding",
  "by": "<hex fingerprint of the party recording the binding>",
  "card": "<hex fingerprint of the bound card>",
  "level": 1,
  "method": "qr-in-person",
  "date": "2026-10-01",
  "note": "…",
  "sig": "<signature by the recorder's sig_key over 'sigelith-handover-v1|binding|' ‖ JCS(record without sig)>"
}
```

`method` is one of `qr-in-person`, `signed-document`, `handshake`, `voice`,
`channel`. The application records it when a contact is verified and stamps
its digest (SHOULD). The stamp shows that the binding was claimed before the
delivery — not invented once a dispute began.

### 3.5 Card changes

When a known contact presents a different card, the application MUST warn and
MUST require a new binding before it sends to or accepts from that card. A
later version MAY let an old key vouch for its successor.

### 3.6 Hardware attestation (optional companion)

When the platform attests the signing key — Windows Hello returns TPM
attestation (format `tpm`, chain to "Microsoft TPM Root Certificate Authority
2014") — the application keeps it as a companion of the card:

```json
{
  "v": "sigelith-handover-v1",
  "type": "attestation",
  "card": "<hex fingerprint of the card>",
  "fmt": "tpm",
  "attestation_object": "<b64: CBOR attestation object returned at key creation>",
  "client_data_json": "<b64: client data of the key creation>"
}
```

- **Separate, not inside the card.** The card stays small, its format and
  fingerprint do not depend on the platform, and two cards made on the same
  computer cannot be linked through the attestation certificate unless their
  owner shows it.
- **Only at key creation.** The platform returns the attestation once, when
  the key is created; the application MUST save it then.
- **Shared by choice.** The application attaches it by default when its owner
  hands out the card and when the evidence of a handover is assembled; the
  owner can turn this off.
- **Verification.** Anybody can check it at any time, offline. A valid
  attestation turns `sig_storage: hardware-uv` from declared into proven, and
  the verifier names the TPM vendor and model from the certificate. Rules, in
  this order (each failure has the code in brackets):
  1. The companion has exactly the fields above, `v` and `type` as shown,
     `card` in hex and both blobs in canonical base64 [`attestation-structure`];
     `fmt` is `tpm` [`attestation-unsupported`]; `card` is the fingerprint of
     the card being checked [`attestation-card`].
  2. `client_data_json` is JSON (no duplicate keys) of type `webauthn.create`
     [`attestation-structure`].
  3. The attestation object is **strict CBOR** — definite and minimal lengths,
     no duplicate map keys, no tags, no floats, nothing after the item — with
     exactly `fmt` (equal to the companion's), `attStmt` and `authData`
     [`attestation-structure`].
  4. authenticatorData: rpIdHash = SHA-256(`"sigelith.org"`), flags UP, UV and
     AT, the credential is a COSE ES256 P-256 key with exactly the keys 1, 3,
     -1, -2, -3, an extension map only when the ED flag is set, nothing after
     it [`attestation-structure`]; the credential equals the card's `sig_key`
     [`attestation-card`].
  5. `attStmt` has exactly `ver` (`"2.0"`), `alg`, `x5c` (1–5 certificates),
     `sig`, `certInfo`, `pubArea` [`attestation-structure`]; `alg` is -65535
     (RS1 — what most TPMs under Windows use), -257 (RS256) or -7 (ES256)
     [`attestation-unsupported`].
  6. `pubArea` (TPMT_PUBLIC) is an ECC NIST P-256 key whose point equals the
     credential, nameAlg SHA-1/256/384/512, nothing after it; `certInfo`
     (TPMS_ATTEST) has magic TPM_GENERATED, type ATTEST_CERTIFY, `extraData` =
     H(authenticatorData ‖ SHA-256(client_data_json)) with the hash of `alg`,
     and `attested.name` = nameAlg ‖ H_nameAlg(pubArea), nothing after it;
     `sig` over `certInfo` verifies with the AIK key of the kind `alg` names
     [`attestation-statement`].
  7. The AIK certificate (`x5c[0]`): X.509 v3, empty subject, a critical
     subject alternative name naming the TPM manufacturer, model and version
     (2.23.133.2.1/2/3), extended key usage including tcg-kp-AIKCertificate
     (2.23.133.8.3), basic constraints present with CA = false, the FIDO AAGUID
     extension (if present) equal to the authenticator's, no unknown critical
     extension [`attestation-certificate`].
  8. The chain: every intermediate is a CA without unknown critical
     extensions; names link byte for byte; certificate signatures are RSA
     PKCS#1 v1.5 with SHA-256/384/512 or ECDSA with SHA-256/384 on
     P-256/384/521 — nothing else, SHA-1 never; it ends in a **pinned** root
     (today only "Microsoft TPM Root Certificate Authority 2014",
     SHA-256 `870c7a35ceab3d59979f2c6a524042d404cb71518004350925fb2ced79a999da`);
     every certificate and the root were valid at the card's `created`
     [`attestation-chain`]. Revocation is not checked: the proof must verify
     offline, for decades.

A **card file** carries a card and, by its owner's choice, its attestation:

```
card file = "SIGELITH-CARD-1" 0x0A ‖ JCS({"card": <card>, "attestation": <companion or null>})
```

The card holds only public keys, so the file has no envelope. The evidence
package (§11.1) lists the attestations of its two cards in `attestations`
(at most two). An attestation adds a line to the report; its absence or
failure never changes the verdict.

## 4. Package

### 4.1 Container (plaintext)

```
container = JCS(manifest) ‖ 0x0A ‖ file_1 bytes ‖ … ‖ file_n bytes
manifest  = {
  "v": "sigelith-handover-v1",
  "type": "manifest",
  "salt": "<b64: 16 random bytes>",
  "title": "Aneks do umowy najmu",
  "note": "…",
  "files": [{"name": "aneks.pdf", "size": 123456, "sha256": "<hex>", "type": "application/pdf"}, …]
}
H = SHA-256(container)
```

- One package MAY carry several files (v1: at most 1000); one answer covers
  all of them. `title` ≤ 200 and `note` ≤ 2000 characters, both optional.
- The `salt` makes `H` unguessable even when the files are known, so `H` may
  appear in the offer.
- JCS escapes line breaks inside strings, so the first `0x0A` ends the
  manifest. The byte count after it MUST equal the sum of `size`.

Text and file-name rules — writers MUST produce, readers MUST reject
otherwise:

- all strings in NFC; no control characters (a line feed is allowed in
  `note` only); no bidirectional marks,
  embeddings, overrides or isolates (U+200E, U+200F, U+202A–U+202E,
  U+2066–U+2069);
- file names: none of the characters Windows forbids (`<>:"/\|?*` — `:` would
  also address a hidden NTFS stream), not `.` or `..`, no Windows reserved
  device name (`CON`, `NUL`, `COM1` …, also with an extension), no trailing dot
  or space; unique ignoring case (compared after full Unicode uppercase
  mapping, as case-insensitive file systems compare names).

Readers MUST show full names with extensions, MUST NOT open received files
automatically, MUST mark saved files with the Mark of the Web
(`Zone.Identifier`) so that Windows treats them as coming from the internet,
and SHOULD warn before opening executable or macro-capable types.

### 4.2 Keys and commitments

```
nonce = 16 random bytes                     # public, in the offer
A     = 32 random bytes                     # travels to R, sealed
B     = 32 random bytes                     # stays with S until completion
K     = HKDF-SHA256(ikm = A ‖ B, salt = nonce, info = "sigelith-handover-v1|content-key|", L = 32)
c_A   = SHA-256("sigelith-handover-v1|part-a|" ‖ A)
c_B   = SHA-256("sigelith-handover-v1|part-b|" ‖ B)
```

`K` depends on both parts: A alone or B alone reveals nothing. Because `c_A`
and `c_B` fix A and B, the offer fixes `K` — the ciphertext decrypts to at
most one plaintext, whoever tries. `nonce`, A and B MUST be fresh for every
offer.

### 4.3 Content encryption

```
nonce_prefix = 7 random bytes
aad          = SHA-256("sigelith-handover-v1|container|" ‖ nonce)
C            = AES-256-GCM-STREAM(K, nonce_prefix, container, aad)     # §2
```

### 4.4 Preview

What R sees before answering. It is encrypted with a key derived from A, so
only R can read it — and R can later prove what it said by revealing A.

```
preview = {"title": "…", "note": "…", "sender_name": "…",
           "files": [{"name": "…", "size": 123, "type": "…"}, …],   # at most 50 entries
           "file_count": 3, "total_size": 4187234}
k_p     = HKDF-SHA256(ikm = A, salt = nonce, info = "sigelith-handover-v1|preview-key|", L = 32)
p_ct    = AES-256-GCM(k_p, iv = 12 zero bytes, pt = JCS(preview),
                      aad = "sigelith-handover-v1|preview|")
```

The rules of §4.1 apply to the preview. `sender_name` is what S calls itself;
R's application shows its own label for a known card and marks the
self-chosen name as such. After opening, R's application MUST compare the
preview with the manifest and flag any difference.

## 5. Offer

```json
{
  "v": "sigelith-handover-v1",
  "type": "offer",
  "nonce": "<b64 16 B>",
  "created": "2026-10-01T12:00:00Z",
  "expires": "2026-10-31T12:00:00Z",
  "complete_within": 1209600,
  "sender_card": { "…full card, §3.1…" },
  "recipient_card": { "…full card, §3.1…" },
  "content": {"sha256": "<hex H>", "size": 4187100},
  "ciphertext": {"aead": "AES-256-GCM-STREAM", "segment": 65536,
                 "nonce_prefix": "<b64 7 B>", "sha256": "<hex>", "size": 4187234},
  "part_a": {"commit": "<hex c_A>",
             "sealed": "<b64: HPKE(recipient enc_key, info='sigelith-handover-v1|seal-a|' ‖ nonce, pt=A)>"},
  "part_b": {"commit": "<hex c_B>"},
  "preview": "<b64 p_ct>",
  "sig": "<signature by sender sig_key over 'sigelith-handover-v1|offer|' ‖ JCS(offer without sig)>"
}
```

```
offer_digest = SHA-256("sigelith-handover-v1|offer|" ‖ JCS(offer without sig))
```

- `created` MUST NOT be more than 5 minutes after the log's time when R
  checks it.
- `expires` — R answers before it. Default 30 days after `created`, at most
  90.
- `complete_within` — seconds S promises to need, at most, between receiving
  an acceptance and publishing B. Default 1209600 (14 days — the answer may
  come by e-mail while S is away); allowed 3600 to 2592000 (1 hour to 30
  days).

## 6. Answer: acceptance or refusal

```json
{
  "v": "sigelith-handover-v1",
  "type": "answer",
  "decision": "accept",
  "offer": "<hex offer_digest>",
  "ciphertext_sha256": "<hex, recomputed from the bytes R holds>",
  "valid_until": "2026-10-15T13:00:00Z",
  "signed_at": "2026-10-01T13:00:00Z",
  "sig": "<signature by recipient sig_key over 'sigelith-handover-v1|answer|' ‖ JCS(answer without sig)>"
}
```

```
answer_digest = SHA-256("sigelith-handover-v1|answer|" ‖ JCS(answer without sig))
```

- `decision` is `accept` or `refuse`. A refusal has no `ciphertext_sha256`
  and no `valid_until`.
- `valid_until` (D) = the log's current time (e.g. the HTTP `Date` header of
  a log response) + `offer.complete_within`. It MUST NOT be later than
  `offer.expires` + `offer.complete_within`; an answer that breaks this is
  invalid.
- `signed_at` is R's clock, informational only.
- Signing requires user verification (§3.1).
- R's application MUST stamp `answer_digest` **before** it releases the
  answer to anybody (T1). S's application stamps it on receipt if it is not
  yet in the log (stamping is idempotent: the first stamp keeps its time).
- **One answer per offer.** R's application MUST NOT sign a second answer for
  the same offer. If two answers exist anyway, an acceptance that took effect
  (§0.4 point 3) governs; otherwise the refusal counts. A hidden refusal
  cannot undo a delivery R has already been able to read.

Meaning — the application shows this text (translated) before the person
approves, and verifiers render it the same way:

- **accept:** "I confirm that I have received package ⟨offer⟩ from ⟨sender
  card⟩ and that I hold its encrypted content. This confirmation takes effect
  at the moment the key part committed in the offer is recorded in the
  Sigelith log, provided that happens no later than ⟨D⟩. Otherwise it has no
  effect."
- **refuse:** "I refuse to accept package ⟨offer⟩ from ⟨sender card⟩."

The signed data is the structured object; the text is its fixed reading, not
a free field, so nobody can make a person sign a different sentence. The
wording is subject to legal review (§14).

## 7. Procedure

### 7.1 S sends

1. S chooses R's card from the address book (its binding level is shown),
   the files, a title and a note.
2. S's application stamps the SHA-256 of every file (SHOULD — "the file has
   its own stamp").
3. Build the manifest (fresh `salt`), the container and `H`. Draw `nonce`, A,
   B and `nonce_prefix`; derive `K`; encrypt → `C`; hash it.
4. Build and encrypt the preview; seal A to R's `enc_key`; compute `c_A` and
   `c_B`.
5. Build the offer; S approves the signature (Windows Hello). Compute
   `offer_digest` and stamp it (SHOULD) → T0.
6. Write the package file (§10.1) and send it by any channel, or put it in
   the exchange folder (§10.3).
7. Keep B (protected by the operating system), A, `nonce`, the files and the
   pending state until completion or expiry.

### 7.2 R checks — automatically, before asking the person

1. Open the envelope with R's `enc_key` (an application with several cards
   tries each). Check both embedded cards (signatures, fingerprints), the
   offer signature, that `recipient_card` is R's own card, `created`,
   `expires` (log time) and `complete_within`.
2. Open `part_a.sealed` → A; check `c_A`. Derive `k_p`; decrypt the preview;
   apply §4.1. Any failure: the offer is defective and is never shown as a
   package to accept.
3. Check the ciphertext's size and SHA-256 against `offer.ciphertext`.
4. Look up the stamp of `offer_digest` (T0), if any.
5. Show the sender: a known card with its label and binding level, or an
   unknown card with its fingerprint and a warning.
6. Only now show the package — title, note, files with extensions, size,
   sender and binding, T0 — with **Accept**, **Refuse** and **Later**.

### 7.3 R answers

- **Accept:** set `valid_until` (§6); the person approves (Windows Hello);
  stamp `answer_digest` (MUST, before anything else); write the answer file
  (§10.1) and send it back by the channel the package came through, or put it
  in the exchange folder. Keep A, `C`, the offer and the answer.
- **Refuse:** sign the refusal, stamp its digest, write the answer file,
  delete A and `C`.
- **Later / nothing:** after `expires` the application drops the offer.

### 7.4 S completes — automatically when the answer arrives

The answer arrives as a file S opens, as text S pastes, or in the exchange
folder the application watches.

1. Open the envelope; check the answer's signature with `recipient_card` of
   the pending offer whose digest is `answer.offer`, and its structure.
2. **Refusal:** keep it as evidence, make sure its digest is stamped, mark the
   offer refused. B is never published.
3. **Acceptance:** check `ciphertext_sha256` against the offer and the bound
   on `valid_until`. Check with the log's time that `valid_until` is at least
   **1 hour** away; otherwise do not publish: the delivery did not happen,
   and S may send a new offer (§7.6). Never publish B for an offer that was
   refused.
4. Make sure `answer_digest` is stamped (T1).
5. **Publish B:** `POST /api/proof/stamp {"digest": hex(B)}`. The recorded
   time T MUST be later than T1 and no later than `valid_until`; keep the
   response and its receipt (§9.2).
6. Build the evidence package (§11.1).

If publishing fails, retry until 1 hour before `valid_until`. If it never
succeeds, the delivery did not happen; the application tells S that B may
have reached the log operator without being recorded (§13, residual risk 4).

### 7.5 R opens — automatically

1. R's application watches the log (§8) for B while it runs, and on every
   start while an acceptance is pending. S does not need to send anything.
2. Found: check `c_B`; T = the time of B's entry.
3. Derive `K`, decrypt `C` segment by segment (a tag failure stops
   everything, as in `beattime-seal-v1`), check `H`, parse the manifest, check
   every size and hash, compare with the preview, apply §4.1.
4. Save the files (Mark of the Web, no automatic opening); keep R's evidence
   copy (§11.2).
5. Any failure in step 3: build the defect proof (§11.3) and tell R that the
   package is defective and the acceptance has no effect.

### 7.6 Expiry

- `expires` passes with no answer: S's application shows "not collected".
  This is a status, not evidence (§0.4).
- An acceptance whose `valid_until` passes without B in the log has no
  effect. S may send a new offer (new `nonce`, A and B).

## 8. Finding B in the log

- The log publishes every entry in real time:
  `GET /api/proof/entries?from=<seq>` (up to 1000 entries per page).
  Independent witnesses mirror it.
- Starting from the last `seq` known when it answered, R's application checks
  each new entry: `SHA-256("sigelith-handover-v1|part-b|" ‖ bytes(digest)) == c_B`.
- The weekly dumps (`/dumps/`, the weekly GitHub release, the quarterly
  Zenodo deposit) keep the same entries permanently.

R therefore never depends on S, on a transport or on Sigelith's goodwill to
obtain B once it is recorded.

## 9. Sigelith's server: stamps only

### 9.1 Stamp (existing, unchanged)

`POST /api/proof/stamp {"digest": "<64 hex>"}`. File hashes, the offer
digest, the answer digest, the binding record digest and part B are ordinary
digests; the log does not know, and cannot tell, what any of them is.

### 9.2 Stamp receipt — `sigelith-receipt-v1` (all stamps)

Every response of `POST /api/proof/stamp` and every "found" response of
`GET /api/proof/verify` carries a field `receipt` (implemented in
`apps/tsa/receipt.py`):

```json
{
  "v": "sigelith-receipt-v1",
  "seq": 1234,
  "digest": "<hex>",
  "utc": "2026-10-01T12:34:56.123456Z",
  "chain_hash": "<hex>",
  "key": "<b64 Ed25519 log key>",
  "sig": "<b64: Ed25519(log key, 'sigelith-receipt-v1|' ‖ JCS(receipt without sig))>"
}
```

A signed receipt for an entry that the log does not hold at `seq` with that
`chain_hash` is provable misbehaviour — like an SCT in Certificate
Transparency, or a signed RFC 3161 token. The field is additive; existing
clients (including the mobile contract) ignore it.

- **Key.** The log's current Ed25519 key — the one that signs weekly roots and
  checkpoints — through the same guard: a retired key, or a key other than the
  one the server expects, signs nothing, and the response then has no
  `receipt`. The domains `sigelith-receipt-v1|`, `beattime-proof-v1|` (roots)
  and `beattime-checkpoint-v1|` (checkpoints) are disjoint: no signature of
  one format reads as another.
- **Deterministic.** Ed25519 signatures are deterministic, so one entry always
  has one receipt; it can be issued on every read, without state.
- **Format.** `utc` always has six fraction digits and `Z` (the form of the
  public entries endpoint); `key` and `sig` are canonical base64 (32 and 64
  bytes).
- **Verification** (codes in brackets): exactly the fields above, `v`, a
  positive `seq`, hex digests, canonical `utc`, canonical base64
  [`receipt-structure`]; `key` among the verifier's **pinned current** log keys
  — a retired key is never accepted [`receipt-key`]; the signature
  [`receipt-signature`]; when checked for a known digest, the same `digest`
  [`receipt-digest`]. In an evidence package a log proof counts only with its
  receipt, and only if its `utc`, `seq` and `chain_hash` equal the receipt's
  (§12.1).

### 9.3 What the server never does

It stores no package, ciphertext, offer, answer, card or contact. It forwards
no message between users, sends no notification, keeps no accounts. It never
receives part A, a private key, the content key, the plaintext, file names,
titles, notes or bindings. Part B reaches it only when S publishes it —
public by design.

## 10. Transport — between the parties

### 10.1 Files and envelopes

```
envelope     = HPKE(addressee enc_key, info = "sigelith-handover-v1|envelope|", pt = JCS(object))
package file = "SIGELITH-HANDOVER-1" 0x0A ‖ JCS({"kind": "package", "envelope_size": n, "ciphertext_size": m}) 0x0A ‖ envelope(offer) ‖ C
answer file  = "SIGELITH-HANDOVER-1" 0x0A ‖ JCS({"kind": "answer", "envelope_size": n}) 0x0A ‖ envelope(answer)
answer text  = "sigelith:answer:" ‖ base64url(answer file)
```

- The envelope hides cards, names and the preview from every channel; the
  header names no party. An application with several cards tries each.
- The signed objects inside are the same objects that go into the evidence;
  the envelope only protects them in transit.
- The answer text fits in an e-mail body or a messenger.

### 10.2 Channels

Any channel the parties already use: e-mail (the application MAY open the
default mail client with the file attached; web-mail users attach it or
paste the answer text), messengers, a USB stick, in person. For large
packages the ciphertext MAY travel separately (S's own cloud link); R's
application checks it against the offer like any other copy.

### 10.3 Exchange folder

Any folder both parties sync — OneDrive, Google Drive, Dropbox, Nextcloud,
Syncthing, a network share. S's application writes package files into it;
R's application watches it, opens packages addressed to its cards and writes
answer files back; S's application watches for answers and completes by
itself. The folder's provider sees envelopes and ciphertext only, and it is
the parties' provider, chosen and contracted by them.

### 10.4 Later

Direct transfer between the applications over Tor onion services (both
online at once; blocked on many company networks) — a later version.

## 11. Evidence

### 11.1 Sender's evidence package

One ZIP file, identifier `sigelith-handover-evidence-v1`:

- `evidence.json` (canonical JSON) with exactly: `v`, `offer`, `answer`,
  `part_b` (hex, or null without an acceptance), `binding` (or null),
  `attestations` (§3.6, at most two, may be empty), `log` (digest → the
  `/api/proof/verify` payload, as received, with its receipt) for the offer
  digest, the answer digest, part B, the binding record digest and the files'
  own stamps, and `disclosure` (`"container.bin"` or null);
- `container.bin` (optional disclosure): the exact container bytes — lets
  anyone recompute `H` and read the files.

Nothing else goes into the ZIP. Next to it — never inside — the application
MAY save a report (PDF) for a reader who runs no verifier: every check of §12
with its result, in the user's language, the SHA-256 of the ZIP it describes
and how to verify that ZIP independently. The report is not evidence; the
ZIP is.

Every log proof MUST carry its receipt (§9.2): a proof without one does not
count (§12.1). `GET /api/proof/verify` issues the receipt for every entry, old
ones included, so the application refreshes such a proof before it builds the
package. Applications SHOULD also check log proofs against checkpoints taken
from an independent copy (GitHub, Internet Archive, Zenodo, a witness) and
show the result — an additional level, not a condition of the verdict: a fresh
package has its receipts at once, a checkpoint only after a day. The
application SHOULD refresh the package once the week has closed and its
Bitcoin anchor is confirmed, so that it verifies without Sigelith's server. Sigelith keeps no copy of any
evidence: the application MUST tell the user to keep the file safe.

Readers of an evidence ZIP MUST reject absolute paths, `..` segments and
duplicate names (no writing outside the chosen folder).

### 11.2 Recipient's copy

R's application keeps the same package from its side. It proves when the
package became readable — useful to R when deadlines run from delivery: T
cannot be earlier than R's own stamped acceptance.

### 11.3 Defect proof

`{offer, A, B, C}`. Anybody recomputes `c_A`, `c_B` and the ciphertext hash,
derives `K` and decrypts. A tag failure, a wrong `H`, a manifest that does not
match its files, or a preview that differs from the manifest shows the offer
was defective: **the acceptance has no effect**. A false claim fails the same
recomputation, so R cannot void a good delivery.

R's application keeps A, B and `C` of a package that failed step 3 of §7.5 and
writes them, on request, as one ZIP file, identifier
`sigelith-handover-defect-v1`, read under the rules of §11.1 (only the two
names below, nothing extracted):

- `defect.json` (canonical JSON) with exactly: `v`, `offer`, `part_a` and
  `part_b` (both hex);
- `ciphertext.bin`: the ciphertext exactly as received (stored, not
  compressed).

Verdicts: **offer defective** (with the code of the first failure),
**not defective** (the package opens with the committed parts and matches its
preview — the claim is unfounded), or **invalid claim** (A, B or `C` are not
the ones the offer commits to, the offer does not verify, or `defect.json`
breaks this format — the file proves nothing about the offer). A file that
is not a ZIP of exactly these two names is rejected before any verdict.

The file discloses A and B: whoever holds it can read the preview and the
content as far as it decrypts. The application MUST say so before it saves
the file. The web verifier reads files up to 512 MiB of content; Sigelith
Desktop has no such limit (ZIP64).

## 12. Verification

The verifier (the web page `/handover/verify/`, Sigelith Desktop) reports each
check separately. Every time it uses — T0, T1, T, the binding's stamp — comes
from a log proof accepted under §12.1:

1. Cards: structure, signatures (§2.1), fingerprints, key validation.
2. Binding record: signature by the recorder, level, and whether its stamp
   predates the offer.
3. Offer: structure, limits, §4.1 rules on what is disclosed, signature by
   `sender_card`.
4. Answer: signature by `recipient_card` of that offer; `answer.offer`
   equals `offer_digest`; `valid_until` within its bound; its stamp T1.
5. Acceptance: `ciphertext_sha256` equals `offer.ciphertext.sha256`; `c_B`
   matches `part_b`; B is in the log at time T; T1 < T ≤ `valid_until`.
6. Conflicting answers: resolved by §6. The other party's package of the same
   offer adds its answer and its log proofs; two accepted proofs that give
   one digest different times are two signed receipts contradicting each
   other — evidence against the log, and the time does not count.
7. Attestations (§3.6): each is matched to the sender's or the recipient's
   card and verified; a valid one is reported as "TPM <vendor> <model>". They
   never change the verdict.
8. Disclosure (optional): `H` of the container; manifest sizes and hashes;
   the files' own stamps.

Verdict: **delivered at T**, **refused** (at the time of the refusal's
stamp), **not completed**, or **offer defective** (§11.3). Both verifiers
tell the two files apart by their names inside the ZIP (`evidence.json` or
`defect.json`) and read a defect proof by §11.3 — arithmetic only, without
the log.

### 12.1 Accepting a time from a log proof

A log proof in the package is the text of a `GET /api/proof/verify` answer.
Nobody signed that text except for its receipt, so whoever brings the package
could change any other field. A digest has a time only if `log[hex(digest)]`
passes, in this order (codes in brackets):

1. It is a string holding a JSON object without duplicate keys or fractions,
   with `found: true` and `digest` equal to the digest [`log-structure`].
2. It carries `receipt` [`receipt-missing`], valid under §9.2 for that digest
   with the verifier's pinned current log keys [`receipt-*`], and its `utc`,
   `seq` and `chain_hash` equal the receipt's [`log-mismatch`].
3. `week` is a real ISO week (`YYYY-Www`) that contains the receipt's `utc`,
   from 5 minutes before its start (a stamp racing the week's closing lands in
   the next open week) to its end [`log-week`].
4. `week_root` and `inclusion_proof` come together or not at all; when
   present, the path — at most 64 steps of exactly `{"side": "L"|"R", "hash"}`
   — folds the digest to the root: leaf `SHA-256(0x00 ‖ digest)`, node
   `SHA-256(0x01 ‖ left ‖ right)` [`log-structure`, `log-inclusion`].
5. `root_signature`, when present, needs `week_root`; its `public_key` is a
   pinned current log key [`log-key`] and it verifies as Ed25519 over
   `beattime-proof-v1|<week>|<week_root>` [`log-signature`].
6. `week_closed`, when present, is a boolean; a closed week has its root,
   path and signature [`log-incomplete`].

A field set to `null` counts as absent. Every other field (`beat`, `time`,
`checkpoint`, anchors…) is ignored. The accepted time is the receipt's `utc`.
The proof's level is reported beside the time and never changes the verdict:
`receipt`; `signed` (rules 4 and 5 passed); `anchored` (signed, and the log
declares a Bitcoin anchor or a confirmed bank anchor of this root — a
declaration the verifier does not check).

## 13. Security analysis

| # | who | tries to | result |
|---|---|---|---|
| 1 | R | read without accepting | impossible: needs B, which only S holds until publication |
| 2 | R | accept, read, then void the delivery with a hidden refusal | the acceptance that took effect governs (§6) |
| 3 | R | accept with a deadline S cannot meet | S publishes only with at least 1 hour left |
| 4 | R | accept with an open-ended deadline | invalid: `valid_until` is bounded by the offer |
| 5 | R | deny the acceptance | signed with user verification and stamped at T1 |
| 6 | R | claim a defect that is not there | the recomputation of §11.3 fails |
| 7 | S | send a package R cannot open (bad part A, bad preview) | caught before R is asked; nothing is signed |
| 8 | S | send a bad ciphertext or content | publicly provable defect; the acceptance has no effect |
| 9 | S | use the acceptance without publishing B | no effect without B in the log by D |
| 10 | S | publish B after D | no effect |
| 11 | S | make the delivery look earlier than it was | T cannot precede R's stamped acceptance; the log cannot be rewritten (hash chain, witnesses, Bitcoin anchors) |
| 12 | S | mislead with the preview or file names | provable by revealing A; §4.1 rules reject spoofing characters |
| 13 | S | deliver malware | received files are untrusted: Mark of the Web, no automatic opening, warnings |
| 14 | anybody | substitute a card in transit | binding levels, fingerprint comparison of at least 80 bits, card-change warnings, stamped binding records |
| 15 | e-mail or cloud provider | read or profile | sealed envelopes: sizes only; the content needs A |
| 16 | a future quantum computer | open packages recorded today | part A sealed with ML-KEM-768 + X25519 |
| 17 | a future quantum computer | forge old signatures | offer and answer digests stamped and anchored before such a machine exists |
| 18 | Sigelith | read, forge or change a package | never receives A, a private key or content |
| 19 | Sigelith | hide B from R | public entries endpoint, independent witnesses, weekly dumps |
| 20 | Sigelith (log) with R | drop S's stamp of B and pass B to R | residual risk 4 |
| 21 | anybody | use Sigelith's server to store or distribute files | nothing to use: it stores 32-byte stamps only |

Residual risks — present in every design of this kind; each MUST be stated in
the product's documentation:

1. **Binding.** Who stands behind a card is outside the protocol (§3.3).
2. **Endpoint compromise.** A compromised device can show one thing and sign
   another; malware running as the user can use the keys and read the files.
   Hardware keys stop key theft, not a lying screen.
3. **Implementation.** The rules of §1, §2, §4.1 and §11.1 (canonical JSON,
   signatures, names, archives) are where real systems fail — including the
   Windows Hello signing path (§2.1), to be verified on real hardware before
   freezing.
4. **The log records what it receives** — the same trust as any stamp. With
   receipts (§9.2) a false promise is provable; an outright refusal to record
   is visible to S (no entry) but not provable.
5. **Liveness.** S's application must receive the answer and act: at once
   with an exchange folder, otherwise when S opens the answer. A delay never
   falsifies the result.
6. **B is public forever.** After delivery the content is protected by part
   A (post-quantum hybrid, sealed to R) and by the ciphertext staying with the
   parties.
7. **Hardware claims need attestation.** `sig_storage` is declared, not
   proven, unless the card's owner shares its attestation (§3.6). Windows
   Hello provides TPM attestation; other platforms may not.
8. **Evidence custody.** Sigelith keeps no copy; a lost evidence package is
   a lost proof (the log holds digests only).

## 14. Legal notes (non-normative)

- **What Sigelith operates for Handover:** the existing stamp log, unchanged.
  It does not store, forward or learn about packages, offers or answers, sends
  no notifications and keeps no accounts. The parties transmit the data
  themselves, over channels they choose.
- **What Sigelith supplies:** software that runs on the parties' devices,
  open source (Apache-2.0), with a verifier anybody can run.
- **Questions for counsel before launch:**
  1. Handover as designed is not an electronic registered delivery service
     (eIDAS art. 3(36)) provided by Sigelith — confirm.
  2. Is the stamp log itself a (non-qualified) trust service — electronic
     time stamps — and what follows (eIDAS art. 19a; NIS2, which covers trust
     service providers regardless of size)? This concerns the log as it runs
     today.
  3. Cyber Resilience Act: reporting of actively exploited vulnerabilities
     applies from 11 September 2026 to products made available in the course
     of a commercial activity — do Sigelith's applications qualify?
  4. Wording and effect of the acceptance: when a declaration reaches its
     addressee (BGB § 130, KC art. 61); weight of a non-qualified time stamp
     in court (eIDAS art. 41).
  5. Terms of use and the limitation of liability for a free feature.
  6. Product claims (§0.4).

## 15. Test vectors

A reference implementation in Python (Sigelith Desktop, `desktop/beatstamp/handover/`;
the server needs none, it only stamps) generates the vectors with
`desktop/tools/handover_vectors.py`, frozen in
`desktop/tests/vectors/handover-v1.json`: card
(both signature encodings), binding record, container, keys and commitments,
preview, sealed part A (with a fixed HPKE ephemeral key for the vectors
only), offer, envelopes and files, acceptance, refusal, the §8 search rule, an
evidence package and defect proofs — the claims and their
`sigelith-handover-defect-v1` files (`defect_files`: a defective, a good and
a false one, and one broken file per rule of §11.3) — plus a deliberately
broken variant for every check of §7.2, §7.4 and §12. A second, independent implementation — the
JavaScript verifier `apps/web/static/web/handover/verify.js` (verification only:
it never opens an HPKE envelope) — MUST pass the same vectors
(`robocze/test_handover_js.py`, also run by the desktop test suite). Cases that
need no HPKE randomness are added with `handover_vectors.py --extend`, without
touching the frozen bytes.

Attestation vectors (§3.6) use a synthetic chain under a **test** root
("Sigelith TEST TPM Root", passed to verifiers explicitly; the pinned
production root must reject it): valid RS1, RS256 and root-in-x5c cases plus
one broken case per rule of §3.6. A real Windows Hello attestation is never
committed — its certificate identifies a computer. It is checked by hand with
`desktop/tools/winhello_probe.py --save <file>` and both verifiers (verified
on 2026-09-28: Intel PTT, RS1, Microsoft TPM Root Certificate Authority 2014).

Receipt and log-proof vectors (§9.2, §12.1) are signed with a **test** log
key (seed in the vectors; the pinned production key must reject them): one
case per rule of §12.1, the ISO-week edge cases (week 53, week 00, year 0000)
and two evidence packages carrying real `/api/proof/verify` answers — a
delivery with disclosed content and a refusal (the recipient's copy), which
together test the conflict rule of §6. The web verifier page is tested on
the page Django actually renders, with those packages
(`robocze/handover_js/test-dom.mjs`).

## 16. Open points for the owner

Decided 2026-09-28: no server-side store at all; hybrid post-quantum
encryption keys from v1; signed stamp receipts for all stamps in v1; defaults
`expires` 30 days and `complete_within` 14 days. Still open:

5. Legal review (§14) before public launch.
6. Hardware attestation. Decided 2026-09-28: the Windows Hello path is the
   WebAuthn platform authenticator (§2.1), and its TPM attestation travels as
   a separate, optional companion of the card (§3.6), not inside it.
   Implementation follows the second (JavaScript) verifier.
7. Later versions: direct transfer over Tor, card succession, revocation,
   platform attestation, binding to a national eID.
