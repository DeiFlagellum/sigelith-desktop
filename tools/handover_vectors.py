"""
Generuje wektory testowe `sigelith-handover-v1` (HANDOVER_SPEC.md §15).

Uruchamiane RAZ, przy zmianie formatu:

    .venv\\Scripts\\python.exe tools\\handover_vectors.py

Wynik — tests/vectors/handover-v1.json — jest ZAMRAZANY w repozytorium
i sprawdzany przez tests/test_handover.py oraz przez drugi, niezalezny
weryfikator (JS). HPKE jest losowe z natury (klucz efemeryczny), wiec ponowne
uruchomienie da inne bajty kopert i czesci A — dlatego wektory sie zamraza,
a nie odtwarza. Wszystko inne (klucze, czasy, pliki, czesci A/B) wyprowadzamy
deterministycznie z etykiet, zeby przypadki byly czytelne.

Przypadki zepsute budujemy tak, jak zbudowalby je atakujacy: najczesciej
POPRAWNIE PODPISANE (inaczej test sprawdzalby tylko podpis, a nie regule).
"""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from beatstamp.handover import (  # noqa: E402
    answer as A_, identity as I, jcs, package as P, primitives as X, stream, transport as T)

OUT = Path(__file__).resolve().parent.parent / 'tests' / 'vectors' / 'handover-v1.json'
UTC = timezone.utc


def ts(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


class Det:
    """Deterministyczny strumien bajtow z etykiety (SHA-256 w trybie licznika)."""

    def __init__(self, label: str) -> None:
        self._label = label.encode()
        self._counter = 0

    def __call__(self, n: int) -> bytes:
        out = b''
        while len(out) < n:
            out += hashlib.sha256(self._label + self._counter.to_bytes(8, 'big')).digest()
            self._counter += 1
        return out[:n]


def p256(label: str) -> ec.EllipticCurvePrivateKey:
    scalar = int.from_bytes(hashlib.sha256(label.encode()).digest(), 'big') % (X.P256_N - 1) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def enc(label: str) -> X.EncKey:
    return X.EncKey(hashlib.sha512(f'{label} mlkem'.encode()).digest(),
                    hashlib.sha256(f'{label} x25519'.encode()).digest())


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def resign(obj: dict, dom: bytes, signer) -> dict:
    obj = {k: v for k, v in obj.items() if k != 'sig'}
    obj['sig'] = signer.sign(X.signed_message(dom, obj))
    return obj


def main() -> None:
    sender_sig = I.SoftwareSigner(p256('vector sender sig'))
    recipient_sig = I.SoftwareWebAuthnSigner(p256('vector recipient sig'), storage='hardware-uv')
    mallory_sig = I.SoftwareSigner(p256('vector mallory sig'))
    sender_enc, recipient_enc, mallory_enc = enc('vector sender'), enc('vector recipient'), enc('vector mallory')

    card_time = ts('2026-09-30T10:00:00')
    sender_card = I.make_card(sender_sig, sender_enc.public_bytes, card_time)
    recipient_card = I.make_card(recipient_sig, recipient_enc.public_bytes, card_time)
    mallory_card = I.make_card(mallory_sig, mallory_enc.public_bytes, card_time)
    S, R, M = (I.read_card(c) for c in (sender_card, recipient_card, mallory_card))
    binding = I.make_binding(sender_sig, S, R, 'voice', date(2026, 9, 30),
                             'Odcisk porownany przez telefon')

    files = [
        ('aneks-umowy.pdf', b'%PDF-1.7\n' + Det('file pdf')(300), 'application/pdf'),
        ('Załącznik — opis.txt', 'Zażółć gęślą jaźń.\n'.encode() * 4, 'text/plain'),
        ('dane.bin', Det('file bin')(65_600), 'application/octet-stream'),
    ]
    inputs = [P.InputFile(n, d, t) for n, d, t in files]
    created = ts('2026-10-01T12:00:00')
    ct = io.BytesIO()
    out = P.create_offer(signer=sender_sig, sender_card=sender_card, recipient_card=recipient_card,
                         files=inputs, ciphertext_out=ct, created=created,
                         title='Aneks do umowy najmu', note='Proszę o potwierdzenie.\nPozdrawiam',
                         sender_name='Anna Nadawca', rng=Det('vector offer rng'))
    offer, info, parts = out.offer, out.info, out.parts
    ciphertext = ct.getvalue()
    container = io.BytesIO()
    P.decrypt_package(info, parts.a, parts.b, io.BytesIO(ciphertext), container)
    container = container.getvalue()
    preview = P.open_preview(info, parts.a)

    answer_time = ts('2026-10-02T09:30:00')
    accept = A_.make_answer(recipient_sig, info, 'accept', log_now=answer_time,
                            ciphertext_sha256=info.ciphertext_sha256)
    refuse = A_.make_answer(recipient_sig, info, 'refuse', log_now=answer_time)
    acc, ref = A_.read_answer(accept, info), A_.read_answer(refuse, info)
    bnd = I.read_binding(binding, S, R)

    log = {
        bnd.digest.hex(): '2026-09-30T18:00:00.000001Z',
        info.digest.hex(): '2026-10-01T12:00:05.123456Z',
        acc.digest.hex(): '2026-10-02T09:30:02.000001Z',
        ref.digest.hex(): '2026-10-02T09:31:00.000001Z',
        parts.b.hex(): '2026-10-02T10:15:00.5Z',
    }

    package_file = io.BytesIO()
    T.write_package_file(package_file, R.enc_key, offer, io.BytesIO(ciphertext), len(ciphertext))
    package_prefix = package_file.getvalue()[:-len(ciphertext)]
    answer_file = T.write_answer_file(S.enc_key, accept)

    # --- przypadki zepsute ---------------------------------------------------
    broken: list[dict] = []

    def case(name: str, kind: str, expect: str, **data) -> None:
        broken.append({'name': name, 'kind': kind, 'expect': expect, **data})

    c = dict(sender_card, created='2026-09-30T10:00:01Z')
    case('card-created-changed', 'card', 'card-signature', card=c)
    sig = base64.b64decode(sender_card['sig'])
    s = int.from_bytes(sig[32:], 'big')
    case('card-high-s', 'card', 'card-signature',
         card=dict(sender_card, sig=b64(sig[:32] + (X.P256_N - s).to_bytes(32, 'big'))))
    case('card-extra-field', 'card', 'card-structure', card=dict(sender_card, name='Anna'))
    key = sender_card['sig_key']
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    alias = key[:-2] + alphabet[alphabet.index(key[-2]) ^ 1] + key[-1]
    case('card-noncanonical-base64', 'card', 'card-structure', card=dict(sender_card, sig_key=alias))
    no_uv = I.SoftwareWebAuthnSigner(p256('vector recipient sig'), storage='hardware-uv',
                                     user_verified=False)
    case('card-webauthn-without-uv', 'card', 'card-signature',
         card=resign(recipient_card, X.D_CARD, no_uv))
    wrong_rp = {k: v for k, v in recipient_card.items() if k != 'sig'}
    wrong_rp['sig'] = X.webauthn_sign(p256('vector recipient sig'),
                                      X.signed_message(X.D_CARD, wrong_rp), rp_id='evil.example')
    case('card-webauthn-wrong-rp', 'card', 'card-signature', card=wrong_rp)

    case('offer-tampered', 'offer', 'offer-signature', offer=dict(offer, complete_within=3600))
    case('offer-signed-by-another-key', 'offer', 'offer-signature',
         offer=resign(offer, X.D_OFFER, mallory_sig))
    case('offer-complete-within-too-short', 'offer', 'offer-limits',
         offer=resign(dict(offer, complete_within=60), X.D_OFFER, sender_sig))
    bad = copy.deepcopy(offer)
    bad['ciphertext']['size'] += 16
    case('offer-ciphertext-size-inconsistent', 'offer', 'offer-limits',
         offer=resign(bad, X.D_OFFER, sender_sig))
    case('offer-same-card-twice', 'offer', 'offer-limits',
         offer=resign(dict(offer, recipient_card=sender_card), X.D_OFFER, sender_sig))
    bad = copy.deepcopy(offer)
    bad['part_a']['commit'] = hashlib.sha256(b'another A').hexdigest()
    case('offer-part-a-commit-wrong', 'offer-open', 'part-a-commit',
         offer=resign(bad, X.D_OFFER, sender_sig))
    bad = copy.deepcopy(offer)
    spoof = dict(preview, title='Faktura ‮FDP.exe')
    bad['preview'] = b64(X.preview_seal(P.preview_key(parts.a, parts.nonce), jcs.dumps(spoof)))
    case('offer-preview-bidi-override', 'offer-open', 'preview-rules',
         offer=resign(bad, X.D_OFFER, sender_sig))
    for_mallory = P.create_offer(signer=sender_sig, sender_card=sender_card, recipient_card=mallory_card,
                                 files=[P.InputFile('x.txt', b'x', 'text/plain')],
                                 ciphertext_out=io.BytesIO(), created=created,
                                 rng=Det('vector mallory offer'))
    case('offer-for-another-card', 'offer-open', 'offer-not-mine', offer=for_mallory.offer)

    case('answer-signed-by-sender', 'answer', 'answer-signature',
         answer=resign(accept, X.D_ANSWER, sender_sig))
    late = dict(accept, valid_until=X.format_ts(info.answer_bound + timedelta(seconds=1)))
    case('answer-valid-until-beyond-offer', 'answer', 'answer-deadline',
         answer=resign(late, X.D_ANSWER, recipient_sig))
    case('answer-for-another-offer', 'answer', 'answer-offer',
         answer=resign(dict(accept, offer=hashlib.sha256(b'other').hexdigest()),
                       X.D_ANSWER, recipient_sig))
    case('answer-other-ciphertext', 'answer', 'answer-ciphertext',
         answer=resign(dict(accept, ciphertext_sha256=hashlib.sha256(b'x').hexdigest()),
                       X.D_ANSWER, recipient_sig))
    case('answer-without-user-verification', 'answer', 'answer-signature',
         answer=resign(accept, X.D_ANSWER, no_uv))
    case('refusal-with-deadline', 'answer', 'answer-structure',
         answer=resign(dict(refuse, valid_until=accept['valid_until']), X.D_ANSWER, recipient_sig))

    # scenariusze dowodu: ten sam pakiet, inne czasy albo inne B
    def scenario(name: str, verdict: str, *, log_patch=None, part_b=parts.b.hex(), answer=accept,
                 extra=(), failing=()):
        patched = dict(log, **(log_patch or {}))
        broken.append({'name': name, 'kind': 'evidence', 'expect': verdict,
                       'answer': answer, 'part_b': part_b, 'extra_answers': list(extra),
                       'log': patched, 'failing': list(failing)})

    scenario('evidence-delivered', 'delivered')
    scenario('evidence-part-b-after-deadline', 'not-completed',
             log_patch={parts.b.hex(): '2026-10-16T09:30:00.000001Z'}, failing=['deadline'])
    scenario('evidence-part-b-before-acceptance-stamp', 'not-completed',
             log_patch={parts.b.hex(): '2026-10-02T09:30:01Z'}, failing=['order'])
    scenario('evidence-without-part-b', 'not-completed', part_b=None, failing=['part-b'])
    scenario('evidence-wrong-part-b', 'not-completed',
             part_b=hashlib.sha256(b'not B').hexdigest(), failing=['part-b-commit'])
    scenario('evidence-refused', 'refused', answer=refuse, part_b=None)
    scenario('evidence-hidden-refusal-does-not-undo-delivery', 'delivered',
             extra=[refuse], log_patch={ref.digest.hex(): '2026-10-02T09:29:00Z'})

    # zarzuty wady: mala paczka, zeby wektor nie rosl
    small = [P.InputFile('pismo.txt', 'Wypowiedzenie umowy.\n'.encode(), 'text/plain')]

    def defect_case(name: str, expect: str, o, ciphertext_bytes: bytes, a: bytes, b: bytes):
        broken.append({'name': name, 'kind': 'defect', 'expect': expect, 'offer': o,
                       'a': b64(a), 'b': b.hex(), 'ciphertext': b64(ciphertext_bytes)})

    # dobra paczka
    ctb = io.BytesIO()
    g = P.create_offer(signer=sender_sig, sender_card=sender_card, recipient_card=recipient_card,
                       files=small, ciphertext_out=ctb, created=created, title='Pismo',
                       rng=Det('vector defect good'))
    defect_case('defect-claim-against-good-package', 'not-defective', g.offer, ctb.getvalue(),
                g.parts.a, g.parts.b)
    defect_case('defect-claim-with-wrong-b', 'invalid-claim', g.offer, ctb.getvalue(),
                g.parts.a, hashlib.sha256(b'wrong').digest())

    # nadawca szyfruje innym kluczem niz K(A, B) — oferta poprawnie podpisana
    rng = Det('vector defect wrong key')
    wp = P.Parts.generate(rng)
    manifest = P.build_manifest(small, title='Pismo', note='', salt=rng(16))
    source = P._ContainerSource(manifest, small)
    wrong_ct = io.BytesIO()
    stream.encrypt(hashlib.sha256(b'not the committed key').digest(), wp.nonce_prefix,
                   P.container_aad(wp.nonce), source, wrong_ct)
    pv = P.build_preview(manifest, '')
    wo = {'v': X.VERSION, 'type': 'offer', 'nonce': b64(wp.nonce),
          'created': X.format_ts(created), 'expires': X.format_ts(created + P.DEFAULT_EXPIRES),
          'complete_within': P.DEFAULT_COMPLETE_WITHIN,
          'sender_card': sender_card, 'recipient_card': recipient_card,
          'content': {'sha256': source.hash.hexdigest(), 'size': source.size},
          'ciphertext': {'aead': P.AEAD_NAME, 'segment': P.SEGMENT,
                         'nonce_prefix': b64(wp.nonce_prefix),
                         'sha256': hashlib.sha256(wrong_ct.getvalue()).hexdigest(),
                         'size': len(wrong_ct.getvalue())},
          'part_a': {'commit': P.commit_a(wp.a).hex(),
                     'sealed': b64(X.hpke_seal(R.enc_key, wp.a, X.D_SEAL_A + wp.nonce))},
          'part_b': {'commit': P.commit_b(wp.b).hex()},
          'preview': b64(X.preview_seal(P.preview_key(wp.a, wp.nonce), jcs.dumps(pv)))}
    wo = resign(wo, X.D_OFFER, sender_sig)
    defect_case('defect-ciphertext-under-another-key', 'defective:ciphertext-tag', wo,
                wrong_ct.getvalue(), wp.a, wp.b)

    # podglad inny niz tresc
    rng = Det('vector defect preview')
    ctp = io.BytesIO()
    po = P.create_offer(signer=sender_sig, sender_card=sender_card, recipient_card=recipient_card,
                        files=small, ciphertext_out=ctp, created=created, title='Pismo', rng=rng)
    lying = dict(P.open_preview(po.info, po.parts.a), title='Zaproszenie na urodziny')
    lo = dict(po.offer, preview=b64(X.preview_seal(P.preview_key(po.parts.a, po.parts.nonce),
                                                   jcs.dumps(lying))))
    defect_case('defect-preview-differs-from-content', 'defective:preview-mismatch',
                resign(lo, X.D_OFFER, sender_sig), ctp.getvalue(), po.parts.a, po.parts.b)

    # --- JCS i reguly tekstu -------------------------------------------------
    jcs_cases = [
        (b'{"a":1,"b":"x"}', None), (b'{"a":1,"a":2}', 'json-duplicate'),
        (b'{"a":1.0}', 'json-number'), (b'{"a": 1}', 'json-canonical'),
        (b'{"b":1,"a":2}', 'json-canonical'), (b'{"a":"\\ud800"}', 'json-string'),
        (b'{"a":NaN}', 'json-number'), (b'{"a":9007199254740992}', 'json-number'),
        (b'{"a":"\xff"}', 'json-utf8'), (b'{"a":"\\u00e9"}', 'json-canonical'),
        ('{"a":"é"}'.encode(), None),
    ]
    names = [
        ('raport.pdf', None), ('Zażółć gęślą jaźń.txt', None),
        ('Faktura ‮FDP.exe', 'file-name'), ('CON.txt', 'file-name'), ('lpt1', 'file-name'),
        ('a:b.txt', 'file-name'), ('plik.', 'file-name'), ('plik ', 'file-name'),
        ('katalog/plik.txt', 'file-name'), ('..', 'file-name'),
        ('Zażółć.txt', 'file-name'), ('tab\there.txt', 'file-name'),
    ]

    doc = {
        'spec': 'sigelith-handover-v1, HANDOVER_SPEC.md DRAFT 0.3',
        'generated_by': 'desktop/tools/handover_vectors.py (frozen: HPKE output is random)',
        'note': 'Test keys only. Never use them for anything real.',
        'keys': {
            'sender': {'sig_private': b64(sender_sig.to_bytes()), 'enc_private': b64(sender_enc.to_bytes())},
            'recipient': {'sig_private': b64(recipient_sig.to_bytes()),
                          'enc_private': b64(recipient_enc.to_bytes())},
            'mallory': {'sig_private': b64(mallory_sig.to_bytes()), 'enc_private': b64(mallory_enc.to_bytes())},
        },
        'cards': {'sender': sender_card, 'recipient': recipient_card, 'mallory': mallory_card},
        'fingerprints': {n: {'hex': c.fingerprint_hex, 'text': c.fingerprint_text}
                         for n, c in (('sender', S), ('recipient', R), ('mallory', M))},
        'binding': binding, 'binding_digest': bnd.digest.hex(),
        'files': [{'name': n, 'type': t, 'data': b64(d)} for n, d, t in files],
        'manifest': out.manifest, 'container': b64(container),
        'content_sha256': info.content_sha256.hex(),
        'parts': {'nonce': b64(parts.nonce), 'a': b64(parts.a), 'b': parts.b.hex(),
                  'nonce_prefix': b64(parts.nonce_prefix),
                  'content_key': P.content_key(parts.a, parts.b, parts.nonce).hex(),
                  'preview_key': P.preview_key(parts.a, parts.nonce).hex(),
                  'commit_a': info.commit_a.hex(), 'commit_b': info.commit_b.hex(),
                  'container_aad': P.container_aad(parts.nonce).hex()},
        'preview': preview,
        'ciphertext': b64(ciphertext), 'ciphertext_sha256': info.ciphertext_sha256.hex(),
        'offer': offer, 'offer_digest': info.digest.hex(),
        'accept': accept, 'accept_digest': acc.digest.hex(),
        'refuse': refuse, 'refuse_digest': ref.digest.hex(),
        'log': log,
        'package_file_prefix': b64(package_prefix),
        'answer_file': b64(answer_file), 'answer_text': T.answer_text(answer_file),
        'log_entries': [{'seq': 1, 'digest': hashlib.sha256(b'someone else').hexdigest()},
                        {'seq': 2, 'digest': parts.b.hex()}],
        'jcs': [{'bytes': b64(raw), 'error': err} for raw, err in jcs_cases],
        'file_names': [{'name': n, 'error': err} for n, err in names],
        'cases': broken,
    }
    doc['evidence_zip'] = evidence_zip(doc)
    extend(doc)
    write(doc)
    print(f'{OUT}  {OUT.stat().st_size // 1024} KiB, {len(doc["cases"])} cases')


def _der_int(n: int, pad: bool = False) -> bytes:
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if b[0] & 0x80:
        b = b'\x00' + b
    if pad:
        b = b'\x00' + b                       # zbedne zero: DER niekanoniczny
    return b'\x02' + bytes([len(b)]) + b


def _webauthn_sig(key: ec.EllipticCurvePrivateKey, message: bytes, *, client: bytes | None = None,
                  pad_r: bool = False) -> dict:
    """Asercja WebAuthn z mozliwoscia popsucia `clientDataJSON` albo DER."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    auth = X.sha256(X.RP_ID.encode()) + bytes([X.FLAG_UP | X.FLAG_UV]) + (1).to_bytes(4, 'big')
    if client is None:
        client = json.dumps({'type': 'webauthn.get', 'challenge': X.webauthn_challenge(message),
                             'origin': 'https://sigelith.org', 'crossOrigin': False},
                            separators=(',', ':')).encode()
    der = key.sign(auth + X.sha256(client), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    if pad_r:
        r, s = decode_dss_signature(der)
        body = _der_int(r, pad=True) + _der_int(s)
        der = b'\x30' + bytes([len(body)]) + body
    return {'authenticator_data': b64(auth), 'client_data_json': b64(client), 'signature': b64(der)}


def _container(files: list[tuple[str, bytes]], *, sha_override: dict | None = None,
               trailing: bytes = b'') -> bytes:
    """Kontener skladany RECZNIE (z pominieciem walidacji) — do przypadkow zepsutych."""
    entries = [{'name': n, 'size': len(d), 'sha256': (sha_override or {}).get(n, hashlib.sha256(d).hexdigest()),
                'type': 'text/plain'} for n, d in files]
    manifest = {'v': X.VERSION, 'type': 'manifest', 'salt': b64(bytes(16)), 'title': '', 'note': '',
                'files': entries}
    return jcs.dumps(manifest) + b'\n' + b''.join(d for _, d in files) + trailing


def extend(doc: dict) -> None:
    """Przypadki zgodnosci miedzy implementacjami — deterministyczne, bez HPKE.

    Tu najlatwiej o rozjazd Python/JS: JSON.parse bierze OSTATNI z powtorzonych
    kluczy, `length` w JS liczy jednostki UTF-16, DER bywa przyjmowany luzno,
    a klucz ML-KEM trzeba sprawdzac recznie. Idempotentne: pomija juz obecne.
    """
    recipient_key = p256('vector recipient sig')
    cases: list[dict] = []
    card = dict(doc['cards']['sender'])
    enc_key = bytearray(base64.b64decode(card['enc_key']))
    enc_key[0], enc_key[1] = 0xFF, (enc_key[1] & 0xF0) | 0x0F      # wspolczynnik 4095 >= q
    cases.append({'name': 'card-mlkem-coefficient-out-of-range', 'kind': 'card',
                  'expect': 'card-structure', 'card': dict(card, enc_key=b64(bytes(enc_key)))})
    cases.append({'name': 'card-sig-key-not-on-curve', 'kind': 'card', 'expect': 'card-structure',
                  'card': dict(card, sig_key=b64(b'\x04' + bytes(64)))})
    rc = {k: v for k, v in doc['cards']['recipient'].items() if k != 'sig'}
    message = X.signed_message(X.D_CARD, rc)
    cases.append({'name': 'card-webauthn-non-canonical-der', 'kind': 'card', 'expect': 'card-signature',
                  'card': dict(rc, sig=_webauthn_sig(recipient_key, message, pad_r=True))})
    good = X.webauthn_challenge(message)
    dup = ('{"type":"webauthn.get","challenge":"' + 'A' * 43 + '","challenge":"' + good
           + '","origin":"https://sigelith.org","crossOrigin":false}').encode()
    cases.append({'name': 'card-webauthn-duplicate-challenge', 'kind': 'card', 'expect': 'card-signature',
                  'card': dict(rc, sig=_webauthn_sig(recipient_key, message, client=dup))})
    for name, files, kw, expect in (
            ('container-duplicate-names-after-uppercase',
             [('Straße.txt', b'a'), ('STRASSE.txt', b'b')], {}, 'manifest-rules'),
            ('container-trailing-bytes', [('a.txt', b'a')], {'trailing': b'x'}, 'container-size'),
            ('container-file-hash-wrong', [('a.txt', b'a')],
             {'sha_override': {'a.txt': hashlib.sha256(b'b').hexdigest()}}, 'file-hash')):
        cases.append({'name': name, 'kind': 'container', 'expect': expect,
                      'container': b64(_container(files, **kw))})
    known = {c['name'] for c in doc['cases']}
    doc['cases'] += [c for c in cases if c['name'] not in known]

    jcs_extra = [(b'{"__proto__":1}', None), (b'{"a":1}\n', 'json-canonical'),
                 (b'\xef\xbb\xbf{"a":1}', 'json-syntax'), (b'{"a":01}', 'json-syntax'),
                 (b'{"a":-0}', 'json-canonical'), (b'[1,2,]', 'json-syntax'),
                 (b'{"a":"\x01"}', 'json-syntax'), (b'{"a":1e2}', 'json-number'),
                 (b'{"a":"\\ud83d\\ude00"}', 'json-canonical')]
    known = {c['bytes'] for c in doc['jcs']}
    doc['jcs'] += [{'bytes': b64(r), 'error': e} for r, e in jcs_extra if b64(r) not in known]

    names_extra = [('\U0001F600' * 255, None), ('\U0001F600' * 256, 'file-name'),
                   ('Straße.txt', None), ('con .txt', 'file-name'), ('COM¹.txt', 'file-name')]
    known = {c['name'] for c in doc['file_names']}
    doc['file_names'] += [{'name': n, 'error': e} for n, e in names_extra if n not in known]

    if 'attestation' not in doc:
        doc['attestation'] = attestation_section(doc)
    doc['receipt'] = receipt_section(doc)          # deterministyczne: zawsze te same bajty
    doc['log_proofs'] = log_proofs_section(doc)    # jw. (Ed25519, drzewa tygodni)
    doc['evidence_signed'] = evidence_signed_section(doc)
    doc['defect_files'] = defect_files_section(doc)


def defect_files_section(doc: dict) -> list[dict]:
    """Pliki `sigelith-handover-defect-v1` (§11.3) z zamrozonych przypadkow `defect`
    i ich zepsute odmiany. Deterministyczne (ZIP bez czasow, stala kolejnosc).

    `expect`: `error:<kod>` — plik odrzuca juz odczyt; `<werdykt>[:<kod>]` —
    werdykt i kod pierwszej kontroli.
    """
    import zipfile

    from beatstamp.handover import evidence as E

    defects = {c['name']: c for c in doc['cases'] if c['kind'] == 'defect'}
    out = []
    for name in ('defect-preview-differs-from-content', 'defect-ciphertext-under-another-key',
                 'defect-claim-against-good-package', 'defect-claim-with-wrong-b'):
        c = defects[name]
        ciphertext = base64.b64decode(c['ciphertext'])
        buf = io.BytesIO()
        E.write_defect(buf, offer=c['offer'], part_a=base64.b64decode(c['a']),
                       part_b=bytes.fromhex(c['b']), ciphertext=io.BytesIO(ciphertext),
                       size=len(ciphertext))
        out.append({'name': 'file-' + name, 'zip': b64(buf.getvalue()), 'expect': c['expect']})

    def raw_zip(members: list[tuple[str, bytes]]) -> str:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            for member, data in members:
                info = zipfile.ZipInfo(member, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = (zipfile.ZIP_STORED if member == E.CIPHERTEXT_BIN
                                      else zipfile.ZIP_DEFLATED)
                z.writestr(info, data)
        return b64(buf.getvalue())

    base = defects['defect-preview-differs-from-content']
    good = {'v': E.DEFECT_V, 'offer': base['offer'],
            'part_a': base64.b64decode(base['a']).hex(), 'part_b': base['b']}
    ct = base64.b64decode(base['ciphertext'])
    for name, members, expect in (
            ('file-extra-member', [(E.DEFECT_JSON, jcs.dumps(good)), (E.CIPHERTEXT_BIN, ct),
                                   ('report.pdf', b'%PDF-1.7')], 'error:defect-archive'),
            ('file-without-ciphertext', [(E.DEFECT_JSON, jcs.dumps(good))],
             'error:defect-archive'),
            ('file-json-not-canonical', [(E.DEFECT_JSON, json.dumps(good).encode()),
                                         (E.CIPHERTEXT_BIN, ct)], 'error:defect-structure'),
            ('file-extra-field', [(E.DEFECT_JSON, jcs.dumps(dict(good, note='x'))),
                                  (E.CIPHERTEXT_BIN, ct)], 'invalid-claim:defect-structure'),
            ('file-evidence-version', [(E.DEFECT_JSON, jcs.dumps(dict(good, v=E.EVIDENCE_V))),
                                       (E.CIPHERTEXT_BIN, ct)], 'invalid-claim:defect-structure'),
            ('file-part-a-base64', [(E.DEFECT_JSON, jcs.dumps(dict(good, part_a=base['a']))),
                                    (E.CIPHERTEXT_BIN, ct)], 'invalid-claim:defect-structure'),
            ('file-ciphertext-truncated', [(E.DEFECT_JSON, jcs.dumps(good)),
                                           (E.CIPHERTEXT_BIN, ct[:-1])],
             'invalid-claim:defect-claim')):
        out.append({'name': name, 'zip': raw_zip(members), 'expect': expect})
    return out


def receipt_section(doc: dict) -> dict:
    """Kwity `sigelith-receipt-v1` (spec §9.2) na TESTOWYM kluczu dziennika.

    Ed25519 jest deterministyczny, wiec sekcja wychodzi zawsze taka sama.
    Test serwera (apps/tsa/tests_receipt.py) wydaje kwit tym samym kluczem
    dla tego samego wpisu i porownuje BAJTY — serwer, Python i JS musza sie
    zgadzac co do formatu, nie tylko co do podpisu.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from beatstamp.handover import receipt as R

    seed = hashlib.sha256(b'vector log key').digest()
    key = Ed25519PrivateKey.from_private_bytes(seed)
    other = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'vector other log key').digest())
    pub = b64(key.public_key().public_bytes_raw())
    other_pub = b64(other.public_key().public_bytes_raw())

    def signed(body: dict, signer=key) -> dict:
        body = {k: v for k, v in body.items() if k != 'sig'}
        return dict(body, sig=b64(signer.sign(R.message(body))))

    base = {'v': 'sigelith-receipt-v1', 'seq': 3, 'digest': doc['offer_digest'],
            'utc': '2026-10-01T12:00:05.123456Z',
            'chain_hash': hashlib.sha256(b'vector chain 3').hexdigest(), 'key': pub}
    valid = signed(base)
    flipped = bytearray(base64.b64decode(valid['sig']))
    flipped[0] ^= 1
    cases = [
        ('receipt-valid', valid, None, 'ok'),
        ('receipt-field-changed', dict(valid, utc='2026-10-01T12:00:05.123457Z'), None, 'receipt-signature'),
        ('receipt-signature-flipped', dict(valid, sig=b64(bytes(flipped))), None, 'receipt-signature'),
        ('receipt-signed-by-another-key', signed(dict(base, key=other_pub), other), None, 'receipt-key'),
        ('receipt-extra-field', dict(valid, week='2026-W40'), None, 'receipt-structure'),
        ('receipt-wrong-version', signed(dict(base, v='beattime-receipt-v1')), None, 'receipt-structure'),
        ('receipt-utc-not-canonical', signed(dict(base, utc='2026-10-01T12:00:05Z')), None, 'receipt-structure'),
        ('receipt-seq-zero', signed(dict(base, seq=0)), None, 'receipt-structure'),
        ('receipt-for-another-digest', valid, hashlib.sha256(b'x').hexdigest(), 'receipt-digest'),
    ]
    return {'log_key': pub, 'log_key_seed': b64(seed), 'other_key': other_pub,
            'note': 'TEST log key only — the production key is pinned in desktop/beatstamp/keys.py',
            'cases': [{'name': n, 'receipt': r, 'expected_digest': d, 'expect': e}
                      for n, r, d, e in cases]}


# --- dowody dziennika w pakiecie (spec §12.1) ----------------------------------

def _log_keys():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'vector log key').digest())
    other = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'vector other log key').digest())
    return key, other


def _leaf(digest_hex: str) -> bytes:
    return hashlib.sha256(b'\x00' + bytes.fromhex(digest_hex)).digest()


def _tree(digests: list[str]) -> tuple[str, dict[str, list[dict]]]:
    """Korzen i sciezki jak apps/tsa/merkle.py (RFC 6962, samotny wezel w gore)."""
    level = [_leaf(d) for d in digests]
    paths: dict[str, list[dict]] = {d: [] for d in digests}
    where = {d: i for i, d in enumerate(digests)}
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                for d, at in where.items():
                    if at == i:
                        paths[d].append({'side': 'R', 'hash': level[i + 1].hex()})
                    elif at == i + 1:
                        paths[d].append({'side': 'L', 'hash': level[i].hex()})
                nxt.append(hashlib.sha256(b'\x01' + level[i] + level[i + 1]).digest())
            else:
                nxt.append(level[i])
        where = {d: at // 2 for d, at in where.items()}
        level = nxt
    return level[0].hex(), paths


def _beat(moment: datetime) -> str:
    """@beat jak serwer (apps/beat/core.py) — pole ignorowane przez §12.1, ale realne."""
    us = (moment.hour * 3600 + moment.minute * 60 + moment.second) * 1_000_000 + moment.microsecond
    beats = (us / 86_400_000) % 1000
    return f'@{int(beats * 100) / 100:06.2f}'


def _canonical(moment: datetime) -> str:
    return moment.strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def _log_world(doc: dict) -> dict:
    """Maly dziennik: zamkniety, podpisany i zakotwiczony tydzien W39 (wlasny
    stempel pliku z kontenera) oraz otwarty W40 (powiazanie, oferta, odpowiedzi,
    czesc B) — odpowiedzi /api/proof/verify zbudowane tak, jak buduje je serwer
    (apps/tsa/views.py: _payload), z kwitami testowego klucza dziennika."""
    from beatstamp.handover import receipt as R

    key, _ = _log_keys()
    pub = b64(key.public_key().public_bytes_raw())
    file_digest = doc['manifest']['files'][0]['sha256']
    entries = [  # (skrot, czas, tydzien) w kolejnosci seq
        (file_digest, ts('2026-09-21T08:00:00.250000'), '2026-W39'),
        (hashlib.sha256(b'vector other stamp').hexdigest(), ts('2026-09-22T10:00:00.000001'), '2026-W39'),
        (hashlib.sha256(b'vector boundary stamp').hexdigest(), ts('2026-09-27T23:57:00.000001'), '2026-W40'),
        *[(d, datetime.fromisoformat(t.replace('Z', '+00:00')), '2026-W40')
          for d, t in sorted(doc['log'].items(), key=lambda kv: kv[1])],
    ]
    weeks: dict[str, list[str]] = {}
    for d, _t, w in entries:
        weeks.setdefault(w, []).append(d)
    trees = {w: _tree(ds) for w, ds in weeks.items()}
    closed = {'2026-W39'}
    payloads: dict[str, dict] = {}
    prev = '0' * 64
    for seq, (d, moment, week) in enumerate(entries, start=1):
        chain = hashlib.sha256((prev + d + _canonical(moment)).encode()).hexdigest()
        prev = chain
        root, paths = trees[week]
        body = {'v': 'sigelith-receipt-v1', 'seq': seq, 'digest': d, 'utc': _canonical(moment),
                'chain_hash': chain, 'key': pub}
        receipt = dict(body, sig=b64(key.sign(R.message(body))))
        p = {'found': True, 'digest': d, 'beat': _beat(moment),
             'utc': moment.isoformat().replace('+00:00', 'Z'), 'seq': seq, 'week': week,
             'chain_hash': chain, 'week_root': root, 'week_closed': week in closed}
        if week in closed:
            p['root_signature'] = b64(key.sign(f'beattime-proof-v1|{week}|{root}'.encode()))
            p['public_key'] = pub
            p['ots_status'] = 'bitcoin'
            p['ots_bitcoin_height'] = 916000
        p['inclusion_proof'] = paths[d]
        p['anchors'] = []
        p['receipt'] = receipt
        payloads[d] = p
    return {'key': pub, 'payloads': payloads, 'file_digest': file_digest,
            'boundary_digest': entries[2][0]}


def _dump(payload) -> str:
    return json.dumps(payload, separators=(',', ':'), ensure_ascii=False)


def log_proofs_section(doc: dict) -> dict:
    """Regula §12.1: kiedy czas z dowodu w pakiecie sie liczy. Deterministyczne."""
    from beatstamp.handover import HandoverError, logproof as LP, receipt as R

    key, other = _log_keys()
    world = _log_world(doc)
    pub, payloads = world['key'], world['payloads']
    other_pub = b64(other.public_key().public_bytes_raw())
    offer = payloads[doc['offer_digest']]
    closed = payloads[world['file_digest']]
    boundary = payloads[world['boundary_digest']]

    def resigned(p: dict, signer=key, **changes) -> dict:
        """Kwit wystawiony od nowa (poprawnie) dla zmienionej odpowiedzi."""
        body = {k: v for k, v in p['receipt'].items() if k != 'sig'}
        body.update(changes)
        if signer is not key:
            body['key'] = b64(signer.public_key().public_bytes_raw())
        return dict(body, sig=b64(signer.sign(R.message(body))))

    def without(p: dict, *keys_: str) -> dict:
        return {k: v for k, v in p.items() if k not in keys_}

    moved = ts('2026-09-27T23:53:59.000001')          # 6 minut przed W40
    early = dict(boundary, utc=moved.isoformat().replace('+00:00', 'Z'))
    early['receipt'] = resigned(boundary, utc=_canonical(moved))
    wrong_path = copy.deepcopy(offer)
    wrong_path['inclusion_proof'][0]['hash'] = hashlib.sha256(b'not a sibling').hexdigest()
    bad_side = copy.deepcopy(offer)
    bad_side['inclusion_proof'][0]['side'] = 'X'
    upper_hash = copy.deepcopy(offer)
    upper_hash['inclusion_proof'][0]['hash'] = upper_hash['inclusion_proof'][0]['hash'].upper()
    foreign_root = dict(closed, public_key=other_pub, root_signature=b64(other.sign(
        f'beattime-proof-v1|2026-W39|{closed["week_root"]}'.encode())))
    other_root = dict(closed, root_signature=b64(key.sign(
        f'beattime-proof-v1|2026-W39|{"0" * 64}'.encode())))
    bank = dict(without(closed, 'ots_status', 'ots_bitcoin_height'), anchors=[
        {'bank': 'TEST', 'date': '2026-09-30', 'status': 'confirmed', 'root': '1' * 64,
         'root_matches_week': False, 'bank_reference': 'X', 'statement_url': ''}])
    duplicate = _dump(offer).replace('"found":true', '"found":true,"utc":"2026-10-01T00:00:00Z"', 1)
    bank_ok = dict(without(closed, 'ots_status', 'ots_bitcoin_height'), anchors=[
        {'bank': 'TEST', 'date': '2026-09-30', 'status': 'confirmed', 'root': closed['week_root'],
         'root_matches_week': True, 'bank_reference': 'X', 'statement_url': ''}])
    bank_flagged = copy.deepcopy(bank_ok)
    bank_flagged['anchors'][0]['root_matches_week'] = False
    bank_other_root = copy.deepcopy(bank_ok)
    bank_other_root['anchors'][0]['root'] = '1' * 64

    cases = [
        ('log-open-week', offer, None, 'receipt'),
        ('log-closed-week-anchored', closed, None, 'anchored'),
        ('log-closed-week-signed', without(closed, 'ots_status', 'ots_bitcoin_height'), None, 'signed'),
        ('log-anchor-for-another-root', bank, None, 'signed'),
        ('log-bank-anchor', bank_ok, None, 'anchored'),
        ('log-bank-anchor-flagged-by-the-log', bank_flagged, None, 'signed'),
        ('log-bank-anchor-of-another-root', bank_other_root, None, 'signed'),
        ('log-stamped-just-before-its-week', boundary, None, 'receipt'),
        ('log-other-fields-ignored', dict(offer, beat='@999.99', time={'x': 1}), None, 'receipt'),
        ('log-without-receipt', without(offer, 'receipt'), None, 'receipt-missing'),
        ('log-receipt-null', dict(offer, receipt=None), None, 'receipt-missing'),
        ('log-receipt-another-key', dict(offer, receipt=resigned(offer, other)), None, 'receipt-key'),
        ('log-receipt-another-digest', dict(offer, receipt=payloads[doc['accept_digest']]['receipt']),
         None, 'receipt-digest'),
        ('log-utc-moved', dict(offer, utc='2026-09-30T12:00:05.123456Z'), None, 'log-mismatch'),
        ('log-seq-changed', dict(offer, seq=offer['seq'] + 1), None, 'log-mismatch'),
        ('log-seq-as-text', dict(offer, seq=str(offer['seq'])), None, 'log-mismatch'),
        ('log-chain-hash-changed', dict(offer, chain_hash='0' * 64), None, 'log-mismatch'),
        ('log-not-found', dict(offer, found=False), None, 'log-structure'),
        ('log-another-digest', dict(offer, digest=doc['accept_digest']), None, 'log-structure'),
        ('log-duplicate-json-key', duplicate, None, 'log-structure'),
        ('log-not-text', offer, 'object', 'log-structure'),
        ('log-week-missing', without(offer, 'week'), None, 'log-week'),
        ('log-week-other', dict(offer, week='2026-W41'), None, 'log-week'),
        ('log-week-earlier', dict(offer, week='2026-W39'), None, 'log-week'),
        ('log-week-not-real', dict(offer, week='2026-W54'), None, 'log-week'),
        ('log-stamped-too-early-for-its-week', early, None, 'log-week'),
        ('log-root-without-path', without(offer, 'inclusion_proof'), None, 'log-structure'),
        ('log-path-bad-side', bad_side, None, 'log-structure'),
        ('log-path-hash-uppercase', upper_hash, None, 'log-structure'),
        ('log-root-not-hex', dict(offer, week_root='x' * 64), None, 'log-structure'),
        ('log-path-wrong', wrong_path, None, 'log-inclusion'),
        ('log-root-signature-for-another-root', other_root, None, 'log-signature'),
        ('log-root-signed-by-another-key', foreign_root, None, 'log-key'),
        ('log-closed-week-unsigned', without(closed, 'root_signature', 'public_key'), None,
         'log-incomplete'),
        ('log-week-closed-not-boolean', dict(offer, week_closed='no'), None, 'log-structure'),
    ]
    out = []
    for name, payload, form, expect in cases:
        raw = payload if form == 'object' or isinstance(payload, str) else _dump(payload)
        digest = doc['offer_digest'] if isinstance(payload, str) else payload['digest']
        if name == 'log-another-digest':
            digest = doc['offer_digest']
        case = {'name': name, 'digest': digest, 'raw': raw}
        if expect in ('receipt', 'signed', 'anchored'):
            case.update(expect='ok', level=expect, utc=json.loads(_dump(payload))['receipt']['utc'])
        else:
            case['expect'] = expect
        out.append(case)
    weeks = []
    for week in ('2026-W01', '2026-W53', '2027-W53', '2020-W53', '2015-W53', '2032-W53', '2004-W53',
                 '2100-W53', '2021-W01', '2026-W00', '2026-W99', '0000-W01', '0001-W01', '9999-W52',
                 '2024-W1', '2024-w01', ' 2024-W01'):
        try:
            monday = LP.week_start(week).date().isoformat()
        except HandoverError:
            monday = None
        weeks.append({'week': week, 'monday': monday})
    return {'log_key': pub, 'other_key': other_pub,
            'note': 'TEST log key (receipt section seed) — proofs as /api/proof/verify returns them',
            'cases': out, 'weeks': weeks}


def evidence_signed_section(doc: dict) -> dict:
    """Pakiety dowodowe z PRAWDZIWYMI odpowiedziami dziennika (testowy klucz):
    doreczony (nadawca, z ujawnionym kontenerem) i odmowa (kopia odbiorcy).
    Na nich pracuje strona weryfikatora (test DOM) i test zgodnosci Python/JS."""
    from beatstamp.handover import evidence as E

    world = _log_world(doc)
    p = world['payloads']
    b = doc['parts']['b']
    delivered_log = {d: _dump(p[d]) for d in (doc['binding_digest'], doc['offer_digest'],
                                              doc['accept_digest'], b, world['file_digest'])}
    refused_log = {d: _dump(p[d]) for d in (doc['offer_digest'], doc['refuse_digest'])}
    delivered = E.build_evidence(offer=doc['offer'], answer=doc['accept'], part_b=bytes.fromhex(b),
                                 binding=doc['binding'], log=delivered_log,
                                 container=base64.b64decode(doc['container']))
    refused = E.build_evidence(offer=doc['offer'], answer=doc['refuse'], part_b=None, binding=None,
                               log=refused_log)
    return {'log_key': world['key'], 'delivered': b64(delivered), 'refused': b64(refused),
            'expect': {'delivered': {'verdict': 'delivered', 'at': p[b]['receipt']['utc']},
                       'refused': {'verdict': 'refused',
                                   'at': p[doc['refuse_digest']]['receipt']['utc']},
                       'both': {'verdict': 'delivered', 'at': p[b]['receipt']['utc']}}}


# --- atestacja TPM (spec §3.6): SYNTETYCZNY lancuch z korzeniem TESTOWYM -------

def _cbor(v) -> bytes:
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, 'big')
        raise ValueError(n)
    if isinstance(v, bool):
        return b'\xf5' if v else b'\xf4'
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        raw = v.encode()
        return head(3, len(raw)) + raw
    if isinstance(v, list):
        return head(4, len(v)) + b''.join(_cbor(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b''.join(_cbor(k) + _cbor(x) for k, x in v.items())
    raise TypeError(type(v))


def attestation_section(doc: dict) -> dict:
    """Atestacje `tpm` zbudowane jak przez Windows Hello, ale na korzeniu TESTOWYM.

    Prawdziwej atestacji (certyfikat TPM konkretnego komputera) nie wkladamy do
    repozytorium — identyfikuje urzadzenie. Klucze RSA sa losowe, wiec sekcja
    powstaje RAZ (`--extend` jej nie nadpisuje) i jest zamrazana jak reszta.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID, ObjectIdentifier

    der = lambda c: c.public_bytes(serialization.Encoding.DER)  # noqa: E731
    utc = lambda y, m=1, d=1: datetime(y, m, d, tzinfo=UTC)    # noqa: E731
    new_rsa = lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)  # noqa: E731
    cn = lambda text: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])  # noqa: E731
    usage = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                 data_encipherment=False, key_agreement=False, key_cert_sign=False,
                 crl_sign=False, encipher_only=False, decipher_only=False)

    root_key, inter_key, aik_key, fake_root_key = new_rsa(), new_rsa(), new_rsa(), new_rsa()
    root_name = cn('Sigelith TEST TPM Root - not a real TPM')

    def ca(subject, key, issuer, issuer_key, start, end, path=None, is_ca=True, pss=False):
        b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(start).not_valid_after(end)
             .add_extension(x509.BasicConstraints(ca=is_ca, path_length=path if is_ca else None),
                            critical=True))
        if is_ca:
            b = b.add_extension(x509.KeyUsage(**dict(usage, key_cert_sign=True, crl_sign=True)),
                                critical=True)
        if pss:                      # RSA-PSS: poza lista dozwolonych podpisow certyfikatow
            return b.sign(issuer_key, hashes.SHA256(), rsa_padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=32))
        return b.sign(issuer_key, hashes.SHA256())

    root = ca(root_name, root_key, root_name, root_key, utc(2020), utc(2040))
    inter = ca(cn('SGTH-KEYID-TEST'), inter_key, root_name, root_key, utc(2024), utc(2034), 0)
    fake_inter = ca(cn('SGTH-KEYID-TEST'), inter_key, root_name, fake_root_key, utc(2024), utc(2034), 0)
    not_ca_inter = ca(cn('SGTH-KEYID-TEST'), inter_key, root_name, root_key, utc(2024), utc(2034),
                      is_ca=False)
    renamed_inter = ca(cn('SGTH-KEYID-OTHER'), inter_key, root_name, root_key, utc(2024), utc(2034), 0)
    pss_inter = ca(cn('SGTH-KEYID-TEST'), inter_key, root_name, root_key, utc(2024), utc(2034), 0,
                   pss=True)
    # Zewnetrzny algorytm podpisu podmieniony na sha1WithRSA; sam podpis jest
    # poprawny dla SHA-256. Lista dozwolonych algorytmow MUSI go odrzucic —
    # weryfikator, ktory „probowalby po swojemu", przyjalby taki certyfikat.
    sha256_rsa = bytes.fromhex('2a864886f70d01010b')
    claims_sha1 = der(inter)
    at = claims_sha1.rfind(sha256_rsa)
    claims_sha1 = claims_sha1[:at] + bytes.fromhex('2a864886f70d010105') + claims_sha1[at + len(sha256_rsa):]
    aaguid = bytes.fromhex('08987058cadc4b81b6e130de50dcbe96')
    tpm_names = [('2.23.133.2.1', 'id:53475448'), ('2.23.133.2.2', 'TEST'), ('2.23.133.2.3', 'id:00010002')]

    def aik(*, subject=x509.Name([]), eku=True, eku_oid='2.23.133.8.3', is_ca=False, san=True,
            san_critical=True, san_names=tpm_names, unknown_critical=False, start=utc(2026),
            end=utc(2030), aaguid_ext=None):
        b = (x509.CertificateBuilder().subject_name(subject).issuer_name(inter.subject)
             .public_key(aik_key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(start).not_valid_after(end)
             .add_extension(x509.KeyUsage(**dict(usage, digital_signature=True)), critical=True)
             .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True))
        if eku:
            b = b.add_extension(x509.ExtendedKeyUsage([ObjectIdentifier(eku_oid)]), critical=False)
        if san:
            dn = x509.Name([x509.NameAttribute(ObjectIdentifier(o), v) for o, v in san_names])
            b = b.add_extension(x509.SubjectAlternativeName([x509.DirectoryName(dn)]),
                                critical=san_critical)
        if unknown_critical:
            b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5'), b'\x05\x00'),
                                critical=True)
        if aaguid_ext is not None:
            b = b.add_extension(x509.UnrecognizedExtension(
                ObjectIdentifier('1.3.6.1.4.1.45724.1.1.4'), b'\x04\x10' + aaguid_ext), critical=False)
        return b.sign(inter_key, hashes.SHA256())

    good_aik = aik()
    u16 = lambda n: n.to_bytes(2, 'big')   # noqa: E731
    tpm2b = lambda b: u16(len(b)) + b     # noqa: E731

    def build(*, key=None, card='recipient', rp=X.RP_ID, flags=0x45, client_type='webauthn.create',
              alg=-65535, pub_key=None, name_from_other=False, magic=0xFF544347, area_tail=b'',
              x5c=None, fmt='tpm', stmt_alg=None, flip_sig=False, tamper_client=False,
              duplicate_key=False, non_minimal=False, ver='2.0', area_type=0x0023):
        """Atestacja dla klucza `key` (domyslnie klucz karty odbiorcy); parametry psuja po jednej regule."""
        rng = Det('vector attestation ' + str(alg))
        key = key or p256('vector recipient sig')
        pn = key.public_key().public_numbers()
        x, y = pn.x.to_bytes(32, 'big'), pn.y.to_bytes(32, 'big')
        cred_id = rng(32)
        cose = _cbor({1: 2, 3: -7, -1: 1, -2: x, -3: y})
        auth = (X.sha256(rp.encode()) + bytes([flags]) + (0).to_bytes(4, 'big') + aaguid
                + u16(len(cred_id)) + cred_id + cose)
        client = json.dumps({'type': client_type, 'challenge': X.b64url(rng(32)),
                             'origin': 'https://sigelith.org', 'crossOrigin': False},
                            separators=(',', ':')).encode()
        pk = (pub_key or key).public_key().public_numbers()
        area = (u16(area_type) + u16(0x000B) + (0x00060472).to_bytes(4, 'big') + tpm2b(rng(32))
                + u16(0x0010) + u16(0x0010) + u16(0x0003) + u16(0x0010)
                + tpm2b(pk.x.to_bytes(32, 'big')) + tpm2b(pk.y.to_bytes(32, 'big')) + area_tail)
        named = area
        if name_from_other:          # Name policzony z INNEGO pubArea (inne objectAttributes)
            named = area[:4] + (0x00060473).to_bytes(4, 'big') + area[8:]
        hash_cls = hashes.SHA1 if alg == -65535 else hashes.SHA256
        h = hashes.Hash(hash_cls())
        h.update(auth + X.sha256(client))
        info = (magic.to_bytes(4, 'big') + u16(0x8017) + tpm2b(u16(0x000B) + rng(32))
                + tpm2b(h.finalize()) + rng(17) + rng(8)
                + tpm2b(u16(0x000B) + hashlib.sha256(named).digest()) + tpm2b(u16(0x000B) + rng(32)))
        sig = aik_key.sign(info, padding.PKCS1v15(), hash_cls())
        if flip_sig:
            sig = sig[:-1] + bytes([sig[-1] ^ 1])
        stmt = {'ver': ver, 'alg': stmt_alg if stmt_alg is not None else alg,
                'x5c': x5c if x5c is not None else [der(good_aik), der(inter)],
                'sig': sig, 'certInfo': info, 'pubArea': area}
        obj = _cbor({'fmt': fmt, 'attStmt': stmt, 'authData': auth})
        if duplicate_key:
            obj = (b'\xa4' + _cbor('fmt') + _cbor(fmt) + _cbor('fmt') + _cbor(fmt)
                   + _cbor('attStmt') + _cbor(stmt) + _cbor('authData') + _cbor(auth))
        if non_minimal:
            obj = b'\xa3' + b'\x78\x03fmt' + _cbor(fmt) + _cbor('attStmt') + _cbor(stmt) + _cbor('authData') + _cbor(auth)
        if tamper_client:
            client = client.replace(b'webauthn.create', b'webauthn.create",' + b'"x":"1', 1)
        fp = I.read_card(doc['cards'][card]).fingerprint_hex
        return {'v': X.VERSION, 'type': 'attestation', 'card': fp, 'fmt': fmt,
                'attestation_object': b64(obj), 'client_data_json': b64(client)}

    good = 'TPM SGTH TEST'
    cases = [
        ('att-valid-rs1', build(), 'ok'),
        ('att-valid-rs256', build(alg=-257), 'ok'),
        ('att-valid-root-in-x5c', build(x5c=[der(good_aik), der(inter), der(root)]), 'ok'),
        ('att-for-another-card', build(card='sender'), 'attestation-card'),
        ('att-key-is-not-the-card-key', build(key=p256('vector mallory sig')), 'attestation-card'),
        ('att-extra-data-does-not-cover-client-data', build(tamper_client=True), 'attestation-statement'),
        ('att-tpm-key-differs', build(pub_key=p256('vector other tpm key')), 'attestation-statement'),
        ('att-name-of-another-key', build(name_from_other=True), 'attestation-statement'),
        ('att-signature-invalid', build(flip_sig=True), 'attestation-statement'),
        ('att-certinfo-not-tpm-generated', build(magic=0xFF544348), 'attestation-statement'),
        ('att-pubarea-trailing-byte', build(area_tail=b'\x00'), 'attestation-statement'),
        ('att-aik-without-aik-usage', build(x5c=[der(aik(eku=False)), der(inter)]), 'attestation-certificate'),
        ('att-aik-usage-is-not-aik', build(x5c=[der(aik(eku_oid='1.3.6.1.5.5.7.3.1')), der(inter)]),
         'attestation-certificate'),
        ('att-aik-san-without-tpm-version', build(x5c=[der(aik(san_names=tpm_names[:2])), der(inter)]),
         'attestation-certificate'),
        ('att-intermediate-not-a-ca', build(x5c=[der(good_aik), der(not_ca_inter)]), 'attestation-chain'),
        ('att-chain-names-do-not-link', build(x5c=[der(good_aik), der(renamed_inter)]), 'attestation-chain'),
        ('att-intermediate-signed-with-rsa-pss', build(x5c=[der(good_aik), der(pss_inter)]),
         'attestation-chain'),
        ('att-intermediate-claims-sha1', build(x5c=[der(good_aik), claims_sha1]), 'attestation-chain'),
        ('att-es256-with-rsa-aik', build(alg=-7), 'attestation-statement'),
        ('att-pubarea-not-ecc', build(area_type=0x0001), 'attestation-statement'),
        ('att-statement-version', build(ver='1.2'), 'attestation-structure'),
        ('att-aik-is-a-ca', build(x5c=[der(aik(is_ca=True)), der(inter)]), 'attestation-certificate'),
        ('att-aik-has-a-subject', build(x5c=[der(aik(subject=cn('AIK'))), der(inter)]), 'attestation-certificate'),
        ('att-aik-unknown-critical-extension', build(x5c=[der(aik(unknown_critical=True)), der(inter)]),
         'attestation-certificate'),
        ('att-aik-san-not-critical', build(x5c=[der(aik(san_critical=False)), der(inter)]),
         'attestation-certificate'),
        ('att-aik-without-tpm-names', build(x5c=[der(aik(san=False)), der(inter)]), 'attestation-certificate'),
        ('att-aik-aaguid-mismatch', build(x5c=[der(aik(aaguid_ext=bytes(16))), der(inter)]),
         'attestation-certificate'),
        ('att-chain-signed-by-another-root', build(x5c=[der(good_aik), der(fake_inter)]), 'attestation-chain'),
        ('att-aik-expired-when-card-made', build(x5c=[der(aik(start=utc(2020), end=utc(2025))), der(inter)]),
         'attestation-chain'),
        ('att-bound-to-another-site', build(rp='evil.example'), 'attestation-structure'),
        ('att-without-user-verification', build(flags=0x41), 'attestation-structure'),
        ('att-client-data-not-create', build(client_type='webauthn.get'), 'attestation-structure'),
        ('att-cbor-duplicate-key', build(duplicate_key=True), 'attestation-structure'),
        ('att-cbor-non-minimal-length', build(non_minimal=True), 'attestation-structure'),
        ('att-format-packed', build(fmt='packed'), 'attestation-unsupported'),
        ('att-algorithm-eddsa', build(stmt_alg=-8), 'attestation-unsupported'),
    ]
    valid = cases[0][1]
    return {
        'test_root_name': 'Sigelith TEST TPM Root',
        'test_root': b64(der(root)),
        'card_file': b64(T.write_card_file(doc['cards']['recipient'], valid)),
        # Kazdy przypadek sprawdzamy WZGLEDEM KARTY ODBIORCY; „obca karta" to
        # pole `card` wewnatrz samej atestacji.
        'cases': [{'name': n, 'card': 'recipient', 'attestation': c, 'expect': e,
                   'description': good if e == 'ok' else None} for n, c, e in cases],
    }


def evidence_zip(doc: dict) -> str:
    """Pakiet dowodowy (ZIP) zlozony z czesci wektora — dla czytnikow w innych jezykach.

    Deterministyczny wzgledem danych, wiec mozna go dolozyc do ZAMROZONEGO
    wektora bez ponownego losowania HPKE (`--add-evidence`).
    """
    from beatstamp.handover import evidence as E

    data = E.build_evidence(offer=doc['offer'], answer=doc['accept'],
                            part_b=bytes.fromhex(doc['parts']['b']), binding=doc['binding'],
                            log={}, container=base64.b64decode(doc['container']))
    return b64(data)


def write(doc: dict) -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + '\n', encoding='utf-8',
                   newline='\n')


if __name__ == '__main__':
    if sys.argv[1:] == ['--extend']:
        # Dokladamy do ZAMROZONEGO wektora to, co nie wymaga losowania HPKE —
        # reszta bajtow zostaje nietknieta.
        frozen = json.loads(OUT.read_text(encoding='utf-8'))
        frozen['evidence_zip'] = evidence_zip(frozen)
        extend(frozen)
        write(frozen)
        print(f'{OUT}: rozszerzony ({len(frozen["cases"])} cases, {len(frozen["jcs"])} jcs, '
              f'{len(frozen["file_names"])} names)')
    else:
        main()
