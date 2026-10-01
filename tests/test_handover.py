"""
Testy implementacji referencyjnej Sigelith Handover (HANDOVER_SPEC.md DRAFT 0.3).

Trzy warstwy:

* `VectorTests` — ZAMROZONE wektory (tests/vectors/handover-v1.json). Ten sam
  plik przechodzi drugi, niezalezny weryfikator (JS), wiec tu pilnujemy, ze
  Python nadal liczy dokladnie te same bajty i te same werdykty. Przypadki
  zepsute sa poprawnie podpisane tam, gdzie to mozliwe — test ma lapac
  REGULE, nie tylko podpis.
* testy regul i prymitywow — kazdy atak z tabeli §13 odtworzony wprost;
* `RoundTripTests` — pelny przebieg na swiezych kluczach, z plikami na dysku.

Test, ktory potwierdza tylko poprawne dane, przeszedlby tez funkcje zwracajaca
zawsze True — dlatego kazda regula ma swoj przypadek negatywny.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from beatstamp.handover import (  # noqa: E402
    HandoverError, answer as A_, attestation as TA, evidence as E, identity as I, jcs, logsearch,
    logproof as LP, package as P, primitives as X, receipt as RC, rules, stream, tpm_roots,
    transport as T)

VECTORS = Path(__file__).resolve().parent / 'vectors' / 'handover-v1.json'
SERVER_STREAM = Path(__file__).resolve().parents[2] / 'apps' / 'seal' / 'stream.py'
UTC = timezone.utc


def ts(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


class _Vectors:
    _doc = None

    @classmethod
    def doc(cls) -> dict:
        if cls._doc is None:
            cls._doc = json.loads(VECTORS.read_text(encoding='utf-8'))
        return cls._doc


def _enc(doc: dict, who: str) -> X.EncKey:
    return X.EncKey.from_bytes(b64d(doc['keys'][who]['enc_private']))


class VectorTests(unittest.TestCase):
    """Zamrozone wektory — wspolne z weryfikatorem JS."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.v = _Vectors.doc()
        cls.offer = P.read_offer(cls.v['offer'])
        cls.recipient = I.read_card(cls.v['cards']['recipient'])
        cls.sender = I.read_card(cls.v['cards']['sender'])

    def test_cards_and_fingerprints(self):
        for who in ('sender', 'recipient', 'mallory'):
            card = I.read_card(self.v['cards'][who])
            self.assertEqual(card.fingerprint_hex, self.v['fingerprints'][who]['hex'])
            self.assertEqual(card.fingerprint_text, self.v['fingerprints'][who]['text'])
        self.assertEqual(self.recipient.sig_alg, 'es256-webauthn')
        self.assertEqual(self.sender.sig_alg, 'es256')

    def test_binding(self):
        b = I.read_binding(self.v['binding'], self.sender, self.recipient)
        self.assertEqual(b.digest.hex(), self.v['binding_digest'])
        self.assertEqual((b.level, b.method), (4, 'voice'))
        with self.assertRaises(HandoverError) as cm:
            I.read_binding(self.v['binding'], self.recipient, self.sender)
        self.assertEqual(cm.exception.code, 'binding-recorder')

    def test_container_and_files(self):
        container = b64d(self.v['container'])
        self.assertEqual(hashlib.sha256(container).hexdigest(), self.v['content_sha256'])
        manifest, datas = P.container_files(container)
        self.assertEqual(manifest, self.v['manifest'])
        self.assertEqual([f['name'] for f in self.v['files']], [e['name'] for e in manifest['files']])
        self.assertEqual([b64d(f['data']) for f in self.v['files']], datas)

    def test_key_derivations(self):
        p = self.v['parts']
        nonce, a, b = b64d(p['nonce']), b64d(p['a']), bytes.fromhex(p['b'])
        self.assertEqual(P.content_key(a, b, nonce).hex(), p['content_key'])
        self.assertEqual(P.preview_key(a, nonce).hex(), p['preview_key'])
        self.assertEqual(P.commit_a(a).hex(), p['commit_a'])
        self.assertEqual(P.commit_b(b).hex(), p['commit_b'])
        self.assertEqual(P.container_aad(nonce).hex(), p['container_aad'])

    def test_ciphertext_is_deterministic_stream(self):
        """Ten sam klucz, prefiks i aad -> ten sam szyfrogram (dwa segmenty)."""
        p = self.v['parts']
        container = b64d(self.v['container'])
        out = io.BytesIO()
        stream.encrypt(bytes.fromhex(p['content_key']), b64d(p['nonce_prefix']),
                       bytes.fromhex(p['container_aad']), io.BytesIO(container), out)
        self.assertEqual(out.getvalue(), b64d(self.v['ciphertext']))
        self.assertGreater(len(container), stream.SEGMENT)

    def test_offer_opens_for_the_recipient(self):
        self.assertEqual(self.offer.digest.hex(), self.v['offer_digest'])
        a, preview = P.open_offer(self.offer, _enc(self.v, 'recipient'), self.recipient)
        self.assertEqual(a, b64d(self.v['parts']['a']))
        self.assertEqual(preview, self.v['preview'])
        with self.assertRaises(HandoverError) as cm:
            P.open_offer(self.offer, _enc(self.v, 'mallory'), I.read_card(self.v['cards']['mallory']))
        self.assertEqual(cm.exception.code, 'offer-not-mine')

    def test_package_file(self):
        data = b64d(self.v['package_file_prefix']) + b64d(self.v['ciphertext'])
        src = io.BytesIO(data)
        offer, size = T.read_package_file(src, [_enc(self.v, 'mallory'), _enc(self.v, 'recipient')])
        self.assertEqual(offer, self.v['offer'])
        self.assertEqual(size, self.offer.ciphertext_size)
        P.copy_ciphertext(self.offer, src)
        with self.assertRaises(HandoverError) as cm:
            T.read_package_file(io.BytesIO(data), [_enc(self.v, 'sender')])
        self.assertEqual(cm.exception.code, 'envelope-not-mine')

    def test_answers_and_answer_transport(self):
        acc = A_.read_answer(self.v['accept'], self.offer)
        ref = A_.read_answer(self.v['refuse'], self.offer)
        self.assertEqual(acc.digest.hex(), self.v['accept_digest'])
        self.assertEqual(ref.digest.hex(), self.v['refuse_digest'])
        self.assertEqual(acc.valid_until, acc.signed_at + timedelta(days=14))
        answer_file = b64d(self.v['answer_file'])
        self.assertEqual(T.read_answer_file(answer_file, [_enc(self.v, 'sender')]), self.v['accept'])
        self.assertEqual(T.parse_answer_text(self.v['answer_text']), answer_file)

    def test_log_search(self):
        found = logsearch.find_part_b(self.v['log_entries'], self.offer.commit_b)
        self.assertIsNotNone(found)
        self.assertEqual(found[1]['seq'], 2)
        self.assertEqual(found[0].hex(), self.v['parts']['b'])

    def test_jcs_cases(self):
        for case in self.v['jcs']:
            raw = b64d(case['bytes'])
            with self.subTest(raw=raw):
                if case['error'] is None:
                    self.assertEqual(jcs.dumps(jcs.loads(raw)), raw)
                else:
                    with self.assertRaises(HandoverError) as cm:
                        jcs.loads(raw)
                    self.assertEqual(cm.exception.code, case['error'])

    def test_file_name_cases(self):
        for case in self.v['file_names']:
            with self.subTest(name=case['name']):
                if case['error'] is None:
                    rules.check_file_name(case['name'])
                else:
                    with self.assertRaises(HandoverError) as cm:
                        rules.check_file_name(case['name'])
                    self.assertEqual(cm.exception.code, case['error'])

    def test_broken_cases(self):
        for case in self.v['cases']:
            with self.subTest(case=case['name']):
                self._run_case(case)

    def _run_case(self, case: dict) -> None:
        kind, expect = case['kind'], case['expect']
        if kind == 'card':
            with self.assertRaises(HandoverError) as cm:
                I.read_card(case['card'])
            self.assertEqual(cm.exception.code, expect)
        elif kind == 'offer':
            with self.assertRaises(HandoverError) as cm:
                P.read_offer(case['offer'])
            self.assertEqual(cm.exception.code, expect)
        elif kind == 'offer-open':
            offer = P.read_offer(case['offer'])
            with self.assertRaises(HandoverError) as cm:
                P.open_offer(offer, _enc(self.v, 'recipient'), self.recipient)
            self.assertEqual(cm.exception.code, expect)
        elif kind == 'answer':
            with self.assertRaises(HandoverError) as cm:
                A_.read_answer(case['answer'], self.offer)
            self.assertEqual(cm.exception.code, expect)
        elif kind == 'evidence':
            doc = {'v': E.EVIDENCE_V, 'offer': self.v['offer'], 'answer': case['answer'],
                   'part_b': case['part_b'], 'binding': self.v['binding'], 'attestations': [],
                   'log': {}, 'disclosure': None}
            report = E.verify_evidence(doc, E.DictLog(case['log']),
                                       extra_answers=case['extra_answers'])
            self.assertEqual(report.verdict, expect, [c for c in report.failed])
            failed = {c.code for c in report.failed}
            for code in case['failing']:
                self.assertIn(code, failed)
            if expect == 'delivered':
                self.assertEqual(report.delivered_at, ts('2026-10-02T10:15:00.500000'))
        elif kind == 'defect':
            report = E.verify_defect(case['offer'], b64d(case['a']), bytes.fromhex(case['b']),
                                     io.BytesIO(b64d(case['ciphertext'])))
            verdict, _, code = expect.partition(':')
            self.assertEqual(report.verdict, verdict)
            if code:
                self.assertEqual(report.checks[0].code, code)
        elif kind == 'container':
            data = b64d(case['container'])
            with self.assertRaises(HandoverError) as cm:
                P.check_container(io.BytesIO(data), len(data))
            self.assertEqual(cm.exception.code, expect)
        else:
            self.fail(f'unknown case kind {kind}')

    # --- atestacja TPM (§3.6) na korzeniu TESTOWYM -------------------------

    def _test_roots(self):
        sec = self.v['attestation']
        return ((sec['test_root_name'], b64d(sec['test_root'])),)

    def test_attestation_cases(self):
        cards = {k: I.read_card(c) for k, c in self.v['cards'].items()}
        for case in self.v['attestation']['cases']:
            with self.subTest(case=case['name']):
                if case['expect'] == 'ok':
                    result = TA.read_attestation(case['attestation'], cards[case['card']],
                                                 roots=self._test_roots())
                    self.assertEqual(result.description, case['description'])
                else:
                    with self.assertRaises(HandoverError) as cm:
                        TA.read_attestation(case['attestation'], cards[case['card']],
                                            roots=self._test_roots())
                    self.assertEqual(cm.exception.code, case['expect'])

    def test_production_roots_reject_the_test_chain(self):
        valid = self.v['attestation']['cases'][0]
        with self.assertRaises(HandoverError) as cm:
            TA.read_attestation(valid['attestation'], self.recipient)
        self.assertEqual(cm.exception.code, 'attestation-chain')

    def test_card_file(self):
        card, att = T.read_card_file(b64d(self.v['attestation']['card_file']))
        self.assertEqual(card, self.v['cards']['recipient'])
        info = I.read_card(card)
        self.assertEqual(TA.read_attestation(att, info, roots=self._test_roots()).vendor_id, 'SGTH')
        with self.assertRaises(HandoverError) as cm:
            T.read_card_file(b'SIGELITH-CARD-1\n{"card":{}}')
        self.assertEqual(cm.exception.code, 'file-format')

    def test_evidence_reports_attestation_without_changing_the_verdict(self):
        doc = {'v': E.EVIDENCE_V, 'offer': self.v['offer'], 'answer': self.v['accept'],
               'part_b': self.v['parts']['b'], 'binding': self.v['binding'],
               'attestations': [self.v['attestation']['cases'][0]['attestation']],
               'log': {}, 'disclosure': None}
        log = E.DictLog(self.v['log'])
        ok = E.verify_evidence(doc, log, attestation_roots=self._test_roots())
        self.assertEqual((ok.verdict, ok.attested), ('delivered', {'recipient': 'TPM SGTH TEST'}))
        rejected = E.verify_evidence(doc, log)            # korzen produkcyjny: lancuch testowy obcy
        self.assertEqual(rejected.verdict, 'delivered')
        self.assertEqual(rejected.attested, {})
        self.assertIn('attestation-chain', {c.code for c in rejected.failed})

    # --- podpisany kwit stempla (§9.2) ---------------------------------------

    def test_receipt_cases(self):
        sec = self.v['receipt']
        for case in sec['cases']:
            expected = bytes.fromhex(case['expected_digest']) if case['expected_digest'] else None
            with self.subTest(case=case['name']):
                if case['expect'] == 'ok':
                    r = RC.read_receipt(case['receipt'], [sec['log_key']], expected_digest=expected)
                    self.assertEqual(r.seq, case['receipt']['seq'])
                else:
                    with self.assertRaises(HandoverError) as cm:
                        RC.read_receipt(case['receipt'], [sec['log_key']], expected_digest=expected)
                    self.assertEqual(cm.exception.code, case['expect'])

    # --- dowody dziennika w pakiecie (§12.1) --------------------------------

    def test_log_proof_cases(self):
        sec = self.v['log_proofs']
        for case in sec['cases']:
            digest = bytes.fromhex(case['digest'])
            with self.subTest(case=case['name']):
                if case['expect'] == 'ok':
                    proof = LP.read_log_proof(case['raw'], digest, [sec['log_key']])
                    self.assertEqual(proof.level, case['level'])
                    self.assertEqual(proof.utc, X.parse_log_utc(case['utc']))
                else:
                    with self.assertRaises(HandoverError) as cm:
                        LP.read_log_proof(case['raw'], digest, [sec['log_key']])
                    self.assertEqual(cm.exception.code, case['expect'])

    def test_iso_weeks(self):
        for case in self.v['log_proofs']['weeks']:
            with self.subTest(week=case['week']):
                if case['monday'] is None:
                    with self.assertRaises(HandoverError) as cm:
                        LP.week_start(case['week'])
                    self.assertEqual(cm.exception.code, 'log-week')
                else:
                    self.assertEqual(LP.week_start(case['week']).date().isoformat(), case['monday'])

    def test_log_proof_needs_a_pinned_key(self):
        """Ta sama odpowiedz, ale klucz dziennika spoza listy — kwit nie wazy nic."""
        sec = self.v['log_proofs']
        ok = next(c for c in sec['cases'] if c['name'] == 'log-open-week')
        with self.assertRaises(HandoverError) as cm:
            LP.read_log_proof(ok['raw'], bytes.fromhex(ok['digest']), [sec['other_key']])
        self.assertEqual(cm.exception.code, 'receipt-key')

    def test_payload_log_keeps_the_reason(self):
        sec = self.v['log_proofs']
        cases = {c['name']: c for c in sec['cases']}
        good, moved = cases['log-open-week'], cases['log-utc-moved']
        digest = bytes.fromhex(good['digest'])
        log = E.PayloadLog({good['digest']: good['raw']}, [sec['log_key']])
        self.assertEqual(log.time_of(digest), X.parse_log_utc(good['utc']))
        self.assertEqual(log.proof_of(digest).level, 'receipt')
        lying = E.PayloadLog({moved['digest']: moved['raw']}, [sec['log_key']])
        self.assertIsNone(lying.time_of(digest))
        self.assertEqual(lying.errors[moved['digest']].code, 'log-mismatch')
        self.assertIsNone(E.PayloadLog({}, [sec['log_key']]).time_of(digest))

    def test_signed_evidence_packages(self):
        """Pakiety z prawdziwymi odpowiedziami dziennika — to samo, co widzi strona."""
        sec = self.v['evidence_signed']
        keys = [sec['log_key']]

        def check(name, extra=None):
            ev = E.Evidence(b64d(sec[name]))
            doc = dict(ev.doc)
            log = ev.payload_log(keys)
            answers = ()
            if extra is not None:
                other = E.Evidence(b64d(sec[extra])).doc
                log = E.MergedLog(log, E.Evidence(b64d(sec[extra])).payload_log(keys))
                answers = (other['answer'],)
                if doc['part_b'] is None:
                    doc['part_b'] = other['part_b']
            return E.verify_evidence(doc, log, container=ev.open_container(), extra_answers=answers)

        for name, extra, expect in (('delivered', None, 'delivered'), ('refused', None, 'refused'),
                                    ('delivered', 'refused', 'both'), ('refused', 'delivered', 'both')):
            with self.subTest(package=name, other=extra):
                report = check(name, extra)
                want = sec['expect'][expect]
                self.assertEqual(report.verdict, want['verdict'], report.failed)
                at = report.delivered_at if want['verdict'] == 'delivered' else report.refused_at
                self.assertEqual(at, X.parse_log_utc(want['at']))
        # Obcy klucz dziennika: podpisy stron sa dobre, ale zaden czas sie nie liczy.
        ev = E.Evidence(b64d(sec['delivered']))
        foreign = E.verify_evidence(ev.doc, ev.payload_log([self.v['log_proofs']['other_key']]))
        self.assertEqual(foreign.verdict, 'not-completed')

    def test_merged_log_refuses_two_different_times(self):
        digest = hashlib.sha256(b'x').digest()
        one = E.DictLog({digest.hex(): '2026-10-01T00:00:00Z'})
        same = E.DictLog({digest.hex(): '2026-10-01T00:00:00.000000Z'})
        other = E.DictLog({digest.hex(): '2026-10-01T00:00:01Z'})
        self.assertEqual(E.MergedLog(one, same, E.DictLog({})).time_of(digest), ts('2026-10-01T00:00:00'))
        merged = E.MergedLog(one, other)
        self.assertIsNone(merged.time_of(digest))
        self.assertEqual(merged.conflicts, {digest.hex()})

    def test_js_mirror_pins_the_same_log_keys(self):
        js = Path(__file__).resolve().parents[2] / 'apps/web/static/web/handover/verify.js'
        if not js.exists():
            self.skipTest('brak weryfikatora JS (repo desktopu bez strony)')
        import re

        from beatstamp import keys

        text = js.read_text(encoding='utf-8')
        block = re.search(r'LOG_KEYS = Object\.freeze\(\{(.*?)\}\);', text, re.S).group(1)
        current = re.findall(r"'([A-Za-z0-9+/=]{44})'", block.split('retired')[0])
        retired = re.findall(r"'([A-Za-z0-9+/=]{44})'", block.split('retired')[1])
        self.assertEqual(current, [k['public_key'] for k in keys.CURRENT_KEYS])
        self.assertEqual(retired, [k['public_key'] for k in keys.RETIRED_KEYS])

    def test_js_mirror_pins_the_same_root(self):
        js = Path(__file__).resolve().parents[2] / 'apps/web/static/web/handover/attestation.js'
        if not js.exists():
            self.skipTest('brak weryfikatora JS (repo desktopu bez strony)')
        import re

        text = js.read_text(encoding='utf-8')
        body = re.search(r"MICROSOFT_TPM_ROOT_2014 =\n((?:\s*'[^']*'\s*\+?\n?)+);", text).group(1)
        pem = ''.join(re.findall(r"'([^']*)'", body))
        self.assertEqual(base64.b64decode(pem), tpm_roots.MICROSOFT_TPM_ROOT_2014)
        self.assertIn(tpm_roots.MICROSOFT_TPM_ROOT_2014_SHA256, text)

    def test_evidence_zip_from_the_vectors(self):
        """ZIP zbudowany przez Pythona — ten sam czyta weryfikator JS."""
        ev = E.Evidence(b64d(self.v['evidence_zip']))
        report = ev.verify(E.DictLog(self.v['log']))
        self.assertEqual(report.verdict, 'delivered', report.failed)
        self.assertEqual(report.failed, [])
        self.assertTrue(report.get('disclosure')[0].ok)

    # --- dowod wady: plik (§11.3) ----------------------------------------

    def test_defect_files_from_the_vectors(self):
        """Te same pliki i te same kody czyta weryfikator JS (test-verify.mjs)."""
        self.assertTrue(self.v['defect_files'])
        for case in self.v['defect_files']:
            with self.subTest(case=case['name']):
                data = b64d(case['zip'])
                verdict, _, code = case['expect'].partition(':')
                if verdict == 'error':
                    with self.assertRaises(HandoverError) as cm:
                        E.Defect(data)
                    self.assertEqual(cm.exception.code, code)
                    continue
                self.assertEqual(E.archive_kind(data), 'defect')
                report = E.Defect(data).verify()
                self.assertEqual(report.verdict, verdict)
                if code:
                    self.assertEqual(report.checks[0].code, code)

    def test_defect_file_bytes_are_frozen(self):
        """`write_defect` pisze deterministycznie — te same bajty co w wektorze."""
        cases = {c['name']: c for c in self.v['cases'] if c['kind'] == 'defect'}
        for entry in self.v['defect_files']:
            case = cases.get(entry['name'].removeprefix('file-'))
            if case is None:
                continue
            with self.subTest(case=case['name']):
                ciphertext = b64d(case['ciphertext'])
                out = io.BytesIO()
                E.write_defect(out, offer=case['offer'], part_a=b64d(case['a']),
                               part_b=bytes.fromhex(case['b']),
                               ciphertext=io.BytesIO(ciphertext), size=len(ciphertext))
                self.assertEqual(out.getvalue(), b64d(entry['zip']))

    def test_defect_report_shows_what_the_preview_hid(self):
        entry = next(c for c in self.v['defect_files']
                     if c['name'] == 'file-defect-preview-differs-from-content')
        check = E.Defect(b64d(entry['zip'])).verify().checks[0]
        self.assertEqual(check.data['differences'], ['title'])
        self.assertEqual(check.data['preview']['title'], 'Zaproszenie na urodziny')
        self.assertEqual(check.data['manifest']['title'], 'Pismo')

    def test_archive_kind_tells_the_two_zips_apart(self):
        self.assertEqual(E.archive_kind(b64d(self.v['evidence_zip'])), 'evidence')
        self.assertEqual(E.archive_kind(b64d(self.v['defect_files'][0]['zip'])), 'defect')
        self.assertIsNone(E.archive_kind(b'not a zip'))


class JcsAndEncodingTests(unittest.TestCase):
    def test_dumps_matches_rfc8785_for_the_subset(self):
        self.assertEqual(jcs.dumps({'b': 'ż\n\x01', 'a': [1, True, None]}),
                         '{"a":[1,true,null],"b":"ż\\n\\u0001"}'.encode())

    def test_dumps_refuses_what_jcs_would_encode_differently(self):
        for bad in ({'a': 1.5}, {'ż': 1}, {'a': 2 ** 53}, {'a': '\ud800'}, {'a': b'x'}):
            with self.subTest(bad=bad), self.assertRaises(HandoverError):
                jcs.dumps(bad)

    def test_depth_limit(self):
        deep: object = 1
        for _ in range(9):
            deep = [deep]
        with self.assertRaises(HandoverError) as cm:
            jcs.dumps(deep)
        self.assertEqual(cm.exception.code, 'json-depth')

    def test_base64_alias_is_rejected(self):
        data = b'\x00\x01'
        good = X.b64encode(data)                     # 'AAE='
        self.assertEqual(X.b64decode(good, 'x'), data)
        with self.assertRaises(HandoverError):
            X.b64decode('AAF=', 'x')                 # ten sam bajt, inne nieuzywane bity

    def test_crockford(self):
        self.assertEqual(X.crockford(bytes(5)), '00000000')
        self.assertEqual(X.crockford(b'\xff' * 5), 'ZZZZZZZZ')
        sample = X.crockford(hashlib.sha512(b'crockford').digest())
        self.assertFalse(set('ILOU') & set(sample))          # litery mylone przy czytaniu


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.pub = X.p256_public_bytes(self.key.public_key())

    def test_es256_round_trip_is_low_s_and_deterministic(self):
        sig = X.es256_sign(self.key, b'hello')
        self.assertEqual(sig, X.es256_sign(self.key, b'hello'))
        self.assertLessEqual(int.from_bytes(sig[32:], 'big'), X.P256_N // 2)
        X.es256_verify(self.pub, b'hello', sig)
        with self.assertRaises(HandoverError):
            X.es256_verify(self.pub, b'hellO', sig)

    def test_high_s_twin_is_rejected(self):
        sig = X.es256_sign(self.key, b'hello')
        s = int.from_bytes(sig[32:], 'big')
        with self.assertRaises(HandoverError):
            X.es256_verify(self.pub, b'hello', sig[:32] + (X.P256_N - s).to_bytes(32, 'big'))

    def test_invalid_point_is_rejected(self):
        bad = b'\x04' + bytes(64)
        with self.assertRaises(HandoverError) as cm:
            X.p256_public(bad)
        self.assertEqual(cm.exception.code, 'key')

    def test_webauthn_requires_user_verification_and_our_rp(self):
        sig = X.webauthn_sign(self.key, b'msg')
        X.webauthn_verify(self.pub, b'msg', sig)
        for bad in (X.webauthn_sign(self.key, b'msg', user_verified=False),
                    X.webauthn_sign(self.key, b'msg', rp_id='evil.example'),
                    X.webauthn_sign(self.key, b'other')):
            with self.subTest(), self.assertRaises(HandoverError):
                X.webauthn_verify(self.pub, b'msg', bad)

    def test_hpke_binds_context(self):
        key = X.EncKey.generate()
        ct = X.hpke_seal(key.public_bytes, b'A' * 32, b'ctx-1')
        self.assertEqual(len(ct), X.HPKE_OVERHEAD + 32)
        self.assertEqual(key.open(ct, b'ctx-1'), b'A' * 32)
        for info, k in ((b'ctx-2', key), (b'ctx-1', X.EncKey.generate())):
            with self.subTest(), self.assertRaises(HandoverError):
                k.open(ct, info)
        self.assertEqual(X.EncKey.from_bytes(key.to_bytes()).public_bytes, key.public_bytes)


@unittest.skipUnless(SERVER_STREAM.exists(),
                     'brak apps/seal/stream.py (publiczna migawka desktopu bez serwera)')
class StreamParityTests(unittest.TestCase):
    """Lustro apps/seal/stream.py: bajt w bajt ten sam szyfrogram co serwer."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('server_seal_stream', SERVER_STREAM)
        cls.server = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.server)

    def test_same_bytes_as_the_server(self):
        key, prefix, aad = bytes(range(32)), b'\x07' * 7, b'aad'
        for size in (0, 1, 65_535, 65_536, 65_537, 200_000):
            data = hashlib.sha256(str(size).encode()).digest() * (size // 32 + 1)
            data = data[:size]
            ours, theirs = io.BytesIO(), io.BytesIO()
            stream.encrypt(key, prefix, aad, io.BytesIO(data), ours)
            self.server.encrypt(key, prefix, aad, io.BytesIO(data), theirs)
            with self.subTest(size=size):
                self.assertEqual(ours.getvalue(), theirs.getvalue())
                self.assertEqual(len(ours.getvalue()), stream.ciphertext_size(size))


class TextRuleTests(unittest.TestCase):
    def test_line_feed_only_in_note(self):
        rules.check_text('a\nb', 'note', 10, allow_lf=True)
        with self.assertRaises(HandoverError):
            rules.check_text('a\nb', 'title', 10)
        with self.assertRaises(HandoverError):
            rules.check_text('a\rb', 'note', 10, allow_lf=True)

    def test_bidi_and_separators(self):
        for ch in ('‮', '⁦', '‏', ' ', '؜'):
            with self.subTest(ch=hex(ord(ch))), self.assertRaises(HandoverError):
                rules.check_text(f'x{ch}y', 'title', 10)

    def test_emoji_joiner_is_allowed(self):
        rules.check_text('rodzina \U0001F468‍\U0001F469‍\U0001F467', 'title', 50)

    def test_risky_extensions(self):
        self.assertTrue(rules.is_risky('faktura.PDF.exe'))
        self.assertTrue(rules.is_risky('umowa.docm'))
        self.assertFalse(rules.is_risky('umowa.pdf'))

    def test_manifest_rejects_case_insensitive_duplicates(self):
        files = [P.InputFile('Umowa.pdf', b'1', 'application/pdf'),
                 P.InputFile('umowa.PDF', b'2', 'application/pdf')]
        with self.assertRaises(HandoverError) as cm:
            P.build_manifest(files, title='', note='', salt=bytes(16))
        self.assertEqual(cm.exception.code, 'manifest-rules')


class _Party:
    def __init__(self, signer):
        self.sig = signer
        self.enc = X.EncKey.generate()
        self.card = I.make_card(signer, self.enc.public_bytes, ts('2026-09-30T10:00:00'))
        self.info = I.read_card(self.card)


class ProtocolRuleTests(unittest.TestCase):
    """Ataki z tabeli §13 odtworzone wprost na swiezych kluczach."""

    def setUp(self):
        self.s = _Party(I.SoftwareSigner())
        self.r = _Party(I.SoftwareSigner())
        self.ct = io.BytesIO()
        self.out = P.create_offer(signer=self.s.sig, sender_card=self.s.card,
                                  recipient_card=self.r.card, ciphertext_out=self.ct,
                                  files=[P.InputFile('a.txt', b'tresc', 'text/plain')],
                                  created=ts('2026-10-01T12:00:00'))
        self.offer = self.out.info

    def test_signer_must_match_the_card(self):
        with self.assertRaises(HandoverError) as cm:
            P.create_offer(signer=self.r.sig, sender_card=self.s.card, recipient_card=self.r.card,
                           ciphertext_out=io.BytesIO(), files=[P.InputFile('a.txt', b'x')],
                           created=ts('2026-10-01T12:00:00'))
        self.assertEqual(cm.exception.code, 'signer')

    def test_offer_times(self):
        P.check_offer_times(self.offer, ts('2026-10-02T00:00:00'))
        for now, code in ((ts('2026-10-01T11:50:00'), 'offer-created-future'),
                          (ts('2026-10-31T12:00:00'), 'offer-expired')):
            with self.subTest(code=code), self.assertRaises(HandoverError) as cm:
                P.check_offer_times(self.offer, now)
            self.assertEqual(cm.exception.code, code)

    def test_no_answer_after_expiry(self):
        with self.assertRaises(HandoverError) as cm:
            A_.make_answer(self.r.sig, self.offer, 'refuse', log_now=ts('2026-10-31T12:00:00'))
        self.assertEqual(cm.exception.code, 'offer-expired')

    def test_publish_margin_and_refusal(self):
        acc = A_.read_answer(A_.make_answer(self.r.sig, self.offer, 'accept',
                                            log_now=ts('2026-10-02T09:00:00'),
                                            ciphertext_sha256=self.offer.ciphertext_sha256),
                             self.offer)
        A_.check_publish(acc, ts('2026-10-16T07:59:59'))
        for now, refused, code in ((ts('2026-10-16T08:00:01'), False, 'answer-deadline-near'),
                                   (ts('2026-10-02T10:00:00'), True, 'offer-refused')):
            with self.subTest(code=code), self.assertRaises(HandoverError) as cm:
                A_.check_publish(acc, now, refused=refused)
            self.assertEqual(cm.exception.code, code)
        ref = A_.read_answer(A_.make_answer(self.r.sig, self.offer, 'refuse',
                                            log_now=ts('2026-10-02T09:00:00')), self.offer)
        with self.assertRaises(HandoverError) as cm:
            A_.check_publish(ref, ts('2026-10-02T10:00:00'))
        self.assertEqual(cm.exception.code, 'answer-refused')

    def test_accept_requires_the_offered_ciphertext(self):
        with self.assertRaises(HandoverError) as cm:
            A_.make_answer(self.r.sig, self.offer, 'accept', log_now=ts('2026-10-02T09:00:00'),
                           ciphertext_sha256=bytes(32))
        self.assertEqual(cm.exception.code, 'answer-ciphertext')

    def test_ciphertext_copy_checks_size_and_hash(self):
        data = self.ct.getvalue()
        P.copy_ciphertext(self.offer, io.BytesIO(data))
        for bad, code in ((data[:-1], 'ciphertext-size'), (data + b'x', 'ciphertext-size'),
                          (data[:-1] + bytes([data[-1] ^ 1]), 'ciphertext-hash')):
            with self.subTest(code=code), self.assertRaises(HandoverError) as cm:
                P.copy_ciphertext(self.offer, io.BytesIO(bad))
            self.assertEqual(cm.exception.code, code)

    def test_file_changed_while_packing(self):
        class Flaky(P.InputFile):
            calls = 0

            def open(self):
                Flaky.calls += 1
                return io.BytesIO(b'first' if Flaky.calls == 1 else b'second')

        with self.assertRaises(HandoverError) as cm:
            P.create_offer(signer=self.s.sig, sender_card=self.s.card, recipient_card=self.r.card,
                           ciphertext_out=io.BytesIO(), files=[Flaky('a.txt', b'')],
                           created=ts('2026-10-01T12:00:00'))
        self.assertEqual(cm.exception.code, 'file-changed')

    def test_wrong_b_never_decrypts(self):
        with self.assertRaises(HandoverError) as cm:
            P.decrypt_package(self.offer, self.out.parts.a, bytes(32),
                              io.BytesIO(self.ct.getvalue()), io.BytesIO())
        self.assertEqual(cm.exception.code, 'part-b-commit')


class ContainerTests(unittest.TestCase):
    def _container(self, files):
        manifest = P.build_manifest(files, title='t', note='', salt=bytes(16))
        src = P._ContainerSource(manifest, files)
        return b''.join(iter(lambda: src.read(4096), b''))

    def test_extract_names_collisions_and_marks(self):
        files = [P.InputFile('umowa.pdf', b'abc', 'application/pdf')]
        data = self._container(files)
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            (folder / 'umowa.pdf').write_bytes(b'moja wersja')
            manifest, saved = P.extract_container(io.BytesIO(data), len(data), folder)
            self.assertEqual([p.name for p in saved], ['umowa (2).pdf'])
            self.assertEqual(saved[0].read_bytes(), b'abc')
            self.assertEqual((folder / 'umowa.pdf').read_bytes(), b'moja wersja')
            if os.name == 'nt':
                zone = Path(f'{saved[0]}:Zone.Identifier')
                self.assertIn('ZoneId=3', zone.read_text(encoding='ascii'))

    def test_tampered_file_is_never_released(self):
        data = bytearray(self._container([P.InputFile('a.txt', b'hello', 'text/plain')]))
        data[-1] ^= 1
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(HandoverError) as cm:
                P.extract_container(io.BytesIO(bytes(data)), len(data), Path(d))
            self.assertEqual(cm.exception.code, 'file-hash')
            self.assertEqual(list(Path(d).iterdir()), [])

    def test_trailing_bytes_and_short_container(self):
        data = self._container([P.InputFile('a.txt', b'hello', 'text/plain')])
        for bad in (data + b'x', data[:-1]):
            with self.subTest(n=len(bad)), self.assertRaises(HandoverError) as cm:
                P.check_container(io.BytesIO(bad), len(bad))
            self.assertEqual(cm.exception.code, 'container-size')


class EvidenceArchiveTests(unittest.TestCase):
    def test_unknown_or_traversing_names_are_rejected(self):
        import warnings
        import zipfile

        for extra in ('../evil.txt', 'other.json', 'evidence.json'):
            out = io.BytesIO()
            with zipfile.ZipFile(out, 'w') as z, warnings.catch_warnings():
                warnings.simplefilter('ignore')             # celowy duplikat nazwy
                z.writestr('evidence.json', b'{}')
                z.writestr(extra, b'x')
            with self.subTest(extra=extra), self.assertRaises(HandoverError) as cm:
                E.Evidence(out.getvalue())
            self.assertEqual(cm.exception.code, 'evidence-archive')



JS_VERIFIER = Path(__file__).resolve().parents[2] / 'robocze' / 'handover_js' / 'test-verify.mjs'


@unittest.skipUnless(shutil.which('node') and JS_VERIFIER.exists(),
                     'brak node albo weryfikatora JS (repo desktopu bez strony)')
class JsVerifierParityTests(unittest.TestCase):
    """Niezalezny weryfikator JS (apps/web/static/web/handover/verify.js) na TYCH
    SAMYCH wektorach. Zmiana w Pythonie albo w wektorach bez zmiany w JS
    wychodzi tutaj, a nie u uzytkownika, ktorego dowod dwa programy ocenia
    roznie."""

    def test_js_verifier_agrees_with_the_vectors(self):
        import subprocess

        root = JS_VERIFIER.parents[2]
        r = subprocess.run([shutil.which('node'), str(JS_VERIFIER), str(root)],
                           capture_output=True, text=True, encoding='utf-8', errors='replace',
                           timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-2000:])


class RoundTripTests(unittest.TestCase):
    """Pelny przebieg §0.1 na swiezych kluczach, z plikami na dysku."""

    def test_full_handover(self):
        s = _Party(I.SoftwareSigner())
        r = _Party(I.SoftwareWebAuthnSigner(storage='hardware-uv'))
        binding = I.make_binding(s.sig, s.info, r.info, 'qr-in-person', date(2026, 9, 30))
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            big = folder / 'skan.bin'
            big.write_bytes(os.urandom(150_000))
            files = [P.InputFile('skan.bin', big), P.InputFile('Opis — ż.txt', 'ż\n'.encode(),
                                                               'text/plain')]
            ct_path = folder / 'ct.bin'
            with open(ct_path, 'wb') as ct:
                out = P.create_offer(signer=s.sig, sender_card=s.card, recipient_card=r.card,
                                     files=files, ciphertext_out=ct, created=ts('2026-10-01T12:00:00'),
                                     title='Skan', sender_name='Nadawca')
            package_path = folder / 'paczka.sigelith'
            with open(package_path, 'wb') as dst, open(ct_path, 'rb') as src:
                T.write_package_file(dst, r.info.enc_key, out.offer, src, out.info.ciphertext_size)

            with open(package_path, 'rb') as src:
                offer_raw, _ = T.read_package_file(src, [r.enc])
                offer = P.read_offer(offer_raw)
                a, preview = P.open_offer(offer, r.enc, r.info)
                held = folder / 'held.bin'
                with open(held, 'wb') as dst:
                    P.copy_ciphertext(offer, src, dst)
            answer = A_.make_answer(r.sig, offer, 'accept', log_now=ts('2026-10-02T09:00:00'),
                                    ciphertext_sha256=offer.ciphertext_sha256)
            text = T.answer_text(T.write_answer_file(offer.sender.enc_key, answer))
            wrapped = '\n'.join(text[i:i + 76] for i in range(0, len(text), 76))
            got = A_.read_answer(T.read_answer_file(T.parse_answer_text(wrapped), [s.enc]),
                                 out.info)
            A_.check_publish(got, ts('2026-10-02T09:05:00'))

            b, _ = logsearch.find_part_b([{'digest': out.parts.b.hex()}], offer.commit_b)
            with open(held, 'rb') as src:
                manifest, saved, diffs = P.open_package(offer, a, b, src, preview, folder / 'odebrane')
            self.assertEqual(diffs, [])
            self.assertEqual(saved[0].read_bytes(), big.read_bytes())

            log = E.DictLog({out.info.digest.hex(): '2026-10-01T12:00:03Z',
                             got.digest.hex(): '2026-10-02T09:00:01Z',
                             b.hex(): '2026-10-02T09:05:02Z',
                             I.read_binding(binding, s.info, r.info).digest.hex():
                                 '2026-09-30T19:00:00Z'})
            with open(held, 'rb') as src:
                container = io.BytesIO()
                P.decrypt_package(offer, a, b, src, container)
            ev = E.Evidence(E.build_evidence(offer=out.offer, answer=answer, part_b=b,
                                             binding=binding, log={},
                                             container=container.getvalue()))
            report = ev.verify(log)
            self.assertEqual(report.verdict, 'delivered', report.failed)
            self.assertEqual(report.failed, [])
            self.assertEqual(report.binding_level, 1)


if __name__ == '__main__':
    unittest.main()
