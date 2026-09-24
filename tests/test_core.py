"""
Testy rdzenia: czas @beat, drzewo Merkle, weryfikacja dowodu.

Sedno tego zestawu to `test_proof.py`-owa część poniżej: sprawdzamy na
PRAWDZIWEJ odpowiedzi z beattime.live, ze lokalna weryfikacja daje wynik
pozytywny — i ze kazda pojedyncza manipulacja danymi ten wynik psuje. Test,
który tylko potwierdza poprawne dane, nie dowodzi niczego o bezpieczenstwie:
funkcja zwracajaca zawsze True przeszlaby go bez problemu.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from beatstamp import beatcore, bundle, i18n, merkle, proof  # noqa: E402

# Jezyk interfejsu PRZYPIETY. Testy sprawdzaja ZNACZENIE napisu — oczekiwany
# tekst bierzemy z tego samego katalogu tlumaczen, ktorego uzywa program
# (`_('<msgid>')`), a nie z przepisanego recznie ciagu znakow. Bez przypiecia
# wynik suite zalezalby od jezyka interfejsu maszyny, na ktorej akurat sie ja
# uruchamia; bez katalogu — sprawdzalibysmy literowke, a nie tresc.
i18n.set_language('pl')
_ = i18n.gettext


# Prawdziwa odpowiedz z https://beattime.live/api/proof/verify — pobrana
# 2026-09-22, po rotacji klucza. Tydzien 2026-W25 jest zamkniety, podpisany
# AKTUALNYM kluczem (keys.CURRENT_KEYS) i zakotwiczony w Bitcoinie, wiec
# pokrywa caly lancuch weryfikacji.
LIVE_PAYLOAD = json.loads(r'''
{"found":true,
 "digest":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
 "beat":"@348.28","utc":"2026-06-15T08:21:32.167366Z","seq":1,"week":"2026-W25",
 "chain_hash":"8a9e069ccaddecfbfe8b4fb71a303b1654686cec0a27bc68cf148f77bf309673",
 "week_root":"1b33c081be206b028d508be5046a3da6a195448fbded7d54a6f2e02d13a5749d",
 "week_closed":true,
 "root_signature":"jE/3hOnElv02G0o96S0VWgFaMdK4UB8S2R7B9ruIcpBL5VvEwoJ5CjjJdIEg/knRLsoR+1hrNPIDT9Lfw3TNCQ==",
 "public_key":"e7y9THJIUKvNKOZHmdBjJ8E0bOKyBFVxxMpAJ8w574Y=",
 "ots_status":"bitcoin","ots_bitcoin_height":954888,
 "ots_url":"/api/proof/ots/2026-W25",
 "inclusion_proof":[
   {"side":"R","hash":"b80134c1a206fef7c721bd6d3ff6f1ee4d92de4a6288c205be89bec651edbb43"},
   {"side":"R","hash":"98c99c1f1e0ccf6fd1740ae796529822971515fbe40548370025f3a28938af4a"},
   {"side":"R","hash":"9b5f044ca1f1245bed281eb6a5a75039357768aa36f40d567b9d46260da87c6b"},
   {"side":"R","hash":"a7392ee06250477afd7dd69386780d7c228a5d976a97168340bb333707add95d"}],
 "anchors":[{"bank":"Swissquote Bank SA (Swiss bank)","date":"2026-06-23",
             "status":"confirmed",
             "root":"1b33c081be206b028d508be5046a3da6a195448fbded7d54a6f2e02d13a5749d",
             "root_matches_week":true,
             "bank_reference":"1122189662","statement_url":""}]}
''')

# Ta sama odpowiedz pobrana 2026-09-12, PRZED rotacja: ten sam korzen, ale
# podpis kluczem, ktory 2026-09-21 trafil do keys.RETIRED_KEYS. Podpis jest
# matematycznie poprawny — i wlasnie dlatego ten przypadek wymaga osobnego
# testu: wycofany klucz podpisal tez inne (testowe) korzenie dla 2026-W25
# i 2026-W30, wiec jego podpis nie moze juz dawac poziomu PODPISANY.
RETIRED_KEY_PAYLOAD = json.loads(r'''
{"found":true,
 "digest":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
 "beat":"@348.28","utc":"2026-06-15T08:21:32.167366Z","seq":1,"week":"2026-W25",
 "chain_hash":"8a9e069ccaddecfbfe8b4fb71a303b1654686cec0a27bc68cf148f77bf309673",
 "week_root":"1b33c081be206b028d508be5046a3da6a195448fbded7d54a6f2e02d13a5749d",
 "week_closed":true,
 "root_signature":"lmfbzd4y7jyyXGPlCgi8LB0NwU1UVhbnAQdScH5Xb+eHU/idT78FNrkS6/TgSdQS6SFyXVFgFxKmJhUkfqRcAg==",
 "public_key":"YNVYXDyg3hQGM3F+/ec+ZNmeN1JI/hZX+CxLqyJdyN0=",
 "ots_status":"bitcoin","ots_bitcoin_height":954888,
 "ots_url":"/api/proof/ots/2026-W25",
 "inclusion_proof":[
   {"side":"R","hash":"b80134c1a206fef7c721bd6d3ff6f1ee4d92de4a6288c205be89bec651edbb43"},
   {"side":"R","hash":"98c99c1f1e0ccf6fd1740ae796529822971515fbe40548370025f3a28938af4a"},
   {"side":"R","hash":"9b5f044ca1f1245bed281eb6a5a75039357768aa36f40d567b9d46260da87c6b"},
   {"side":"R","hash":"a7392ee06250477afd7dd69386780d7c228a5d976a97168340bb333707add95d"}],
 "anchors":[{"bank":"Swissquote Bank SA (Swiss bank","date":"2026-06-23",
             "status":"confirmed",
             "root":"1b33c081be206b028d508be5046a3da6a195448fbded7d54a6f2e02d13a5749d",
             "bank_reference":"1122189662","statement_url":""}]}
''')

DIGEST = LIVE_PAYLOAD['digest']


class BeatCoreTests(unittest.TestCase):
    """Czas @beat musi zgadzac się z serwerem co do centibeatu."""

    def test_midnight_is_zero(self):
        dt = datetime(2026, 6, 15, 0, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(beatcore.format_beat(beatcore.beats_from_utc(dt)), '@000')

    def test_noon_is_500(self):
        dt = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(beatcore.format_beat(beatcore.beats_from_utc(dt)), '@500')

    def test_exact_centibeat_boundary(self):
        # 00:21:36 to dokladnie @015.00. Liczenie przez /86.4 dawalo tu 14.99
        # (86.4 nie jest przedstawialne binarnie) — stad mikrosekundy w rdzeniu.
        dt = datetime(2026, 6, 15, 0, 21, 36, tzinfo=timezone.utc)
        self.assertEqual(beatcore.format_beat(beatcore.beats_from_utc(dt), decimals=2),
                         '@015.00')

    def test_never_wraps_to_1000(self):
        # Zaokraglenie 999.6 daloby '@1000' — wartosc nieistniejaca.
        self.assertEqual(beatcore.format_beat(999.6), '@999')
        self.assertEqual(beatcore.format_beat(999.999, decimals=2), '@999.99')

    def test_matches_live_server_value(self):
        dt = beatcore.parse_iso_utc(LIVE_PAYLOAD['utc'])
        self.assertEqual(
            beatcore.format_beat(beatcore.beats_from_utc(dt), decimals=2),
            LIVE_PAYLOAD['beat'])

    def test_roundtrip_beat_to_utc(self):
        day = datetime(2026, 6, 15, tzinfo=timezone.utc)
        for beats in (0.0, 1.5, 250.25, 500.0, 999.99):
            back = beatcore.beats_from_utc(beatcore.beat_to_utc(beats, day))
            self.assertAlmostEqual(beats, back, places=4)

    def test_naive_datetime_treated_as_utc(self):
        naive = datetime(2026, 6, 15, 12, 0, 0)
        aware = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(beatcore.beats_from_utc(naive), beatcore.beats_from_utc(aware))

    def test_parse_iso_accepts_both_forms(self):
        a = beatcore.parse_iso_utc('2026-06-15T08:21:32.167366Z')
        b = beatcore.parse_iso_utc('2026-06-15T08:21:32.167366+00:00')
        self.assertEqual(a, b)

    def test_parse_iso_rejects_garbage(self):
        for value in ('', 'nie data', None, '2026-13-45'):
            self.assertIsNone(beatcore.parse_iso_utc(value))


class MerkleTests(unittest.TestCase):

    def test_digest_format_check(self):
        self.assertTrue(merkle.is_digest(DIGEST))
        # Wielkie litery PRZYJMUJEMY i normalizujemy. Hash wklejony z maila
        # albo z innego narzedzia bywa zapisany wielkimi literami, a odrzucenie
        # go komunikatem "nieprawidlowy skrot" byloby myleniem uzytkownika.
        # Do sieci i do porownan i tak zawsze idzie forma mala (api._require_digest,
        # merkle.fold_proof, proof.verify_payload).
        self.assertTrue(merkle.is_digest(DIGEST.upper()))
        self.assertTrue(merkle.is_digest(f'  {DIGEST}  '))    # spacje obcinamy
        self.assertFalse(merkle.is_digest(DIGEST[:-1]))      # 63 znaki
        self.assertFalse(merkle.is_digest(DIGEST + 'a'))     # 65 znakow
        self.assertFalse(merkle.is_digest('z' * 64))
        self.assertFalse(merkle.is_digest(None))

    def test_live_inclusion_proof_folds_to_root(self):
        """Sedno: prawdziwa ścieżka z serwera zwija się do prawdziwego korzenia."""
        self.assertTrue(merkle.verify_inclusion(
            DIGEST, LIVE_PAYLOAD['inclusion_proof'], LIVE_PAYLOAD['week_root']))

    def test_flipped_side_breaks_proof(self):
        tampered = copy.deepcopy(LIVE_PAYLOAD['inclusion_proof'])
        tampered[0]['side'] = 'L'
        self.assertFalse(merkle.verify_inclusion(
            DIGEST, tampered, LIVE_PAYLOAD['week_root']))

    def test_one_changed_bit_breaks_proof(self):
        tampered = copy.deepcopy(LIVE_PAYLOAD['inclusion_proof'])
        first = tampered[0]['hash']
        tampered[0]['hash'] = ('0' if first[0] != '0' else '1') + first[1:]
        self.assertFalse(merkle.verify_inclusion(
            DIGEST, tampered, LIVE_PAYLOAD['week_root']))

    def test_different_digest_breaks_proof(self):
        other = 'a' * 64
        self.assertFalse(merkle.verify_inclusion(
            other, LIVE_PAYLOAD['inclusion_proof'], LIVE_PAYLOAD['week_root']))

    def test_malformed_proof_returns_false_not_exception(self):
        for bad in ([{'side': 'X', 'hash': 'a' * 64}],
                    [{'side': 'R', 'hash': 'nie hex'}],
                    [{'side': 'R'}],
                    ['nie slownik'],
                    [{'side': 'R', 'hash': 'ab'}]):
            self.assertFalse(merkle.verify_inclusion(
                DIGEST, bad, LIVE_PAYLOAD['week_root']))


class ProofVerificationTests(unittest.TestCase):

    def test_live_payload_is_fully_trusted(self):
        r = proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST)
        self.assertTrue(r.found)
        self.assertTrue(r.inclusion_checked and r.inclusion_ok)
        self.assertTrue(r.signature_checked and r.signature_ok)
        self.assertTrue(r.key_pinned_ok)
        self.assertEqual(r.signer_status, 'current')
        self.assertTrue(r.trusted)
        self.assertIs(r.level, proof.Level.ANCHORED)
        self.assertEqual(r.problems, [])
        self.assertEqual(r.warnings, [])

    def test_server_answering_about_another_document_is_rejected(self):
        """Serwer odpowiada dowodem na INNY skrót niż wysłany."""
        r = proof.verify_payload(LIVE_PAYLOAD, expected_digest='b' * 64)
        self.assertFalse(r.found)
        self.assertFalse(r.trusted)
        self.assertTrue(any('INNY skrót' in p for p in r.problems))

    def test_tampered_root_is_caught(self):
        payload = copy.deepcopy(LIVE_PAYLOAD)
        payload['week_root'] = 'f' * 64
        r = proof.verify_payload(payload, expected_digest=DIGEST)
        self.assertFalse(r.inclusion_ok)
        self.assertFalse(r.signature_ok)     # podpis dotyczy prawdziwego korzenia
        self.assertFalse(r.trusted)

    def test_tampered_signature_is_caught(self):
        payload = copy.deepcopy(LIVE_PAYLOAD)
        sig = payload['root_signature']
        payload['root_signature'] = ('A' if sig[0] != 'A' else 'B') + sig[1:]
        r = proof.verify_payload(payload, expected_digest=DIGEST)
        self.assertFalse(r.signature_ok)
        self.assertFalse(r.trusted)

    def test_foreign_key_with_valid_signature_is_rejected(self):
        """Najwazniejszy test bezpieczeństwa w całym zestawie.

        Podszywajacy się serwer generuje WLASNA pare kluczy i podpisuje nią
        korzeń. Podpis jest wtedy matematycznie POPRAWNY — sprawdzony własnym
        kluczem zgadza się idealnie. Obronic może tylko porównanie z lista
        kluczy wbudowana w aplikacje (keys.py).
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import base64

        rogue = Ed25519PrivateKey.generate()
        message = f"beattime-proof-v1|{LIVE_PAYLOAD['week']}|{LIVE_PAYLOAD['week_root']}"
        payload = copy.deepcopy(LIVE_PAYLOAD)
        payload['root_signature'] = base64.b64encode(
            rogue.sign(message.encode())).decode()
        payload['public_key'] = base64.b64encode(rogue.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

        r = proof.verify_payload(payload, expected_digest=DIGEST)
        self.assertTrue(r.signature_ok, 'podpis jest poprawny własnym kluczem')
        self.assertFalse(r.key_pinned_ok, 'ale klucza nie ma na liście BeatTime')
        self.assertEqual(r.signer_status, 'unknown')
        self.assertFalse(r.trusted, 'więc calosc musi być odrzucona')
        self.assertTrue(any('INNYM kluczem' in p for p in r.problems))

    def test_not_found_payload(self):
        r = proof.verify_payload({'found': False, 'digest': DIGEST})
        self.assertFalse(r.found)
        self.assertIs(r.level, proof.Level.NONE)

    def test_open_week_is_trusted_but_only_recorded(self):
        """Swiezy stempel: nie ma jeszcze czego sprawdzac — i to jest w porzadku."""
        payload = {'found': True, 'digest': DIGEST, 'beat': '@100.00',
                   'utc': '2026-09-12T02:24:00Z', 'seq': 99, 'week': '2026-W37',
                   'week_closed': False, 'week_root': '', 'ots_status': 'none'}
        r = proof.verify_payload(payload, expected_digest=DIGEST)
        self.assertTrue(r.found)
        self.assertTrue(r.trusted)
        self.assertIs(r.level, proof.Level.RECORDED)
        self.assertFalse(r.signature_checked)

    def test_garbage_input_does_not_raise(self):
        for bad in (None, [], 'tekst', 42, {'found': True, 'digest': 'zle'}):
            r = proof.verify_payload(bad)          # type: ignore[arg-type]
            self.assertFalse(r.trusted)


class BundleTests(unittest.TestCase):

    def test_roundtrip_from_live_payload(self):
        result = proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST)
        data = bundle.build(result, file_name='umowa.pdf')
        # Nic nie uzupelniamy recznie: dowod zbudowany z wyniku weryfikacji
        # musi byc od razu KOMPLETNY. Gdyby gubil podpis korzenia, plik
        # .beatproof nie dalby sie sprawdzic offline u odbiorcy — a to jedyny
        # powod, dla ktorego ten format istnieje.
        self.assertEqual(data['root_signature'], LIVE_PAYLOAD['root_signature'])
        check = bundle.check(data, document_digest=DIGEST)
        self.assertTrue(check.ok, check.problems)
        self.assertTrue(check.file_matches)
        self.assertTrue(check.inclusion_ok)
        self.assertTrue(check.signature_ok)
        self.assertTrue(check.key_pinned_ok)

    def test_wrong_document_is_detected(self):
        result = proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST)
        data = bundle.build(result)
        check = bundle.check(data, document_digest='c' * 64)
        self.assertFalse(check.ok)
        self.assertFalse(check.file_matches)
        self.assertTrue(any('NIE zgadza' in p for p in check.problems))

    def test_bundle_via_history_entry_is_complete(self):
        """Regresja: eksport z HISTORII tez musi być weryfikowalny offline.

        Dowód idzie do pliku dwiema drogami — prosto z wyniku weryfikacji
        i z zapisanego wpisu historii. Druga droga przechodzi przez
        `entry_from_verification`, gdzie podpis korzenia dało się zgubic.
        """
        from beatstamp.history import Entry, entry_from_verification

        result = proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST)
        entry = entry_from_verification(result, file_name='umowa.pdf')
        self.assertEqual(entry.root_signature, LIVE_PAYLOAD['root_signature'])

        # Pelna droga: wpis -> JSON -> wpis -> dowod (tak jak po restarcie).
        restored = Entry.from_dict(entry.to_dict())
        check = bundle.check(bundle.build(restored), document_digest=DIGEST)
        self.assertTrue(check.ok, check.problems)

    def test_unknown_format_rejected(self):
        check = bundle.check({'format': 'cos-innego-v9', 'digest': DIGEST})
        self.assertFalse(check.ok)
        self.assertTrue(any('Nieznany format' in p for p in check.problems))

    def test_incomplete_bundle_is_not_ok_but_has_no_problems(self):
        """Dowód z otwartego tygodnia: niekompletny, ale nie fałszywy."""
        data = bundle.build(proof.verify_payload(
            {'found': True, 'digest': DIGEST, 'week': '2026-W37',
             'week_closed': False}, expected_digest=DIGEST))
        check = bundle.check(data, document_digest=DIGEST)
        self.assertFalse(check.ok)
        self.assertEqual(check.problems, [])
        self.assertTrue(check.notes)


if __name__ == '__main__':
    unittest.main(verbosity=2)
