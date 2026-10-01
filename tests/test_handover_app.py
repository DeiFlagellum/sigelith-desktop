"""
Testy warstwy aplikacji Sigelith Handover (beatstamp/handover_app/).

Protokol sprawdza tests/test_handover.py na zamrozonych wektorach. Tutaj:
sekrety na dysku (DPAPI), Windows Hello (bez pytania o PIN — to robi reczna
sonda tools/winhello_probe.py) i magazyn stanu.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from beatstamp.handover import identity as I, primitives as X  # noqa: E402
from beatstamp.handover_app import dpapi, store as S, winhello as WH  # noqa: E402

WINDOWS = sys.platform == 'win32'
NOW = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)


def _card():
    signer = I.SoftwareSigner()
    enc = X.EncKey.generate()
    card = I.make_card(signer, enc.public_bytes, NOW)
    return card, I.read_card(card).fingerprint_hex


@unittest.skipUnless(WINDOWS, 'DPAPI jest tylko w Windows')
class DpapiTests(unittest.TestCase):
    def test_round_trip(self):
        blob = dpapi.protect(b'\x00sekret\xff', 'enc-key')
        self.assertNotIn(b'sekret', blob)
        self.assertEqual(dpapi.unprotect(blob, 'enc-key'), b'\x00sekret\xff')

    def test_purpose_is_bound(self):
        """Blob klucza nie da sie podsunac jako blob czesci B."""
        blob = dpapi.protect(b'x' * 32, 'enc-key')
        with self.assertRaises(dpapi.DpapiError):
            dpapi.unprotect(blob, 'part-b')

    def test_tampered_blob_is_rejected(self):
        blob = bytearray(dpapi.protect(b'x' * 32, 'part-b'))
        blob[-1] ^= 1
        with self.assertRaises(dpapi.DpapiError):
            dpapi.unprotect(bytes(blob), 'part-b')

    def test_purpose_must_be_ascii(self):
        with self.assertRaises(ValueError):
            dpapi.protect(b'x', 'część')


class _FakeDll:
    def __init__(self, name=''):
        self.name = name

    def WebAuthNGetErrorName(self, hr):  # noqa: N802 — nazwa z webauthn.h
        return self.name


class WindowsHelloTests(unittest.TestCase):
    """Bez okna systemowego: tylko to, co nie wymaga czlowieka."""

    def test_errors_of_the_person_are_not_failures(self):
        for hr, name, kind in ((0x800704C7, '', 'cancelled'), (0x80090036, '', 'cancelled'),
                               (0x80004005, 'NotAllowedError', 'cancelled'),
                               (0x80090011, '', 'not-found'), (0x80004005, 'UnknownError', 'failed')):
            with self.subTest(hr=hex(hr), name=name):
                with self.assertRaises(WH.HelloError) as cm:
                    WH._check(_FakeDll(name), hr - (1 << 32), 'x')
                self.assertEqual(cm.exception.kind, kind)
        WH._check(_FakeDll(), 0, 'x')                  # S_OK nie rzuca

    def test_companion_only_for_tpm(self):
        cred = WH.Credential(cred_id=b'id', public=b'\x04' + bytes(64), fmt='tpm',
                             attestation_object=b'\xa0', client_data_json=b'{}')
        comp = cred.companion('ab' * 32)
        self.assertEqual(set(comp), {'v', 'type', 'card', 'fmt', 'attestation_object',
                                     'client_data_json'})
        self.assertEqual((comp['type'], comp['fmt'], comp['card']), ('attestation', 'tpm', 'ab' * 32))
        packed = WH.Credential(cred_id=b'id', public=b'', fmt='packed', attestation_object=b'',
                               client_data_json=b'')
        self.assertIsNone(packed.companion('ab' * 32))

    def test_signer_refuses_a_key_off_the_curve(self):
        with self.assertRaises(Exception):
            WH.WindowsHelloSigner(b'id', b'\x04' + bytes(64))

    def test_availability_is_a_plain_answer(self):
        self.assertIsInstance(WH.available(), bool)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.store = S.HandoverStore(self.dir)

    def test_contacts_round_trip_sorted(self):
        (a, fa), (b, fb) = _card(), _card()
        self.store.save_contact(S.Contact(fingerprint=fa, card=a, label='zenon', binding={}, added='x'))
        self.store.save_contact(S.Contact(fingerprint=fb, card=b, label='Ala', binding={}, added='x'))
        self.assertEqual([c.label for c in self.store.contacts()], ['Ala', 'zenon'])
        self.store.remove_contact(fb)
        self.assertEqual([c.fingerprint for c in self.store.contacts()], [fa])

    def test_broken_card_never_reaches_the_store(self):
        card, fp = _card()
        card['created'] = '2026-09-29T00:00:00Z'               # podpis juz nie pasuje
        with self.assertRaises(Exception):
            self.store.save_contact(S.Contact(fingerprint=fp, card=card, label='x', binding={}, added='x'))
        self.assertFalse((self.dir / 'contacts.json').exists())

    def test_active_identity_is_the_newest_live_one(self):
        (c1, f1), (c2, f2) = _card(), _card()
        self.store.save_identity(S.Identity(fingerprint=f1, card=c1, enc_blob='', created='1'))
        self.store.save_identity(S.Identity(fingerprint=f2, card=c2, enc_blob='', created='2',
                                            archived=True))
        self.assertEqual(self.store.active_identity().fingerprint, f1)
        self.assertEqual(len(self.store.identities()), 2)

    def test_items_round_trip_and_digest_rule(self):
        rec = S.Outgoing(offer_digest='ab' * 32, offer={}, contact='cd' * 32, title='t',
                         files=['a.pdf'], total_size=3, part_a_blob='', part_b_blob='',
                         created='2026-09-28T12:00:00Z')
        self.store.save_outgoing(rec)
        self.assertEqual(self.store.get_outgoing('ab' * 32), rec)
        self.assertIsNone(self.store.get_outgoing('cd' * 32))
        for bad in ('AB' * 32, '../x', 'ab' * 31):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.store.get_outgoing(bad)
        self.assertEqual(self.store.ciphertext_path('outgoing', 'ab' * 32).name,
                         'ab' * 32 + '.ciphertext')

    def test_newer_fields_are_ignored_and_unknown_format_refused(self):
        rec = S.Incoming(offer_digest='ab' * 32, offer={}, sender='x', my_card='y', preview={},
                         part_a_blob='', received='1')
        self.store.save_incoming(rec)
        path = self.dir / 'incoming' / ('ab' * 32 + '.json')
        data = json.loads(path.read_text(encoding='utf-8'))
        data['item']['future_field'] = 1
        path.write_text(json.dumps(data), encoding='utf-8')
        self.assertEqual(self.store.get_incoming('ab' * 32).status, 'new')
        data['format'] = 99
        path.write_text(json.dumps(data), encoding='utf-8')
        with self.assertRaises(ValueError):
            self.store.get_incoming('ab' * 32)

    def test_atomic_write_leaves_no_temporary_files(self):
        card, fp = _card()
        for label in ('a', 'b', 'c'):
            self.store.save_contact(S.Contact(fingerprint=fp, card=card, label=label, binding={}, added='x'))
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ['contacts.json'])


class PackagedSelftestTests(unittest.TestCase):
    """`--selftest` zbudowanej paczki: Handover bez PIN-u i bez sieci."""

    def test_the_whole_protocol_runs(self):
        from beatstamp import selftest
        detail = selftest._check_handover()
        self.assertIn('obieg protokolu OK', detail)
        self.assertIn('dowod wady OK', detail)
        if WINDOWS:
            self.assertIn('DPAPI OK', detail)
        self.assertIn(('Sigelith Handover', selftest._check_handover), selftest.LOCAL_CHECKS)

    def test_the_pdf_report_is_written(self):
        import os
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        from beatstamp import selftest
        self.assertIn('PDF/A', selftest._check_handover_report())
        self.assertIn(('raport PDF dla bieglego', selftest._check_handover_report),
                      selftest.LOCAL_CHECKS)

    @unittest.skipUnless(WINDOWS, 'DPAPI jest tylko w Windows')
    def test_dpapi_that_ignores_the_purpose_fails_the_check(self):
        from unittest import mock
        from beatstamp import selftest
        real = dpapi.unprotect
        with mock.patch.object(dpapi, 'unprotect', lambda blob, _purpose: real(blob, 'selftest')):
            with self.assertRaises(selftest.Failure):
                selftest._check_handover()


if __name__ == '__main__':
    unittest.main()
