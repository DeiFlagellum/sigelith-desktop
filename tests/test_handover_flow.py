"""
Pelny przebieg Sigelith Handover w aplikacji (HANDOVER_SPEC.md §7) — dwa
profile (nadawca i odbiorca, osobne katalogi) i dziennik w pamieci, ktory
wystawia kwity TESTOWYM kluczem dokladnie jak serwer (§9.2).

Karty sa programowe (Windows Hello wymaga czlowieka — reczna sonda
tools/winhello_probe.py), sekrety ida przez prawdziwe DPAPI (na Windows).
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from beatstamp.handover import evidence as E, package as P, primitives as X, receipt as R  # noqa: E402
from beatstamp.handover_app import service as SV  # noqa: E402
from beatstamp.handover_app.store import HandoverStore  # noqa: E402

UTC = timezone.utc
WINDOWS = sys.platform == 'win32'


def _canonical(moment: datetime) -> str:
    return moment.strftime('%Y-%m-%dT%H:%M:%S.%fZ')


class FakeLog:
    """Dziennik Sigelith w pamieci: stempel idempotentny, kwit, wpisy od `seq`."""

    def __init__(self, start: datetime = datetime(2026, 10, 1, 9, 0, 0, 123456, tzinfo=UTC)) -> None:
        self.key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'vector log key').digest())
        self.public = X.b64encode(self.key.public_key().public_bytes_raw())
        self.clock = start
        self.rows: list[dict] = []
        self.by_digest: dict[str, dict] = {}
        self.prev = '0' * 64
        self.offline = False
        # Kolejne wywolania `stamp`: 'down' — blad sieci, nic nie zapisane;
        # 'lost' — wpis zapisany, ale odpowiedz nie dotarla. Pusta lista = normalnie.
        self.stamp_faults: list[str] = []
        self.entries_from: list[int] = []

    def _online(self) -> None:
        if self.offline:
            raise OSError('brak sieci (test)')

    def advance(self, **delta) -> None:
        self.clock += timedelta(**delta)

    def now(self) -> datetime:
        self._online()
        return self.clock

    def stamp(self, digest: bytes) -> dict:
        self._online()
        fault = self.stamp_faults.pop(0) if self.stamp_faults else 'ok'
        if fault == 'down':
            raise OSError('brak sieci (test)')
        h = digest.hex()
        if h not in self.by_digest:
            self.advance(seconds=2)
            chain = hashlib.sha256((self.prev + h + _canonical(self.clock)).encode()).hexdigest()
            self.prev = chain
            row = {'seq': len(self.rows) + 1, 'digest': h, 'utc': self.clock, 'chain_hash': chain}
            self.rows.append(row)
            self.by_digest[h] = row
        if fault == 'lost':
            raise OSError('odpowiedz nie dotarla (test)')
        return self._payload(h)

    def _payload(self, h: str) -> dict:
        row = self.by_digest[h]
        body = {'v': 'sigelith-receipt-v1', 'seq': row['seq'], 'digest': h,
                'utc': _canonical(row['utc']), 'chain_hash': row['chain_hash'], 'key': self.public}
        year, week, _ = row['utc'].isocalendar()
        return {'found': True, 'digest': h, 'utc': row['utc'].isoformat().replace('+00:00', 'Z'),
                'seq': row['seq'], 'week': f'{year}-W{week:02d}', 'chain_hash': row['chain_hash'],
                'receipt': dict(body, sig=X.b64encode(self.key.sign(R.message(body))))}

    def verify_text(self, digest: bytes) -> str | None:
        self._online()
        h = digest.hex()
        return json.dumps(self._payload(h)) if h in self.by_digest else None

    def entries(self, from_seq: int) -> list[dict]:
        self._online()
        self.entries_from.append(from_seq)
        return [{'seq': r['seq'], 'digest': r['digest'], 'utc': _canonical(r['utc'])}
                for r in self.rows if r['seq'] >= from_seq][:SV.ENTRIES_PAGE]

    def has(self, digest: bytes) -> bool:
        return digest.hex() in self.by_digest


def _plain(data: bytes, _purpose: str) -> bytes:
    return data


class HandoverFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.log = FakeLog()
        extra = {} if WINDOWS else {'protect': _plain, 'unprotect': _plain}
        self.sender = SV.HandoverService(HandoverStore(self.tmp / 'S'), self.log,
                                         receipt_keys=[self.log.public], **extra)
        self.recipient = SV.HandoverService(HandoverStore(self.tmp / 'R'), self.log,
                                            receipt_keys=[self.log.public], **extra)
        self.sender.create_identity(display_name='Nadawca', use_windows_hello=False)
        self.recipient.create_identity(display_name='Odbiorca', use_windows_hello=False)
        # Wymiana kart i zapis powiazania po obu stronach.
        r_card = self.sender.read_card_file(self.recipient.card_file())
        self.contact_r = self.sender.add_contact(r_card, label='Odbiorca', method='voice',
                                                 day=date(2026, 9, 30), note='telefon')
        s_card = self.recipient.read_card_file(self.sender.card_file())
        self.recipient.add_contact(s_card, label='Nadawca', method='qr-in-person',
                                   day=date(2026, 9, 30))
        self.files = []
        for name, data in (('umowa.pdf', b'%PDF-1.7 tresc umowy'), ('Załącznik.txt', 'żółw'.encode())):
            path = self.tmp / name
            path.write_bytes(data)
            self.files.append(path)
        self.exchange = self.tmp / 'wymiana'

    def _send(self, **kw):
        return self.sender.send(self.contact_r.fingerprint, self.files, title='Aneks',
                                note='Prosze o potwierdzenie', sender_name='Jan',
                                out_dir=self.exchange, **kw)

    def test_full_delivery_with_disclosed_evidence(self):
        out = self._send()
        self.assertTrue(out.offer_stamped)
        self.assertTrue(self.log.has(hashlib.sha256(b'%PDF-1.7 tresc umowy').digest()),
                        'wlasny stempel pliku (§7.1.2)')
        package = Path(out.package_path)
        self.assertTrue(package.name.endswith(SV.PACKAGE_SUFFIX))

        inc = self.recipient.receive(package)
        self.assertEqual(inc.status, 'new')
        self.assertEqual(inc.sender, self.sender.identity().fingerprint)
        self.assertEqual(inc.preview['title'], 'Aneks')
        self.assertEqual([f['name'] for f in inc.preview['files']], ['umowa.pdf', 'Załącznik.txt'])
        self.assertIsNotNone(self.recipient.offer_stamp_time(inc))
        self.assertEqual(self.recipient.receive(package), inc)   # drugi raz: ten sam rekord

        seq_before = len(self.log.rows)
        inc = self.recipient.answer(inc.offer_digest, 'accept')
        self.assertEqual(inc.status, 'accepted')
        self.assertEqual(len(self.log.rows), seq_before + 1, 'odpowiedz ostemplowana przed wydaniem')
        with self.assertRaises(SV.ServiceError) as cm:
            self.recipient.answer(inc.offer_digest, 'refuse')
        self.assertEqual(cm.exception.code, 'already-answered')

        # Odbiorca jeszcze nic nie widzi: B nie ma w dzienniku.
        folder = self.tmp / 'odebrane'
        self.assertEqual(self.recipient.look_for_part_b(inc.offer_digest, folder=folder).status,
                         'accepted')

        out = self.sender.take_answer(self.recipient.answer_file(inc))
        self.assertEqual(out.status, 'delivered')
        self.assertIsNotNone(out.delivered_at)

        opened = self.recipient.look_for_part_b(inc.offer_digest, folder=folder)
        self.assertEqual(opened.status, 'opened')
        self.assertEqual(opened.preview_differences, [])
        self.assertEqual(sorted(Path(p).read_bytes() for p in opened.saved),
                         sorted(p.read_bytes() for p in self.files))
        if WINDOWS:
            zone = Path(f'{opened.saved[0]}:Zone.Identifier')
            self.assertIn('ZoneId=3', zone.read_text(encoding='ascii'))

        evidence = self.sender.evidence(out.offer_digest, disclose=True)
        report = self.sender.check_evidence(evidence)
        self.assertEqual(report.verdict, 'delivered', [c for c in report.failed])
        self.assertEqual(report.failed, [])
        self.assertTrue(any(c.code == 'disclosure' and c.ok for c in report.checks))
        self.assertEqual(report.binding_level, 4)

        copy = self.recipient.incoming_evidence(inc.offer_digest)
        mine = self.recipient.check_evidence(copy)
        self.assertEqual(mine.verdict, 'delivered')
        self.assertEqual(mine.delivered_at, report.delivered_at)

    def _deliver(self, **kw):
        """Wysylka -> akceptacja -> publikacja B -> otwarcie u odbiorcy."""
        inc = self.recipient.receive(Path(self._send(**kw).package_path))
        inc = self.recipient.answer(inc.offer_digest, 'accept')
        self.assertEqual(self.sender.take_answer(self.recipient.answer_file(inc)).status,
                         'delivered')
        return self.recipient.look_for_part_b(inc.offer_digest, folder=self.tmp / 'odebrane')

    def test_defect_proof_of_a_preview_that_lied(self):
        real = P.build_preview
        lying = lambda manifest, name: dict(real(manifest, name), title='Zaproszenie na urodziny')
        with mock.patch.object(P, 'build_preview', lying):
            out = self._send()
        inc = self.recipient.receive(Path(out.package_path))
        self.assertEqual(inc.preview['title'], 'Zaproszenie na urodziny')
        inc = self.recipient.answer(inc.offer_digest, 'accept')
        self.sender.take_answer(self.recipient.answer_file(inc))
        opened = self.recipient.look_for_part_b(inc.offer_digest, folder=self.tmp / 'odebrane')
        self.assertEqual((opened.status, opened.preview_differences), ('opened', ['title']))
        self.assertTrue(self.recipient.has_defect(opened))

        target = self.tmp / f'dowod{SV.DEFECT_SUFFIX}'
        self.assertEqual(self.recipient.defect_proof(opened.offer_digest, target), target)
        self.assertFalse(target.with_name(target.name + '.part').exists())
        with open(target, 'rb') as f:
            self.assertEqual(E.archive_kind(f), 'defect')
            report = E.Defect(f).verify()
        self.assertEqual((report.verdict, report.checks[0].code), ('defective', 'preview-mismatch'))
        self.assertEqual(report.checks[0].data['manifest']['title'], 'Aneks')

    def test_no_defect_proof_for_a_good_package(self):
        opened = self._deliver()
        self.assertEqual(opened.status, 'opened')
        self.assertFalse(self.recipient.has_defect(opened))
        target = self.tmp / f'dowod{SV.DEFECT_SUFFIX}'
        with self.assertRaises(SV.ServiceError) as cm:
            self.recipient.defect_proof(opened.offer_digest, target)
        self.assertEqual(cm.exception.code, 'not-defective')
        self.assertFalse(target.exists())

    def test_answer_as_text(self):
        inc = self.recipient.receive(Path(self._send().package_path))
        inc = self.recipient.answer(inc.offer_digest, 'accept')
        text = self.recipient.answer_text(inc)
        self.assertTrue(text.startswith('sigelith:answer:'))
        wrapped = '\n'.join(text[i:i + 60] for i in range(0, len(text), 60))   # z maila
        self.assertEqual(self.sender.take_answer(wrapped).status, 'delivered')

    def test_refusal_never_publishes_b(self):
        out = self._send()
        inc = self.recipient.answer(self.recipient.receive(Path(out.package_path)).offer_digest,
                                    'refuse')
        self.assertEqual(inc.status, 'refused')
        self.assertFalse(self.recipient.store.ciphertext_path('incoming', inc.offer_digest).exists())
        rows = len(self.log.rows)
        done = self.sender.take_answer(self.recipient.answer_file(inc))
        self.assertEqual(done.status, 'refused')
        self.assertEqual(len(self.log.rows), rows, 'po odmowie nic nowego w dzienniku (B nigdy)')
        self.assertEqual((done.part_a_blob, done.part_b_blob), ('', ''), 'B po odmowie znika')
        self.assertFalse(self.sender.store.ciphertext_path('outgoing', done.offer_digest).exists())
        self.assertFalse(self.sender.has_pending())
        report = self.sender.check_evidence(self.sender.evidence(done.offer_digest))
        self.assertEqual(report.verdict, 'refused')

    def test_no_publication_close_to_the_deadline(self):
        out = self._send(complete_within_days=1)
        inc = self.recipient.answer(self.recipient.receive(Path(out.package_path)).offer_digest,
                                    'accept')
        self.log.advance(hours=23, minutes=30)                 # valid_until za 30 minut
        rows = len(self.log.rows)
        with self.assertRaises(SV.ServiceError) as cm:
            self.sender.take_answer(self.recipient.answer_file(inc))
        self.assertEqual((cm.exception.code, cm.exception.detail), ('publish-refused', 'answer-deadline-near'))
        self.assertEqual(len(self.log.rows), rows, 'B nie trafilo do dziennika')
        record = self.sender.store.get_outgoing(out.offer_digest)
        self.assertEqual((record.status, record.error), ('failed', 'answer-deadline-near'))
        self.assertFalse(record.publish_attempted)

    def test_package_for_someone_else_does_not_open(self):
        out = self._send()
        stranger = SV.HandoverService(HandoverStore(self.tmp / 'X'), self.log,
                                      receipt_keys=[self.log.public],
                                      **({} if WINDOWS else {'protect': _plain, 'unprotect': _plain}))
        stranger.create_identity(display_name='Obcy', use_windows_hello=False)
        with self.assertRaises(SV.ServiceError) as cm:
            stranger.receive(Path(out.package_path))
        self.assertEqual(cm.exception.code, 'package-invalid')

    def test_tampered_ciphertext_is_refused_before_any_question(self):
        package = Path(self._send().package_path)
        data = bytearray(package.read_bytes())
        data[-1] ^= 1
        package.write_bytes(bytes(data))
        with self.assertRaises(SV.ServiceError) as cm:
            self.recipient.receive(package)
        self.assertEqual((cm.exception.code, cm.exception.detail), ('package-invalid', 'ciphertext-hash'))

    def test_answer_is_not_released_without_its_stamp(self):
        inc = self.recipient.receive(Path(self._send().package_path))
        self.log.offline = True
        with self.assertRaises(OSError):
            self.recipient.answer(inc.offer_digest, 'accept')
        self.log.offline = False
        record = self.recipient.store.get_incoming(inc.offer_digest)
        self.assertIsNone(record.answer)
        self.assertIsNone(record.answer_file)
        self.assertEqual(self.recipient.answer(inc.offer_digest, 'accept').status, 'accepted')

    def test_expired_offer_is_not_shown(self):
        out = self._send(expires_days=1)
        self.log.advance(days=2)
        with self.assertRaises(SV.ServiceError) as cm:
            self.recipient.receive(Path(out.package_path))
        self.assertEqual((cm.exception.code, cm.exception.detail), ('package-invalid', 'offer-expired'))

    def test_exchange_folder_carries_the_whole_handover(self):
        """Wspolny folder (OneDrive...): kazda strona bierze tylko to, co do niej."""
        out = self._send()                                     # paczka laduje w folderze
        self.assertEqual(self.sender.scan_exchange(self.exchange).received, [],
                         'wlasna paczka nie jest dla nadawcy')
        got = self.recipient.scan_exchange(self.exchange)
        self.assertEqual([r.offer_digest for r in got.received], [out.offer_digest])
        self.assertEqual(got.problems, [])
        self.assertEqual(self.recipient.scan_exchange(self.exchange).received, [], 'drugi raz nic')
        inc = self.recipient.answer(out.offer_digest, 'accept')
        self.recipient.write_answer_to(inc, self.exchange)
        self.assertEqual(self.recipient.scan_exchange(self.exchange).answered, [],
                         'wlasna odpowiedz nie jest dla odbiorcy')
        done = self.sender.scan_exchange(self.exchange)
        self.assertEqual([r.status for r in done.answered], ['delivered'])
        opened = self.recipient.look_for_part_b(out.offer_digest, folder=self.tmp / 'odebrane')
        self.assertEqual(opened.status, 'opened')

    def test_exchange_scan_retries_after_a_network_error(self):
        self._send()
        self.log.offline = True
        self.assertEqual(self.recipient.scan_exchange(self.exchange).received, [])
        self.log.offline = False
        self.assertEqual(len(self.recipient.scan_exchange(self.exchange).received), 1)

    def test_contact_with_my_own_card_is_refused(self):
        mine = self.sender.read_card_file(self.sender.card_file())
        with self.assertRaises(SV.ServiceError) as cm:
            self.sender.add_contact(mine, label='ja', method='voice', day=date(2026, 9, 30))
        self.assertEqual(cm.exception.code, 'card-is-mine')

    def test_new_card_archives_the_old_one_and_still_opens_old_packages(self):
        out = self._send()
        self.recipient.create_identity(display_name='Odbiorca 2', use_windows_hello=False)
        self.assertEqual(len(self.recipient.store.identities()), 2)
        inc = self.recipient.receive(Path(out.package_path))   # przyszla na stara karte
        self.assertEqual(inc.status, 'new')

    # --- terminy (§7.3 „Pozniej", §7.6) i ponawianie publikacji (§7.4) ---------------

    def test_unanswered_offer_expires_on_both_sides(self):
        out = self._send(expires_days=1)
        inc = self.recipient.receive(Path(out.package_path))
        self.log.advance(days=1, minutes=1)
        self.assertEqual([r.offer_digest for r in self.recipient.expire_overdue()],
                         [inc.offer_digest])
        inc = self.recipient.store.get_incoming(inc.offer_digest)
        self.assertEqual((inc.status, inc.part_a_blob), ('expired', ''))
        self.assertFalse(self.recipient.store.ciphertext_path('incoming', inc.offer_digest).exists())
        with self.assertRaises(SV.ServiceError) as cm:
            self.recipient.answer(inc.offer_digest, 'accept')
        self.assertEqual(cm.exception.code, 'offer-expired')

        self.sender.expire_overdue()
        record = self.sender.store.get_outgoing(out.offer_digest)
        self.assertEqual(record.status, 'expired', '„nieodebrana"')
        self.assertTrue(record.part_b_blob, 'akceptacja sprzed terminu moze jeszcze dojsc')
        self.log.advance(days=14, minutes=11)                  # expires + complete_within + zapas
        self.sender.expire_overdue()
        record = self.sender.store.get_outgoing(out.offer_digest)
        self.assertEqual((record.status, record.part_a_blob, record.part_b_blob),
                         ('expired', '', ''))
        self.assertFalse(self.sender.store.ciphertext_path('outgoing', out.offer_digest).exists())
        self.assertFalse(self.sender.has_pending())
        self.assertFalse(self.recipient.has_pending())

    def test_answer_after_the_offer_deadline_is_refused_with_its_reason(self):
        inc = self.recipient.receive(Path(self._send(expires_days=1).package_path))
        self.log.advance(days=1, minutes=1)
        with self.assertRaises(SV.ServiceError) as cm:
            self.recipient.answer(inc.offer_digest, 'accept')
        self.assertEqual(cm.exception.code, 'offer-expired')
        self.assertEqual(self.recipient.store.get_incoming(inc.offer_digest).status, 'expired')

    def test_acceptance_signed_in_time_still_delivers_after_the_offer_deadline(self):
        """Akceptacja sprzed `expires`, ktora dotarla po nim (np. poczta po urlopie)."""
        out = self._send(expires_days=1)
        inc = self.recipient.receive(Path(out.package_path))
        self.log.advance(hours=23)
        inc = self.recipient.answer(inc.offer_digest, 'accept')
        self.log.advance(hours=2)
        self.sender.expire_overdue()
        self.assertEqual(self.sender.store.get_outgoing(out.offer_digest).status, 'expired')
        self.assertEqual(self.sender.take_answer(self.recipient.answer_file(inc)).status,
                         'delivered')

    def test_acceptance_lapses_without_the_key_part(self):
        out = self._send(complete_within_days=1)
        inc = self.recipient.answer(self.recipient.receive(Path(out.package_path)).offer_digest,
                                    'accept')
        folder = self.tmp / 'odebrane'
        self.log.advance(hours=23)
        self.assertEqual(self.recipient.look_for_part_b(inc.offer_digest, folder=folder).status,
                         'accepted')
        self.log.advance(hours=1, minutes=5)                   # po valid_until, ale w zapasie
        self.assertEqual(self.recipient.look_for_part_b(inc.offer_digest, folder=folder).status,
                         'accepted', 'stempel B sprzed terminu moze byc jeszcze w drodze')
        self.log.advance(minutes=6)
        for n in range(3):                                     # cudze stemple po przegladzie
            self.log.stamp(hashlib.sha256(b'cudzy %d' % n).digest())
        with mock.patch.object(SV, 'ENTRIES_PAGE', 1):
            partial = self.recipient.look_for_part_b(inc.offer_digest, folder=folder, max_pages=1)
        self.assertEqual(partial.status, 'accepted',
                         'przeglad, ktory nie doszedl do konca dziennika, niczego nie przesadza')
        lapsed = self.recipient.look_for_part_b(inc.offer_digest, folder=folder)
        self.assertEqual((lapsed.status, lapsed.error), ('expired', 'acceptance-lapsed'))
        self.assertFalse(self.recipient.store.ciphertext_path('incoming', inc.offer_digest).exists())
        # Nadawca, do ktorego odpowiedz dotarla za pozno, niczego nie publikuje.
        rows = len(self.log.rows)
        with self.assertRaises(SV.ServiceError):
            self.sender.take_answer(self.recipient.answer_file(inc))
        self.assertEqual(len(self.log.rows), rows)
        self.assertEqual(self.sender.store.get_outgoing(out.offer_digest).status, 'failed')

    def test_refusal_after_delivery_changes_nothing(self):
        """§6: przyjecie, ktore weszlo w zycie, rozstrzyga — pozniejsza odmowa (ze
        zmienionej aplikacji odbiorcy) zostaje tylko w rekordzie."""
        from beatstamp.handover import answer as A_, package as P, transport as T
        out = self._send()
        inc = self.recipient.answer(self.recipient.receive(Path(out.package_path)).offer_digest,
                                    'accept')
        self.sender.take_answer(self.recipient.answer_file(inc))
        offer = P.read_offer(out.offer)
        refusal = A_.make_answer(self.recipient.signer(self.recipient.identity()), offer, 'refuse',
                                 log_now=self.log.now())
        done = self.sender.take_answer(T.write_answer_file(offer.sender.enc_key, refusal))
        self.assertEqual((done.status, len(done.answers)), ('delivered', 2))
        self.assertTrue(done.part_b_blob and done.part_a_blob, 'nic nie skasowane')
        report = self.sender.check_evidence(self.sender.evidence(done.offer_digest, disclose=True))
        self.assertEqual(report.verdict, 'delivered')

    def test_publication_is_retried_after_a_network_error(self):
        out = self._send()
        inc = self.recipient.answer(self.recipient.receive(Path(out.package_path)).offer_digest,
                                    'accept')
        self.log.stamp_faults = ['ok', 'down']                 # T1 przechodzi, B nie
        with self.assertRaises(OSError):
            self.sender.take_answer(self.recipient.answer_file(inc))
        record = self.sender.store.get_outgoing(out.offer_digest)
        self.assertEqual((record.status, len(record.answers)), ('sent', 1),
                         'odpowiedz zapisana mimo bledu sieci')
        self.assertTrue(self.sender.has_pending())
        delivered, problems = self.sender.complete_pending()
        self.assertEqual(problems, [])
        self.assertEqual([r.status for r in delivered], ['delivered'])

    def test_answer_survives_a_network_error_before_its_stamp(self):
        out = self._send()
        inc = self.recipient.answer(self.recipient.receive(Path(out.package_path)).offer_digest,
                                    'accept')
        self.log.stamp_faults = ['down']                       # juz T1 nie przechodzi
        with self.assertRaises(OSError):
            self.sender.take_answer(self.recipient.answer_file(inc))
        self.assertEqual(len(self.sender.store.get_outgoing(out.offer_digest).answers), 1)
        delivered, problems = self.sender.complete_pending()
        self.assertEqual(([r.status for r in delivered], problems), (['delivered'], []))

    def test_lost_response_does_not_publish_twice(self):
        """B zapisane, odpowiedz dziennika nie dotarla (§13 p. 4). Ponowienie tuz
        przed terminem nie moze juz publikowac — ale znajduje wpis, ktory jest."""
        out = self._send(complete_within_days=1)
        inc = self.recipient.answer(self.recipient.receive(Path(out.package_path)).offer_digest,
                                    'accept')
        self.log.stamp_faults = ['ok', 'lost']
        with self.assertRaises(OSError):
            self.sender.take_answer(self.recipient.answer_file(inc))
        rows = len(self.log.rows)
        b_time = self.log.rows[-1]['utc'].isoformat().replace('+00:00', 'Z')
        self.log.advance(hours=23, minutes=30)                 # do valid_until mniej niz godzina
        delivered, problems = self.sender.complete_pending()
        self.assertEqual(problems, [])
        self.assertEqual([(r.status, r.delivered_at) for r in delivered], [('delivered', b_time)])
        self.assertEqual(len(self.log.rows), rows, 'B zapisane jeden raz')

    def test_uncertain_publication_is_reported(self):
        """B wyslane, nic nie zapisane, termin minal: „moglo dotrzec do operatora"."""
        out = self._send(complete_within_days=1)
        inc = self.recipient.answer(self.recipient.receive(Path(out.package_path)).offer_digest,
                                    'accept')
        self.log.stamp_faults = ['ok', 'down']
        with self.assertRaises(OSError):
            self.sender.take_answer(self.recipient.answer_file(inc))
        self.log.advance(hours=23, minutes=30)
        delivered, problems = self.sender.complete_pending()
        self.assertEqual([p[1].detail for p in problems], ['answer-deadline-near'])
        record = self.sender.store.get_outgoing(out.offer_digest)
        self.assertEqual((record.status, record.error), ('failed', 'publish-uncertain'))

    def test_maintenance_opens_the_package_and_resumes_the_search(self):
        out = self._send()
        inc = self.recipient.answer(self.recipient.receive(Path(out.package_path)).offer_digest,
                                    'accept')
        folder = self.tmp / 'odebrane'
        first = self.recipient.maintain(folder)
        self.assertEqual((first.opened, first.expired, first.problems), ([], [], []))
        searched = self.recipient.store.get_incoming(inc.offer_digest).search_seq
        self.assertEqual(searched, len(self.log.rows) + 1)
        self.sender.take_answer(self.recipient.answer_file(inc))
        self.log.entries_from.clear()
        second = self.recipient.maintain(folder)
        self.assertEqual([r.offer_digest for r in second.opened], [inc.offer_digest])
        self.assertEqual(self.log.entries_from, [searched],
                         'przeglad zaczyna tam, gdzie skonczyl poprzedni')
        opened = Path(second.opened[0].folder)
        self.assertEqual((opened.parent, opened.name), (folder, f'Aneks ({out.offer_digest[:8]})'))


class PackageFolderTests(unittest.TestCase):
    def test_title_is_cleaned_and_the_digest_keeps_packages_apart(self):
        from types import SimpleNamespace
        base = Path('odebrane')
        record = SimpleNamespace(preview={'title': 'Umowa: 1/2 <final>?.'}, offer_digest='ab' * 32)
        self.assertEqual(SV.package_folder(base, record), base / 'Umowa 12 final (abababab)')
        record = SimpleNamespace(preview={'title': ''}, offer_digest='cd' * 32)
        self.assertEqual(SV.package_folder(base, record), base / ('cd' * 8))


if __name__ == '__main__':
    unittest.main()
