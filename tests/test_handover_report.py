"""
Raport PDF dla bieglego (ui/handover_report.py) — tresc, kierunek tekstu,
bezpieczenstwo HTML i sam plik PDF.

Platforma `offscreen` nie ma czcionek systemowych: PDF z testu ma prostokaty
zamiast liter. Sprawdzamy wiec tresc na HTML-u, a PDF — jako plik: naglowek,
znacznik PDF/A, liczba stron i brak pozostalosci `.part`.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtWidgets import QApplication  # noqa: E402

from beatstamp import handover_tasks as HT, i18n, witness  # noqa: E402
from beatstamp.handover.evidence import Check, Report  # noqa: E402
from beatstamp.handover_app import service as SV  # noqa: E402
from beatstamp.handover_app.store import HandoverStore  # noqa: E402
from beatstamp.ui import handover_report as R  # noqa: E402

_app = QApplication.instance() or QApplication(sys.argv)
WINDOWS = sys.platform == 'win32'
VECTORS = Path(__file__).resolve().parent / 'vectors' / 'handover-v1.json'

from test_handover_flow import FakeLog  # noqa: E402


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls._tmp.name)
        log = FakeLog()
        extra = {} if WINDOWS else {'protect': lambda d, _p: d, 'unprotect': lambda d, _p: d}
        cls.sender = SV.HandoverService(HandoverStore(tmp / 'S'), log, receipt_keys=[log.public],
                                        **extra)
        recipient = SV.HandoverService(HandoverStore(tmp / 'R'), log, receipt_keys=[log.public],
                                       **extra)
        cls.sender.create_identity(display_name='S', use_windows_hello=False)
        recipient.create_identity(display_name='R', use_windows_hello=False)
        contact = cls.sender.add_contact(cls.sender.read_card_file(recipient.card_file()),
                                         label='R', method='voice', day=date(2026, 9, 30))
        doc = tmp / 'umowa.txt'
        doc.write_text('tresc umowy', encoding='utf-8')
        out = cls.sender.send(contact.fingerprint, [doc], title='Umowa', out_dir=tmp / 'paczki')
        inc = recipient.answer(recipient.receive(Path(out.package_path)).offer_digest, 'accept')
        done = cls.sender.take_answer(recipient.answer_file(inc))
        cls.evidence = cls.sender.evidence(done.offer_digest, disclose=True)
        cls.check = HT.CheckEvidenceTask(cls.sender, cls.evidence, None, witness.WitnessState(),
                                         '').step()
        cls.source = R.Source('handover-test.sigelith-evidence.zip', cls.check.size,
                              cls.check.sha256)
        vectors = json.loads(VECTORS.read_text(encoding='utf-8'))
        defect = next(c for c in vectors['defect_files']
                      if c['name'] == 'file-defect-preview-differs-from-content')
        cls.defect_path = tmp / 'handover-test.sigelith-defect.zip'
        cls.defect_path.write_bytes(base64.b64decode(defect['zip']))

    @classmethod
    def tearDownClass(cls):
        i18n.set_language('pl')
        cls._tmp.cleanup()

    def setUp(self):
        i18n.set_language('pl')

    def test_evidence_report_names_the_file_and_every_check(self):
        page = R.evidence_html(self.check, self.source, self.sender.receipt_keys())
        self.assertEqual(self.check.report.verdict, 'delivered')
        for text in (self.check.sha256, self.source.name, 'certutil -hashfile',
                     self.sender.receipt_keys()[0], R.VERIFY_URL, R.SOURCE_URL,
                     i18n._('Delivered'), i18n._('Key part recorded in the log'),
                     i18n._('How to check this independently')):
            self.assertIn(text, page)
        for check in self.check.report.checks:
            self.assertIn(check.code, page, 'kod kontroli dla bieglego')
        self.assertIn(' UTC', page, 'czasy w UTC, nie lokalnie')
        self.assertIn(self.check.doc['part_b'][:16], page, 'dowod czesci B w tabeli dziennika')

    def test_right_to_left_report_reverses_table_cells(self):
        i18n.set_language('ar')
        page = R.evidence_html(self.check, self.source, self.sender.receipt_keys())
        self.assertIn('<body dir="rtl">', page)
        # Etykieta stoi PO wartosci w zapisie wiersza: Qt nie odwraca kolumn sam.
        name_row = page.split(i18n._('Name'))[0].rsplit('<tr>', 1)[1]
        self.assertIn(self.source.name, name_row)

    def test_defect_report_and_text_from_the_file_is_escaped(self):
        check = HT.CheckDefectTask(self.sender, self.defect_path).step()
        page = R.defect_html(check, R.Source(self.defect_path.name, check.size, check.sha256))
        for text in (i18n._('Offer defective'), 'Zaproszenie na urodziny', check.sha256,
                     'preview-mismatch'):
            self.assertIn(text, page)
        manifest = {'title': '<img src=x onerror=alert(1)>', 'note': '', 'files': []}
        preview = {'title': 'Pismo', 'note': '', 'sender_name': '', 'files': [], 'file_count': 0,
                   'total_size': 0}
        fake = HT.DefectCheck(report=Report('defective', [Check(
            'preview-mismatch', False, 'x', {'preview': preview, 'manifest': manifest,
                                             'differences': ['title']})]), offer=None,
            sha256='0' * 64, size=1)
        page = R.defect_html(fake, R.Source('a<b>.zip', 1, '0' * 64))
        self.assertNotIn('<img', page)
        self.assertNotIn('a<b>', page)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', page)

    def test_pdf_file(self):
        from PySide6.QtPdf import QPdfDocument
        target = Path(self._tmp.name) / 'raport.pdf'
        R.write_pdf(R.evidence_html(self.check, self.source, self.sender.receipt_keys()), target,
                    title='test')
        data = target.read_bytes()
        self.assertTrue(data.startswith(b'%PDF-'))
        self.assertIn(b'pdfaid:part', data, 'PDF/A — format archiwalny')
        self.assertFalse(target.with_name(target.name + '.part').exists())
        doc = QPdfDocument()
        doc.load(str(target))
        self.assertGreaterEqual(doc.pageCount(), 2)
        doc.close()


if __name__ == '__main__':
    unittest.main()
