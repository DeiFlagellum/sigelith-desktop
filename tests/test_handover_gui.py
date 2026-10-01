"""
Sigelith Handover w oknie glownym (offscreen).

Rzeczy, ktore w Qt lamia sie po cichu: routing plikow (paczka NIE MOZE trafic
do stemplowania — jej skrot poszedlby do publicznego dziennika), panel na
prawdziwym stanie i to, czy kazde okno Handover w ogole sie buduje.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import date
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtWidgets import QApplication  # noqa: E402

from beatstamp import i18n  # noqa: E402
from beatstamp.config import Settings  # noqa: E402
from beatstamp.handover_app import service as SV  # noqa: E402
from beatstamp.ui import handover_dialogs as D, theme  # noqa: E402
from beatstamp.ui.handover_controller import is_handover_file  # noqa: E402

i18n.set_language('pl')
_app = QApplication.instance() or QApplication(sys.argv)
WINDOWS = sys.platform == 'win32'

from test_handover_flow import FakeLog  # noqa: E402


class HandoverWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        os.environ['SIGELITH_DATA_DIR'] = cls._tmp.name
        os.environ['LOCALAPPDATA'] = cls._tmp.name
        (Path(cls._tmp.name) / '.tvs-zaimportowano').write_text('test')
        theme.apply_theme(_app, 'light')
        from beatstamp.ui.main_window import MainWindow
        cls.window = MainWindow(Settings(background_checks=False))
        # Usluga okna na dzienniku w pamieci (bez sieci), karty programowe.
        cls.log = FakeLog()
        service = cls.window.handover.service
        service.log = cls.log
        service._receipt_keys = (cls.log.public,)
        if not WINDOWS:
            service._protect = service._unprotect = lambda d, _p: d

    @classmethod
    def tearDownClass(cls):
        cls.window.close()
        _app.processEvents()
        cls.window.deleteLater()
        _app.processEvents()
        cls._tmp.cleanup()

    def test_handover_files_never_go_to_stamping(self):
        tmp = Path(self._tmp.name)
        package = tmp / 'x.sigelith-handover'
        package.write_bytes(b'SIGELITH-HANDOVER-1\n')
        other = tmp / 'umowa.pdf'
        other.write_bytes(b'%PDF')
        with mock.patch.object(self.window, 'stamp_files') as stamp, \
                mock.patch.object(self.window.handover, 'open_files') as opened:
            self.window.open_paths([package, other])
            stamp.assert_not_called()
            opened.assert_called_once_with([package])
            self.window.open_paths([other])
            stamp.assert_called_once_with([other])
            self.window.activate_from_other_instance([str(package)])
            self.assertEqual(opened.call_count, 2)

    def test_suffixes(self):
        for name, expected in (('a.sigelith-handover', True), ('A.SIGELITH-ANSWER', True),
                               ('karta.sigelith-card', True), ('dowod.zip', False),
                               ('umowa.pdf', False)):
            with self.subTest(name=name):
                self.assertIs(is_handover_file(Path(name)), expected)

    def test_panel_shows_the_real_state(self):
        service = self.window.handover.service
        me = service.create_identity(display_name='Test', use_windows_hello=False)
        other = SV.HandoverService(SV.HandoverStore(Path(self._tmp.name) / 'inny'), self.log,
                                   receipt_keys=[self.log.public],
                                   **({} if WINDOWS else {'protect': lambda d, _p: d,
                                                          'unprotect': lambda d, _p: d}))
        other.create_identity(display_name='Inny', use_windows_hello=False)
        contact = service.add_contact(service.read_card_file(other.card_file()), label='Anna',
                                      method='voice', day=date(2026, 9, 30))
        self.window.handover.refresh()
        panel = self.window.handover.panel
        self.assertIn('-', panel.card_fingerprint.text())
        self.assertEqual(panel.contacts_table.rowCount(), 1)
        self.assertEqual(panel.contacts_table.item(0, 0).text(), 'Anna')
        self.assertTrue(panel.send_button.isEnabled())
        self.assertTrue(panel.check_button.isEnabled(), 'B w dzienniku sprawdza sie tez bez folderu')
        self.assertTrue(me.fingerprint)

        # Okna: kazde sie buduje (bez exec) na prawdziwych danych.
        card_file = service.read_card_file(other.card_file())
        D.AddContactDialog(card_file, parent=self.window).deleteLater()
        D.CreateCardDialog(hello=False, replacing=True, parent=self.window).deleteLater()
        send = D.SendDialog([contact], exchange='', start_dir='', parent=self.window)
        doc = Path(self._tmp.name) / 'aneks.txt'
        doc.write_text('tresc', encoding='utf-8')
        send.add_paths([doc])
        self.assertEqual(send.files.count(), 1)
        send.deleteLater()

        out = service.send(contact.fingerprint, [doc], title='Aneks',
                           out_dir=Path(self._tmp.name) / 'wyslane')
        inc = other.receive(Path(out.package_path))
        dialog = D.IncomingDialog(inc, contact=None, offer_time=inc.offer_stamped_at,
                                  parent=self.window)
        dialog.deleteLater()
        inc = other.answer(inc.offer_digest, 'accept')
        D.IncomingDialog(inc, contact=None, offer_time=None, parent=self.window).deleteLater()
        done = service.take_answer(other.answer_file(inc))
        D.OutgoingDialog(done, contact=contact, parent=self.window).deleteLater()
        for status, error in (('expired', None), ('failed', 'publish-uncertain'),
                              ('failed', 'answer-deadline-near')):
            D.OutgoingDialog(replace(done, status=status, error=error), contact=contact,
                             parent=self.window).deleteLater()
        for answer in (None, inc.answer):
            D.IncomingDialog(replace(inc, status='expired', answer=answer), contact=None,
                             offer_time=None, parent=self.window).deleteLater()
        D.LoadAnswerDialog('', parent=self.window).deleteLater()
        check = service.check_evidence(service.evidence(done.offer_digest, disclose=True))
        from beatstamp.handover_tasks import EvidenceCheck
        D.EvidenceDialog(EvidenceCheck(report=check, confirmations={}, log_errors={}),
                         has_container=True, parent=self.window).deleteLater()
        self.window.handover.refresh()
        self.assertEqual(panel.outgoing_table.rowCount(), 1)
        self.assertEqual(panel.outgoing_table.item(0, 3).text()[:4], i18n._('Delivered')[:4])

    def _services(self, name: str):
        extra = {} if WINDOWS else {'protect': lambda d, _p: d, 'unprotect': lambda d, _p: d}
        pair = []
        for who in ('S', 'R'):
            svc = SV.HandoverService(SV.HandoverStore(Path(self._tmp.name) / name / who), self.log,
                                     receipt_keys=[self.log.public], **extra)
            svc.create_identity(display_name=who, use_windows_hello=False)
            pair.append(svc)
        return pair

    def test_defect_dialogs(self):
        """Dowod wady (§11.3): werdykt z pliku z wektorow i przycisk w odebranej paczce."""
        import base64
        import json
        from PySide6.QtWidgets import QLabel, QPushButton
        from beatstamp.handover import evidence as E, package as P
        from beatstamp.handover_tasks import DefectCheck
        vectors = json.loads((Path(__file__).resolve().parent / 'vectors' / 'handover-v1.json')
                             .read_text(encoding='utf-8'))
        files = {c['name']: base64.b64decode(c['zip']) for c in vectors['defect_files']}
        defect = E.Defect(files['file-defect-preview-differs-from-content'])
        dialog = D.DefectDialog(DefectCheck(report=defect.verify(),
                                            offer=P.read_offer(defect.doc['offer'])),
                                parent=self.window)
        texts = [lbl.text() for lbl in dialog.findChildren(QLabel)]
        self.assertIn(i18n._('Offer defective'), texts)
        self.assertIn(i18n._('Preview: %(value)s') % {'value': 'Zaproszenie na urodziny'}, texts)
        self.assertIn(i18n._('Content: %(value)s') % {'value': 'Pismo'}, texts)
        self.assertIn('✗  ' + i18n._('The preview matches the content'), texts)
        self.assertNotIn('preview-mismatch', '\n'.join(texts), 'surowy kod w oknie')
        self.assertIn(i18n._('Save a PDF report…'),
                      [b.text() for b in dialog.findChildren(QPushButton)])
        dialog.deleteLater()

        # Raport PDF zapisuje kontroler — obok sprawdzonego pliku, przez okno zapisu.
        target = Path(self._tmp.name) / 'raport-wady.pdf'
        with mock.patch.object(self.window, '_choose_save_path', return_value=target) as choose, \
                mock.patch.object(self.window, '_offer_open') as offered:
            self.window.handover._save_report(Path(self._tmp.name) / 'x.sigelith-defect.zip',
                                              '<html><body><p>raport</p></body></html>', 'test')
        self.assertEqual(choose.call_args[0][1].name, 'x.sigelith-defect.pdf')
        self.assertTrue(target.read_bytes().startswith(b'%PDF-'))
        offered.assert_called_once()
        bad = E.Defect(files['file-extra-field'])
        D.DefectDialog(DefectCheck(report=bad.verify(), offer=None),
                       parent=self.window).deleteLater()

        sender, recipient = self._services('wada')
        contact = sender.add_contact(sender.read_card_file(recipient.card_file()), label='R',
                                     method='voice', day=date(2026, 9, 30))
        doc = Path(self._tmp.name) / 'wada' / 'pismo.txt'
        doc.write_text('tresc', encoding='utf-8')
        inc = recipient.receive(Path(sender.send(contact.fingerprint, [doc], title='Pismo',
                                                 out_dir=Path(self._tmp.name) / 'wada' / 'p')
                                     .package_path))
        buttons = lambda dlg: [b.text() for b in dlg.findChildren(QPushButton)]  # noqa: E731
        defective = replace(inc, status='defective', error='ciphertext-tag',
                            answer_file='x', part_b='00' * 32)
        dlg = D.IncomingDialog(defective, contact=None, offer_time=None, defect=True,
                               parent=self.window)
        self.assertIn(i18n._('Save the defect proof…'), buttons(dlg))
        self.assertTrue(any('ciphertext-tag' in t for t in
                            (lbl.text() for lbl in dlg.findChildren(QLabel))))
        dlg.deleteLater()
        dlg = D.IncomingDialog(inc, contact=None, offer_time=None, parent=self.window)
        self.assertNotIn(i18n._('Save the defect proof…'), buttons(dlg))
        dlg.deleteLater()

    def test_evidence_dialog_speaks_the_interface_language(self):
        """Test na sprzecie (2026-09-29): „Wszystkie kontrole" pokazywaly surowe kody
        i angielskie opisy z czasem ISO. Teraz etykiety, czas lokalny, role dowodow."""
        from PySide6.QtWidgets import QLabel
        from beatstamp import beatcore
        from beatstamp.handover_tasks import EvidenceCheck
        sender, recipient = self._services('dowod')
        contact = sender.add_contact(sender.read_card_file(recipient.card_file()), label='R',
                                     method='voice', day=date(2026, 9, 30))
        doc = Path(self._tmp.name) / 'dowod' / 'umowa.txt'
        doc.write_text('tresc', encoding='utf-8')
        out = sender.send(contact.fingerprint, [doc], title='Umowa',
                          out_dir=Path(self._tmp.name) / 'dowod' / 'paczki')
        inc = recipient.answer(recipient.receive(Path(out.package_path)).offer_digest, 'accept')
        done = sender.take_answer(recipient.answer_file(inc))
        report = sender.check_evidence(sender.evidence(done.offer_digest, disclose=True))
        self.assertEqual(report.verdict, 'delivered')
        texts = [lbl.text() for lbl in D.EvidenceDialog(
            EvidenceCheck(report=report, confirmations={d: None for d in (out.offer_digest,)},
                          log_errors={}), has_container=True, parent=self.window)
            .findChildren(QLabel)]
        joined = '\n'.join(texts)
        for code in ('part-b-commit', 'offer-stamp', 'cards:', 'file(s)'):
            self.assertNotIn(code, joined, 'surowy kod kontroli w oknie')
        self.assertIn('✓  ' + i18n._('Key part recorded in the log'), texts)
        self.assertIn(beatcore.local_str(report.delivered_at), texts, 'czas lokalny, nie ISO')
        self.assertTrue(any(t.startswith(i18n._('Offer') + ' — ') for t in texts),
                        'dowod z dziennika opisany rola, nie skrotem')
        self.assertIn('(1 = ', joined, 'kierunek skali poziomu powiazania')

    def test_folder_button_follows_the_selected_package(self):
        from types import SimpleNamespace as NS
        panel = self.window.handover.panel

        def record(digest: str, status: str, folder=None):
            return NS(offer_digest=digest * 64, offer={}, sender='0' * 64, preview={'title': digest},
                      received='2026-09-29T08:00:00Z', status=status, folder=folder)

        opened, waiting = record('a', 'opened', self._tmp.name), record('b', 'accepted')
        try:
            panel.set_incoming([opened, waiting])
            self.assertEqual(panel.incoming_table.currentRow(), 0, 'najnowsza wybrana od razu')
            self.assertTrue(panel.incoming_folder_button.isEnabled())
            emitted = []
            panel.openFolderRequested.disconnect()          # bez kontrolera: zadnych okienek
            panel.openFolderRequested.connect(emitted.append)
            panel.incoming_folder_button.click()
            self.assertEqual(emitted, ['a' * 64])
            panel.incoming_table.selectRow(1)
            self.assertFalse(panel.incoming_folder_button.isEnabled(), 'tu plikow jeszcze nie ma')
            panel.set_incoming([opened, waiting])
            self.assertEqual(panel.incoming_table.currentRow(), 1, 'odswiezenie nie gubi wyboru')
        finally:
            panel.openFolderRequested.disconnect()
            panel.openFolderRequested.connect(self.window.handover.open_incoming_folder)
            self.window.handover.refresh()

    def test_opened_package_notice_and_missing_folder(self):
        from types import SimpleNamespace as NS
        from PySide6.QtWidgets import QMessageBox
        controller = self.window.handover
        record = NS(offer_digest='c' * 64, preview={'title': 'Umowa'}, folder=self._tmp.name,
                    preview_differences=['files'])
        with mock.patch.object(QMessageBox, 'exec', return_value=0) as shown:
            controller._opened_notice(record)
        shown.assert_called_once()
        with mock.patch.object(controller, '_info') as info:
            controller.open_incoming_folder('d' * 64)           # przesylki nie ma w magazynie
        info.assert_called_once()

    def test_settings_tab_carries_the_handover_choices(self):
        from PySide6.QtWidgets import QFileDialog
        from beatstamp.ui.dialogs import SettingsDialog
        folder = Path(self._tmp.name) / 'wspolny'
        folder.mkdir(exist_ok=True)
        dialog = SettingsDialog(Settings(handover_exchange_dir=str(folder)), self.window)
        try:
            self.assertEqual(dialog.exchange_field.text(), str(folder))
            dialog.exchange_clear.click()                      # z powrotem: pliki wysylam sam
            dialog.attestation.setChecked(False)               # §3.6: wlasciciel moze wylaczyc
            result = dialog.result_settings()
            self.assertEqual((result.handover_exchange_dir, result.handover_attestation),
                             ('', False))
            with mock.patch.object(QFileDialog, 'getExistingDirectory',
                                   return_value=str(folder)):
                dialog._pick_folder(dialog.downloads_field, 'x')
            self.assertEqual(dialog.result_settings().handover_downloads_dir, str(folder))
            dialog._restore_defaults()
            result = dialog.result_settings()
            self.assertEqual((result.handover_downloads_dir, result.handover_attestation),
                             ('', True))
        finally:
            dialog.deleteLater()

    def test_statement_is_the_fixed_reading(self):
        """Ta sama tresc co na stronie weryfikatora (apps/web/views.py)."""
        i18n.set_language('en')
        try:
            text = D.statement_accept('ab' * 32, 'XXXX-YYYY', '16.10.2026, 09:30:00')
        finally:
            i18n.set_language('pl')
        self.assertTrue(text.startswith('I confirm that I have received package ' + 'ab' * 32))
        self.assertIn('no later than 16.10.2026, 09:30:00. Otherwise it has no effect.', text)


if __name__ == '__main__':
    unittest.main()
