"""
`sigelith-desktop.exe --handover <plik>` — wysyłka przez Sigelith Handover na prośbę
innego programu (Sigelith Backup: „Przekaż…” przy pliku z kopii).

Pilnujemy trzech rzeczy: podział wiersza polecen (pliki do otwarcia vs do wyslania),
przekazanie prosby do juz dzialajacej kopii (klucz `handover`, ktory starsze wersje
pomijaja) i alias w manifescie paczki.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtCore import QCoreApplication  # noqa: E402

from beatstamp import instance  # noqa: E402


class SplitArgumentsTests(unittest.TestCase):

    def test_files_after_the_flag_are_to_be_sent(self):
        with tempfile.TemporaryDirectory() as tmp:
            one, two = Path(tmp) / 'umowa.pdf', Path(tmp) / 'aneks.pdf'
            one.write_bytes(b'1')
            two.write_bytes(b'2')
            files, handover = instance.split_arguments(['--handover', str(one), str(two)])
            self.assertEqual((files, handover), ([], [str(one), str(two)]))
            files, handover = instance.split_arguments([str(one), '--background'])
            self.assertEqual((files, handover), ([str(one)], []))
            files, handover = instance.split_arguments(
                ['--handover', str(Path(tmp) / 'nie-ma.pdf'), str(two)])
            self.assertEqual(handover, [str(two)], 'nieistniejacy plik pominiety')


class ForwardedHandoverTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QCoreApplication.instance() or QCoreApplication([])

    def test_running_copy_receives_the_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            guard = instance.SingleInstance(Path(tmp))
            opened, sent = [], []
            guard.activated.connect(opened.append)
            guard.handover_requested.connect(sent.append)
            guard._deliver(json.dumps({'files': [], 'handover': ['C:/kopia/umowa.pdf']}).encode() + b'\n')
            self.assertEqual(opened, [[]], 'okno i tak sie pokazuje')
            self.assertEqual(sent, [['C:/kopia/umowa.pdf']])

    def test_message_without_handover_changes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            guard = instance.SingleInstance(Path(tmp))
            sent = []
            guard.handover_requested.connect(sent.append)
            guard._deliver(json.dumps({'files': ['C:/a.pdf']}).encode() + b'\n')
            guard._deliver(json.dumps({'handover': 'nie-lista'}).encode() + b'\n')
            self.assertEqual(sent, [])


class ManifestAliasTests(unittest.TestCase):

    def test_alias_is_declared(self):
        manifest = (Path(__file__).resolve().parent.parent / 'packaging' / 'AppxManifest.xml'
                    ).read_text(encoding='utf-8')
        self.assertIn('<desktop:ExecutionAlias Alias="sigelith-desktop.exe" />', manifest)
        self.assertIn('windows.appExecutionAlias', manifest)
        self.assertIn('IgnorableNamespaces="uap rescap uap3 desktop"', manifest)


if __name__ == '__main__':
    unittest.main()
