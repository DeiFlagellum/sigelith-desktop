"""
Nazwy zapisywanych plikow (`naming.py`) i adresy stron w jezyku interfejsu
(`config.site_url`).
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from beatstamp import beatcore, naming  # noqa: E402
from beatstamp.config import site_url  # noqa: E402

ENTRY = SimpleNamespace(file_name='Umowa najmu.pdf', utc='2026-09-12T10:10:38.559217Z',
                        beat='@424.05', digest='4b' * 32)


class NamingTests(unittest.TestCase):

    def setUp(self):
        # Czas lokalny w nazwie zalezy od strefy maszyny — przypinamy UTC+2,
        # zeby wynik testu nie zalezal od tego, gdzie go uruchomiono.
        patcher = mock.patch.object(
            beatcore, 'local_str',
            lambda dt, fmt=None: (dt + __import__('datetime').timedelta(hours=2)).strftime(
                fmt or beatcore.DATETIME_FORMAT))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_all_parts(self):
        self.assertEqual(naming.certificate_name(ENTRY),
                         'Umowa najmu_2026-09-12_12-10-38_@424.05_sigelith.pdf')
        self.assertEqual(naming.bundle_name(ENTRY),
                         'Umowa najmu_2026-09-12_12-10-38_@424.05.beatproof')

    def test_parts_can_be_switched_off(self):
        self.assertEqual(naming.certificate_name(ENTRY, moment=False, beat=False),
                         'Umowa najmu_sigelith.pdf')
        self.assertEqual(naming.certificate_name(ENTRY, source=False, beat=False),
                         '2026-09-12_12-10-38_sigelith.pdf')
        # Nic nie zostalo — nazwa po skrocie, nigdy pusta.
        self.assertEqual(naming.certificate_name(ENTRY, source=False, moment=False,
                                                 beat=False),
                         '4b4b4b4b4b4b4b4b_sigelith.pdf')

    def test_no_colon_and_no_forbidden_characters(self):
        entry = SimpleNamespace(file_name='a:b<c>|d?.pdf', utc=ENTRY.utc,
                                beat='@424.05', digest='')
        name = naming.certificate_name(entry)
        for ch in '<>:"/\\|?*':
            self.assertNotIn(ch, name)

    def test_a_forged_beat_never_reaches_the_name(self):
        entry = SimpleNamespace(file_name='x.pdf', utc=ENTRY.utc,
                                beat='@424/../../evil', digest='')
        self.assertNotIn('evil', naming.certificate_name(entry))

    def test_unique_path_never_points_at_an_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'Umowa_sigelith.pdf'
            self.assertEqual(naming.unique_path(target), target)
            target.write_bytes(b'1')
            second = naming.unique_path(target)
            self.assertEqual(second.name, 'Umowa_sigelith (2).pdf')
            second.write_bytes(b'2')
            self.assertEqual(naming.unique_path(target).name, 'Umowa_sigelith (3).pdf')


class SiteUrlTests(unittest.TestCase):

    def test_localized_pages_get_the_language_prefix(self):
        self.assertEqual(site_url('proof', 'pl'), 'https://sigelith.org/pl/proof/')
        self.assertEqual(site_url('evidence', 'de'), 'https://sigelith.org/de/evidence/')
        self.assertEqual(site_url('', 'pl'), 'https://sigelith.org/pl/')

    def test_english_has_no_prefix(self):
        self.assertEqual(site_url('proof', 'en'), 'https://sigelith.org/proof/')

    def test_single_language_pages_keep_one_address(self):
        for page in ('spec', 'checkpoints', 'open-source', 'docs'):
            self.assertEqual(site_url(page, 'pl'), f'https://sigelith.org/{page}/')

    def test_query_is_kept(self):
        self.assertEqual(site_url('proof?h=ab', 'pl'),
                         'https://sigelith.org/pl/proof/?h=ab')

    def test_the_manifesto_original_is_polish(self):
        self.assertEqual(site_url('manifesto', 'pl'), 'https://sigelith.org/pl/manifesto/')
        # Po niemiecku manifestu nie ma — prowadzimy na tlumaczenie EN.
        self.assertEqual(site_url('manifesto', 'de'), 'https://sigelith.org/manifesto/')


if __name__ == '__main__':
    unittest.main()
