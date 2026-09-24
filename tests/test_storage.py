"""
Testy trwalosci danych: zapis atomowy, historia, migracja z TVS, skróty.

Każdy test w klasie `HistoryTests` odpowiada konkretnej usterce poprzedniej
wersji. Chodzi o to, żeby te usterki nie mogly wrocic po cichu przy
jakiejkolwiek pozniejszej zmianie.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from beatstamp import hashing, i18n  # noqa: E402
from beatstamp.config import Settings, write_atomic  # noqa: E402
# Jezyk interfejsu PRZYPIETY. Testy sprawdzaja ZNACZENIE napisu — oczekiwany
# tekst bierzemy z tego samego katalogu tlumaczen, ktorego uzywa program
# (`_('<msgid>')`), a nie z przepisanego recznie ciagu znakow. Bez przypiecia
# wynik suite zalezalby od jezyka interfejsu maszyny, na ktorej akurat sie ja
# uruchamia; bez katalogu — sprawdzalibysmy literowke, a nie tresc.
i18n.set_language('pl')
_ = i18n.gettext

from beatstamp.history import SOURCE_TVS_LEGACY, Entry, History  # noqa: E402


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()


class AtomicWriteTests(TempDirTest):

    def test_writes_content(self):
        target = self.dir / 'plik.json'
        write_atomic(target, b'{"a": 1}')
        self.assertEqual(target.read_bytes(), b'{"a": 1}')

    def test_replaces_existing_completely(self):
        target = self.dir / 'plik.json'
        target.write_bytes(b'x' * 5000)
        write_atomic(target, b'krotko')
        self.assertEqual(target.read_bytes(), b'krotko')

    def test_creates_missing_directories(self):
        target = self.dir / 'a' / 'b' / 'c.json'
        write_atomic(target, b'ok')
        self.assertTrue(target.exists())

    def test_failure_leaves_no_temporary_files(self):
        """Nieudany zapis nie może zasmiecac katalogu plikami .tmp."""
        target = self.dir / 'plik.json'
        target.write_bytes(b'oryginal')

        class Boom(Exception):
            pass

        real_replace = os.replace

        def failing_replace(src, dst):
            raise Boom('symulowana awaria')

        os.replace = failing_replace
        try:
            with self.assertRaises(Boom):
                write_atomic(target, b'nowa tresc')
        finally:
            os.replace = real_replace

        # Oryginal nietkniety, zaden smiec nie zostal.
        self.assertEqual(target.read_bytes(), b'oryginal')
        self.assertEqual([p.name for p in self.dir.iterdir()], ['plik.json'])


class HistoryTests(TempDirTest):

    def _history(self, limit: int = 5000) -> History:
        return History(self.dir / 'history.json', limit=limit)

    @staticmethod
    def _entry(digest_seed: str, **kwargs) -> Entry:
        digest = hashlib.sha256(digest_seed.encode()).hexdigest()
        return Entry(digest=digest, utc='2026-09-12T10:00:00Z', beat='@416.66', **kwargs)

    def test_add_and_reload(self):
        history = self._history()
        history.add(self._entry('a', file_name='a.pdf'))
        history.add(self._entry('b', file_name='b.pdf'))
        reloaded = self._history().load()
        self.assertEqual(len(reloaded.entries), 2)
        self.assertEqual(reloaded.entries[1].file_name, 'b.pdf')
        self.assertEqual(reloaded.load_problem, '')

    def test_corrupt_file_is_quarantined_not_lost(self):
        """Regresja: dawniej `except: pass` kasowal cala historie po cichu."""
        path = self.dir / 'history.json'
        path.write_text('{to nie jest poprawny json', encoding='utf-8')

        history = self._history().load()

        self.assertEqual(history.entries, [])
        self.assertIn('uszkodzony', history.load_problem.lower())
        quarantined = list(self.dir.glob('historia.uszkodzona-*.json'))
        self.assertEqual(len(quarantined), 1, 'uszkodzony plik musi zostac zachowany')
        self.assertIn('to nie jest poprawny json',
                      quarantined[0].read_text(encoding='utf-8'))

    def test_single_broken_entry_does_not_invalidate_rest(self):
        path = self.dir / 'history.json'
        good = self._entry('a', file_name='a.pdf').to_dict()
        path.write_text(json.dumps([good, 'nie slownik', {}, good]), encoding='utf-8')

        history = self._history().load()

        self.assertEqual(len(history.entries), 2)
        self.assertEqual(history.load_problem, _(
            'Skipped %(count)s damaged history entries; the rest were read '
            'correctly.') % {'count': 2})

    def test_unknown_keys_are_ignored(self):
        """Plik z nowszej wersji programu nie może wywrocic starszej."""
        path = self.dir / 'history.json'
        raw = self._entry('a').to_dict()
        raw['pole_z_przyszlosci'] = {'cos': [1, 2, 3]}
        path.write_text(json.dumps([raw]), encoding='utf-8')

        history = self._history().load()
        self.assertEqual(len(history.entries), 1)

    def test_limit_drops_oldest_entries(self):
        history = self._history(limit=10)
        for i in range(25):
            history.entries.append(self._entry(str(i), file_name=f'{i}.txt'))
        history.save()
        reloaded = self._history().load()
        self.assertEqual(len(reloaded.entries), 10)
        self.assertEqual(reloaded.entries[0].file_name, '15.txt')   # najstarsze odpadly
        self.assertEqual(reloaded.entries[-1].file_name, '24.txt')

    def test_replace_preserves_user_owned_fields(self):
        """Odswiezenie z serwera nie ma prawa skasowac notatki uzytkownika."""
        history = self._history()
        original = self._entry('a', file_name='umowa.pdf', note='moja notatka',
                               file_size=1234, level='recorded')
        history.add(original)

        fresh = self._entry('a', level='anchored', ots_status='bitcoin')
        history.replace(fresh)

        stored = history.entries[0]
        self.assertEqual(stored.level, 'anchored')      # status sie zmienil
        self.assertEqual(stored.note, 'moja notatka')   # notatka przetrwala
        self.assertEqual(stored.file_name, 'umowa.pdf')
        self.assertEqual(stored.file_size, 1234)

    def test_remove_and_find(self):
        history = self._history()
        a, b = self._entry('a'), self._entry('b')
        history.add(a)
        history.add(b)
        self.assertIsNotNone(history.find(a.digest))
        self.assertEqual(history.remove([a.digest]), 1)
        self.assertIsNone(history.find(a.digest))
        self.assertEqual(len(history.entries), 1)

    def test_legacy_tvs_import(self):
        legacy = self.dir / 'stara_history.json'
        real = hashlib.sha256(b'dokument').hexdigest()
        legacy.write_text(json.dumps([
            {'hash': 'unknown', 'cert_id': 'TVS-1',           # bez skrotu — pomijamy
             'timestamp': '2025-07-20T15:31:05.085945+00:00'},
            {'hash': real, 'cert_id': 'TVS-2', 'note': 'stara notatka',
             'signature': '2025-07-20T15:37:53+00:00.abc',
             'timestamp': '2025-07-20T15:37:53.281243+00:00',
             'verify_url': 'https://timevaultsecure.com/codegate/verify?id=TVS-2'},
        ]), encoding='utf-8')

        history = self._history()
        added = history.import_legacy_tvs(legacy)

        self.assertEqual(added, 1, 'wpis bez prawdziwego skrótu nie niesie nic')
        entry = history.entries[0]
        self.assertEqual(entry.digest, real)
        self.assertEqual(entry.source, SOURCE_TVS_LEGACY)
        self.assertEqual(entry.note, 'stara notatka')
        self.assertEqual(entry.legacy['cert_id'], 'TVS-2')
        self.assertTrue(entry.beat.startswith('@'), 'czas przeliczony na @beat')
        self.assertFalse(entry.verified_ok, 'archiwum TVS nie udaje zweryfikowanego')

    def test_legacy_import_is_idempotent(self):
        legacy = self.dir / 'stara_history.json'
        real = hashlib.sha256(b'x').hexdigest()
        legacy.write_text(json.dumps([{'hash': real, 'cert_id': 'TVS-9',
                                       'timestamp': '2025-07-20T15:37:53+00:00'}]),
                          encoding='utf-8')
        history = self._history()
        self.assertEqual(history.import_legacy_tvs(legacy), 1)
        self.assertEqual(history.import_legacy_tvs(legacy), 0)
        self.assertEqual(len(history.entries), 1)

    def test_csv_export_is_excel_friendly(self):
        """Regresja: stary eksport dawal w polskim Excelu jedna kolumne krzakow."""
        history = self._history()
        history.add(self._entry('a', file_name='zażółć.pdf', note='gęślą jaźń'))
        target = self.dir / 'eksport.csv'
        history.export_csv(target)

        raw = target.read_bytes()
        self.assertTrue(raw.startswith(b'\xef\xbb\xbf'), 'brak BOM — Excel czyta jako cp1250')
        text = raw.decode('utf-8-sig')
        self.assertIn(';', text.splitlines()[0], 'Excel PL rozdziela kolumny srednikiem')
        self.assertIn('zażółć.pdf', text)
        self.assertIn('gęślą jaźń', text)

    def test_json_export_roundtrip(self):
        history = self._history()
        history.add(self._entry('a', file_name='a.pdf'))
        target = self.dir / 'eksport.json'
        history.export_json(target)
        data = json.loads(target.read_text(encoding='utf-8'))
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['file_name'], 'a.pdf')


class HashingTests(TempDirTest):

    def test_known_digest(self):
        path = self.dir / 'plik.bin'
        path.write_bytes(b'BeatTime')
        result = hashing.sha256_file(path)
        self.assertEqual(result.digest, hashlib.sha256(b'BeatTime').hexdigest())
        self.assertEqual(result.size, 8)

    def test_empty_file(self):
        path = self.dir / 'pusty.bin'
        path.write_bytes(b'')
        result = hashing.sha256_file(path)
        self.assertEqual(result.digest, hashlib.sha256(b'').hexdigest())

    def test_multi_chunk_file_matches_hashlib(self):
        """Plik wiekszy od bufora — sprawdza sklejanie kolejnych odczytow."""
        payload = os.urandom(hashing.CHUNK_SIZE * 2 + 1234)
        path = self.dir / 'duży.bin'
        path.write_bytes(payload)
        result = hashing.sha256_file(path)
        self.assertEqual(result.digest, hashlib.sha256(payload).hexdigest())
        self.assertEqual(result.size, len(payload))

    def test_progress_is_reported_and_monotonic(self):
        payload = os.urandom(hashing.CHUNK_SIZE * 3)
        path = self.dir / 'duży.bin'
        path.write_bytes(payload)
        seen: list[int] = []
        hashing.sha256_file(path, progress=lambda done, total: seen.append(done))
        self.assertGreaterEqual(len(seen), 2)
        self.assertEqual(seen, sorted(seen), 'postep nie może się cofac')
        self.assertEqual(seen[-1], len(payload))

    def test_cancellation_stops_work(self):
        payload = os.urandom(hashing.CHUNK_SIZE * 4)
        path = self.dir / 'duży.bin'
        path.write_bytes(payload)
        with self.assertRaises(hashing.HashCancelled):
            hashing.sha256_file(path, cancelled=lambda: True)

    def test_missing_file_gives_polish_message(self):
        with self.assertRaises(hashing.HashError) as ctx:
            hashing.sha256_file(self.dir / 'nie ma takiego pliku')
        self.assertIn('nie istnieje', str(ctx.exception))

    def test_directory_is_rejected(self):
        with self.assertRaises(hashing.HashError):
            hashing.sha256_file(self.dir)

    def test_human_size_uses_the_decimal_separator_of_the_language(self):
        self.assertEqual(hashing.human_size(0), '0 B')
        self.assertEqual(hashing.human_size(512), '512 B')
        self.assertEqual(hashing.human_size(1536), '1,5 KB')
        self.assertEqual(hashing.human_size(5 * 1024 * 1024), '5,0 MB')


class SettingsTests(TempDirTest):

    def setUp(self):
        super().setUp()
        # Katalog danych wskazuje teraz `BEATSTAMP_DATA_DIR` — sciezka do
        # samego katalogu, nie do jego rodzica (patrz `config.app_data_dir`).
        self._old = os.environ.get('BEATSTAMP_DATA_DIR')
        os.environ['BEATSTAMP_DATA_DIR'] = str(self.dir)

    def tearDown(self):
        if self._old is None:
            os.environ.pop('BEATSTAMP_DATA_DIR', None)
        else:
            os.environ['BEATSTAMP_DATA_DIR'] = self._old
        super().tearDown()

    def test_roundtrip(self):
        settings = Settings(theme='dark', use_tor=True, timeout_seconds=42.5,
                            history_limit=100)
        settings.save()
        loaded = Settings.load()
        self.assertEqual(loaded.theme, 'dark')
        self.assertTrue(loaded.use_tor)
        self.assertEqual(loaded.timeout_seconds, 42.5)
        self.assertEqual(loaded.history_limit, 100)

    def test_broken_file_falls_back_to_defaults(self):
        from beatstamp.config import settings_path
        settings_path().write_text('to nie jest json', encoding='utf-8')
        loaded = Settings.load()
        self.assertEqual(loaded.theme, Settings().theme)

    def test_wrong_types_fall_back_per_field(self):
        from beatstamp.config import settings_path
        settings_path().write_text(json.dumps({
            'theme': 'dark',
            'timeout_seconds': 'nie liczba',      # zle — wraca do domyslnej
            'nieznane_pole': 123,                 # ignorowane
        }), encoding='utf-8')
        loaded = Settings.load()
        self.assertEqual(loaded.theme, 'dark')
        self.assertEqual(loaded.timeout_seconds, Settings().timeout_seconds)

    def test_onion_switches_url_and_disables_tls_bundle(self):
        settings = Settings(use_tor=True)
        self.assertIn('.onion', settings.effective_base_url)
        self.assertFalse(settings.verify_tls)
        self.assertEqual(settings.proxies['https'], settings.tor_proxy)

    def test_clearnet_uses_certifi_bundle(self):
        settings = Settings(use_tor=False)
        self.assertTrue(settings.effective_base_url.startswith('https://'))
        self.assertIsInstance(settings.verify_tls, str)
        self.assertTrue(Path(settings.verify_tls).exists(), 'magazyn CA musi istniec')
        self.assertIsNone(settings.proxies)


if __name__ == '__main__':
    unittest.main(verbosity=2)


class PluralTests(unittest.TestCase):
    """Odmiana liczebników — „6 wpis(ow)" to nie jest polski.

    Sedno jest w wyjątku dla nastolatków: 2 → „wpisy", ale 12 → „wpisów",
    mimo że obie liczby kończą się tą samą cyfrą. Na tym rozbijają się
    doraźne implementacje sprawdzające samo `n % 10`.
    """

    def test_one(self):
        from beatstamp import plural
        self.assertEqual(plural.entries(1), '1 wpis')
        self.assertEqual(plural.files(1), '1 plik')

    def test_few(self):
        from beatstamp import plural
        for n in (2, 3, 4, 22, 23, 24, 102, 1002):
            self.assertEqual(plural.entries(n), f'{n} wpisy', f'dla {n}')

    def test_many(self):
        from beatstamp import plural
        for n in (0, 5, 6, 9, 10, 11, 15, 21, 25, 100, 111):
            self.assertEqual(plural.entries(n), f'{n} wpisów', f'dla {n}')

    def test_teens_exception(self):
        """12, 13, 14 biorą formę „many", mimo końcówki 2/3/4."""
        from beatstamp import plural
        for n in (12, 13, 14, 112, 113, 114, 212):
            self.assertEqual(plural.entries(n), f'{n} wpisów', f'dla {n}')

    def test_no_placeholder_parentheses_remain(self):
        """Regresja: nigdzie w interfejsie nie może zostać „(ow)" ani „(ów)"."""
        import pathlib
        import re
        root = pathlib.Path(__file__).resolve().parent.parent / 'beatstamp'
        offenders = []
        for path in root.rglob('*.py'):
            if path.name == 'plural.py':
                continue      # tam „6 wpis(ow)" stoi jako CYTAT zlego przykladu
            for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
                if re.search(r'\((?:ow|ów|y|i)\)', line) and 'plural' not in line:
                    offenders.append(f'{path.name}:{number}')
        self.assertEqual(offenders, [], f'skrótowa odmiana zamiast plural.*: {offenders}')
