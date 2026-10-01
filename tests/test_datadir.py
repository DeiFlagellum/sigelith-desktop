"""
Testy lokalizacji danych uzytkownika, przeprowadzki i ZABLOKOWANEGO ZAPISU.

Powod istnienia tego pliku jest konkretny i ma dwie czesci.

1. Paczka MSIX wirtualizuje kazdy NOWO utworzony plik w `AppData` do
   prywatnego magazynu paczki i kasuje go przy odinstalowaniu.
   `config.write_atomic` tworzy nowy plik przy KAZDYM zapisie, wiec historia
   stempli — jedyne dane, ktorych uzytkownik nie odtworzy — znikalaby przy
   odinstalowaniu ze Sklepu.
2. Katalog „Dokumenty", do ktorego dane uciekly przed punktem 1, jest po
   stronie Windows folderem CHRONIONYM: ochrona przed ransomware blokuje tam
   zapis kazdej aplikacji, ktorej Defender nie zna. Blokada NIE zglasza sie
   jako odmowa dostepu — `tempfile.mkstemp` przewraca sie na
   `FileNotFoundError` w katalogu, ktory istnieje. Kod lapiacy sam
   `PermissionError` nie zauwazy jej nigdy.

Stad dzisiejsza lokalizacja: `%USERPROFILE%\\Sigelith` (do 2.2.0, jeszcze
jako BeatStamp: `%USERPROFILE%\\BeatStamp`) — poza `AppData`,
poza domyslna lista folderow chronionych i poza OneDrive. Zadne z tych miejsc
nie jest jednak gwarantowane: uzytkownik moze dodac DOWOLNY folder do listy
chronionej, wiec zapis jest jeszcze sprawdzany (`probe_write`), a wybor
innego katalogu zapamietywany (`remember_data_dir`).

Kazdy test ponizej pilnuje jednego warunku, bez ktorego wraca albo cicha
strata danych, albo slad wyjatku na ekranie uzytkownika.

Tryb spakowany (MSIX) i zwykly `.exe` rozpoznaje `config.is_packaged()`:
najpierw `GetCurrentPackageFullName` z `kernel32` (poza paczka zwraca
`APPMODEL_ERROR_NO_PACKAGE` = 15700), zapasowo sciezka procesu pod
`C:\\Program Files\\WindowsApps\\`. Lokalizacja danych od tego NIE zalezy —
jest jedna dla obu trybow i wlasnie to sprawdza `DataDirModeTests`.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from beatstamp import config, i18n  # noqa: E402
from beatstamp.history import Entry, History  # noqa: E402

# Jezyk interfejsu PRZYPIETY. Testy sprawdzaja ZNACZENIE napisu — oczekiwany
# tekst bierzemy z tego samego katalogu tlumaczen, ktorego uzywa program
# (`_('<msgid>')`), a nie z przepisanego recznie ciagu znakow. Bez przypiecia
# wynik suite zalezalby od jezyka interfejsu maszyny, na ktorej akurat sie ja
# uruchamia; bez katalogu — sprawdzalibysmy literowke, a nie tresc.
i18n.set_language('pl')
_ = i18n.gettext


WINDOWS_ONLY = unittest.skipUnless(sys.platform == 'win32', 'sciezki specyficzne dla Windows')

#: Zmienne, ktore wplywaja na rozstrzyganie sciezek. Kazdy test zaczyna
#: z czystym kompletem, zeby ustawienia maszyny deweloperskiej (na przyklad
#: wlaczony OneDrive) nie decydowaly o wyniku.
_ENV_KEYS = ('SIGELITH_DATA_DIR', 'BEATSTAMP_DATA_DIR', 'LOCALAPPDATA', 'USERPROFILE',
             'XDG_DATA_HOME', 'OneDrive', 'OneDriveConsumer', 'OneDriveCommercial')


class EnvIsolatedTest(unittest.TestCase):
    """Katalog tymczasowy + odtworzenie srodowiska po kazdym tescie."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self._saved = {key: os.environ.get(key) for key in _ENV_KEYS}
        for key in _ENV_KEYS:
            os.environ.pop(key, None)
        # Obie zmienne maja wartosc IZOLOWANA, nie brak wartosci. Bez
        # `LOCALAPPDATA` program szuka wskaznika katalogu danych
        # (`config.location_file`) w prawdziwym katalogu domowym — wynik testu
        # zalezalby wtedy od tego, czy wlasciciel maszyny kiedys zmienil sobie
        # katalog danych. Bez `USERPROFILE` to samo dotyczy lokalizacji
        # domyslnej. Test, ktory bada wlasnie te sciezki, nadpisuje je u siebie.
        os.environ['LOCALAPPDATA'] = str(self.dir / 'AppData' / 'Local')
        os.environ['USERPROFILE'] = str(self.dir / 'Profil')

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._tmp.cleanup()


# --- Rozstrzyganie sciezki --------------------------------------------------


class DataDirResolutionTests(EnvIsolatedTest):

    def test_env_variable_points_at_the_directory_itself(self):
        """`SIGELITH_DATA_DIR` to katalog danych, nie jego rodzic."""
        target = self.dir / 'przenosne' / 'dane'
        os.environ['SIGELITH_DATA_DIR'] = str(target)

        self.assertEqual(config.resolved_data_dir(), target)
        self.assertEqual(config.app_data_dir(), target)
        self.assertEqual(config.history_path(), target / 'history.json')
        self.assertEqual(config.settings_path(), target / 'settings.json')
        self.assertEqual(config.log_path(), target / 'sigelith.log')

    def test_env_variable_wins_over_the_default_location(self):
        os.environ['USERPROFILE'] = str(self.dir / 'profil')
        os.environ['SIGELITH_DATA_DIR'] = str(self.dir / 'wybrany')

        self.assertEqual(config.resolved_data_dir(), self.dir / 'wybrany')

    def test_the_beatstamp_variable_still_works(self):
        """Skrypt albo skrot z wersja przenosna z czasow BeatStampa ustawia
        `BEATSTAMP_DATA_DIR` — po aktualizacji ma dalej pisac TAM, a nie
        po cichu w nowej lokalizacji domyslnej."""
        os.environ['USERPROFILE'] = str(self.dir / 'profil')
        os.environ['BEATSTAMP_DATA_DIR'] = str(self.dir / 'pendrive')

        self.assertEqual(config.resolved_data_dir(), self.dir / 'pendrive')
        self.assertEqual(config.forced_data_dir(),
                         ('BEATSTAMP_DATA_DIR', str(self.dir / 'pendrive')))

    def test_the_new_variable_wins_over_the_beatstamp_one(self):
        os.environ['BEATSTAMP_DATA_DIR'] = str(self.dir / 'stara')
        os.environ['SIGELITH_DATA_DIR'] = str(self.dir / 'nowa')

        self.assertEqual(config.resolved_data_dir(), self.dir / 'nowa')
        self.assertEqual(config.forced_data_dir()[0], 'SIGELITH_DATA_DIR')

    def test_blank_env_variable_is_ignored(self):
        """Pusta zmienna to nie jest wybor uzytkownika, tylko smiec po skrypcie."""
        os.environ['SIGELITH_DATA_DIR'] = '   '
        os.environ['BEATSTAMP_DATA_DIR'] = ''
        os.environ['USERPROFILE'] = str(self.dir / 'profil')
        with mock.patch.object(config, '_windows_documents_dir', return_value=None):
            self.assertEqual(config.resolved_data_dir(), self.dir / 'profil' / 'Sigelith')

    def test_relative_env_variable_is_rejected(self):
        """Regresja do wady nr 1 z naglowka `config.py`: sciezka wzgledna.

        Katalog roboczy to miejsce, z ktorego uzytkownik akurat uruchomil
        program — historia rozsypywalaby sie po dysku, dokladnie jak
        u poprzednika.
        """
        os.environ['SIGELITH_DATA_DIR'] = 'dane'
        os.environ['USERPROFILE'] = str(self.dir / 'profil')
        with mock.patch.object(config, '_windows_documents_dir', return_value=None):
            resolved = config.resolved_data_dir()

        self.assertTrue(resolved.is_absolute())
        self.assertNotEqual(resolved, Path('dane'))

    @WINDOWS_ONLY
    def test_onedrive_detection_ignores_letter_case(self):
        """Windows nie rozroznia wielkosci liter w sciezkach — wykrywanie tez nie moze.

        Wykrywanie OneDrive nie decyduje juz o lokalizacji domyslnej (korzen
        profilu jest poza zasiegiem Known Folder Move), ale OSTRZEGA
        uzytkownika, ktory sam wskaze katalog w chmurze — historia to lista
        nazw i skrotow jego dokumentow.
        """
        os.environ['OneDrive'] = str(self.dir / 'OneDrive')
        self.assertTrue(config.is_inside_onedrive(
            Path(str(self.dir / 'onedrive' / 'Dokumenty' / 'Sigelith'))))

    def test_app_data_dir_creates_the_directory(self):
        target = self.dir / 'a' / 'b' / 'dane'
        os.environ['SIGELITH_DATA_DIR'] = str(target)

        self.assertTrue(config.app_data_dir().is_dir())

    def test_app_data_dir_never_raises_when_location_is_unusable(self):
        """Niedostepny udzial sieciowy nie moze gasic programu przy starcie."""
        os.environ['SIGELITH_DATA_DIR'] = str(self.dir / 'nieosiagalny')
        with mock.patch.object(Path, 'mkdir', side_effect=OSError('sieć nie odpowiada')):
            path = config.app_data_dir()
        self.assertEqual(path, self.dir / 'nieosiagalny')

    @WINDOWS_ONLY
    def test_default_location_is_outside_appdata(self):
        """Pierwsza polowa sedna: dane nie moga lezec w `AppData`.

        Paczka MSIX wirtualizuje tam nowe pliki i kasuje je razem z paczka —
        historia stempli znikalaby przy odinstalowaniu ze Sklepu.
        """
        os.environ['LOCALAPPDATA'] = str(self.dir / 'AppData' / 'Local')
        os.environ['USERPROFILE'] = str(self.dir)

        resolved = config.resolved_data_dir()

        self.assertEqual(resolved, self.dir / 'Sigelith')
        # Porownanie z prawdziwym `%LOCALAPPDATA%` testu, a nie szukanie slowa
        # „appdata" w sciezce: katalog tymczasowy testu sam lezy w AppData.
        self.assertFalse(config._is_inside(resolved, Path(os.environ['LOCALAPPDATA'])))
        self.assertFalse(config._is_inside(resolved, config.legacy_app_data_dir()))

    @WINDOWS_ONLY
    def test_default_location_is_outside_the_documents_folder(self):
        """Druga polowa sedna: „Dokumenty" sa folderem CHRONIONYM.

        Ochrona przed ransomware blokuje tam zapis aplikacji, ktorej Defender
        nie zna z reputacji — a swiezo zbudowany `.exe` nie jest znany z
        definicji, przy kazdym nowym wydaniu od nowa. Lokalizacja domyslna nie
        moze wiec zalezec od tego, gdzie leza „Dokumenty", ani nawet o nie
        pytac.
        """
        os.environ['USERPROFILE'] = str(self.dir)
        documents = self.dir / 'Dokumenty'
        with mock.patch.object(config, '_windows_documents_dir',
                               return_value=documents) as asked:
            resolved = config.resolved_data_dir()

        self.assertEqual(resolved, self.dir / 'Sigelith')
        self.assertFalse(config._is_inside(resolved, documents))
        self.assertEqual(asked.call_count, 0,
                         'lokalizacja domyslna nie ma prawa pytac o Dokumenty')

    @WINDOWS_ONLY
    def test_default_location_stays_out_of_onedrive(self):
        """Historia to skróty dokumentow — nie ma sama wedrowac do chmury.

        OneDrive Known Folder Move obejmuje Pulpit, Dokumenty i Obrazy;
        korzen profilu zostawia w spokoju. Sam fakt, ze OneDrive jest
        zainstalowany, nie ma wiec prawa niczego przesunac.
        """
        onedrive = self.dir / 'OneDrive'
        os.environ['OneDrive'] = str(onedrive)
        os.environ['USERPROFILE'] = str(self.dir)

        resolved = config.resolved_data_dir()

        self.assertEqual(resolved, self.dir / 'Sigelith')
        self.assertFalse(config.is_inside_onedrive(resolved))

    @WINDOWS_ONLY
    def test_commercial_onedrive_is_detected_too(self):
        onedrive = self.dir / 'OneDrive - Firma'
        os.environ['OneDriveCommercial'] = str(onedrive)
        self.assertTrue(config.is_inside_onedrive(onedrive / 'Documents' / 'Sigelith'))

    @WINDOWS_ONLY
    def test_unavailable_profile_variable_still_gives_a_home(self):
        """Brak `%USERPROFILE%` nie moze zostawic programu bez katalogu."""
        os.environ.pop('USERPROFILE', None)

        resolved = config.resolved_data_dir()

        self.assertTrue(resolved.is_absolute())
        self.assertEqual(resolved.name, 'Sigelith')

    @WINDOWS_ONLY
    def test_chosen_folder_gets_the_application_subfolder(self):
        """Wskazanie `D:\\Dane` nie ma wysypywac plikow programu do korzenia."""
        self.assertEqual(config.data_dir_for_choice(self.dir / 'Dane'),
                         self.dir / 'Dane' / 'Sigelith')

    def test_choosing_an_existing_data_folder_is_not_nested_twice(self):
        """Uzytkownik wskazuje katalog przeniesiony recznie — bez `Sigelith\\Sigelith`."""
        chosen = self.dir / 'Kopia' / 'Sigelith'
        self.assertEqual(config.data_dir_for_choice(chosen), chosen)

    def test_choosing_an_old_beatstamp_folder_is_not_nested_either(self):
        """Katalog danych z czasow BeatStampa to TEZ katalog danych — bez
        `BeatStamp\\Sigelith`."""
        chosen = self.dir / 'Kopia' / 'BeatStamp'
        self.assertEqual(config.data_dir_for_choice(chosen), chosen)

    @WINDOWS_ONLY
    def test_legacy_location_is_still_the_old_appdata_path(self):
        os.environ['LOCALAPPDATA'] = str(self.dir / 'AppData' / 'Local')
        self.assertEqual(config.legacy_app_data_dir(),
                         self.dir / 'AppData' / 'Local' / 'BeatStamp')

    def test_legacy_location_is_not_created_by_asking_for_it(self):
        """Samo pytanie „czy jest co przenosic" nie zostawia pustego katalogu."""
        os.environ['LOCALAPPDATA'] = str(self.dir / 'AppData' / 'Local')
        os.environ['XDG_DATA_HOME'] = str(self.dir / 'share')
        legacy = config.legacy_app_data_dir()
        self.assertFalse(legacy.exists())


# --- Tryb spakowany (MSIX) kontra zwykly .exe -------------------------------


class DataDirModeTests(EnvIsolatedTest):

    def test_this_process_is_not_packaged(self):
        """Testy chodza z interpretera, nie z paczki — inaczej cos jest nie tak."""
        self.assertFalse(config.is_packaged())

    @WINDOWS_ONLY
    def test_windowsapps_path_is_recognised_as_packaged(self):
        """Zapasowe rozpoznanie po sciezce, gdy `kernel32` nie odpowie."""
        exe = (r'C:\Program Files\WindowsApps\AdamKoch.SigelithDesktop_3.0.0.0_x64__abcdef'
               r'\SigelithDesktop.exe')
        with mock.patch.object(config, 'Path') as fake_path:
            fake_path.return_value.resolve.return_value.parts = tuple(exe.split('\\'))
            with mock.patch('ctypes.windll') as windll:
                windll.kernel32.GetCurrentPackageFullName.side_effect = AttributeError
                self.assertTrue(config.is_packaged())

    @WINDOWS_ONLY
    def test_no_package_error_means_plain_exe(self):
        with mock.patch('ctypes.windll') as windll:
            windll.kernel32.GetCurrentPackageFullName.return_value = 15700
            self.assertFalse(config.is_packaged())

    @WINDOWS_ONLY
    def test_buffer_error_means_packaged(self):
        """W paczce API zwraca ERROR_INSUFFICIENT_BUFFER, bo pytamy pustym buforem."""
        with mock.patch('ctypes.windll') as windll:
            windll.kernel32.GetCurrentPackageFullName.return_value = 122
            self.assertTrue(config.is_packaged())

    def test_data_location_is_the_same_in_both_modes(self):
        """Instalacja ze Sklepu na maszynie po zwyklym `.exe` widzi te sama historie."""
        os.environ['USERPROFILE'] = str(self.dir)
        with mock.patch.object(config, '_windows_documents_dir',
                               return_value=self.dir / 'Dokumenty'):
            with mock.patch.object(config, 'is_packaged', return_value=False):
                plain = config.resolved_data_dir()
            with mock.patch.object(config, 'is_packaged', return_value=True):
                packaged = config.resolved_data_dir()

        self.assertEqual(plain, packaged)


# --- Przeprowadzka ----------------------------------------------------------


class MigrationTest(EnvIsolatedTest):
    """Stara i nowa lokalizacja wskazane wprost — bez zgadywania po systemie.

    Podmieniamy funkcje, a nie zmienne srodowiskowe, z dwoch powodow:

    * `SIGELITH_DATA_DIR` (i dawna `BEATSTAMP_DATA_DIR`) WYLACZA przeprowadzke (patrz
      `config.migrate_legacy_data`) — to zmienna dla wersji przenosnej
      i dla `tools/verify_exe.py`, wiec nie da sie nia wskazac celu;
    * `legacy_documents_data_dir` musi byc unieszkodliwione jawnie. Bez tego
      test na Windows siegnalby do PRAWDZIWYCH „Dokumentow" osoby
      uruchamiajacej testy i wciagnal jej historie do katalogu tymczasowego.
      Tak samo `legacy_profile_data_dir` (`%USERPROFILE%\\BeatStamp`) — to
      zrodlo ma wlasne testy (`MigrationFromBeatStampTests`).
    """

    def setUp(self):
        super().setUp()
        self.old = self.dir / 'AppData' / 'Local' / 'BeatStamp'
        self.new = self.dir / 'Profil' / 'Sigelith'
        self._patch = mock.patch.object(config, 'legacy_app_data_dir',
                                        return_value=self.old)
        self._patch.start()
        self.addCleanup(self._patch.stop)
        for name, value in (('legacy_documents_data_dir', None),
                            ('legacy_profile_data_dir', None),
                            ('app_data_dir', self.new),
                            ('resolved_data_dir', self.new)):
            patch = mock.patch.object(config, name, return_value=value)
            patch.start()
            self.addCleanup(patch.stop)

    def _entry(self, digest_seed: str, file_name: str = 'a.pdf') -> Entry:
        return Entry(digest=digest_seed * 64, file_name=file_name)

    def _old_history(self, *names: str) -> bytes:
        payload = json.dumps([self._entry('a', n).to_dict() for n in names],
                             indent=2, ensure_ascii=False).encode('utf-8')
        self.old.mkdir(parents=True, exist_ok=True)
        (self.old / 'history.json').write_bytes(payload)
        return payload


class MigrationWithDataTests(MigrationTest):

    def test_moves_history_settings_and_tvs_marker(self):
        payload = self._old_history('stary.pdf')
        (self.old / 'settings.json').write_text(
            json.dumps({'theme': 'dark'}), encoding='utf-8')
        (self.old / '.tvs-zaimportowano').write_text('ok', encoding='utf-8')

        report = config.migrate_legacy_data()

        self.assertEqual(sorted(report.copied),
                         ['.tvs-zaimportowano', 'history.json', 'settings.json'])
        self.assertEqual((self.new / 'history.json').read_bytes(), payload)
        self.assertEqual(json.loads((self.new / 'settings.json').read_text('utf-8')),
                         {'theme': 'dark'})
        self.assertTrue((self.new / '.tvs-zaimportowano').exists())
        self.assertTrue(report.done)

    def test_history_is_readable_from_the_new_location(self):
        """Test od konca do konca: po przeprowadzce widac te same wpisy."""
        self._old_history('umowa.pdf', 'faktura.pdf')

        config.migrate_legacy_data()
        history = History().load()

        self.assertEqual([e.file_name for e in history.entries],
                         ['umowa.pdf', 'faktura.pdf'])
        self.assertEqual(history.load_problem, '')

    def test_source_is_never_deleted(self):
        """Kopiujemy, nie przenosimy — przerwanie zostawia komplet oryginalow."""
        payload = self._old_history('stary.pdf')

        config.migrate_legacy_data()

        self.assertTrue((self.old / 'history.json').is_file())
        self.assertEqual((self.old / 'history.json').read_bytes(), payload)

    def test_quarantine_backups_are_moved_too(self):
        """Kopia ratunkowa uszkodzonej historii to jedyny slad po tych danych."""
        self.old.mkdir(parents=True, exist_ok=True)
        (self.old / 'historia.uszkodzona-20260101-101010.json').write_text(
            '{urwany', encoding='utf-8')

        config.migrate_legacy_data()

        self.assertTrue((self.new / 'historia.uszkodzona-20260101-101010.json').is_file())

    def test_forwarding_note_is_left_in_the_old_location(self):
        self._old_history('stary.pdf')

        config.migrate_legacy_data()

        note = (self.old / config.FORWARDING_NOTE).read_text(encoding='utf-8')
        self.assertIn(str(self.new), note)

    def test_report_message_names_the_new_location(self):
        self._old_history('stary.pdf')

        report = config.migrate_legacy_data()

        self.assertTrue(report.changed)
        self.assertIn(str(self.new), report.message)


class MigrationWithoutDataTests(MigrationTest):

    def test_missing_legacy_directory_still_writes_the_marker(self):
        report = config.migrate_legacy_data()

        self.assertFalse(report.changed)
        self.assertIsNone(report.source)
        self.assertTrue(report.done)
        self.assertTrue((self.new / config.MIGRATION_MARKER).exists())

    def test_missing_legacy_directory_is_not_created(self):
        config.migrate_legacy_data()
        self.assertFalse(self.old.exists())

    def test_empty_legacy_directory_copies_nothing(self):
        self.old.mkdir(parents=True, exist_ok=True)

        report = config.migrate_legacy_data()

        self.assertEqual(report.copied, [])
        self.assertEqual(report.message, '')
        self.assertTrue(report.done)

    def test_same_source_and_target_is_a_no_op(self):
        """macOS i Linux: stara lokalizacja JEST nowa — konczymy w pierwszym warunku."""
        self._patch.stop()
        with mock.patch.object(config, 'legacy_app_data_dir', return_value=self.new):
            report = config.migrate_legacy_data()
        self._patch.start()

        self.assertTrue(report.done)
        self.assertIsNone(report.source)
        self.assertFalse((self.new / config.MIGRATION_MARKER).exists())


class MigrationCorruptFileTests(MigrationTest):

    def test_corrupt_history_is_copied_byte_for_byte(self):
        """Przeprowadzka nie parsuje niczego, wiec nie ma czego zgubic."""
        self.old.mkdir(parents=True, exist_ok=True)
        broken = b'{to nie jest poprawny json'
        (self.old / 'history.json').write_bytes(broken)

        report = config.migrate_legacy_data()

        self.assertIn('history.json', report.copied)
        self.assertEqual((self.new / 'history.json').read_bytes(), broken)

    def test_corrupt_history_is_quarantined_at_the_new_location(self):
        """Decyzje o uszkodzonym pliku podejmuje `History.load` — juz na miejscu."""
        self.old.mkdir(parents=True, exist_ok=True)
        (self.old / 'history.json').write_bytes(b'{to nie jest poprawny json')

        config.migrate_legacy_data()
        history = History().load()

        self.assertEqual(history.entries, [])
        self.assertIn('uszkodzony', history.load_problem.lower())
        quarantined = list(self.new.glob('historia.uszkodzona-*.json'))
        self.assertEqual(len(quarantined), 1)
        self.assertIn('to nie jest poprawny json',
                      quarantined[0].read_text(encoding='utf-8'))
        # Oryginal w starej lokalizacji zostaje nietkniety.
        self.assertEqual((self.old / 'history.json').read_bytes(),
                         b'{to nie jest poprawny json')

    def test_unreadable_source_leaves_the_marker_unwritten(self):
        """Blad odczytu = przeprowadzka niedokonczona, powtarzana przy starcie."""
        self._old_history('stary.pdf')

        real_read = Path.read_bytes

        def boom(self_path, *args, **kwargs):
            if self_path.name == 'history.json' and self_path.parent == self.old:
                raise OSError('plik zajęty')
            return real_read(self_path, *args, **kwargs)

        with mock.patch.object(Path, 'read_bytes', boom):
            report = config.migrate_legacy_data()

        self.assertEqual(report.failed, ['history.json'])
        self.assertFalse(report.done)
        self.assertFalse((self.new / config.MIGRATION_MARKER).exists())


class MigrationRepeatTests(MigrationTest):

    def test_running_twice_changes_nothing(self):
        payload = self._old_history('stary.pdf')

        first = config.migrate_legacy_data()
        second = config.migrate_legacy_data()

        self.assertEqual(first.copied, ['history.json'])
        self.assertEqual(second.copied, [])
        self.assertEqual(second.kept_aside, [])
        self.assertIsNone(second.source)          # znacznik przerwal od razu
        self.assertEqual((self.new / 'history.json').read_bytes(), payload)
        self.assertEqual(list(self.new.glob('*.z-appdata-*')), [])

    def test_interrupted_run_resumes_without_duplicating(self):
        """Powtorka po przerwaniu rozpoznaje wlasne kopie po zawartosci.

        Bez tego warunku kazdy kolejny start uznawalby juz skopiowany plik za
        „cudzy" i produkowal nowa kopie `*.z-appdata-*`.
        """
        payload = self._old_history('stary.pdf')
        # Stan po przerwaniu: plik juz skopiowany, znacznika jeszcze nie ma.
        self.new.mkdir(parents=True, exist_ok=True)
        (self.new / 'history.json').write_bytes(payload)
        self.assertFalse((self.new / config.MIGRATION_MARKER).exists())

        report = config.migrate_legacy_data()

        self.assertEqual(report.copied, [])
        self.assertEqual(report.kept_aside, [])
        self.assertEqual(report.already_there, ['history.json'])
        self.assertEqual(list(self.new.glob('*.z-appdata-*')), [])
        self.assertTrue(report.done)

    def test_existing_different_file_is_kept_aside_not_overwritten(self):
        """Nadpisanie historii uzytkownika jest wykluczone w kazdym wariancie."""
        self._old_history('stary.pdf')
        self.new.mkdir(parents=True, exist_ok=True)
        nowa = json.dumps([self._entry('b', 'nowy.pdf').to_dict()],
                          indent=2, ensure_ascii=False).encode('utf-8')
        (self.new / 'history.json').write_bytes(nowa)

        report = config.migrate_legacy_data()

        self.assertEqual((self.new / 'history.json').read_bytes(), nowa)
        self.assertEqual(len(report.kept_aside), 1)
        aside = self.new / report.kept_aside[0]
        self.assertTrue(aside.name.startswith('history.json.z-appdata-'))
        self.assertIn('stary.pdf', aside.read_text(encoding='utf-8'))
        self.assertIn(aside.name, report.message)

    def test_marker_stops_a_later_run_from_touching_anything(self):
        """Uzytkownik, ktory sam cos wrzucil do starego katalogu, nie dostaje tego z powrotem."""
        config.migrate_legacy_data()               # swieza instalacja, znacznik zapisany
        self._old_history('pozniejszy.pdf')

        report = config.migrate_legacy_data()

        self.assertIsNone(report.source)
        self.assertFalse((self.new / 'history.json').exists())


class MigrationFromDocumentsTests(EnvIsolatedTest):
    """DRUGIE zrodlo przeprowadzki: `Dokumenty\\BeatStamp`.

    Na dyskach uzytkownikow, ktorzy stemplowali cokolwiek w okresie miedzy
    ucieczka z `AppData` a odkryciem blokady, leza tam prawdziwe dane. Scalenie
    obu zrodel musi dac JEDEN komplet, bez nadpisania czegokolwiek.
    """

    def setUp(self):
        super().setUp()
        self.appdata = self.dir / 'AppData' / 'Local' / 'BeatStamp'
        self.documents = self.dir / 'Dokumenty' / 'BeatStamp'
        self.new = self.dir / 'Profil' / 'Sigelith'
        for name, value in (('legacy_app_data_dir', self.appdata),
                            ('legacy_documents_data_dir', self.documents),
                            ('legacy_profile_data_dir', None),
                            ('app_data_dir', self.new),
                            ('resolved_data_dir', self.new)):
            patch = mock.patch.object(config, name, return_value=value)
            patch.start()
            self.addCleanup(patch.stop)

    def _history(self, directory: Path, name: str) -> bytes:
        payload = json.dumps([Entry(digest='a' * 64, file_name=name).to_dict()],
                             indent=2, ensure_ascii=False).encode('utf-8')
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'history.json').write_bytes(payload)
        return payload

    def test_documents_are_a_full_source_of_their_own(self):
        payload = self._history(self.documents, 'z-dokumentow.pdf')

        report = config.migrate_legacy_data()

        self.assertEqual((self.new / 'history.json').read_bytes(), payload)
        self.assertIn('history.json', report.copied)
        self.assertIn(self.documents, report.sources)
        self.assertTrue(report.done)

    def test_documents_are_never_emptied(self):
        """Kopiujemy. Uzytkownik ma prawo znalezc swoje pliki tam, gdzie byly."""
        payload = self._history(self.documents, 'z-dokumentow.pdf')

        config.migrate_legacy_data()

        self.assertEqual((self.documents / 'history.json').read_bytes(), payload)

    def test_each_source_has_its_own_marker(self):
        """Wspolny znacznik zamknalby droge danym z drugiego zrodla."""
        self._history(self.documents, 'z-dokumentow.pdf')
        self._history(self.appdata, 'z-appdata.pdf')

        config.migrate_legacy_data()

        self.assertTrue((self.new / config.DOCUMENTS_MARKER).is_file())
        self.assertTrue((self.new / config.MIGRATION_MARKER).is_file())

    def test_both_sources_are_merged_without_overwriting(self):
        """Dwie rozne historie = jedna na miejscu, druga OBOK, zadna stracona.

        Pierwszenstwo ma zrodlo najswiezsze, czyli Dokumenty — tam program
        pisal ostatnio.
        """
        documents = self._history(self.documents, 'z-dokumentow.pdf')
        appdata = self._history(self.appdata, 'z-appdata.pdf')

        report = config.migrate_legacy_data()

        self.assertEqual((self.new / 'history.json').read_bytes(), documents)
        self.assertEqual(len(report.kept_aside), 1)
        aside = self.new / report.kept_aside[0]
        self.assertTrue(aside.name.startswith('history.json.z-appdata-'),
                        f'sufiks ma mowic, skad plik pochodzi: {aside.name}')
        self.assertEqual(aside.read_bytes(), appdata)

    def test_marker_left_in_documents_travels_with_the_data(self):
        """Lancuch AppData -> Dokumenty -> profil nie ma sie rozdwajac.

        W `Dokumenty\\BeatStamp` lezy juz znacznik przeprowadzki z `AppData`
        (Dokumenty byly jej CELEM). Gdyby nie powedrowal dalej, STARSZA
        historia z `AppData` wrocilaby obok nowszej jako kopia `z-appdata`.
        """
        merged = self._history(self.documents, 'scalona.pdf')
        (self.documents / config.MIGRATION_MARKER).write_text('{}', encoding='utf-8')
        self._history(self.appdata, 'stara.pdf')

        report = config.migrate_legacy_data()

        self.assertEqual((self.new / 'history.json').read_bytes(), merged)
        self.assertEqual(report.kept_aside, [])
        self.assertEqual(list(self.new.glob('*.z-appdata-*')), [])
        self.assertNotIn(self.appdata, report.sources)

    def test_running_twice_copies_nothing_new(self):
        self._history(self.documents, 'z-dokumentow.pdf')

        first = config.migrate_legacy_data()
        second = config.migrate_legacy_data()

        self.assertEqual(first.copied, ['history.json'])
        self.assertEqual(second.copied, [])
        self.assertEqual(second.sources, [])
        self.assertEqual(list(self.new.glob('*.z-dokumentow-*')), [])

    def test_a_forced_data_dir_skips_the_migration_entirely(self):
        """`SIGELITH_DATA_DIR` znaczy „dokladnie ten katalog, nic wiecej".

        Wersja przenosna i `tools/verify_exe.py` maja dostac katalog pusty.
        Wciagniecie tam historii z maszyny byloby zabraniem cudzych danych na
        pendrive, a w wydaniu — wymieszaniem stempla probnego z prawdziwa
        historia osoby skladajacej paczke.
        """
        self._history(self.documents, 'z-dokumentow.pdf')
        os.environ['SIGELITH_DATA_DIR'] = str(self.new)

        report = config.migrate_legacy_data()

        self.assertTrue(report.done)
        self.assertEqual(report.sources, [])
        self.assertFalse((self.new / 'history.json').exists())


class BlockedWriteTests(EnvIsolatedTest):
    """Zapis zablokowany przez system — rozpoznanie i komunikat.

    Sedno: ochrona przed ransomware NIE daje `PermissionError`. Daje
    `FileNotFoundError` z `tempfile.mkstemp`, w katalogu, ktory istnieje
    i ktory widac w Eksploratorze. Kod lapiacy sam `PermissionError` nie
    wykryje blokady nigdy — a uzytkownik zobaczy slad wyjatku mowiacy
    o brakujacym pliku, ktorego nigdy nie bylo.
    """

    def test_permission_error_is_a_block(self):
        self.assertTrue(config.looks_protected(
            self.dir, PermissionError(13, 'Access is denied')))

    def test_missing_temp_file_in_an_existing_folder_is_a_block(self):
        """Podpis „Kontrolowanego dostepu do folderow"."""
        self.assertTrue(config.looks_protected(
            self.dir, FileNotFoundError(2, 'No such file or directory')))

    def test_missing_folder_is_not_a_block(self):
        """Odlaczony dysk wymienny to inna awaria i inny komunikat."""
        self.assertFalse(config.looks_protected(
            self.dir / 'nie-ma-takiego', FileNotFoundError(2, 'No such file')))

    def test_disk_full_is_not_a_block(self):
        self.assertFalse(config.looks_protected(
            self.dir, OSError(28, 'No space left on device')))

    def test_probe_passes_in_a_writable_folder(self):
        os.environ['SIGELITH_DATA_DIR'] = str(self.dir / 'dane')
        self.assertIsNone(config.probe_write())

    def test_probe_leaves_no_rubbish_behind(self):
        target = self.dir / 'dane'
        config.probe_write(target)
        self.assertEqual(list(target.iterdir()), [])

    def test_probe_reports_a_blocked_folder(self):
        """Blokada wychodzi z `mkstemp`, czyli z tej samej sciezki co historia."""
        target = self.dir / 'chroniony'
        target.mkdir()
        with mock.patch('tempfile.mkstemp',
                        side_effect=FileNotFoundError(2, 'No such file or directory')):
            problem = config.probe_write(target)

        self.assertIsNotNone(problem)
        self.assertTrue(problem.protected)
        self.assertEqual(problem.directory, target)

    def test_probe_reports_a_permission_error_too(self):
        target = self.dir / 'bez-prawa'
        target.mkdir()
        with mock.patch('tempfile.mkstemp',
                        side_effect=PermissionError(13, 'Access is denied')):
            problem = config.probe_write(target)

        self.assertIsNotNone(problem)
        self.assertTrue(problem.protected)

    def test_probe_survives_a_folder_that_cannot_be_created(self):
        target = self.dir / 'nie-powstanie'
        with mock.patch.object(Path, 'mkdir', side_effect=OSError(28, 'No space')):
            problem = config.probe_write(target)

        self.assertIsNotNone(problem)
        self.assertFalse(problem.protected)

    def test_the_message_says_what_to_do_not_what_threw(self):
        problem = config.describe_write_problem(
            self.dir, FileNotFoundError(2, 'No such file or directory'))

        self.assertTrue(problem.protected)
        text = problem.message
        self.assertIn(str(self.dir), text)
        # Nazwa ochrony musi paść dosłownie — i to w KAŻDYM języku. Uzytkownik
        # ma znalezc to samo slowo w Zabezpieczeniach Windows; polskie
        # „ochrona przed ransomware" i niemiecki „Ransomware-Schutz" niosa je
        # tak samo jak angielski oryginal. Dzieki temu warunek sprawdza
        # ZNACZENIE, a nie jezyk, w ktorym akurat chodzi suite.
        self.assertIn('ransomware', text.lower())
        # Zadnego zargonu: to wlasnie widzial uzytkownik zamiast komunikatu.
        for jargon in ('FileNotFoundError', 'mkstemp', 'Errno', 'Traceback'):
            self.assertNotIn(jargon, text)
        self.assertNotEqual(
            text, config.describe_write_problem(
                self.dir / 'nie-ma', OSError(28, 'No space')).message,
            'blokada i brak miejsca to dwie rozne przyczyny i dwa rozne wyjscia')

    def test_a_plain_failure_quotes_the_system_reason(self):
        problem = config.describe_write_problem(
            self.dir / 'nie-ma', OSError(28, 'No space left on device'))

        self.assertFalse(problem.protected)
        self.assertIn('No space left on device', problem.message)
        self.assertTrue(problem.title)


class StoredDataDirTests(EnvIsolatedTest):
    """Wybor katalogu przez uzytkownika: zapis, odczyt, pierwszenstwo."""

    def test_a_remembered_folder_wins_over_the_default(self):
        chosen = self.dir / 'Wybrany' / 'Sigelith'
        self.assertTrue(config.remember_data_dir(chosen))

        self.assertEqual(config.stored_data_dir(), chosen)
        self.assertEqual(config.resolved_data_dir(), chosen)

    def test_the_pointer_lives_outside_the_data_folder(self):
        """Wskaznik musi dac sie odczytac, ZANIM wiadomo, gdzie sa dane."""
        chosen = self.dir / 'Wybrany' / 'Sigelith'
        config.remember_data_dir(chosen)

        self.assertTrue(config.location_file().is_file())
        self.assertFalse(config._is_inside(config.location_file(), chosen))

    def test_clearing_the_choice_goes_back_to_the_default(self):
        config.remember_data_dir(self.dir / 'Wybrany')
        self.assertTrue(config.remember_data_dir(None))

        self.assertIsNone(config.stored_data_dir())
        self.assertEqual(config.resolved_data_dir(), config._default_data_dir())

    def test_clearing_a_choice_that_was_never_made_is_not_an_error(self):
        self.assertTrue(config.remember_data_dir(None))

    def test_the_environment_variable_still_wins(self):
        """Narzucony katalog (testy, wersja przenosna) bije zapamietany wybor."""
        config.remember_data_dir(self.dir / 'Wybrany')
        os.environ['SIGELITH_DATA_DIR'] = str(self.dir / 'Narzucony')

        self.assertEqual(config.resolved_data_dir(), self.dir / 'Narzucony')

    def test_a_damaged_pointer_is_ignored(self):
        """Uszkodzony wskaznik nie moze byc powodem, dla ktorego program nie startuje."""
        pointer = config.location_file()
        pointer.parent.mkdir(parents=True, exist_ok=True)
        pointer.write_text('{to nie jest json', encoding='utf-8')

        self.assertIsNone(config.stored_data_dir())
        self.assertEqual(config.resolved_data_dir(), config._default_data_dir())

    def test_a_relative_path_in_the_pointer_is_rejected(self):
        """Ta sama wada nr 1 co przy zmiennej srodowiskowej: sciezka wzgledna."""
        pointer = config.location_file()
        pointer.parent.mkdir(parents=True, exist_ok=True)
        pointer.write_text(json.dumps({'katalog': 'dane'}), encoding='utf-8')

        self.assertIsNone(config.stored_data_dir())

    def test_an_unwritable_pointer_does_not_raise(self):
        with mock.patch.object(config, 'write_atomic',
                               side_effect=PermissionError(13, 'nie wolno')):
            self.assertFalse(config.remember_data_dir(self.dir / 'Wybrany'))


class ChangeDataDirTests(EnvIsolatedTest):
    """Zmiana katalogu w Ustawieniach: kopia, nie przeprowadzka."""

    def setUp(self):
        super().setUp()
        self.old = self.dir / 'Stary' / 'Sigelith'
        self.new = self.dir / 'Nowy' / 'Sigelith'
        os.environ['SIGELITH_DATA_DIR'] = str(self.old)
        self.old.mkdir(parents=True)
        self.payload = json.dumps(
            [Entry(digest='b' * 64, file_name='umowa.pdf').to_dict()],
            indent=2, ensure_ascii=False).encode('utf-8')
        (self.old / 'history.json').write_bytes(self.payload)
        (self.old / 'settings.json').write_text('{"theme": "dark"}', encoding='utf-8')

    def test_data_are_copied_to_the_new_folder(self):
        report = config.copy_data_to(self.new)

        self.assertEqual((self.new / 'history.json').read_bytes(), self.payload)
        self.assertEqual(sorted(report.copied), ['history.json', 'settings.json'])
        self.assertTrue(report.done)

    def test_the_old_folder_is_left_untouched(self):
        """Uzytkownik, ktory sie rozmysli, ma komplet w poprzednim miejscu."""
        config.copy_data_to(self.new)

        self.assertEqual((self.old / 'history.json').read_bytes(), self.payload)
        self.assertTrue((self.old / 'settings.json').is_file())

    def test_a_note_is_left_in_the_old_folder(self):
        config.copy_data_to(self.new)

        note = (self.old / config.FORWARDING_NOTE).read_text(encoding='utf-8')
        self.assertIn(str(self.new), note)

    def test_nothing_is_overwritten_in_the_new_folder(self):
        self.new.mkdir(parents=True)
        other = json.dumps(
            [Entry(digest='c' * 64, file_name='inna.pdf').to_dict()],
            indent=2, ensure_ascii=False).encode('utf-8')
        (self.new / 'history.json').write_bytes(other)

        report = config.copy_data_to(self.new)

        self.assertEqual((self.new / 'history.json').read_bytes(), other)
        self.assertEqual(len(report.kept_aside), 1)
        self.assertTrue(report.kept_aside[0].startswith('history.json.z-poprzedniego-'))

    def test_markers_travel_so_the_old_places_are_not_read_twice(self):
        (self.old / config.MIGRATION_MARKER).write_text('{}', encoding='utf-8')
        (self.old / config.DOCUMENTS_MARKER).write_text('{}', encoding='utf-8')

        config.copy_data_to(self.new)

        self.assertTrue((self.new / config.MIGRATION_MARKER).is_file())
        self.assertTrue((self.new / config.DOCUMENTS_MARKER).is_file())

    def test_choosing_the_same_folder_changes_nothing(self):
        report = config.copy_data_to(self.old)

        self.assertTrue(report.done)
        self.assertEqual(report.copied, [])
        self.assertEqual(report.sources, [])

    def test_repeating_the_copy_makes_no_duplicates(self):
        config.copy_data_to(self.new)
        report = config.copy_data_to(self.new)

        self.assertEqual(report.copied, [])
        self.assertEqual(report.kept_aside, [])
        self.assertEqual(sorted(report.already_there),
                         ['history.json', 'settings.json'])
        self.assertEqual(list(self.new.glob('*.z-poprzedniego-*')), [])

    def test_the_witness_travels_with_the_data(self):
        """Stan swiadka i material dowodowy ida razem z historia (3.0.0).

        Bez tego zmiana katalogu zaczynala swiadka od zera, a pliki
        `witness/evidence/` — dowod po alarmie — zostawaly w starym miejscu.
        """
        (self.old / 'witness' / 'evidence').mkdir(parents=True)
        (self.old / 'witness' / 'state.json').write_text('{"version": 1}', encoding='utf-8')
        (self.old / 'witness' / 'evidence' / 'a.json').write_bytes(b'dowod')

        report = config.copy_data_to(self.new)

        self.assertIn('witness/state.json', report.copied)
        self.assertEqual((self.new / 'witness' / 'evidence' / 'a.json').read_bytes(), b'dowod')


# --- Sigelith Desktop 3.0.0: %USERPROFILE%\BeatStamp -> %USERPROFILE%\Sigelith ----


class MigrationFromBeatStampTests(EnvIsolatedTest):
    """TRZECIE zrodlo przeprowadzki: `%USERPROFILE%\\BeatStamp` (BeatStamp 2.2.0).

    Po zmianie nazwy programu lokalizacja domyslna to `%USERPROFILE%\\Sigelith`.
    Kazdy, kto uzywal wersji 2.2, ma swoje dane pod stara nazwa — historia
    stempli, ustawienia i stan swiadka musza przejsc same, a stary katalog
    zostac nietkniety.
    """

    def setUp(self):
        super().setUp()
        self.beatstamp = self.dir / 'Profil' / 'BeatStamp'
        self.documents = self.dir / 'Dokumenty' / 'BeatStamp'
        self.appdata = self.dir / 'AppData' / 'Local' / 'BeatStamp'
        self.new = self.dir / 'Profil' / 'Sigelith'
        for name, value in (('legacy_profile_data_dir', self.beatstamp),
                            ('legacy_documents_data_dir', self.documents),
                            ('legacy_app_data_dir', self.appdata),
                            ('_default_data_dir', self.new),
                            ('app_data_dir', self.new),
                            ('resolved_data_dir', self.new)):
            patch = mock.patch.object(config, name, return_value=value)
            patch.start()
            self.addCleanup(patch.stop)

    def _old_install(self) -> dict[str, bytes]:
        """Katalog BeatStampa 2.2.0 tak, jak lezy u uzytkownika."""
        files = {
            'history.json': json.dumps(
                [Entry(digest='d' * 64, file_name='umowa.pdf').to_dict()],
                indent=2, ensure_ascii=False).encode('utf-8'),
            'settings.json': json.dumps(
                {'theme': 'dark', 'language': 'pl',
                 'base_url': 'https://beattime.live'}).encode('utf-8'),
            '.tvs-zaimportowano': b'ok',
            'witness/state.json': b'{"version": 1, "checkpoints": {}}',
            'witness/checkpoints/000001.json': b'{"n": 1}',
            'witness/log.jsonl': b'{"seq": 1}\n',
            'witness/evidence/20260927T120000Z-new-000002.json': b'dowod',
        }
        for name, data in files.items():
            path = self.beatstamp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        # Tego NIE przenosimy: dziennik, pamiec podreczna, plik tymczasowy.
        (self.beatstamp / 'beatstamp.log').write_text('stary dziennik', encoding='utf-8')
        (self.beatstamp / 'supporters.json').write_text('{}', encoding='utf-8')
        (self.beatstamp / 'witness' / 'state.json.abc.tmp').write_bytes(b'polowa')
        return files

    def test_history_settings_and_witness_come_over(self):
        files = self._old_install()

        report = config.migrate_legacy_data()

        for name, data in files.items():
            with self.subTest(file=name):
                self.assertEqual((self.new / name).read_bytes(), data)
        self.assertTrue(report.done)
        self.assertIn(self.beatstamp, report.sources)
        self.assertTrue((self.new / config.BEATSTAMP_MARKER).is_file())
        for skipped in ('beatstamp.log', 'sigelith.log', 'supporters.json',
                        'witness/state.json.abc.tmp'):
            self.assertFalse((self.new / skipped).exists(), skipped)

    def test_the_old_folder_is_never_deleted_or_changed(self):
        files = self._old_install()
        before = {p.relative_to(self.beatstamp).as_posix(): p.read_bytes()
                  for p in self.beatstamp.rglob('*') if p.is_file()}

        config.migrate_legacy_data()

        after = {p.relative_to(self.beatstamp).as_posix(): p.read_bytes()
                 for p in self.beatstamp.rglob('*') if p.is_file()}
        # Jedyna zmiana: notatka dla kogos, kto tam zajrzy.
        self.assertEqual(set(after) - set(before), {config.FORWARDING_NOTE})
        self.assertEqual({k: after[k] for k in before}, before)
        self.assertIn(str(self.new),
                      (self.beatstamp / config.FORWARDING_NOTE).read_text(encoding='utf-8'))
        self.assertTrue(files)

    def test_settings_and_history_survive_end_to_end(self):
        """Po przeprowadzce program widzi te same wpisy i te same ustawienia."""
        self._old_install()

        config.migrate_legacy_data()
        history = History().load()
        settings = config.Settings.load()

        self.assertEqual([e.file_name for e in history.entries], ['umowa.pdf'])
        self.assertEqual(settings.theme, 'dark')
        self.assertEqual(settings.language, 'pl')
        # Utrwalona wartosc domyslna BeatStampa to nie wybor uzytkownika.
        self.assertEqual(settings.base_url, 'https://sigelith.org')

    def test_earlier_moves_are_not_repeated(self):
        """Dokumenty i AppData scalono juz w 2.2 — znaczniki wedruja z danymi.

        Bez tego starsza historia z Dokumentow wrocilaby obok nowszej jako
        `history.json.z-dokumentow-<czas>`.
        """
        self._old_install()
        (self.beatstamp / config.DOCUMENTS_MARKER).write_text('{}', encoding='utf-8')
        (self.beatstamp / config.MIGRATION_MARKER).write_text('{}', encoding='utf-8')
        self.documents.mkdir(parents=True)
        (self.documents / 'history.json').write_text('[]', encoding='utf-8')

        report = config.migrate_legacy_data()

        self.assertNotIn(self.documents, report.sources)
        self.assertEqual(report.kept_aside, [])
        self.assertEqual(list(self.new.glob('*.z-dokumentow-*')), [])

    def test_the_newest_source_wins_and_nothing_is_lost(self):
        """Historia z Dokumentow bez znacznika: BeatStamp 2.2.0 ma pierwszenstwo."""
        files = self._old_install()
        self.documents.mkdir(parents=True)
        (self.documents / 'history.json').write_text('[]', encoding='utf-8')

        report = config.migrate_legacy_data()

        self.assertEqual((self.new / 'history.json').read_bytes(), files['history.json'])
        aside = [name for name in report.kept_aside if name.startswith('history.json.')]
        self.assertEqual(len(aside), 1)
        self.assertIn('z-dokumentow', aside[0])

    def test_running_twice_copies_nothing_new(self):
        self._old_install()

        first = config.migrate_legacy_data()
        second = config.migrate_legacy_data()

        self.assertTrue(first.copied)
        self.assertEqual(second.copied, [])
        self.assertEqual(second.sources, [])
        self.assertEqual(list(self.new.glob('*.z-beatstamp-*')), [])

    def test_the_message_says_the_program_was_renamed(self):
        self._old_install()

        report = config.migrate_legacy_data()

        self.assertEqual(report.message,
                         _('BeatStamp is now Sigelith Desktop — your data has been '
                           'moved to: %(path)s') % {'path': self.new})

    def test_a_folder_chosen_by_the_user_is_not_refilled(self):
        """Katalog wybrany w BeatStampie dostal dane STAD przy zmianie katalogu.

        Ponowne kopiowanie przynioslo by same starsze wersje „obok"
        (`history.json.z-beatstamp-…`). Zamiast tego — sam znacznik, zeby
        nastepna zmiana katalogu nie sciagnela ich tez.
        """
        self._old_install()
        chosen = self.dir / 'D' / 'Dane' / 'BeatStamp'
        chosen.mkdir(parents=True)
        (chosen / 'history.json').write_text('[]', encoding='utf-8')
        with mock.patch.object(config, 'app_data_dir', return_value=chosen), \
                mock.patch.object(config, 'resolved_data_dir', return_value=chosen):
            report = config.migrate_legacy_data()

        self.assertEqual((chosen / 'history.json').read_text(encoding='utf-8'), '[]')
        self.assertEqual(report.kept_aside, [])
        self.assertNotIn(self.beatstamp, report.sources)
        self.assertTrue((chosen / config.BEATSTAMP_MARKER).is_file())
        self.assertFalse((self.beatstamp / config.FORWARDING_NOTE).exists())

    def test_a_forced_folder_skips_it_too(self):
        """`SIGELITH_DATA_DIR`/`BEATSTAMP_DATA_DIR` = katalog izolowany."""
        self._old_install()
        for variable in ('SIGELITH_DATA_DIR', 'BEATSTAMP_DATA_DIR'):
            with self.subTest(variable=variable):
                os.environ[variable] = str(self.new)
                try:
                    report = config.migrate_legacy_data()
                finally:
                    os.environ.pop(variable, None)
                self.assertEqual(report.sources, [])
                self.assertFalse((self.new / 'history.json').exists())


@WINDOWS_ONLY
class DefaultLocationRenameTests(EnvIsolatedTest):
    """Prawdziwe sciezki Windows (bez podmieniania funkcji)."""

    def test_the_new_default_and_the_old_one(self):
        os.environ['USERPROFILE'] = str(self.dir / 'Profil')

        self.assertEqual(config.resolved_data_dir(), self.dir / 'Profil' / 'Sigelith')
        self.assertEqual(config.legacy_profile_data_dir(), self.dir / 'Profil' / 'BeatStamp')
        self.assertEqual(config.legacy_locations()[0][0], self.dir / 'Profil' / 'BeatStamp')

    def test_a_real_upgrade_from_beatstamp(self):
        """Od konca do konca, na zmiennych srodowiskowych, jak u uzytkownika."""
        os.environ['USERPROFILE'] = str(self.dir / 'Profil')
        old = self.dir / 'Profil' / 'BeatStamp'
        old.mkdir(parents=True)
        payload = json.dumps([Entry(digest='e' * 64, file_name='a.pdf').to_dict()]).encode()
        (old / 'history.json').write_bytes(payload)
        with mock.patch.object(config, '_windows_documents_dir', return_value=None):
            report = config.migrate_legacy_data()

        self.assertTrue(report.done)
        self.assertEqual((self.dir / 'Profil' / 'Sigelith' / 'history.json').read_bytes(),
                         payload)
        self.assertEqual((old / 'history.json').read_bytes(), payload)


class LegacyPointerTests(EnvIsolatedTest):
    """Wybor katalogu zapisany przez BeatStampa (`%LOCALAPPDATA%\\BeatStamp`)."""

    def _legacy_pointer(self, target: Path) -> Path:
        pointer = config.legacy_location_file()
        pointer.parent.mkdir(parents=True, exist_ok=True)
        pointer.write_text(json.dumps({'katalog': str(target)}), encoding='utf-8')
        return pointer

    def test_a_choice_made_in_beatstamp_is_still_honoured(self):
        chosen = self.dir / 'D' / 'Dane' / 'BeatStamp'
        self._legacy_pointer(chosen)

        self.assertEqual(config.stored_data_dir(), chosen)
        self.assertEqual(config.resolved_data_dir(), chosen)

    def test_the_new_pointer_wins(self):
        self._legacy_pointer(self.dir / 'Stary')
        config.remember_data_dir(self.dir / 'Nowy')

        self.assertEqual(config.resolved_data_dir(), self.dir / 'Nowy')

    def test_new_choices_go_to_the_sigelith_folder(self):
        pointer = self._legacy_pointer(self.dir / 'Stary')
        before = pointer.read_bytes()

        config.remember_data_dir(self.dir / 'Nowy')

        self.assertEqual(config.location_file().parent.name, 'Sigelith')
        self.assertTrue(config.location_file().is_file())
        self.assertEqual(pointer.read_bytes(), before)

    def test_going_back_to_the_default_shadows_the_old_choice(self):
        """Powrot do domyslnego nie moze wskrzesic wyboru z BeatStampa —
        a stary plik zostaje nietkniety."""
        pointer = self._legacy_pointer(self.dir / 'Stary')
        before = pointer.read_bytes()

        self.assertTrue(config.remember_data_dir(None))

        self.assertIsNone(config.stored_data_dir())
        self.assertEqual(config.resolved_data_dir(), config._default_data_dir())
        self.assertEqual(pointer.read_bytes(), before)


class BaseUrlMigrationTests(EnvIsolatedTest):
    """Adres API: domyslnie sigelith.org, utrwalony stary domyslny — tez."""

    def _settings(self, raw: dict) -> 'config.Settings':
        os.environ['SIGELITH_DATA_DIR'] = str(self.dir / 'dane')
        config.settings_path().parent.mkdir(parents=True, exist_ok=True)
        config.settings_path().write_text(json.dumps(raw), encoding='utf-8')
        return config.Settings.load()

    def test_the_default_is_sigelith(self):
        self.assertEqual(config.DEFAULT_BASE_URL, 'https://sigelith.org')
        self.assertEqual(config.Settings().base_url, 'https://sigelith.org')
        self.assertEqual(config.Settings().effective_base_url, 'https://sigelith.org')

    def test_the_stored_beatstamp_default_moves_to_sigelith(self):
        for stored in ('https://beattime.live', 'https://beattime.live/',
                       'HTTPS://BEATTIME.LIVE'):
            with self.subTest(stored=stored):
                self.assertEqual(self._settings({'base_url': stored}).base_url,
                                 'https://sigelith.org')

    def test_an_own_instance_is_left_alone(self):
        for stored in ('https://example.org', 'https://beattime.live.example.org',
                       'https://staging.beattime.live'):
            with self.subTest(stored=stored):
                self.assertEqual(self._settings({'base_url': stored}).base_url, stored)

    def test_tor_keeps_the_existing_onion_service(self):
        settings = config.Settings(use_tor=True)
        self.assertEqual(settings.effective_base_url, config.ONION_BASE_URL)
        self.assertTrue(config.ONION_BASE_URL.endswith('.onion'))


if __name__ == '__main__':
    unittest.main()
