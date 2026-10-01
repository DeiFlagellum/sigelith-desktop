"""
Test dymny warstwy GUI — uruchamiany bez ekranu (platforma `offscreen`).

Nie sprawdza wygladu. Sprawdza rzeczy, które w Qt lamia się po cichu i
ujawniaja dopiero u uzytkownika:

* czy okno w ogole da się zbudowac (literowka w nazwie sygnalu albo zły typ
  argumentu w `connect` wywala się dopiero przy tworzeniu widgetu);
* czy każdy element sterujacy ma podpowiedz — wymog UX przyjety dla tej
  wersji, latwy do zgubienia przy kolejnych zmianach;
* czy motyw jasny i ciemny w ogole się skladaja;
* czy zbieranie upuszczonych sciezek rozwija katalogi i pilnuje limitu.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Musi byc ustawione PRZED pierwszym importem QtGui/QtWidgets.
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtGui import QAction  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QApplication, QCheckBox, QComboBox, QHBoxLayout, QLineEdit, QPushButton,
)

from beatstamp import i18n  # noqa: E402
from beatstamp.config import Settings  # noqa: E402
from beatstamp.ui import theme  # noqa: E402
from beatstamp.ui.widgets import MAX_DROPPED_FILES, collect_paths  # noqa: E402

# Jezyk interfejsu PRZYPIETY. Testy sprawdzaja ZNACZENIE napisu — oczekiwany
# tekst bierzemy z tego samego katalogu tlumaczen, ktorego uzywa program
# (`_('<msgid>')`), a nie z przepisanego recznie ciagu znakow. Bez przypiecia
# wynik suite zalezalby od jezyka interfejsu maszyny, na ktorej akurat sie ja
# uruchamia; bez katalogu — sprawdzalibysmy literowke, a nie tresc.
i18n.set_language('pl')
_ = i18n.gettext

_app = QApplication.instance() or QApplication(sys.argv)


class ThemeTests(unittest.TestCase):

    def test_both_palettes_define_the_same_roles(self):
        self.assertEqual(set(theme.LIGHT), set(theme.DARK),
                         'brak koloru w jednym motywie = pusta wartość w arkuszu')

    def test_stylesheets_build(self):
        for colors in (theme.LIGHT, theme.DARK):
            sheet = theme.stylesheet(colors)
            self.assertIn('QPushButton', sheet)
            self.assertNotIn('{}', sheet, 'niepodstawiony placeholder w arkuszu')

    def test_apply_theme_accepts_every_mode(self):
        for mode in ('light', 'dark', 'auto'):
            colors = theme.apply_theme(_app, mode)
            self.assertIn('accent', colors)


class CollectPathsTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_expands_directories_recursively(self):
        (self.dir / 'pod' / 'glebiej').mkdir(parents=True)
        (self.dir / 'a.txt').write_text('a')
        (self.dir / 'pod' / 'b.txt').write_text('b')
        (self.dir / 'pod' / 'glebiej' / 'c.txt').write_text('c')

        found = collect_paths([str(self.dir)])

        self.assertEqual({p.name for p in found}, {'a.txt', 'b.txt', 'c.txt'})

    def test_deduplicates(self):
        (self.dir / 'a.txt').write_text('a')
        found = collect_paths([str(self.dir / 'a.txt'), str(self.dir),
                               str(self.dir / 'a.txt')])
        self.assertEqual(len(found), 1)

    def test_respects_hard_limit(self):
        """Upuszczenie ogromnego katalogu nie może zamrozic aplikacji."""
        for i in range(MAX_DROPPED_FILES + 50):
            (self.dir / f'{i}.txt').write_text('x')
        found = collect_paths([str(self.dir)])
        self.assertLessEqual(len(found), MAX_DROPPED_FILES)

    def test_ignores_empty_and_missing(self):
        self.assertEqual(collect_paths(['', None, str(self.dir / 'nie ma')]), [])


def _rogue_public_key() -> str:
    """Poprawny klucz Ed25519 (base64), ktorego nie ma na liscie Sigelith."""
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def _inside_dialog(widget) -> bool:
    from PySide6.QtWidgets import QDialog
    parent = widget.parent()
    while parent is not None:
        if isinstance(parent, QDialog):
            return True
        parent = parent.parent()
    return False


class MainWindowTests(unittest.TestCase):
    """Buduje pełne okno i sprawdza jego kontrakt UX."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        # `SIGELITH_DATA_DIR` wskazuje katalog danych WPROST; `LOCALAPPDATA`
        # zostaje podmienione osobno, zeby nic w tescie nie siegnelo do STAREJ
        # lokalizacji prawdziwego uzytkownika (patrz `config.app_data_dir`
        # i `config.legacy_app_data_dir`).
        os.environ['SIGELITH_DATA_DIR'] = cls._tmp.name
        os.environ['LOCALAPPDATA'] = cls._tmp.name
        # Znacznik "juz zmigrowano": bez niego okno odklada na petle zdarzen
        # modalne okienko o przeniesieniu historii z TVS. W tescie petla
        # rusza dopiero wewnatrz innego modalnego dialogu i oba sie blokuja.
        (Path(cls._tmp.name) / '.tvs-zaimportowano').write_text('test')
        theme.apply_theme(_app, 'light')
        from beatstamp.ui.main_window import MainWindow
        cls.window = MainWindow(Settings())

    @classmethod
    def tearDownClass(cls):
        # `close()`, a nie samo `deleteLater()`. Konstruktor okna planuje
        # wywolania na 0-300 ms; bez petli zdarzen czekaja one w kolejce i
        # wystrzeliwuja przy pierwszym `processEvents()` W INNYM tescie —
        # na oknie, ktorego katalog danych juz nie istnieje. `close()`
        # podnosi flage zamykania, przerywa zadania i czeka na pule.
        cls.window.close()
        _app.processEvents()
        cls.window.deleteLater()
        _app.processEvents()
        cls._tmp.cleanup()

    def test_five_tabs_are_named_in_the_interface_language(self):
        # Handover (3.0) jest OSTATNIA: indeksy 0-3 sa zaszyte w oknie glownym.
        tabs = [self.window.tabs.tabText(i) for i in range(self.window.tabs.count())]
        self.assertEqual(
            tabs, [_('Stamping'), _('Verification'), _('History'), _('Witnesses'),
                   _('Handover')])

    def test_every_tab_has_a_tooltip(self):
        for i in range(self.window.tabs.count()):
            self.assertTrue(self.window.tabs.tabToolTip(i),
                            f'zakładka {i} bez podpowiedzi')

    def test_every_control_has_a_tooltip(self):
        """Wymog UX: każdy element sterujacy glownego okna tlumaczy się sam.

        Zakres celowo ograniczony do glownego okna. Standardowe przyciski
        okien dialogowych (Zapisz, Anuluj, Zamknij) opisuje już ich własny
        tekst — podpowiedz "Zamknij: zamyka okno" była by szumem, a nie
        pomoca.
        """
        from PySide6.QtWidgets import QDialog

        missing = []
        for kind in (QPushButton, QCheckBox, QComboBox, QLineEdit):
            for widget in self.window.findChildren(kind):
                # Elementy wbudowane w inne widgety (przycisk czyszczenia
                # pola, strzalka listy) nie maja wlasnej tresci do opisania.
                if widget.objectName().startswith('qt_'):
                    continue
                if _inside_dialog(widget):
                    continue
                if widget.toolTip():
                    continue
                if kind is QLineEdit and widget.placeholderText():
                    continue             # placeholder pelni te sama role
                text = widget.text() if hasattr(widget, 'text') else ''
                missing.append(f'{kind.__name__}("{text}")')
        self.assertEqual(missing, [], f'elementy bez podpowiedzi: {missing}')

    def test_menu_is_complete_and_translated(self):
        menus = [a.text() for a in self.window.menuBar().actions()]
        self.assertEqual(menus, [_('&File'), _('&Tools'), _('Hel&p')])

    def test_menu_accelerators_survive_translation(self):
        """Akcelerator (`&`) jest czescia TLUMACZENIA, nie kodu.

        Tlumacz musi go przeniesc i postawic przy innej literze niz sasiednie
        menu. Zgubiony `&` odbiera obsluge z klawiatury; powtorzona litera
        sprawia, ze Alt+X otwiera raz jedno, raz drugie menu. Jedno i drugie
        przechodzi przez komplet pozostalych testow niezauwazone.
        """
        letters = []
        for action in self.window.menuBar().actions():
            text = action.text()
            self.assertIn('&', text, f'menu bez akceleratora: {text!r}')
            letters.append(text[text.index('&') + 1].lower())
        self.assertEqual(len(set(letters)), len(letters),
                         f'powtórzona litera akceleratora: {letters}')

    def test_result_buttons_start_disabled(self):
        for button in (self.window.button_pdf, self.window.button_bundle,
                       self.window.button_browser, self.window.button_details):
            self.assertFalse(button.isEnabled(),
                             'przycisk aktywny bez wyniku prowadzilby do pustej akcji')

    def test_verify_button_follows_digest_validity(self):
        self.window.verify_input.setText('nie skrót')
        self.assertFalse(self.window.verify_button.isEnabled())
        self.window.verify_input.setText('e' * 64)
        self.assertTrue(self.window.verify_button.isEnabled())
        self.window.verify_input.clear()
        self.assertFalse(self.window.verify_button.isEnabled())

    def test_window_accepts_drops(self):
        self.assertTrue(self.window.acceptDrops())
        self.assertTrue(self.window.drop_zone.acceptDrops())
        self.assertTrue(self.window.verify_drop.acceptDrops())

    def test_busy_state_blocks_drop_zones(self):
        # `isVisible()` na dziecku NIEPOKAZANEGO okna zawsze zwraca False,
        # niezaleznie od wlasnego stanu — pytamy wiec o `isHidden()`.
        try:
            self.window._set_busy_ui(True, 'test')
            self.assertFalse(self.window.drop_zone.acceptDrops())
            self.assertFalse(self.window.verify_drop.acceptDrops())
            self.assertFalse(self.window.cancel_button.isHidden())
            self.assertFalse(self.window.progress.isHidden())
        finally:
            # Bez tego awaria tego testu przenosi sie na kazdy nastepny,
            # ktory zaklada, ze okno jest bezczynne.
            self.window._set_busy_ui(False)
        self.assertTrue(self.window.drop_zone.acceptDrops())
        self.assertTrue(self.window.cancel_button.isHidden())

    def _fill_history(self, count: int = 5) -> None:
        import hashlib
        from beatstamp.history import Entry
        self.window.history.entries = [
            Entry(digest=hashlib.sha256(str(i).encode()).hexdigest(),
                  file_name=f'{i}.pdf', utc='2026-09-12T10:00:00Z',
                  beat='@416.66', level='anchored', note=f'notatka {i}')
            for i in range(count)]
        self.window._refresh_history_view()

    def test_history_view_reflects_model(self):
        self._fill_history(5)
        self.assertEqual(self.window.history_model.rowCount(), 5)
        self.assertIn('5 wpis', self.window.history_summary.text())

    def test_history_filter_finds_by_full_digest(self):
        import hashlib
        self._fill_history(5)
        try:
            wanted = hashlib.sha256(b'3').hexdigest()
            self.window.history_proxy.set_text(wanted)
            self.assertEqual(self.window.history_proxy.rowCount(), 1,
                             'wklejenie pelnego skrótu musi trafiac w wpis')
            self.window.history_proxy.set_text('notatka 2')
            self.assertEqual(self.window.history_proxy.rowCount(), 1)
            self.window.history_proxy.set_text('nie ma takiego')
            self.assertEqual(self.window.history_proxy.rowCount(), 0)
        finally:
            self.window.history_proxy.set_text('')
        self.assertEqual(self.window.history_proxy.rowCount(), 5)

    def test_history_level_filter(self):
        from beatstamp.proof import Level
        self._fill_history(3)
        self.window.history.entries[0].level = Level.RECORDED.value
        self.window._refresh_history_view()
        try:
            self.window.history_proxy.set_level(Level.ANCHORED.value)
            self.assertEqual(self.window.history_proxy.rowCount(), 2)
            self.window.history_proxy.set_level(Level.RECORDED.value)
            self.assertEqual(self.window.history_proxy.rowCount(), 1)
        finally:
            self.window.history_proxy.set_level('')

    def test_dialogs_build(self):
        from beatstamp.ui.dialogs import (AboutDialog, DetailsDialog,
                                          LicensesDialog, SettingsDialog)
        for dialog in (AboutDialog(self.window),
                       SettingsDialog(Settings(), self.window),
                       DetailsDialog('Test', {'a': 1}, self.window),
                       LicensesDialog(self.window)):
            self.assertTrue(dialog.windowTitle())
            dialog.deleteLater()

    def test_the_licences_window_really_shows_a_text(self):
        """Okno z tekstami licencji jest JEDYNA droga do nich w wydaniu ze
        Sklepu: `C:\\Program Files\\WindowsApps` nalezy do TrustedInstallera,
        a Eksplorator dziala poza kontenerem paczki i pokazalby uzytkownikowi
        odmowe dostepu. Puste okno spelnialoby wymog LGPLv3 par. 4(c) tak
        samo jak jego brak, wiec sprawdzamy TRESC, a nie sam tytul.
        """
        from PySide6.QtWidgets import QListWidget, QPlainTextEdit

        from beatstamp.ui.dialogs import LicensesDialog

        dialog = LicensesDialog(self.window)
        try:
            listing = dialog.findChild(QListWidget)
            names = [listing.item(row).text()
                     for row in range(listing.count())]
            self.assertIn('LGPL-3.0.txt', names)
            self.assertIn('GPL-3.0.txt', names)
            view = dialog.findChild(QPlainTextEdit)
            self.assertGreater(len(view.toPlainText()), 500)
            for row, name in enumerate(names):
                if name == 'LGPL-3.0.txt':
                    listing.setCurrentRow(row)
                    break
            self.assertIn('GNU LESSER GENERAL PUBLIC LICENSE',
                          view.toPlainText())
        finally:
            dialog.deleteLater()

    def test_the_licences_button_always_opens_the_window(self):
        """Od 2.2 okno licencji jest wspolne dla obu wydan: spis skladnikow
        z licencja i zastosowaniem plus pelne teksty. Katalog w Eksploratorze
        jest przyciskiem W OKNIE — i tylko w wersji przenosnej, bo w wydaniu
        ze Sklepu Eksplorator pokazalby odmowe dostepu."""
        from unittest import mock

        from beatstamp.ui import dialogs

        for packaged in (False, True):
            with mock.patch.object(dialogs, 'is_packaged', return_value=packaged), \
                    mock.patch.object(dialogs, 'open_licenses_dir',
                                      return_value=True) as opener, \
                    mock.patch.object(dialogs, 'LicensesDialog') as window:
                dialogs.show_licenses(self.window)
            opener.assert_not_called()
            window.assert_called_once()

    def test_the_licences_window_lists_components_with_their_purpose(self):
        from PySide6.QtWidgets import QTableWidget

        from beatstamp.ui.dialogs import LicensesDialog

        dialog = LicensesDialog(self.window)
        try:
            table = dialog.findChild(QTableWidget)
            titles = [table.item(r, 0).text() for r in range(table.rowCount())]
            self.assertTrue(any(t.startswith('Qt ') for t in titles))
            for row in range(table.rowCount()):
                self.assertTrue(table.item(row, 1).text(), titles[row])
                self.assertTrue(table.item(row, 2).text(),
                                f'skladnik bez opisu zastosowania: {titles[row]}')
        finally:
            dialog.deleteLater()

    # --- Katalog danych -----------------------------------------------------

    def test_data_directory_action_points_at_the_real_directory(self):
        """Podpowiedz menu musi niesc sciezke, ktora program NAPRAWDE uzywa.

        Regresja do pilnowania: pod paczka MSIX Eksplorator dziala poza
        kontenerem paczki, wiec adres w `%LOCALAPPDATA%` otwieral u niego
        prawdziwy, PUSTY katalog, podczas gdy aplikacja pisala do swojej
        prywatnej kopii. Przycisk wygladal na zepsuty.
        """
        from beatstamp.config import app_data_dir
        from beatstamp.ui.dialogs import data_dir_button_text

        actions = [a for a in self.window.findChildren(QAction)
                   if a.text() == data_dir_button_text()]
        self.assertEqual(len(actions), 1, 'pozycja „katalog danych" musi byc jedna')
        self.assertIn(str(app_data_dir()), actions[0].toolTip())

    def test_data_directory_button_creates_the_directory_before_opening(self):
        """Pierwszy start: katalogu jeszcze nie ma, a przycisk ma cos pokazac."""
        from beatstamp.ui import dialogs

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'jeszcze-nie-ma'
            saved = os.environ.get('SIGELITH_DATA_DIR')
            os.environ['SIGELITH_DATA_DIR'] = str(target)
            opened = []
            real_open = dialogs.QDesktopServices.openUrl
            dialogs.QDesktopServices.openUrl = staticmethod(
                lambda url: opened.append(url) or True)
            try:
                dialogs.open_data_dir()
            finally:
                dialogs.QDesktopServices.openUrl = real_open
                if saved is None:
                    os.environ.pop('SIGELITH_DATA_DIR', None)
                else:
                    os.environ['SIGELITH_DATA_DIR'] = saved

            self.assertTrue(target.is_dir(), 'katalog musi powstac przed otwarciem')
            self.assertEqual(len(opened), 1)
            self.assertEqual(Path(opened[0].toLocalFile()), target)

    def test_about_dialog_shows_the_current_data_directory(self):
        from beatstamp.config import app_data_dir
        from beatstamp.ui.dialogs import AboutDialog, data_dir_button_text

        dialog = AboutDialog(self.window)
        buttons = [b for b in dialog.findChildren(QPushButton)
                   if b.text() == data_dir_button_text()]
        self.assertEqual(len(buttons), 1)
        self.assertIn(str(app_data_dir()), buttons[0].toolTip())
        dialog.deleteLater()

    def test_migration_is_reported_on_the_status_bar_not_in_a_dialog(self):
        """Przeprowadzka danych to czynnosc programu, nie problem uzytkownika."""
        from beatstamp.config import MigrationReport

        window = self.window
        saved = window._migration
        try:
            window._migration = MigrationReport(
                target=Path('C:/Dokumenty/BeatStamp'), sources=[Path('C:/Stare')],
                copied=['history.json'])
            window._report_migration()
            self.assertIn('Dokumenty', window.statusBar().currentMessage())

            # Brak przeprowadzki = brak komunikatu; pasek zostaje bez zmian.
            window.statusBar().clearMessage()
            window._migration = None
            window._report_migration()
            self.assertEqual(window.statusBar().currentMessage(), '')
        finally:
            window._migration = saved
            window.statusBar().clearMessage()

    # --- Zablokowany zapis --------------------------------------------------

    def test_startup_makes_sure_the_data_can_be_written(self):
        """Blokade trzeba zglosic PRZED praca, nie po policzeniu skrotu.

        Skrot pliku o wielkosci kilku gigabajtow liczy sie minutami, a stempel
        jest nieodwracalny — wpis idzie do publicznego rejestru. Uzytkownik,
        ktory dowiaduje sie o blokadzie dopiero na koncu tej drogi, traci czas,
        a swiezy dowod przepada razem z nieudanym zapisem historii.
        """
        from unittest import mock
        from beatstamp.config import WriteProblem
        from beatstamp.ui import main_window as mw

        problem = WriteProblem(directory=Path('C:/Dokumenty/BeatStamp'),
                               reason='No such file or directory', protected=True)
        self.window.statusBar().clearMessage()
        with mock.patch.object(mw, 'probe_write', return_value=problem) as probe:
            with mock.patch.object(mw, 'resolve_data_dir_problem',
                                   return_value=None) as shown:
                self.window._check_data_dir()

        self.assertEqual(probe.call_count, 1, 'proba zapisu musi sie odbyc')
        self.assertEqual(shown.call_count, 1, 'blokada ma byc pokazana od razu')
        message = self.window.statusBar().currentMessage()
        self.assertIn('Dokumenty', message)
        self.window.statusBar().clearMessage()

    def test_a_writable_folder_raises_no_dialog_at_startup(self):
        from unittest import mock
        from beatstamp.ui import main_window as mw

        with mock.patch.object(mw, 'resolve_data_dir_problem') as shown:
            self.window._check_data_dir()

        self.assertEqual(shown.call_count, 0)

    def test_a_blocked_save_shows_a_message_and_retries_after_the_move(self):
        """Regresja wprost: `FileNotFoundError` ze slotu Qt zamiast komunikatu.

        Ochrona przed ransomware przewraca `write_atomic` na wyjatku, ktory
        MOWI O BRAKUJACYM PLIKU TYMCZASOWYM. Bez tej obslugi uzytkownik
        dostawal slad wyjatku, a swiezy stempel przepadal.
        """
        from unittest import mock
        from beatstamp.ui import main_window as mw

        attempts = []

        def blocked():
            attempts.append('zapis')
            raise FileNotFoundError(2, 'No such file or directory')

        saved = []
        with mock.patch.object(mw, 'resolve_data_dir_problem',
                               return_value=Path(self._tmp.name)) as shown:
            result = self.window._store(blocked, lambda: saved.append('ponowiony'))

        self.assertTrue(result)
        self.assertEqual(attempts, ['zapis'])
        self.assertEqual(saved, ['ponowiony'], 'po zmianie katalogu zapis ma sie powtorzyc')
        self.assertEqual(shown.call_count, 1)
        problem = shown.call_args.args[0]
        self.assertTrue(problem.protected, 'brak pliku tymczasowego = blokada')

    def test_a_blocked_save_loses_none_of_the_stamps_from_a_batch(self):
        """Regresja: blokada gubila wszystkie stemple procz PIERWSZEGO.

        Uzytkownik upuszcza kilka plikow naraz. Serwer rejestruje komplet —
        nieodwracalnie, bo wpisy ida do publicznego rejestru. Dopoki kazdy
        wpis zapisywal historie osobno, pierwszy nieudany zapis PRZERYWAL
        petle wyjatkiem: stemple 2..N nie trafialy nawet do pamieci, a
        `_store` powtarzal zapis juz na komplecie niepelnym. Uzytkownik
        widzial jedna pozycje zamiast pieciu i ani slowa o stracie.
        """
        from unittest import mock
        from test_core import DIGEST, LIVE_PAYLOAD
        from beatstamp import proof, workers
        from beatstamp.history import Entry
        from beatstamp.ui import main_window as mw

        result = proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST)
        successes = [
            workers.StampOutcome(
                Entry(digest=f'{n:064x}', file_name=f'plik{n}.txt', file_size=10,
                      beat='@000.00', utc='2026-01-01T00:00:00Z', seq=n,
                      week='2026-W01', verified_ok=True),
                result, True, None)
            for n in (1, 2, 3)]

        kept = list(self.window.history.entries)
        real_save = self.window.history.save
        attempts = []

        def blocked_once():
            attempts.append('zapis')
            if len(attempts) == 1:
                raise FileNotFoundError(2, 'No such file or directory')
            real_save()

        self.window.history.entries = []
        self.window.history.save = blocked_once
        try:
            with mock.patch.object(mw, 'resolve_data_dir_problem',
                                   return_value=Path(self._tmp.name)):
                self.window._on_stamped(workers.BatchOutcome(successes, []))

            names = [e.file_name for e in self.window.history.entries]
            self.assertEqual(names, ['plik1.txt', 'plik2.txt', 'plik3.txt'],
                             'blokada zapisu nie moze zgubic zadnego stempla')
            # Komplet ma byc takze NA DYSKU, nie tylko w pamieci okna.
            on_disk = json.loads(
                (Path(self._tmp.name) / 'history.json').read_text(encoding='utf-8'))
            self.assertEqual([e['digest'] for e in on_disk],
                             [f'{n:064x}' for n in (1, 2, 3)])
            # Jeden zapis na cala paczke, nie jeden na plik.
            self.assertEqual(len(attempts), 2,
                             'zapis raz na paczke + jedno ponowienie po zmianie katalogu')
        finally:
            self.window.history.save = real_save
            self.window.history.entries = kept
            self.window._refresh_history_view()
            self.window._enable_result_buttons(False)

    def test_a_refused_move_leaves_a_warning_and_no_exception(self):
        from unittest import mock
        from beatstamp.ui import main_window as mw

        def blocked():
            raise PermissionError(13, 'Access is denied')

        self.window.statusBar().clearMessage()
        with mock.patch.object(mw, 'resolve_data_dir_problem', return_value=None):
            result = self.window._store(blocked)

        self.assertFalse(result)
        self.assertTrue(self.window.statusBar().currentMessage(),
                        'rezygnacja musi zostawic ostrzezenie na pasku stanu')
        self.window.statusBar().clearMessage()

    def test_the_history_writes_to_the_new_folder_after_a_move(self):
        """`History` zapamietuje sciezke przy tworzeniu — trzeba ja odswiezyc."""
        with tempfile.TemporaryDirectory() as tmp:
            saved = os.environ.get('SIGELITH_DATA_DIR')
            os.environ['SIGELITH_DATA_DIR'] = tmp
            try:
                self.window._adopt_data_dir()
                self.assertEqual(self.window.history.path,
                                 Path(tmp) / 'history.json')
            finally:
                if saved is None:
                    os.environ.pop('SIGELITH_DATA_DIR', None)
                else:
                    os.environ['SIGELITH_DATA_DIR'] = saved
                self.window._adopt_data_dir()
        self.window.statusBar().clearMessage()

    def test_settings_show_the_data_folder_and_the_way_to_change_it(self):
        from beatstamp.config import app_data_dir
        from beatstamp.ui.dialogs import SettingsDialog

        from PySide6.QtWidgets import QTabWidget

        dialog = SettingsDialog(Settings(), self.window)
        try:
            tabs = dialog.findChildren(QTabWidget)[0]
            names = [tabs.tabText(i) for i in range(tabs.count())]
            self.assertIn(_('Data'), names)
            self.assertEqual(dialog.data_dir_field.text(), str(app_data_dir()))
            self.assertTrue(dialog.data_dir_field.isReadOnly())
            self.assertTrue(dialog.data_dir_change.toolTip())
            # W tym tescie katalog narzuca `SIGELITH_DATA_DIR`, wiec przycisk
            # musi byc WYLACZONY: inaczej program powiedzialby „katalog
            # zmieniony", a pisal dalej w starym miejscu.
            self.assertFalse(dialog.data_dir_change.isEnabled())
        finally:
            dialog.deleteLater()

    def test_file_dialog_entry_points_survive_a_cancel(self):
        """Regresja: `path, _ = QFileDialog...` w funkcji, ktora tlumaczy tytul.

        Przypisanie do `_` czyni te nazwe LOKALNA dla calej funkcji, wiec
        `_('Wybierz plik')` W TYM SAMYM wywolaniu konczylo sie
        `UnboundLocalError` — menu „Plik → Zastempluj pliki…" nie otwieralo
        niczego. Zaden wczesniejszy test tego nie widzial, bo trzeba OTWORZYC
        okno wyboru pliku.
        """
        from unittest import mock
        from PySide6.QtWidgets import QFileDialog

        cases = (
            ('getOpenFileNames', ([], ''), self.window.browse_files_to_stamp),
            ('getOpenFileName', ('', ''), self.window.browse_file_to_verify),
            ('getOpenFileName', ('', ''), self.window.check_bundle_file),
            ('getSaveFileName', ('', ''),
             lambda: self.window._choose_save_path('t', 'plik.pdf', '*.pdf')),
        )
        for method, value, call in cases:
            with self.subTest(method=method):
                with mock.patch.object(QFileDialog, method, return_value=value):
                    call()          # brak wyjatku = caly warunek tego testu

    def test_settings_dialog_rejects_plain_http(self):
        from beatstamp.ui.dialogs import SettingsDialog
        dialog = SettingsDialog(Settings(), self.window)
        dialog.use_tor.setChecked(False)
        dialog.base_url.setText('http://przyklad.pl')
        problem = dialog.validate()
        self.assertIsNotNone(problem, 'adres bez TLS nie może zostac przyjety')
        self.assertIn('https', problem[1])
        dialog.base_url.setText('https://beattime.live')
        self.assertIsNone(dialog.validate())
        dialog.deleteLater()

    def test_settings_dialog_rejects_malformed_key(self):
        from beatstamp.ui.dialogs import SettingsDialog
        dialog = SettingsDialog(Settings(), self.window)
        for bad in ('to nie jest klucz', 'YWJj', 'x' * 44):
            dialog.pinned_key.setText(bad)
            self.assertIsNotNone(dialog.validate(), f'przyjęto zły klucz: {bad}')
        # Puste pole jest dozwolone (= wbudowana lista kluczy) i aktualny
        # klucz tez musi przechodzic.
        dialog.pinned_key.setText('')
        self.assertIsNone(dialog.validate())
        from beatstamp.proof import PINNED_PUBLIC_KEY
        dialog.pinned_key.setText(PINNED_PUBLIC_KEY)
        self.assertIsNone(dialog.validate())
        dialog.deleteLater()

    def test_settings_dialog_refuses_retired_key(self):
        """Wycofanego klucza nie da się „przywrócić" przez ustawienia."""
        from beatstamp import keys
        from beatstamp.ui.dialogs import SettingsDialog
        dialog = SettingsDialog(Settings(), self.window)
        dialog.pinned_key.setText(keys.RETIRED_KEYS[0]['public_key'])
        problem = dialog.validate()
        self.assertIsNotNone(problem)
        self.assertIn('wycofany', problem[0].lower())
        dialog.deleteLater()

    def test_settings_dialog_trust_field_defaults_to_builtin_list(self):
        from beatstamp import keys
        from beatstamp.ui.dialogs import SettingsDialog
        # Stara wartosc fabryczna z settings.json nie moze pojawic sie w polu.
        dialog = SettingsDialog(
            Settings(pinned_public_key=keys.LEGACY_DEFAULT_PINNED_KEY), self.window)
        self.assertEqual(dialog.pinned_key.text(), '')
        self.assertEqual(dialog.pinned_key.placeholderText(), 'wbudowana lista kluczy')
        self.assertEqual(dialog.result_settings().pinned_public_key, '')

        custom = _rogue_public_key()
        dialog.pinned_key.setText(custom)
        self.assertEqual(dialog.result_settings().pinned_public_key, custom)
        # „Przywróć wbudowaną listę" czyści pole, zamiast wpisywac jakis klucz.
        restore = [b for b in dialog.findChildren(QPushButton)
                   if b.text() == _('Restore the built-in list')]
        self.assertEqual(len(restore), 1)
        restore[0].click()
        self.assertEqual(dialog.pinned_key.text(), '')
        dialog.deleteLater()

    def test_status_bar_warns_only_about_custom_key(self):
        from beatstamp import keys
        window = self.window
        saved = window.settings.pinned_public_key
        try:
            for quiet in ('', keys.LEGACY_DEFAULT_PINNED_KEY, keys.primary_key()):
                window.settings.pinned_public_key = quiet
                window._update_connection_label()
                self.assertFalse(window.status_connection.text().startswith('⚠'),
                                 f'fałszywy alarm dla {quiet!r}')
            window.settings.pinned_public_key = _rogue_public_key()
            window._update_connection_label()
            self.assertTrue(window.status_connection.text().startswith('⚠'))
            self.assertIn(
                _('YOUR OWN public key is set — besides the built-in list of '
                  'Sigelith keys the application also accepts signatures made '
                  'with that key.'),
                window.status_connection.toolTip())
        finally:
            window.settings.pinned_public_key = saved
            window._update_connection_label()

    def test_retired_key_result_is_shown_as_needing_refresh(self):
        from test_core import DIGEST, LIVE_PAYLOAD, RETIRED_KEY_PAYLOAD
        from beatstamp import proof
        window = self.window
        window._verify_source_name = ''
        window._on_verified(proof.verify_payload(RETIRED_KEY_PAYLOAD,
                                                 expected_digest=DIGEST))
        self.assertIn(_('The proof needs refreshing'), window.verify_title.text())
        self.assertEqual(window.verify_badge.text(), _('Retired key'))
        self.assertIn(_('Sigelith key RETIRED — the proof needs refreshing'),
                      window.verify_checks.text())
        self.assertIn(
            _('Refresh the proof online (History -> Refresh statuses, F5) to '
              'fetch a signature made with the current key.'),
            window.verify_description.text())

        window._on_verified(proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST))
        self.assertTrue(window.verify_title.text().startswith(_('Confirmed')))
        self.assertIn(_('Sigelith key from the list built into the application'),
                      window.verify_checks.text())

    def test_retired_key_bundle_is_shown_as_needing_refresh(self):
        from test_core import DIGEST, RETIRED_KEY_PAYLOAD
        from beatstamp import bundle, proof, workers
        data = bundle.build(proof.verify_payload(RETIRED_KEY_PAYLOAD,
                                                 expected_digest=DIGEST))
        check = bundle.check(data, document_digest=DIGEST)
        self.window._on_bundle_checked(
            workers.BundleOutcome(Path('stary.beatproof'), check, data))
        self.assertIn(_('The proof needs refreshing'),
                      self.window.verify_title.text())
        self.assertEqual(self.window.verify_badge.text(), _('Retired key'))
        self.assertIn(_('Sigelith key RETIRED — the proof needs refreshing'),
                      self.window.verify_checks.text())

    def test_rejected_proof_disables_pdf_and_bundle(self):
        """Regresja: PDF z dowodu „niespójnego" pisał „korzeń podpisany"."""
        from test_core import DIGEST, LIVE_PAYLOAD
        from test_keys import _rogue_pair, _signed_by
        from beatstamp import proof
        window = self.window
        priv, pub = _rogue_pair()
        rejected = proof.verify_payload(_signed_by(priv, pub), expected_digest=DIGEST)
        self.assertTrue(rejected.problems)

        window._verify_source_name = ''
        window._on_verified(rejected)
        self.assertEqual(window.verify_title.text(), _('Inconsistent proof'))
        self.assertFalse(window.verify_pdf_button.isEnabled())
        self.assertFalse(window.verify_bundle_button.isEnabled())
        self.assertTrue(window.verify_details_button.isEnabled())

        good = proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST)
        window._on_verified(good)
        self.assertTrue(window.verify_pdf_button.isEnabled())
        self.assertTrue(window.verify_bundle_button.isEnabled())

        # Karta stempla jest wspolna dla testow, a jeden z nich sprawdza, ze
        # jej przyciski startuja wylaczone — sprzatamy po sobie.
        try:
            window._show_result(rejected, None, newly_created=True)
            self.assertEqual(window.result_title.text(), _('Inconsistent proof'))
            self.assertFalse(window.button_pdf.isEnabled())
            self.assertFalse(window.button_bundle.isEnabled())
            self.assertTrue(window.button_details.isEnabled())
            window._show_result(good, None, newly_created=True)
            self.assertTrue(window.button_pdf.isEnabled())
            self.assertTrue(window.button_bundle.isEnabled())
        finally:
            window._enable_result_buttons(False)

    def test_stamp_result_with_retired_key_needs_refresh(self):
        """Mutant M25: gałąź needs_refresh w _show_result nie była testowana."""
        from test_core import DIGEST, RETIRED_KEY_PAYLOAD
        from beatstamp import proof
        result = proof.verify_payload(RETIRED_KEY_PAYLOAD, expected_digest=DIGEST)
        try:
            self.window._show_result(result, None, newly_created=False)
            self.assertEqual(self.window.result_title.text(),
                             _('The proof needs refreshing'))
            self.assertEqual(self.window.result_badge.text(), _('Retired key'))
            self.assertIn(
                _('Refresh the proof online (History -> Refresh statuses, F5) '
                  'to fetch a signature made with the current key.'),
                self.window.result_description.text())
            self.assertIn(_('Sigelith key RETIRED — the proof needs refreshing'),
                          self.window.result_checks.text())
        finally:
            self.window._enable_result_buttons(False)

    def test_time_row_shows_the_signed_week_as_the_bound(self):
        from test_core import DIGEST, LIVE_PAYLOAD
        from beatstamp import proof
        window = self.window
        window._verify_source_name = ''
        window._on_verified(proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST))
        from beatstamp.ui.main_window import _week_note
        text = window.verify_time.text()
        # Wiersz czasu ma mowic, co podpis NAPRAWDE obejmuje: tydzien, a nie
        # dokladna chwile. Oczekiwany napis skladamy ta sama funkcja, wiec
        # test sprawdza tresc, a nie przepisany ciag znakow.
        self.assertIn(_week_note('2026-W25', True), text)
        self.assertIn(proof.week_end_text('2026-W25'), text)
        self.assertIn('2026-W25', text)

    def test_backdated_bundle_is_rejected_in_the_view(self):
        """Regresja: zmyślona data w .beatproof dawała „Zweryfikowany offline"."""
        from test_core import DIGEST, LIVE_PAYLOAD
        from beatstamp import bundle, proof, workers
        data = bundle.build(proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST))
        data.update(utc='2019-01-01T00:00:00Z', beat='@041.66')
        check = bundle.check(data, document_digest=DIGEST)
        self.window._on_bundle_checked(
            workers.BundleOutcome(Path('umowa.beatproof'), check, data))
        from beatstamp.ui.main_window import _week_note
        self.assertEqual(self.window.verify_title.text(), _('Inconsistent proof'))
        self.assertEqual(self.window.verify_badge.text(), _('Rejected'))
        # Zastrzezenie musi byc TYM zastrzezeniem: czas spoza podpisanego
        # tygodnia. Oczekiwana tresc liczymy ta sama funkcja co program.
        expected = proof.time_claim_problems(data['utc'], data['beat'], data['week'])
        self.assertTrue(expected, 'test bez sensu, gdyby czas byl poprawny')
        for problem in expected:
            self.assertIn(problem, self.window.verify_description.text())
        self.assertTrue(check.week)
        self.assertNotIn(_week_note(check.week, True),
                         self.window.verify_time.text())

    def test_badge_tooltip_is_never_markup(self):
        badge = self.window.verify_badge
        badge.show_state('warn', 'Test', '<img src="//198.51.100.7/a.png"/>\nlinia')
        self.assertNotIn('<img', badge.toolTip())
        self.assertIn('&lt;img', badge.toolTip())

    def test_retired_bundle_export_warns(self):
        """Mutant M23: ostrzeżenie przy eksporcie dowodu z wycofanym kluczem."""
        from unittest import mock
        from test_core import DIGEST, RETIRED_KEY_PAYLOAD
        from beatstamp import proof
        from beatstamp.history import entry_from_verification
        from beatstamp.ui import main_window as mw
        entry = entry_from_verification(
            proof.verify_payload(RETIRED_KEY_PAYLOAD, expected_digest=DIGEST))
        target = Path(self._tmp.name) / 'stary.beatproof'
        with mock.patch.object(self.window, '_choose_save_path', return_value=target), \
                mock.patch.object(mw.QMessageBox, 'warning') as warning, \
                mock.patch.object(self.window, '_offer_open') as offer:
            self.window._write_bundle(entry)
        self.assertTrue(target.exists())
        warning.assert_called_once()
        self.assertEqual(warning.call_args.args[1],
                         _('Proof saved — it needs refreshing'))
        offer.assert_not_called()

    def test_removing_override_in_settings_demotes_history(self):
        """Regresja: po usunięciu własnego klucza wpisy zostawały „Zakotwiczony"."""
        from dataclasses import replace
        from unittest import mock
        from test_core import DIGEST
        from test_keys import _rogue_pair, _signed_by
        from beatstamp import proof
        from beatstamp.history import entry_from_verification
        from beatstamp.ui import main_window as mw
        window = self.window
        priv, pub = _rogue_pair()
        entry = entry_from_verification(proof.verify_payload(
            _signed_by(priv, pub), expected_digest=DIGEST, key_override=pub))
        self.assertEqual(entry.level, 'anchored')

        class FakeDialog:
            Accepted = 1

            def __init__(self, settings, parent=None):
                self._settings = settings

            def exec(self):
                return 1

            def result_settings(self):
                return replace(self._settings, pinned_public_key='')

        saved_settings, saved_entries = window.settings, window.history.entries
        try:
            window.settings = replace(saved_settings, pinned_public_key=pub)
            window.history.entries = [entry]
            with mock.patch.object(mw, 'SettingsDialog', FakeDialog):
                window.open_settings()
            self.assertEqual(entry.level, 'recorded')
            self.assertFalse(entry.verified_ok)
        finally:
            window.settings = saved_settings
            window.history.entries = saved_entries
            window._refresh_history_view()
            window._update_connection_label()

    def test_settings_dialog_refuses_non_canonical_alias_of_retired_key(self):
        from test_keys import _alias
        from beatstamp import keys
        from beatstamp.ui.dialogs import SettingsDialog
        dialog = SettingsDialog(Settings(), self.window)
        dialog.pinned_key.setText(_alias(keys.RETIRED_KEYS[0]['public_key']))
        self.assertIsNotNone(dialog.validate(), 'alias klucza wycofanego przyjęty')
        dialog.pinned_key.setText(_alias(keys.primary_key()))
        self.assertIsNotNone(dialog.validate())
        dialog.deleteLater()

    def test_onion_mode_allows_non_https_address(self):
        """Przez Tora adres .onion jest po http — i to jest poprawne."""
        from beatstamp.ui.dialogs import SettingsDialog
        dialog = SettingsDialog(Settings(), self.window)
        dialog.use_tor.setChecked(True)
        dialog.base_url.setText('http://cos.onion')
        self.assertIsNone(dialog.validate())
        dialog.deleteLater()

    # --- 2.2: uwagi z testow uzytkownika ------------------------------------

    def _stamped(self, note: str = ''):
        from test_core import DIGEST, LIVE_PAYLOAD
        from beatstamp import proof, workers
        from beatstamp.history import entry_from_verification
        result = proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST)
        entry = entry_from_verification(result, file_name='umowa.pdf', note=note)
        return workers.BatchOutcome([workers.StampOutcome(entry, result, True)], [])

    def test_the_note_is_written_after_stamping_not_before(self):
        """Uzytkownik przeciaga plik OD RAZU, a notatke chce dopisac potem.

        Do 2.1 pole notatki trzeba bylo wypelnic przed przeciagnieciem pliku
        — kto o tym nie wiedzial, nie mial jak dopisac notatki do stempla.
        """
        window = self.window
        saved_entries = list(window.history.entries)
        try:
            window.current_entry = None
            window._current_batch = []
            window._show_note_for_current()
            self.assertFalse(window.note_input.isEnabled(),
                             'notatka bez stempla nie ma do czego trafic')
            window._on_stamped(self._stamped())
            self.assertTrue(window.note_input.isEnabled())
            window.note_input.setText('umowa z klientem')
            window._save_note_to_current()
            from test_core import DIGEST
            self.assertEqual(window.history.find(DIGEST).note, 'umowa z klientem')
        finally:
            window.history.entries = saved_entries
            window.current_entry = None
            window._current_batch = []
            window._refresh_history_view()
            window._enable_result_buttons(False)

    def test_the_certificate_name_carries_file_time_and_beat(self):
        from unittest import mock
        from test_core import DIGEST, LIVE_PAYLOAD
        from beatstamp import naming, proof
        from beatstamp.history import entry_from_verification
        entry = entry_from_verification(
            proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST),
            file_name='Umowa najmu.pdf')
        with mock.patch.object(self.window, '_choose_save_path',
                               return_value=None) as choose:
            self.window._write_certificate(entry)
        proposed = choose.call_args.args[1]
        self.assertEqual(proposed, naming.certificate_name(entry))
        self.assertTrue(proposed.startswith('Umowa najmu_'))
        self.assertIn(entry.beat, proposed)
        self.assertIn(naming.stamp_moment_text(entry.utc), proposed)

    def test_the_proposed_name_never_points_at_an_existing_file(self):
        from unittest import mock
        window = self.window
        folder = Path(self._tmp.name) / 'certy'
        folder.mkdir(exist_ok=True)
        (folder / 'a_beattime.pdf').write_bytes(b'1')
        saved = window.settings.last_directory
        window.settings.last_directory = str(folder)
        try:
            with mock.patch('beatstamp.ui.main_window.QFileDialog.getSaveFileName',
                            return_value=('', '')) as dialog:
                window._choose_save_path('t', 'a_beattime.pdf', '*.pdf')
            self.assertTrue(dialog.call_args.args[2].endswith('a_beattime (2).pdf'))
        finally:
            window.settings.last_directory = saved

    def test_help_pages_open_in_the_interface_language(self):
        """Do 2.1 „Jak to dziala" prowadzilo na strone angielska."""
        urls = [a.data() for a in self.window.findChildren(QAction)
                if isinstance(a.data(), str) and a.data().startswith('https://sigelith.org')]
        self.assertIn('https://sigelith.org/pl/proof/', urls)
        self.assertIn('https://sigelith.org/pl/evidence/', urls)
        # Strony jednojezyczne maja jeden adres.
        self.assertIn('https://sigelith.org/checkpoints/', urls)
        # Manifest nosi tytul „The BeatTime Manifesto" i ma PL oraz EN.
        self.assertIn('https://sigelith.org/pl/manifesto/', urls)
        every = [a.data() for a in self.window.findChildren(QAction)
                 if isinstance(a.data(), str)]
        self.assertEqual([u for u in every if 'beattime.live' in u], [],
                         'menu prowadzi pod sigelith.org — ta sama instancja')

    def test_the_clock_shows_local_time_and_utc(self):
        """Do 2.1 obok @beat stal tylko czas UTC — w Polsce „spozniony" o 2 h."""
        from beatstamp import beatcore
        clock = self.window.clock
        clock._tick()
        self.assertIn(beatcore.utc_offset_label(), clock.local_text())
        self.assertIn('UTC', clock.utc_text())

    def test_a_narrow_header_never_cuts_the_clock(self):
        """Uwaga z testow 2.2.0: przy minimalnej szerokosci okna Qt obcinal
        koncowke zegara i poczatek pastylki swiadkow. Skracac sie maja
        podpis i pastylka (wielokropkiem), zegar nigdy."""
        header = self.window._header
        clock = self.window.clock
        self.window.witness_button.setText('Dziennik sprawdzony · punkt kontrolny #2')
        # Okno ma minimum 980 px, czyli naglowek ok. 944 px; 820 to zapas.
        for width in (1100, 944, 820):
            header.resize(width, 90)
            header.layout().setGeometry(header.rect())
            self.assertGreaterEqual(clock.width(), clock.sizeHint().width(), width)
            self.assertLessEqual(clock.geometry().right(), header.width())
        shown = self.window.witness_button.text()
        self.assertTrue(shown.endswith('#2') or '…' not in shown, shown)

    def test_badges_measure_their_own_text(self):
        """Plakietka nie moze byc wezsza niz jej tekst z marginesami."""
        from PySide6.QtGui import QFontMetrics
        badge = self.window.verify_badge
        for text in ('Zakotwiczony', 'Zweryfikowano offline', 'W'):
            badge.show_state('ok', text)
            width = QFontMetrics(badge.font()).horizontalAdvance(text)
            self.assertGreaterEqual(badge.sizeHint().width(),
                                    width + 2 * badge.PAD_X)

    def test_the_verification_buttons_are_spaced_like_the_history_ones(self):
        layouts = []
        for button in (self.window.verify_pdf_button, self.window.button_pdf,
                       self.window.history_buttons['pdf']):
            parent_layout = None
            for layout in button.parentWidget().findChildren(QHBoxLayout):
                if layout.indexOf(button) >= 0:
                    parent_layout = layout
            self.assertIsNotNone(parent_layout)
            layouts.append(parent_layout.spacing())
        self.assertEqual(len(set(layouts)), 1, layouts)
        self.assertGreaterEqual(layouts[0], 8)


class DataDirDialogTests(unittest.TestCase):
    """Zmiana katalogu danych: kopia, zapamietanie i droga wyjscia z blokady.

    Bez okna glownego — te funkcje sa celowo osobne, zeby dalo sie je wywolac
    takze ze startu programu, zanim okno powstanie.
    """

    def setUp(self):
        from beatstamp.ui import dialogs

        self.dialogs = dialogs
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.old = self.dir / 'Stary'
        self.new = self.dir / 'Nowy'
        self.old.mkdir()
        (self.old / 'history.json').write_text('[]', encoding='utf-8')
        self._saved = {key: os.environ.get(key)
                       for key in ('SIGELITH_DATA_DIR', 'LOCALAPPDATA')}
        os.environ['SIGELITH_DATA_DIR'] = str(self.old)
        # Wskaznik wyboru trafia pod `%LOCALAPPDATA%` — w tescie do katalogu
        # tymczasowego, zeby nie ruszyc prawdziwego wyboru wlasciciela maszyny.
        os.environ['LOCALAPPDATA'] = str(self.dir / 'AppData')

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._tmp.cleanup()

    def test_changing_the_folder_copies_the_data_and_remembers_the_choice(self):
        from unittest import mock
        from beatstamp import config

        target = config.data_dir_for_choice(self.new)
        with mock.patch.object(self.dialogs, 'QMessageBox'):
            self.assertTrue(self.dialogs.switch_data_dir(target))

        self.assertEqual((target / 'history.json').read_text(encoding='utf-8'), '[]')
        self.assertTrue((self.old / 'history.json').is_file(),
                        'stare dane zostaja na miejscu — nie kasujemy niczego')
        self.assertEqual(config.stored_data_dir(), target)

    def test_a_blocked_folder_is_refused_and_not_remembered(self):
        """Zamiana jednej blokady na druga, tyle ze trwala, jest wykluczona."""
        from unittest import mock
        from beatstamp import config

        problem = config.WriteProblem(directory=self.new, reason='No such file',
                                      protected=True)
        with mock.patch.object(self.dialogs, 'probe_write', return_value=problem):
            with mock.patch.object(self.dialogs, 'QMessageBox') as box:
                self.assertFalse(self.dialogs.switch_data_dir(self.new))

        self.assertIsNone(config.stored_data_dir())
        self.assertTrue(box.warning.called, 'uzytkownik musi zobaczyc powod')

    def test_cancelling_the_folder_picker_changes_nothing(self):
        from unittest import mock
        from beatstamp import config
        from PySide6.QtWidgets import QFileDialog

        with mock.patch.object(QFileDialog, 'getExistingDirectory', return_value=''):
            self.assertFalse(self.dialogs.switch_data_dir_interactively())

        self.assertIsNone(config.stored_data_dir())

    def test_the_picker_adds_the_application_subfolder(self):
        from unittest import mock
        from PySide6.QtWidgets import QFileDialog

        with mock.patch.object(QFileDialog, 'getExistingDirectory',
                               return_value=str(self.new)):
            chosen = self.dialogs.choose_data_dir()

        self.assertEqual(chosen, self.new / 'Sigelith')

    def test_settings_change_the_folder_from_end_to_end(self):
        """Ustawienia -> Dane -> „Zmień…": wybor, kopia, zapamietanie, nowa sciezka."""
        from unittest import mock
        from beatstamp import config
        from beatstamp.config import Settings
        from beatstamp.ui.dialogs import SettingsDialog
        from PySide6.QtWidgets import QFileDialog

        # Bez zmiennej srodowiskowej — inaczej przycisk jest (slusznie)
        # wylaczony, bo katalog narzuca uruchomienie, a nie uzytkownik.
        os.environ.pop('SIGELITH_DATA_DIR', None)
        config.remember_data_dir(self.old)
        dialog = SettingsDialog(Settings())
        try:
            self.assertTrue(dialog.data_dir_change.isEnabled())
            self.assertEqual(dialog.data_dir_field.text(), str(self.old))
            with mock.patch.object(QFileDialog, 'getExistingDirectory',
                                   return_value=str(self.new)):
                with mock.patch.object(self.dialogs, 'QMessageBox'):
                    dialog.data_dir_change.click()

            target = self.new / 'Sigelith'
            self.assertEqual(dialog.data_dir_field.text(), str(target))
            self.assertEqual(config.stored_data_dir(), target)
            self.assertEqual((target / 'history.json').read_text(encoding='utf-8'), '[]')
            self.assertTrue((self.old / 'history.json').is_file())
        finally:
            dialog.deleteLater()

    def test_the_block_dialog_offers_both_ways_out(self):
        from beatstamp import config

        problem = config.WriteProblem(directory=self.old, reason='No such file',
                                      protected=True)
        dialog = self.dialogs.DataDirProblemDialog(problem)
        try:
            self.assertTrue(dialog.windowTitle())
            for button in (dialog._choose_button, dialog._settings_button,
                           dialog._retry_button):
                self.assertTrue(button.text())
                self.assertTrue(button.toolTip(), f'{button.text()} bez podpowiedzi')
            self.assertIn(str(self.old), dialog._text.text())
            self.assertIsNone(dialog.chosen)
        finally:
            dialog.deleteLater()

    def test_the_windows_settings_button_opens_windows_and_keeps_the_dialog(self):
        """Przycisk do ustawien systemu NIE MOZE zamykac okna.

        Uzytkownik idzie do Zabezpieczen Windows, dodaje program do
        dozwolonych i wraca — a wtedy ma tu czekac „Sprawdz jeszcze raz".
        """
        from unittest import mock
        from beatstamp import config

        problem = config.WriteProblem(directory=self.old, reason='No such file',
                                      protected=True)
        dialog = self.dialogs.DataDirProblemDialog(problem)
        opened = []
        try:
            with mock.patch.object(self.dialogs.QDesktopServices, 'openUrl',
                                   staticmethod(lambda url: opened.append(url.toString())
                                                or True)):
                dialog._settings_button.click()
            # `QUrl` zapisuje czlon po `//` malymi literami (to nazwa hosta,
            # a te sa w URI nierozrozniane co do wielkosci liter) — Windows
            # przyjmuje oba zapisy.
            self.assertEqual(opened, ['windowsdefender://ransomwareprotection'])
            self.assertTrue(dialog.isVisible() or not dialog.result(),
                            'okno ma zostac otwarte po powrocie z ustawien')
        finally:
            dialog.deleteLater()

    def test_checking_again_accepts_a_folder_that_started_working(self):
        """Uzytkownik dodaje program do dozwolonych w Windows i wraca do okna."""
        from unittest import mock
        from beatstamp import config

        problem = config.WriteProblem(directory=self.old, reason='No such file',
                                      protected=True)
        dialog = self.dialogs.DataDirProblemDialog(problem)
        try:
            with mock.patch.object(self.dialogs, 'QMessageBox'):
                dialog._retry()
            self.assertEqual(dialog.chosen, self.old)
        finally:
            dialog.deleteLater()

    def test_checking_again_keeps_the_dialog_open_while_the_block_lasts(self):
        from unittest import mock
        from beatstamp import config

        problem = config.WriteProblem(directory=self.old, reason='No such file',
                                      protected=True)
        dialog = self.dialogs.DataDirProblemDialog(problem)
        try:
            with mock.patch.object(self.dialogs, 'probe_write', return_value=problem):
                dialog._retry()
            self.assertIsNone(dialog.chosen)
        finally:
            dialog.deleteLater()


class HistoryTooltipTests(unittest.TestCase):
    """Podpowiedzi tabeli historii: treść i bezpieczeństwo."""

    def _tooltip(self, entry, column):
        from PySide6.QtCore import Qt
        from beatstamp.ui.history_model import HistoryModel
        model = HistoryModel([entry])
        return model.data(model.index(0, column), Qt.ToolTipRole)

    def test_retired_entry_tooltip_explains_refresh(self):
        """Mutant M26: podpowiedź dla wpisu z wycofanym kluczem."""
        from test_core import DIGEST, RETIRED_KEY_PAYLOAD
        from beatstamp import proof
        from beatstamp.history import entry_from_verification
        from beatstamp.ui.history_model import COL_LEVEL
        entry = entry_from_verification(
            proof.verify_payload(RETIRED_KEY_PAYLOAD, expected_digest=DIGEST))
        self.assertTrue(entry.signed_by_retired_key)
        from beatstamp.ui.widgets import plain_tooltip
        tip = self._tooltip(entry, COL_LEVEL)
        self.assertEqual(tip, plain_tooltip(_(
            'The week root was signed with a Sigelith key that has been\n'
            'retired — such a signature is no longer a proof, so the level\n'
            'stays "Recorded".\n\n'
            'Refresh statuses (F5) to fetch a signature made with the current '
            'key.')))

    def test_note_and_file_name_tooltips_are_escaped(self):
        """Notatki wchodzą też z automatycznie importowanej historii TVS."""
        from beatstamp.history import Entry
        from beatstamp.ui.history_model import COL_ANCHOR, COL_FILE, COL_NOTE
        evil = '<img src="//198.51.100.7/a.png"/>'
        entry = Entry(digest='a' * 64, note=evil, file_name=evil,
                      anchors=[{'bank': evil}])
        for column in (COL_NOTE, COL_FILE, COL_ANCHOR):
            tip = self._tooltip(entry, column)
            self.assertNotIn('<img', tip, column)
            self.assertIn('&lt;img', tip, column)


class TaskLifetimeTests(unittest.TestCase):
    """Regresja: zadanie w tle nie może zniknac spod pracujacego watku.

    To była wada poprzedniej wersji programu (worker trzymany w polu
    nadpisywanym przy każdym pliku) i wrocila przy pierwszym podejsciu do tej
    — bo jest NIEDETERMINISTYCZNA: ujawnia się tylko wtedy, gdy odsmiecacz
    zdazy zadzialac przed koncem zadania. Dlatego wymuszamy tu `gc.collect()`
    zaraz po oddaniu zadania do puli.
    """

    def setUp(self):
        from PySide6.QtCore import QThreadPool
        self.pool = QThreadPool()
        self.pool.setMaxThreadCount(1)

    def tearDown(self):
        self.pool.waitForDone(5000)

    def _drain(self, predicate, timeout_ms: int = 5000) -> bool:
        from PySide6.QtCore import QDeadlineTimer
        deadline = QDeadlineTimer(timeout_ms)
        while not deadline.hasExpired():
            _app.processEvents()
            if predicate():
                return True
        return False

    def test_task_survives_garbage_collection(self):
        import gc
        import time
        from beatstamp import workers

        received = []

        class SlowTask(workers.Task):
            def work(self):
                time.sleep(0.25)      # dosc dlugo, by odsmiecacz zdazyl
                return 'wynik'

        task = SlowTask()
        task.signals.finished.connect(received.append)
        workers.launch(self.pool, task)

        # Wywolujacy porzuca referencje — dokladnie tak, jak w kodzie okna,
        # gdzie zadanie zyje w zmiennej lokalnej metody.
        del task
        gc.collect()

        self.assertTrue(self._drain(lambda: bool(received)),
                        'sygnal nie dotarl — obiekt zadania został zwolniony')
        self.assertEqual(received, ['wynik'])

    def test_reference_is_released_after_completion(self):
        """Zbior nie może być wyciekiem pamieci — po `done` zadanie znika."""
        from beatstamp import workers

        before = workers.running_count()

        class QuickTask(workers.Task):
            def work(self):
                return 1

        workers.launch(self.pool, QuickTask())
        self.assertTrue(self._drain(
            lambda: workers.running_count() == before), 'referencja nie zwolniona')

    def test_exception_in_work_becomes_failed_signal(self):
        """Wyjątek nie może wyjsc z `run()` — w Qt konczy cały proces."""
        from beatstamp import workers

        problems = []

        class BrokenTask(workers.Task):
            def work(self):
                raise RuntimeError('celowa awaria')

        task = BrokenTask()
        task.signals.failed.connect(problems.append)
        # Awaria jest tu ZAMIERZONA — jej slad stosu w wyjsciu testow tylko
        # myli czytajacego raport. Wyciszamy na czas tego jednego testu.
        logging.getLogger('beatstamp.workers').setLevel(logging.CRITICAL)
        try:
            workers.launch(self.pool, task)
            self.assertTrue(self._drain(lambda: bool(problems)))
        finally:
            logging.getLogger('beatstamp.workers').setLevel(logging.NOTSET)
        self.assertEqual(problems[0], _(
            'An unexpected error occurred. The details were written to the log '
            '(Help -> Show event log).'))

    def test_api_error_message_reaches_the_user_unchanged(self):
        from beatstamp import workers
        from beatstamp.api import ApiError

        problems = []

        class FailingTask(workers.Task):
            def work(self):
                raise ApiError('Brak połączenia z sigelith.org.')

        task = FailingTask()
        task.signals.failed.connect(problems.append)
        workers.launch(self.pool, task)
        self.assertTrue(self._drain(lambda: bool(problems)))
        self.assertEqual(problems[0], 'Brak połączenia z sigelith.org.')


class CertificateTests(unittest.TestCase):
    """Certyfikat musi się zlozyc także dla danych niekompletnych i wrogich."""

    def test_builds_for_complete_entry(self):
        from beatstamp import certificate
        from beatstamp.history import Entry
        entry = Entry(digest='a' * 64, file_name='umowa.pdf', file_size=2048,
                      beat='@348.28', utc='2026-06-15T08:21:32Z', seq=1,
                      week='2026-W25', week_closed=True, week_root='b' * 64,
                      level='anchored', ots_status='bitcoin', ots_height=954888,
                      inclusion_proof=[{'side': 'R', 'hash': 'c' * 64}],
                      anchors=[{'bank': 'Bank', 'date': '2026-06-23',
                                'status': 'confirmed', 'bank_reference': '123'}],
                      note='notatka')
        pdf = certificate.build_certificate(entry)
        self.assertTrue(pdf.startswith(b'%PDF'))
        self.assertGreater(len(pdf), 3000)

    def test_builds_for_minimal_entry(self):
        from beatstamp import certificate
        from beatstamp.history import Entry
        pdf = certificate.build_certificate(Entry(digest='a' * 64))
        self.assertTrue(pdf.startswith(b'%PDF'))

    def test_xml_special_characters_do_not_break_pdf(self):
        """Regresja: nazwa pliku z '&' albo '<' wywracala stara generacje."""
        from beatstamp import certificate
        from beatstamp.history import Entry
        entry = Entry(digest='a' * 64,
                      file_name='umowa <Kowalski & Syn> "v2".pdf',
                      note='<b>uwaga</b> & spolka')
        pdf = certificate.build_certificate(entry)
        self.assertTrue(pdf.startswith(b'%PDF'))

    def test_no_temporary_files_left_behind(self):
        """Regresja: stara wersja zostawiala PNG kodu QR w %TEMP% po każdym PDF."""
        from beatstamp import certificate
        from beatstamp.history import Entry
        temp = Path(tempfile.gettempdir())
        before = set(temp.glob('*.png'))
        for _ in range(3):
            certificate.build_certificate(Entry(digest='d' * 64))
        self.assertEqual(set(temp.glob('*.png')) - before, set())


if __name__ == '__main__':
    unittest.main(verbosity=2)


class LevelColorContrastTests(unittest.TestCase):
    """Kolory poziomu dowodu w tabeli musza nadazac za motywem.

    Wczesniej byly wpisane na sztywno barwami motywu JASNEGO, wiec w ciemnym
    ciemna zielen `#1f8a4c` ladowala na ciemnym tle — a na tle zaznaczonego
    wiersza (`#4a2a1e`) stawala sie praktycznie nieczytelna.
    """

    @staticmethod
    def _contrast(fg: str, bg: str) -> float:
        def lum(hex_color: str) -> float:
            c = hex_color.lstrip('#')
            channels = [int(c[i:i + 2], 16) / 255 for i in (0, 2, 4)]
            channels = [x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4
                        for x in channels]
            return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]
        a, b = sorted((lum(fg), lum(bg)), reverse=True)
        return (a + 0.05) / (b + 0.05)

    def test_level_colors_follow_theme(self):
        from beatstamp.ui import theme
        theme.apply_theme(_app, 'dark')
        self.assertEqual(theme.current()['ok'], theme.DARK['ok'])
        theme.apply_theme(_app, 'light')
        self.assertEqual(theme.current()['ok'], theme.LIGHT['ok'])

    def test_readable_on_normal_and_selected_rows(self):
        """Kontrast >= 3:1 (WCAG dla tekstu nie-podstawowego) w obu motywach."""
        for name, colors in (('jasny', theme.LIGHT), ('ciemny', theme.DARK)):
            for role in ('ok', 'warn'):
                for background in ('surface', 'surface_alt', 'selection'):
                    ratio = self._contrast(colors[role], colors[background])
                    self.assertGreaterEqual(
                        ratio, 3.0,
                        f'motyw {name}: {role} na {background} ma kontrast '
                        f'{ratio:.2f}:1 — za malo')
