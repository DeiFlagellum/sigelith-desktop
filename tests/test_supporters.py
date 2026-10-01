"""
Okno podziekowan i dokumenty prawne w aplikacji.

Trzy rodzaje awarii, ktorych zaden inny test nie zobaczy.

**Odpowiedz serwera.** Lista nazw przychodzi z sieci, a Sigelith Desktop jest
zainstalowany u ludzi i nie aktualizuje sie razem z serwerem. Musi wiec
przezyc odpowiedz zepsuta (blad wdrozenia), cudza (DNS, proxy, firmowa
inspekcja TLS) i zlosliwa: zbyt dluga, o zlych typach, z nazwa udajaca
znacznik HTML albo zlozona z samych znakow niewidocznych. Zadne z tego nie
ma prawa dotrzec do widgetu ani wywrocic okna.

**Termin waznosci kopii.** Zgoda ze strony (`apps/support/consent.py`:
APP_THANKS) obiecuje, ze wycofanie dziala w kazdej chwili. Kopia listy
trzymana dluzej niz dobe zamienialaby te obietnice w nieprawde — i to
wylacznie u osob, ktore juz sie wypisaly, czyli tam, gdzie nikt tego nie
sprawdza.

**Dwa klikniecia do impressum.** § 5 DDG wymaga, zeby impressum bylo
osiagalne bezposrednio. Pozycja schowana w oknie „O programie" to trzy
klikniecia; test pilnuje, ze droga przez menu Pomoc istnieje i prowadzi pod
STALY adres niemieckich stron, a nie pod serwer wpisany w Ustawieniach.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Musi byc ustawione PRZED pierwszym importem QtGui/QtWidgets.
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QThreadPool  # noqa: E402
from PySide6.QtGui import QAction  # noqa: E402
from PySide6.QtWidgets import QApplication, QMenu, QPushButton  # noqa: E402

from beatstamp import i18n, supporters  # noqa: E402
from beatstamp.api import ApiError  # noqa: E402
from beatstamp.config import (  # noqa: E402
    IMPRESSUM_URL,
    PRIVACY_POLICY_URL,
    Settings,
    privacy_policy_url,
)
from beatstamp.i18n import current_language  # noqa: E402

# Jezyk przypiety tak samo jak w `test_gui_smoke`: sprawdzamy ZNACZENIE
# napisu, a oczekiwany tekst bierzemy z tego samego katalogu, ktorego uzywa
# program.
i18n.set_language('pl')
_ = i18n.gettext

_app = QApplication.instance() or QApplication(sys.argv)


def answer(names=(), updated=None, version=1) -> dict:
    """Odpowiedz w ksztalcie `apps/support/views.SupportersThanksView`."""
    return {'v': version, 'updated': updated, 'names': list(names)}


class FakeClient:
    """Klient API bez sieci. Liczy wywolania i zapamietuje watek roboczy."""

    def __init__(self, *replies, error: Exception | None = None):
        self.replies = list(replies)
        self.error = error
        self.calls = 0
        self.threads: list[int] = []

    def supporters_thanks(self) -> dict:
        self.calls += 1
        self.threads.append(threading.get_ident())
        if self.error is not None:
            raise self.error
        if not self.replies:
            return answer()
        return self.replies[0] if len(self.replies) == 1 else self.replies.pop(0)


class DataDirMixin:
    """Katalog danych w katalogu tymczasowym — kopia listy nigdzie nie wycieka."""

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self._saved_dir = os.environ.get('SIGELITH_DATA_DIR')
        os.environ['SIGELITH_DATA_DIR'] = self._tmp.name

    def tearDown(self):
        if self._saved_dir is None:
            os.environ.pop('SIGELITH_DATA_DIR', None)
        else:
            os.environ['SIGELITH_DATA_DIR'] = self._saved_dir
        self._tmp.cleanup()
        super().tearDown()


class ThanksContractTests(unittest.TestCase):
    """Ksztalt odpowiedzi — lustro `apps/support/tests_desktop_contract.py`."""

    def test_todays_production_answer_is_accepted(self):
        """Dokladnie to, co oddaje dzis produkcja przy wylaczonej fladze."""
        data = supporters.parse({'v': 1, 'updated': None, 'names': []})
        self.assertEqual(data.names, ())
        self.assertEqual(data.updated, '')
        self.assertFalse(data.truncated)

    def test_names_keep_the_order_the_server_sent(self):
        data = supporters.parse(answer(['Anna', 'zed', 'Łukasz']))
        self.assertEqual(data.names, ('Anna', 'zed', 'Łukasz'))

    def test_updated_is_kept_when_it_is_a_real_moment(self):
        data = supporters.parse(answer(['Anna'], updated='2026-03-02T10:00:00+00:00'))
        self.assertEqual(data.updated, '2026-03-02T10:00:00+00:00')

    def test_extra_fields_are_ignored_not_fatal(self):
        """Dokladanie pol po stronie serwera jest wstecznie zgodne."""
        data = supporters.parse({'v': 1, 'updated': None, 'names': ['Anna'],
                                 'total': 7, 'etap': 2})
        self.assertEqual(data.names, ('Anna',))

    def test_the_path_is_the_one_the_server_publishes(self):
        from beatstamp.api import SUPPORTERS_THANKS_PATH
        self.assertEqual(SUPPORTERS_THANKS_PATH, '/api/supporters/thanks')


class HostileAnswerTests(unittest.TestCase):
    """Odpowiedz serwera to dane niezaufane."""

    def test_an_answer_that_is_not_an_object_is_refused(self):
        for payload in ([], 'Anna', None, 7, b'{}'):
            with self.subTest(payload=payload):
                with self.assertRaises(ApiError):
                    supporters.parse(payload)

    def test_a_newer_contract_version_is_refused_with_a_clear_message(self):
        with self.assertRaises(ApiError) as caught:
            supporters.parse(answer(['Anna'], version=2))
        self.assertIn('2', str(caught.exception))

    def test_version_of_the_wrong_type_is_refused(self):
        for version in ('1', True, None, 1.0):
            with self.subTest(version=version):
                with self.assertRaises(ApiError):
                    supporters.parse(answer(['Anna'], version=version))

    def test_names_that_are_not_a_list_are_refused(self):
        for names in ('Anna', {'a': 1}, 7, None):
            with self.subTest(names=names):
                with self.assertRaises(ApiError):
                    supporters.parse({'v': 1, 'updated': None, 'names': names})

    def test_items_that_are_not_strings_are_dropped(self):
        data = supporters.parse({'v': 1, 'updated': None,
                                 'names': [1, None, {'a': 1}, ['x'], 'Anna']})
        self.assertEqual(data.names, ('Anna',))

    def test_more_names_than_the_ceiling_are_cut(self):
        data = supporters.parse(answer([f'Osoba {n}'
                                        for n in range(supporters.MAX_NAMES + 120)]))
        self.assertEqual(len(data.names), supporters.MAX_NAMES)
        self.assertTrue(data.truncated)

    def test_a_very_long_name_is_shortened(self):
        data = supporters.parse(answer(['A' * 4000]))
        self.assertLessEqual(len(data.names[0]), supporters.MAX_NAME_LENGTH + 1)
        self.assertTrue(data.names[0].endswith('…'))

    def test_invisible_characters_never_make_a_name(self):
        """Zero-width i znaczniki kierunku tekstu: caly wiersz bylby pusty."""
        data = supporters.parse(answer(['​​‮', '﻿', 'Anna']))
        self.assertEqual(data.names, ('Anna',))

    def test_invisible_characters_are_stripped_from_a_real_name(self):
        data = supporters.parse(answer(['An​na‮']))
        self.assertEqual(data.names, ('Anna',))

    def test_a_line_break_does_not_glue_words_or_add_a_row(self):
        data = supporters.parse(answer(['Anna\nMaria\tNowak']))
        self.assertEqual(data.names, ('Anna Maria Nowak',))

    def test_zalgo_is_capped(self):
        zalgo = 'A' + '͑' * 60 + 'B'
        data = supporters.parse(answer([zalgo]))
        self.assertEqual(data.names[0], 'A' + '͑' * supporters.MAX_MARKS + 'B')

    def test_markup_in_a_name_stays_a_plain_character(self):
        """Nazwa nie jest odkazana z „<" — ma nie byc INTERPRETOWANA."""
        data = supporters.parse(answer(['<img src=x onerror=1>']))
        self.assertEqual(data.names, ('<img src=x onerror=1>',))

    def test_an_unreadable_updated_does_not_lose_the_names(self):
        data = supporters.parse(answer(['Anna'], updated='wczoraj wieczorem'))
        self.assertEqual(data.names, ('Anna',))
        self.assertEqual(data.updated, '')

    def test_updated_of_the_wrong_type_does_not_lose_the_names(self):
        for updated in (7, [], {'a': 1}, True):
            with self.subTest(updated=updated):
                self.assertEqual(supporters.parse(answer(['Anna'], updated)).names,
                                 ('Anna',))


class ThanksCacheTests(DataDirMixin, unittest.TestCase):
    """Kopia listy: przezywa restart, ale nie przezywa doby."""

    def _save(self, names, age_seconds: float = 0.0) -> supporters.ThanksList:
        data = supporters.ThanksList(names=tuple(names),
                                     fetched_at=time.time() - age_seconds)
        supporters.save_cache(data)
        return data

    def test_missing_cache_is_not_an_error(self):
        self.assertIsNone(supporters.load_cache())

    def test_cache_survives_a_restart(self):
        self._save(['Anna', 'Borys'])
        loaded = supporters.load_cache()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.names, ('Anna', 'Borys'))

    def test_cache_older_than_a_day_is_never_shown(self):
        """Wycofanie zgody ma znikac z aplikacji takze bez sieci."""
        self._save(['Anna'], age_seconds=supporters.CACHE_MAX_AGE_SECONDS + 60)
        self.assertIsNone(supporters.load_cache())

    def test_cache_older_than_an_hour_asks_for_a_refresh(self):
        self._save(['Anna'], age_seconds=supporters.CACHE_FRESH_SECONDS + 60)
        loaded = supporters.load_cache()
        self.assertTrue(loaded.stale)
        self.assertFalse(loaded.expired)

    def test_a_fresh_cache_does_not_ask_for_a_refresh(self):
        self._save(['Anna'])
        self.assertFalse(supporters.load_cache().stale)

    def test_cache_from_the_future_is_ignored(self):
        """Zegar cofniety po zapisie nie moze przedluzyc kopii w nieskonczonosc."""
        self._save(['Anna'], age_seconds=-30 * 24 * 3600)
        self.assertIsNone(supporters.load_cache())

    def test_a_damaged_cache_file_is_ignored(self):
        supporters.cache_path().write_text('{to nie jest json', encoding='utf-8')
        self.assertIsNone(supporters.load_cache())

    def test_a_cache_of_another_version_is_ignored(self):
        supporters.cache_path().write_text(
            json.dumps({'v': 99, 'fetched_at': time.time(), 'names': ['Anna']}),
            encoding='utf-8')
        self.assertIsNone(supporters.load_cache())

    def test_a_hostile_cache_file_is_cleaned_like_a_server_answer(self):
        """Plik lezy w katalogu uzytkownika — moze go zmienic cokolwiek."""
        supporters.cache_path().write_text(json.dumps({
            'v': supporters.CACHE_VERSION, 'fetched_at': time.time(),
            'names': ['B' * 900] + [f'x{n}' for n in range(supporters.MAX_NAMES + 50)],
        }), encoding='utf-8')
        loaded = supporters.load_cache()
        self.assertEqual(len(loaded.names), supporters.MAX_NAMES)
        self.assertLessEqual(len(loaded.names[0]), supporters.MAX_NAME_LENGTH + 1)

    def test_a_cache_with_broken_names_is_ignored(self):
        supporters.cache_path().write_text(
            json.dumps({'v': supporters.CACHE_VERSION, 'fetched_at': time.time(),
                        'names': 'Anna'}), encoding='utf-8')
        self.assertIsNone(supporters.load_cache())

    def test_forgetting_the_cache_leaves_no_file(self):
        self._save(['Anna'])
        supporters.forget_cache()
        self.assertFalse(supporters.cache_path().exists())
        self.assertIsNone(supporters.load_cache())


class ThanksDialogTests(DataDirMixin, unittest.TestCase):
    """Okno podziekowan: stany, watek roboczy i tekst ZWYKLY."""

    def setUp(self):
        super().setUp()
        self.pool = QThreadPool()
        self.pool.setMaxThreadCount(1)
        self.dialogs = []

    def tearDown(self):
        for dialog in self.dialogs:
            dialog.close()
            dialog.deleteLater()
        _app.processEvents()
        self.pool.clear()
        self.pool.waitForDone(5000)
        super().tearDown()

    def _open(self, client):
        from beatstamp.ui.dialogs import ThanksDialog
        dialog = ThanksDialog(client, self.pool)
        self.dialogs.append(dialog)
        return dialog

    def _settle(self):
        """Dowozi zadanie i jego sygnaly — bez uruchamiania modalnej petli."""
        for _unused in range(5):
            _app.processEvents()
        self.pool.waitForDone(5000)
        for _unused in range(10):
            _app.processEvents()

    def _items(self, dialog) -> list[str]:
        return [dialog.names.item(row).text() for row in range(dialog.names.count())]

    def test_names_from_the_server_are_shown(self):
        dialog = self._open(FakeClient(answer(['Anna', 'Borys'])))
        self._settle()
        self.assertEqual(self._items(dialog), ['Anna', 'Borys'])

    def test_the_download_never_runs_in_the_gui_thread(self):
        client = FakeClient(answer(['Anna']))
        self._open(client)
        self._settle()
        self.assertEqual(client.calls, 1)
        self.assertNotIn(threading.main_thread().ident, client.threads)

    def test_an_empty_list_is_named_instead_of_loading_forever(self):
        """Dzis to jest stan prawdziwy — flaga na serwerze jest wylaczona."""
        dialog = self._open(FakeClient(answer([])))
        self._settle()
        self.assertEqual(self._items(dialog), [])
        self.assertEqual(dialog.status.text(), _('Nobody is named here right now.'))
        self.assertNotIn(_('Loading the list…'), dialog.status.text())

    def test_no_network_shows_the_reason_and_leaves_the_window_usable(self):
        reason = _('No connection to sigelith.org. Check your internet access '
                   'and firewall settings.')
        dialog = self._open(FakeClient(error=ApiError(reason)))
        self._settle()
        self.assertIn(reason, dialog.status.text())
        self.assertTrue(dialog.refresh.isEnabled())

    def test_a_broken_answer_is_reported_and_never_reaches_the_list(self):
        dialog = self._open(FakeClient({'v': 1, 'names': 'Anna'}))
        self._settle()
        self.assertEqual(self._items(dialog), [])
        self.assertIn(_('The list of supporters came back in an unexpected '
                        'format.'), dialog.status.text())

    def test_a_hostile_answer_is_cut_before_it_reaches_the_window(self):
        dialog = self._open(FakeClient(answer(
            ['<b>%s</b>' % n for n in range(supporters.MAX_NAMES + 200)])))
        self._settle()
        self.assertEqual(dialog.names.count(), supporters.MAX_NAMES)

    def test_a_name_with_markup_stays_literal_text(self):
        dialog = self._open(FakeClient(answer(['<b>Anna</b>'])))
        self._settle()
        self.assertEqual(self._items(dialog), ['<b>Anna</b>'])

    def test_the_list_tooltip_is_never_parsed_as_markup(self):
        dialog = self._open(FakeClient(answer(['Anna'])))
        self.assertTrue(dialog.names.toolTip().startswith('<qt>'))

    def test_a_cached_list_is_visible_before_the_network_answers(self):
        supporters.save_cache(supporters.ThanksList(names=('Anna', 'Borys'),
                                                    fetched_at=time.time()))
        dialog = self._open(FakeClient(error=ApiError('brak sieci')))
        self.assertEqual(self._items(dialog), ['Anna', 'Borys'])

    def test_a_fresh_cache_saves_a_request(self):
        supporters.save_cache(supporters.ThanksList(names=('Anna',),
                                                    fetched_at=time.time()))
        client = FakeClient(answer(['Anna']))
        self._open(client)
        self._settle()
        self.assertEqual(client.calls, 0)

    def test_refresh_asks_the_server_even_with_a_fresh_cache(self):
        supporters.save_cache(supporters.ThanksList(names=('Anna',),
                                                    fetched_at=time.time()))
        client = FakeClient(answer(['Anna', 'Borys']))
        dialog = self._open(client)
        self._settle()
        dialog.refresh.click()
        self._settle()
        self.assertEqual(client.calls, 1)
        self.assertEqual(self._items(dialog), ['Anna', 'Borys'])

    def test_a_name_removed_on_the_server_disappears_from_the_window(self):
        supporters.save_cache(supporters.ThanksList(
            names=('Anna', 'Borys'),
            fetched_at=time.time() - supporters.CACHE_FRESH_SECONDS - 60))
        dialog = self._open(FakeClient(answer(['Anna'])))
        self._settle()
        self.assertEqual(self._items(dialog), ['Anna'])
        self.assertEqual(supporters.load_cache().names, ('Anna',))

    def test_an_error_keeps_the_cached_names_but_says_they_are_not_fresh(self):
        supporters.save_cache(supporters.ThanksList(
            names=('Anna',),
            fetched_at=time.time() - supporters.CACHE_FRESH_SECONDS - 60))
        dialog = self._open(FakeClient(error=ApiError('serwer milczy')))
        self._settle()
        self.assertEqual(self._items(dialog), ['Anna'])
        self.assertIn('serwer milczy', dialog.status.text())

    def test_a_download_that_never_ends_stops_pretending_to_load(self):
        """Pula ma jeden watek — zapytanie moze czekac za dlugim zadaniem."""
        dialog = self._open(FakeClient(answer(['Anna'])))
        dialog._loading = True
        dialog._on_timeout()
        self.assertFalse(dialog._loading)
        self.assertTrue(dialog.refresh.isEnabled())
        self.assertEqual(dialog.status.text(),
                         _('The list did not arrive in time. Please try again '
                           'in a moment.'))

    def test_the_watchdog_stops_once_the_list_has_arrived(self):
        """Spozniony strzal zegara nie moze zgasic stanu nastepnego zapytania."""
        dialog = self._open(FakeClient(answer(['Anna'])))
        self._settle()
        self.assertFalse(dialog._watchdog.isActive())
        self.assertFalse(dialog._loading)

    def test_the_window_says_what_the_thanks_is_and_what_it_is_not(self):
        """Copy musi zgadzac sie z `apps/support/consent.py`: APP_THANKS_NOTE."""
        from PySide6.QtWidgets import QLabel
        dialog = self._open(FakeClient(answer([])))
        texts = ' '.join(lbl.text() for lbl in dialog.findChildren(QLabel))
        self.assertIn(_('A thank-you at our discretion — not an entitlement '
                        'and not something a payment buys.'), texts)


class LegalDocumentsTests(unittest.TestCase):
    """§ 5 DDG: impressum i ochrona danych w najwyzej dwoch klikneciach."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls._saved = {name: os.environ.get(name)
                      for name in ('SIGELITH_DATA_DIR', 'LOCALAPPDATA')}
        os.environ['SIGELITH_DATA_DIR'] = cls._tmp.name
        os.environ['LOCALAPPDATA'] = cls._tmp.name
        (Path(cls._tmp.name) / '.tvs-zaimportowano').write_text('test')
        from beatstamp.ui.main_window import MainWindow
        cls.window = MainWindow(Settings(base_url='https://wlasny.example'))
        # Okno sluzy tu tylko do czytania menu. Flaga zamykania zdejmuje
        # odlozona synchronizacje zegara, zeby zaden test nie poszedl do sieci.
        cls.window._closing = True
        # Menu szukamy przez `findChildren` i TRZYMAMY referencje przez caly
        # czas zycia klasy. `QAction.menu()` w PySide6 oddaje wlasnosc obiektu
        # C++ zwroconemu opakowaniu Pythona: gdy opakowanie zginie (a przy
        # wywolaniu w wyrazeniu ginie od razu), menu jest KASOWANE i kazdy
        # kolejny odczyt konczy sie „Internal C++ object already deleted".
        cls.help_menu = next(
            menu for menu in cls.window.menuBar().findChildren(QMenu)
            if menu.menuAction().text() == _('Hel&p'))

    @classmethod
    def tearDownClass(cls):
        cls.window.close()
        _app.processEvents()
        cls.window.deleteLater()
        _app.processEvents()
        for name, value in cls._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        cls._tmp.cleanup()

    def _help_menu(self) -> QMenu:
        """Menu Pomoc — jedno klikniecie od paska menu okna glownego."""
        self.assertIn(_('Hel&p'),
                      [a.text() for a in self.window.menuBar().actions()])
        return self.help_menu

    def _action_for(self, url: str) -> QAction:
        matches = [a for a in self._help_menu().actions() if a.data() == url]
        self.assertEqual(len(matches), 1, f'pozycja menu dla {url}')
        return matches[0]

    def test_impressum_is_two_clicks_from_the_main_window(self):
        """Menu (1) -> pozycja (2). Przez „O programie" byloby trzy."""
        action = self._action_for(IMPRESSUM_URL)
        self.assertIn('Impressum', action.text())
        self.assertIn(IMPRESSUM_URL, action.toolTip())

    def _privacy_url(self) -> str:
        return privacy_policy_url(current_language())

    def test_the_privacy_policy_is_two_clicks_from_the_main_window(self):
        action = self._action_for(self._privacy_url())
        self.assertTrue(action.text())
        self.assertIn(self._privacy_url(), action.toolTip())

    def test_the_documents_point_at_the_german_originals(self):
        # sigelith.org i beattime.live to ta sama instancja i ten sam wydawca
        # (Adam Koch, Hagen) — od 3.0.0 program linkuje pod sigelith.org.
        self.assertEqual(IMPRESSUM_URL, 'https://sigelith.org/de/impressum/')
        self.assertEqual(PRIVACY_POLICY_URL, 'https://sigelith.org/de/datenschutz/')

    def test_the_privacy_policy_follows_the_interface_language(self):
        """Niemiecki interfejs — oryginal; kazdy inny — tlumaczenie angielskie
        (innych wersji tej strony nie ma, a angielska odsyla do oryginalu)."""
        self.assertEqual(privacy_policy_url('de'), PRIVACY_POLICY_URL)
        for language in ('en', 'pl', 'zh', 'ar', ''):
            with self.subTest(language=language):
                self.assertEqual(privacy_policy_url(language),
                                 'https://sigelith.org/privacy/')

    def test_the_links_do_not_follow_the_server_from_the_settings(self):
        """Wlasny serwer w Ustawieniach nie podmienia impressum wydawcy."""
        self.assertEqual(self.window.settings.base_url, 'https://wlasny.example')
        for url in (IMPRESSUM_URL, self._privacy_url()):
            self.assertNotIn('wlasny.example', self._action_for(url).data())

    def test_triggering_the_item_opens_the_browser_at_that_address(self):
        from beatstamp.ui import dialogs

        opened = []
        real = dialogs.QDesktopServices.openUrl
        dialogs.QDesktopServices.openUrl = staticmethod(
            lambda url: opened.append(url.toString()) or True)
        try:
            self._action_for(IMPRESSUM_URL).trigger()
            self._action_for(self._privacy_url()).trigger()
        finally:
            dialogs.QDesktopServices.openUrl = real
        self.assertEqual(opened, [IMPRESSUM_URL, self._privacy_url()])

    def test_the_about_dialog_repeats_both_documents(self):
        from beatstamp.ui.dialogs import AboutDialog

        dialog = AboutDialog(self.window)
        try:
            urls = {b.property('url') for b in dialog.findChildren(QPushButton)}
            self.assertIn(IMPRESSUM_URL, urls)
            self.assertIn(self._privacy_url(), urls)
        finally:
            dialog.deleteLater()

    def test_the_thanks_window_is_one_item_in_the_help_menu(self):
        from beatstamp.ui import main_window as mw

        opened = []

        class FakeThanks:
            def __init__(self, client, pool, parent=None):
                opened.append((client, pool))

            def exec(self):
                return 0

        matches = [a for a in self._help_menu().actions()
                   if a.text() == _('Thank you to the supporters…')]
        self.assertEqual(len(matches), 1)
        with mock.patch.object(mw, 'ThanksDialog', FakeThanks):
            matches[0].trigger()
        self.assertEqual(len(opened), 1)
        client, pool = opened[0]
        self.assertIs(client, self.window.client)
        self.assertIs(pool, self.window.pool, 'lista musi isc przez istniejaca pule')


if __name__ == '__main__':
    unittest.main(verbosity=2)
