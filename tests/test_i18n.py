"""
Warstwa tlumaczen: katalogi, liczba mnoga, wykrywanie jezyka, oznaczenie napisow.

Kazdy test tutaj odpowiada awarii, ktora przechodzi przez pozostale 263 testy
niezauwazona, bo wszystkie one dzialaja w JEDNYM jezyku:

* napis zapomniany w kodzie — u polskiego uzytkownika wyglada normalnie,
  u niemieckiego jest jedynym angielskim zdaniem w oknie;
* `%(nazwa)s` zgubione albo przekrecone w tlumaczeniu — `KeyError` dopiero
  w chwili, gdy ten konkretny komunikat sie pojawi;
* znacznik `<b>` rozjechany w tlumaczeniu — `QMessageBox` interpretuje tekst
  wzbogacony, wiec komunikat rozsypuje sie wizualnie;
* akcelerator `&` zgubiony przy tlumaczeniu menu — Alt+P przestaje dzialac;
* regula liczby mnogiej rozjechana z katalogiem — „12 wpisy" zamiast
  „12 wpisów", czyli dokladnie ta usterka, dla ktorej `plural.py` powstal;
* `.mo` niezgodne z `.po` — wydanie ze STARYM tlumaczeniem, bez zadnego sladu.
"""
from __future__ import annotations

import ast
import gettext as _gettext
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))

import po  # noqa: E402
from beatstamp import history, i18n, plural, proof  # noqa: E402
from beatstamp.ui import history_model  # noqa: E402

i18n.set_language('pl')
_ = i18n.gettext

LOCALE = ROOT / 'locale'
PACKAGE = ROOT / 'beatstamp'
POT = LOCALE / 'beatstamp.pot'

#: Nazwy jezykow, dla ktorych utrzymujemy plik `.po`.
CATALOGS = ('pl', 'de', 'es', 'fr', 'ru', 'tr', 'ja', 'ko', 'zh', 'ar')

#: Wszystkie jezyki, ktore aplikacja deklaruje — razem z angielskim, ktory
#: pliku nie ma i miec nie bedzie (`msgid` SA jego tlumaczeniem).
#: Kompletnosci calej trojki pilnuje `EveryLanguageIsCompleteTests`.
LANGUAGES = i18n.SUPPORTED

#: Katalog sprawdzany przez `test_polish_catalog_is_complete`. Historycznie
#: byl jedynym kompletnym; dzis kompletne sa oba, a test zostaje, bo nazywa
#: wprost jezyk, w ktorym program powstal.
COMPLETE = 'pl'

_PLACEHOLDER = re.compile(r'%\([a-z_]+\)s')
_TAG = re.compile(r'</?([a-z]+)[^>]*>')


def _catalog(language: str) -> list[po.Entry]:
    path = LOCALE / language / 'LC_MESSAGES' / 'beatstamp.po'
    return po.parse(path.read_text(encoding='utf-8'))


def _translated(entry: po.Entry) -> list[str]:
    """Formy z tlumaczeniem; pusta lista, gdy wpis jest nieprzetlumaczony."""
    return [s for s in entry.msgstr if s]


class CatalogShapeTests(unittest.TestCase):
    """Katalogi musza zgadzac sie z kodem i miedzy soba."""

    def test_pot_matches_the_code(self):
        """`.pot` to migawka kodu — nieaktualna znaczy, ze ktos zapomnial
        uruchomic ekstraktor, a nowy napis nie trafil do zadnego katalogu."""
        import extract_messages
        entries, problems = extract_messages.collect()
        self.assertEqual(problems, [], 'ekstraktor zgłosił problemy')
        self.assertEqual(
            sorted(e.key for e in entries),
            sorted(e.key for e in _parse_pot()),
            'locale/beatstamp.pot nieaktualny — uruchom '
            'tools/extract_messages.py --update')

    def test_every_language_has_every_message(self):
        expected = sorted(e.key for e in _parse_pot())
        for language in CATALOGS:
            with self.subTest(language=language):
                self.assertEqual(sorted(e.key for e in _catalog(language)
                                        if e.msgid), expected)

    def test_polish_catalog_is_complete(self):
        missing = [e.msgid for e in _catalog(COMPLETE)
                   if e.msgid and not e.translated]
        self.assertEqual(missing, [], f'brak tłumaczenia: {missing[:5]}')

    def test_no_fuzzy_entry_reaches_a_release(self):
        """`fuzzy` to tlumaczenie NIEZWERYFIKOWANE. Kompilator je pomija, wiec
        w gotowym programie zamienia sie w cichy powrot do angielskiego."""
        for language in CATALOGS:
            fuzzy = [e.msgid for e in _catalog(language) if e.msgid and e.fuzzy]
            self.assertEqual(fuzzy, [], f'{language}: {fuzzy[:5]}')


class CatalogContentTests(unittest.TestCase):
    """Tresc tlumaczen: wartosci, znaczniki, slowa zakazane."""

    def test_placeholders_are_preserved(self):
        """Zgubione `%(nazwa)s` to `KeyError` w chwili, gdy komunikat sie pojawi
        — czyli zwykle u uzytkownika, przy bledzie, ktory wlasnie zglasza."""
        for language in CATALOGS:
            for entry in _catalog(language):
                for form in _translated(entry):
                    with self.subTest(language=language, msgid=entry.msgid[:40]):
                        self.assertEqual(
                            sorted(_PLACEHOLDER.findall(entry.msgid)),
                            sorted(_PLACEHOLDER.findall(form)))

    def test_markup_is_preserved(self):
        """39 napisow niesie `<b>`/`<br>`/`<i>`, a `QMessageBox` i etykiety Qt
        interpretuja tekst wzbogacony. Znacznik zgubiony albo dopisany przez
        tlumacza rozsypuje komunikat — i nikt tego nie widzi w jezyku zrodlowym."""
        for language in CATALOGS:
            for entry in _catalog(language):
                for form in _translated(entry):
                    with self.subTest(language=language, msgid=entry.msgid[:40]):
                        self.assertEqual(sorted(_TAG.findall(entry.msgid)),
                                         sorted(_TAG.findall(form)))

    def test_no_forbidden_words(self):
        """Reguła copy projektu: żadnego słowa sugerującego darowiznę i żadnego
        „beta". Ten sam zakaz pilnuje `apps/support/tests.py` po stronie
        serwera — tu obejmuje warstwę, której tamten test nie widzi."""
        forbidden = ('beta', 'donat', 'spende', 'darowizn')
        for language in CATALOGS:
            for entry in _catalog(language):
                for form in _translated(entry):
                    lowered = form.lower()
                    for word in forbidden:
                        with self.subTest(word=word, msgid=entry.msgid[:40]):
                            self.assertNotIn(word, lowered)

    def test_menu_accelerators_are_unique_per_language(self):
        """`&` jest czescia tlumaczenia. W obrebie paska menu kazda litera
        akceleratora musi byc inna, inaczej Alt+X otwiera raz jedno, raz drugie."""
        menus = ('&File', '&Tools', 'Hel&p')
        for language in CATALOGS:
            translations = {e.msgid: e.msgstr[0] for e in _catalog(language)
                            if e.msgid in menus and e.translated}
            if not translations:
                continue                 # katalog jeszcze nieprzetlumaczony
            letters = []
            for msgid in menus:
                text = translations.get(msgid, msgid)
                self.assertIn('&', text, f'{language}: {msgid} bez akceleratora')
                letters.append(text[text.index('&') + 1].lower())
            self.assertEqual(len(set(letters)), len(letters),
                             f'{language}: powtórzona litera {letters}')


class EveryLanguageIsCompleteTests(unittest.TestCase):
    """Zaden napis nie zostal bez tlumaczenia w ZADNYM z trzech jezykow.

    Brak tlumaczenia nie objawia sie awaria: `gettext` po cichu zwraca
    `msgid`, wiec u niemieckiego uzytkownika pojawia sie jedno angielskie
    zdanie posrod niemieckich — i nikt tego nie zglasza. Dopoki katalog byl
    jeden, pilnowal tego `test_polish_catalog_is_complete`. Przy trzech
    jezykach potrzebne jest jedno miejsce, ktore wymienia je wszystkie, bo
    inaczej kazdy nowy jezyk trzeba pamietac o dopisaniu do testu.

    Kazdy jezyk jest sprawdzany po JEGO wlasnej regule:

    * `pl` i `de` maja plik `.po` — kazdy wpis musi miec kazda forme
      wypelniona i zadnego `fuzzy` (kompilator pomija `fuzzy`, wiec w
      gotowym programie tlumaczenie niezweryfikowane zamienia sie w ciche
      zdanie po angielsku);
    * `en` pliku NIE MA — `msgid` sa jego tlumaczeniem. Kompletny jest
      wtedy, gdy kazdy `msgid` naprawde jest gotowym napisem po angielsku,
      a nie fragmentem zostawionym po polsku albo niemiecku, ktory przy
      jezyku zrodlowym trafilby na ekran bez zmiany.

    Sprawdzamy `.po` (zrodlo) ORAZ `.mo` wczytany tak, jak wczytuje go
    program: plik skompilowany moze zgubic wpis, ktorego zrodlo ma — a to
    jest dokladnie ta awaria, ktorej nie widac w zadnym innym tescie.
    """

    #: Znaki spoza ASCII dopuszczalne w `msgid`. Angielski nie potrzebuje
    #: zadnej litery z diakrytykiem — tylko typografii, ktora jest w calym
    #: serwisie: pauza, kropka srodkowa i wielokropek.
    TYPOGRAPHY = frozenset('—·…✓')

    def test_every_catalog_translates_every_message(self):
        for language in CATALOGS:
            missing = [e.msgid for e in _catalog(language)
                       if e.msgid and not e.translated]
            with self.subTest(language=language):
                self.assertEqual(missing, [],
                                 f'{language}: {len(missing)} bez tlumaczenia, '
                                 f'np. {missing[:3]}')

    def test_no_catalog_hides_a_translation_behind_fuzzy(self):
        for language in CATALOGS:
            fuzzy = [e.msgid for e in _catalog(language)
                     if e.msgid and e.fuzzy]
            with self.subTest(language=language):
                self.assertEqual(fuzzy, [], f'{language}: {fuzzy[:3]}')

    def test_compiled_catalog_carries_every_message(self):
        """`.po` kompletny, `.mo` niekompletny — po stronie uzytkownika
        wyglada tak samo jak brak tlumaczenia, a w repozytorium nie widac
        niczego podejrzanego."""
        for language in CATALOGS:
            translation = _gettext.translation(
                i18n.DOMAIN, localedir=str(LOCALE), languages=[language])
            forms = int(po.header_fields(_catalog(language))['Plural-Forms']
                        .split('nplurals=')[1].split(';')[0])
            missing = []
            for entry in _parse_pot():
                if entry.msgid_plural:
                    missing += [(entry.msgid, index)
                                for index in range(forms)
                                if not translation._catalog.get(
                                    (entry.msgid, index))]
                elif not translation._catalog.get(entry.msgid):
                    missing.append(entry.msgid)
            with self.subTest(language=language):
                self.assertEqual(missing, [],
                                 f'{language}: brak w .mo — uruchom '
                                 'tools/compile_catalogs.py')

    def test_the_source_language_has_no_catalog_of_its_own(self):
        """Gdyby `locale/en/` powstal, byloby dwoch zrodel prawdy dla tego
        samego tekstu i kazda zmiana napisu w kodzie cicho rozjechalaby sie
        z jednym z nich."""
        self.assertFalse((LOCALE / i18n.SOURCE_LANGUAGE).exists())
        self.assertIn(i18n.SOURCE_LANGUAGE, i18n.available_languages())

    def test_every_msgid_is_finished_english(self):
        """`msgid` JEST tlumaczeniem angielskim — wiec musi nim byc naprawde.

        Napis zostawiony w kodzie po polsku („Zapisano %(name)s.") przejdzie
        przez oba katalogi, bo tlumacz go przetlumaczy — a u angielskiego
        uzytkownika zostanie po polsku. Litera z diakrytykiem jest jedynym
        sygnalem, ktory to lapie wczesniej niz zgloszenie uzytkownika.
        """
        offenders = []
        for entry in _parse_pot():
            for text in (entry.msgid, entry.msgid_plural):
                strange = {ch for ch in text
                           if ord(ch) > 127 and ch not in self.TYPOGRAPHY}
                if strange:
                    offenders.append((sorted(strange), text[:60]))
                elif text is entry.msgid and not text.strip():
                    offenders.append(([], text))
        self.assertEqual(offenders, [], f'msgid nie po angielsku: {offenders[:3]}')

    def test_english_shows_the_msgid_for_every_message(self):
        """Angielski nie ma katalogu, wiec „kompletny" znaczy: kazdy napis
        wraca w calosci, z wlasciwa forma liczby mnogiej."""
        i18n.set_language('en')
        try:
            for entry in _parse_pot():
                with self.subTest(msgid=entry.msgid[:40]):
                    if entry.msgid_plural:
                        self.assertEqual(i18n.ngettext(
                            entry.msgid, entry.msgid_plural, 1), entry.msgid)
                        self.assertEqual(i18n.ngettext(
                            entry.msgid, entry.msgid_plural, 2),
                            entry.msgid_plural)
                    else:
                        self.assertEqual(i18n.gettext(entry.msgid), entry.msgid)
                    self.assertTrue(i18n.gettext(entry.msgid).strip())
        finally:
            i18n.set_language('pl')

    def test_every_declared_language_is_really_usable(self):
        """Lista w Ustawieniach musi pokrywac sie z tym, co da sie wczytac —
        pozycja bez katalogu przelaczalaby program po cichu na angielski."""
        self.assertEqual(sorted(LANGUAGES), sorted(i18n.available_languages()))
        for language in LANGUAGES:
            with self.subTest(language=language):
                self.assertEqual(i18n.set_language(language), language)
        i18n.set_language('pl')


class CompiledCatalogTests(unittest.TestCase):
    """`.mo` sa commitowane — musza wiec odpowiadac `.po` w tym samym commicie."""

    def test_mo_matches_po(self):
        import compile_catalogs
        for language in CATALOGS:
            directory = LOCALE / language / 'LC_MESSAGES'
            expected = compile_catalogs.generate_mo(
                compile_catalogs.to_messages(_catalog(language)))
            with self.subTest(language=language):
                self.assertEqual(
                    (directory / 'beatstamp.mo').read_bytes(), expected,
                    f'{language}: .mo nie odpowiada .po — uruchom '
                    'tools/compile_catalogs.py')

    def test_runtime_reads_the_compiled_catalog(self):
        self.assertEqual(proof.Level.RECORDED.label, 'Zarejestrowany')
        self.assertEqual(proof.Level.ANCHORED.label, 'Zakotwiczony')


class PluralRuleTests(unittest.TestCase):
    """Regula z naglowka `.po` musi byc TA SAMA, ktora opisuje `plural.py`."""

    def test_catalog_rule_matches_the_polish_rule(self):
        header = po.header_fields(_catalog('pl'))
        rule = header.get('Plural-Forms', '')
        self.assertIn('nplurals=3', rule, 'polski ma trzy formy')
        select = _gettext.c2py(rule.split('plural=')[1].rstrip(';').strip())
        for number in range(0, 301):
            with self.subTest(number=number):
                self.assertEqual(select(number),
                                 plural.polish_plural_index(number))

    def test_forms_come_from_the_catalog(self):
        self.assertEqual(plural.entries(1), '1 wpis')
        self.assertEqual(plural.entries(3), '3 wpisy')
        self.assertEqual(plural.entries(12), '12 wpisów')

    def test_english_falls_back_to_two_forms(self):
        i18n.set_language('en')
        try:
            self.assertEqual(plural.entries(1), '1 entry')
            self.assertEqual(plural.entries(2), '2 entries')
            self.assertEqual(plural.files(12), '12 files')
        finally:
            i18n.set_language('pl')

    def test_every_plural_entry_has_all_forms(self):
        header = po.header_fields(_catalog('pl'))
        count = int(header['Plural-Forms'].split('nplurals=')[1].split(';')[0])
        for entry in _catalog('pl'):
            if entry.msgid_plural:
                with self.subTest(msgid=entry.msgid):
                    self.assertEqual(len(entry.msgstr), count)
                    self.assertTrue(all(entry.msgstr))


class LanguageResolutionTests(unittest.TestCase):
    """Wybor jezyka: ustawienie, zmienna srodowiskowa, system."""

    def setUp(self):
        self._saved = os.environ.get(i18n.LANGUAGE_ENV)
        os.environ.pop(i18n.LANGUAGE_ENV, None)

    def tearDown(self):
        if self._saved is None:
            os.environ.pop(i18n.LANGUAGE_ENV, None)
        else:
            os.environ[i18n.LANGUAGE_ENV] = self._saved
        i18n.set_language('pl')

    def test_explicit_choice_wins_over_everything(self):
        os.environ[i18n.LANGUAGE_ENV] = 'de'
        self.assertEqual(i18n.resolve('pl'), 'pl')

    def test_environment_wins_over_the_system(self):
        os.environ[i18n.LANGUAGE_ENV] = 'de'
        self.assertEqual(i18n.resolve('auto'), 'de')

    def test_unknown_code_falls_back_to_the_source_language(self):
        """Recznie zepsuty `settings.json` nie moze wywrocic startu programu."""
        for bad in ('klingon', 'PL-pl-x', '', '   '):
            with self.subTest(value=bad):
                self.assertIn(i18n.resolve(bad), i18n.available_languages())

    def test_available_languages_need_a_compiled_catalog(self):
        available = i18n.available_languages()
        self.assertIn('en', available, 'jezyk zrodlowy nie potrzebuje pliku')
        self.assertIn('pl', available)
        for code in available:
            self.assertIn(code, i18n.SUPPORTED)

    def test_system_languages_are_bare_codes(self):
        for code in i18n.system_languages():
            self.assertRegex(code, r'^[a-z]{2,3}$')

    @unittest.skipUnless(sys.platform == 'win32', 'API tylko dla Windows')
    def test_windows_reports_interface_languages_not_regional_format(self):
        """NIE `QLocale.system()` ani `locale.getlocale()`.

        Oba zwracaja FORMAT REGIONALNY. Na maszynie deweloperskiej tego
        projektu daja `de_DE`, mimo ze jezykiem interfejsu jest polski —
        naiwne wykrycie uruchomiloby program po niemiecku u polskiego
        uzytkownika i zaden test tego nie zauwazyl.
        """
        ui = i18n._windows_ui_languages()
        self.assertTrue(ui, 'GetUserPreferredUILanguages nic nie zwrocilo')
        for tag in ui:
            self.assertRegex(tag, r'^[A-Za-z]{2,3}(-[A-Za-z0-9]+)*$')

    def test_switching_language_changes_the_texts(self):
        self.assertEqual(i18n.set_language('en'), 'en')
        try:
            self.assertEqual(proof.Level.RECORDED.label, 'Recorded')
        finally:
            i18n.set_language('pl')
        self.assertEqual(proof.Level.RECORDED.label, 'Zarejestrowany')


class LazyStringTests(unittest.TestCase):
    """Napisy liczone W CZASIE IMPORTU zamrozilyby jezyk sprzed ustawien.

    Ustawienia wczytujemy PO pierwszym imporcie modulow, wiec kazda tablica
    napisow na poziomie modulu pokazywalaby jezyk domyslny bez wzgledu na
    wybor uzytkownika — i to wylacznie w gotowym programie, nigdy w testach,
    ktore jezyk ustawiaja pierwsze.
    """

    def _both_languages(self, produce):
        i18n.set_language('en')
        try:
            english = produce()
        finally:
            i18n.set_language('pl')
        return english, produce()

    def test_level_labels_follow_the_language(self):
        english, polish = self._both_languages(
            lambda: [level.label for level in proof.Level])
        self.assertNotEqual(english, polish)

    def test_level_descriptions_follow_the_language(self):
        english, polish = self._both_languages(
            lambda: proof.Level.ANCHORED.description)
        self.assertNotEqual(english, polish)

    def test_history_table_headers_follow_the_language(self):
        english, polish = self._both_languages(
            lambda: [name for name, _tip in history_model.headers()])
        self.assertNotEqual(english, polish)
        self.assertEqual(len(polish), history_model.COLUMN_COUNT)

    def test_csv_headers_follow_the_language(self):
        english, polish = self._both_languages(history.History.csv_headers)
        self.assertNotEqual(english, polish)
        self.assertEqual(len(polish), len(history.History.CSV_FIELDS))

    def test_formats_follow_the_language(self):
        self.assertEqual(i18n.decimal_separator('pl'), ',')
        self.assertEqual(i18n.decimal_separator('en'), '.')
        self.assertEqual(i18n.format_iso_date('2026-09-21'), '21.09.2026')


class MarkedStringTests(unittest.TestCase):
    """Czy w kodzie nie zostal napis widoczny dla uzytkownika, ale nieoznaczony.

    Sprawdzamy po znakach diakrytycznych: napis po polsku, ktory NIE jest ani
    komunikatem dziennika, ani komentarzem, jest napisem zapomnianym przy
    przenoszeniu tekstow do katalogu. Dziennik zostaje po polsku swiadomie —
    czyta go autor programu przy zgloszeniu bledu, nie uzytkownik.
    """

    POLISH = re.compile(r'[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]')

    #: Metody, po ktorych poznajemy wywolanie dziennika — niezaleznie od tego,
    #: czy rejestrator siedzi w zmiennej `log`, czy powstaje w miejscu
    #: (`logging.getLogger('beatstamp').critical(...)`).
    LOG_METHODS = frozenset({'debug', 'info', 'warning', 'error',
                             'critical', 'exception', 'log'})

    @classmethod
    def _log_call(cls, node: ast.Call) -> bool:
        func = node.func
        return isinstance(func, ast.Attribute) and func.attr in cls.LOG_METHODS

    def test_no_unmarked_polish_string_is_left_in_the_code(self):
        offenders = []
        for path in sorted(PACKAGE.rglob('*.py')):
            if '__pycache__' in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            skip = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                    skip.add(id(node.value))          # docstring
                elif isinstance(node, ast.Call) and self._log_call(node):
                    for arg in node.args:
                        skip.add(id(arg))             # komunikat dziennika
            for node in ast.walk(tree):
                if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                        and id(node) not in skip and self.POLISH.search(node.value)):
                    offenders.append(
                        f'{path.relative_to(ROOT).as_posix()}:{node.lineno}: '
                        f'{node.value[:60]!r}')
        self.assertEqual(offenders, [], 'napisy poza katalogiem tłumaczeń: '
                                        f'{offenders}')

    def test_gettext_name_is_never_shadowed(self):
        """`path, _ = QFileDialog...` w tej samej funkcji, co `_('…')`.

        To nie jest czystosc stylu, tylko awaria: przypisanie do `_` w ciele
        funkcji czyni te nazwe LOKALNA dla calej funkcji, wiec wczesniejsze
        `_('Wybierz plik')` w tym samym wywolaniu konczy sie
        `UnboundLocalError`. Wzorzec „odrzuc drugi wynik do `_`" jest tak
        powszechny, ze wroci przy pierwszej nowej funkcji z `QFileDialog` —
        a zaden istniejacy test go nie widzi, bo trzeba OTWORZYC okno pliku.
        """
        offenders = []
        for path in sorted(PACKAGE.rglob('*.py')):
            if '__pycache__' in path.parts:
                continue
            source = path.read_text(encoding='utf-8')
            tree = ast.parse(source, filename=str(path))
            imports_gettext = any(
                isinstance(node, ast.ImportFrom)
                and any(alias.asname == '_' or alias.name == '_'
                        for alias in node.names)
                for node in ast.walk(tree))
            if not imports_gettext:
                continue
            for node in ast.walk(tree):
                targets = []
                if isinstance(node, (ast.Assign, ast.For, ast.comprehension)):
                    targets = (node.targets if isinstance(node, ast.Assign)
                               else [node.target])
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                    targets = [node.target]
                elif isinstance(node, ast.withitem) and node.optional_vars:
                    targets = [node.optional_vars]
                for target in targets:
                    for name in ast.walk(target):
                        if isinstance(name, ast.Name) and name.id == '_':
                            offenders.append(
                                f'{path.relative_to(ROOT).as_posix()}:'
                                f'{name.lineno}')
        self.assertEqual(offenders, [], 'nazwa `_` przesłonięta: ' + str(offenders))

    def test_extractor_rejects_an_f_string(self):
        """Najdrozsza klasa bledow w tej warstwie: wpis wyglada poprawnie,
        a w czasie dzialania nigdy sie nie dopasuje, bo f-string jest sklejany
        PRZED wywolaniem funkcji tlumaczacej."""
        import extract_messages
        collector = extract_messages.Collector(PACKAGE / 'przyklad.py')
        collector.visit(ast.parse("x = 1\n_(f'Zapisano {x}.')\n"))
        self.assertTrue(collector.problems)
        self.assertIn('f-string', collector.problems[0])
        self.assertEqual(collector.found, [])


class SettingsTests(unittest.TestCase):
    """Wybor jezyka jest zwyklym ustawieniem — musi przezyc zapis i odczyt."""

    def setUp(self):
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        self._tmp = tempfile.TemporaryDirectory()
        self._saved = os.environ.get('SIGELITH_DATA_DIR')
        os.environ['SIGELITH_DATA_DIR'] = self._tmp.name

    def tearDown(self):
        if self._saved is None:
            os.environ.pop('SIGELITH_DATA_DIR', None)
        else:
            os.environ['SIGELITH_DATA_DIR'] = self._saved
        self._tmp.cleanup()

    def test_language_survives_save_and_load(self):
        from beatstamp.config import Settings
        Settings(language='de').save()
        self.assertEqual(Settings.load().language, 'de')

    def test_default_is_the_system_language(self):
        from beatstamp.config import Settings
        self.assertEqual(Settings().language, i18n.AUTO)

    def test_broken_value_does_not_break_the_start(self):
        """`settings.json` to zwykly tekst w katalogu uzytkownika."""
        from beatstamp.config import Settings, settings_path
        settings_path().write_text('{"language": 7}', encoding='utf-8')
        loaded = Settings.load()
        self.assertEqual(loaded.language, '7')
        self.assertIn(i18n.resolve(loaded.language), i18n.available_languages())

    def test_settings_dialog_carries_the_choice(self):
        from PySide6.QtWidgets import QApplication
        from beatstamp.config import Settings
        from beatstamp.ui.dialogs import SettingsDialog
        app = QApplication.instance() or QApplication([])
        dialog = SettingsDialog(Settings(language='en'))
        try:
            self.assertEqual(dialog.language.currentData(), 'en')
            self.assertTrue(dialog.language.toolTip())
            index = dialog.language.findData('de')
            self.assertGreaterEqual(index, 0, 'niemiecki musi byc na liscie')
            dialog.language.setCurrentIndex(index)
            self.assertEqual(dialog.result_settings().language, 'de')
        finally:
            dialog.deleteLater()
            app.processEvents()


class PackagingTests(unittest.TestCase):
    """Katalogi musza trafic do gotowego `.exe`.

    Inaczej wersja skompilowana startuje po angielsku niezaleznie od ustawien
    — awaria niewidoczna w testach, bo one dzialaja na kodzie zrodlowym,
    gdzie `locale/` lezy obok pakietu.
    """

    def test_spec_bundles_the_catalogs(self):
        spec = (ROOT / 'beatstamp.spec').read_text(encoding='utf-8')
        self.assertIn("rglob('*.mo')", spec)
        self.assertIn('locale', spec)

    def test_resource_path_finds_the_locale_directory(self):
        from beatstamp.config import resource_path
        self.assertTrue((resource_path('locale') / 'pl' / 'LC_MESSAGES'
                         / 'beatstamp.mo').is_file())


def _parse_pot() -> list[po.Entry]:
    return [e for e in po.parse(POT.read_text(encoding='utf-8')) if e.msgid]


if __name__ == '__main__':
    unittest.main(verbosity=2)
