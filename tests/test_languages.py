"""
Jedenascie jezykow — te same co strona (sigelith.org / beattime.live) i aplikacja mobilna.

`test_i18n.py` pilnuje KATALOGOW (kompletnosc, znaczniki, liczba mnoga).
Tutaj jest to, co z jezykiem dzieje sie POZA katalogiem i czego tamte testy
nie widza:

* lista jezykow rozjezdza sie z paczka MSIX, ze strona albo z aplikacja
  mobilna — Sklep pokazuje jezyk, ktorego program nie ma, albo odwrotnie;
* chwilowa zmiana jezyka na potrzeby certyfikatu przecieka do watkow
  roboczych;
* certyfikat drukuje znaki, ktorych nie ma jego czcionka — czytnik PDF
  pokazuje w ich miejscu NIC, wiec zdanie gubi slowa bez zadnego sladu;
* po arabsku okno jest odbite, ale widgety rysowane recznie nie.
"""
from __future__ import annotations

import os
import re
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

import extract_messages  # noqa: E402
import po  # noqa: E402
from beatstamp import certificate, config, fonts, i18n  # noqa: E402
from beatstamp.history import Entry  # noqa: E402
from beatstamp.ui import theme  # noqa: E402
from beatstamp.ui.widgets import (  # noqa: E402
    STEP_DONE, STEP_PENDING, JourneyStep, ProofJourney, StatusBadge)

_app = QApplication.instance() or QApplication(sys.argv)
theme.apply_theme(_app, 'light')

LOCALE = ROOT / 'locale'

#: Kod jezyka aplikacji -> jezyk w manifescie MSIX.
MSIX = {'en': 'en-US', 'pl': 'pl-PL', 'de': 'de-DE', 'es': 'es-ES', 'fr': 'fr-FR',
        'ru': 'ru-RU', 'tr': 'tr-TR', 'ja': 'ja-JP', 'ko': 'ko-KR', 'zh': 'zh-CN',
        'ar': 'ar-SA'}


def _catalog(language: str) -> list[po.Entry]:
    path = LOCALE / language / 'LC_MESSAGES' / 'beatstamp.po'
    return po.parse(path.read_text(encoding='utf-8'))


class LanguageListTests(unittest.TestCase):
    """Jedna lista jezykow — w kodzie, w paczce i w calym BeatTime."""

    def test_every_language_has_a_name_and_formats(self):
        for code in i18n.SUPPORTED:
            with self.subTest(language=code):
                self.assertIn(code, i18n.LANGUAGE_NAMES)
                self.assertIn(code, i18n._FORMATS)

    def test_extractor_knows_every_catalog_and_its_plural_rule(self):
        expected = {c for c in i18n.SUPPORTED if c != i18n.SOURCE_LANGUAGE}
        self.assertEqual(set(extract_messages.CATALOGS), expected)
        for code in expected:
            with self.subTest(language=code):
                header = po.header_fields(_catalog(code))
                self.assertEqual(header.get('Plural-Forms'),
                                 extract_messages.PLURAL_FORMS[code])

    def test_msix_manifest_declares_exactly_these_languages(self):
        text = (ROOT / 'packaging' / 'AppxManifest.xml').read_text(encoding='utf-8')
        declared = re.findall(r'<Resource Language="([^"]+)"', text)
        self.assertEqual(declared[0], 'en-US', 'pierwszy wpis = jezyk domyslny paczki')
        self.assertEqual(sorted(declared), sorted(MSIX[c] for c in i18n.SUPPORTED))

    def test_msix_resource_index_uses_the_same_languages(self):
        text = (ROOT / 'packaging' / 'build_msix.ps1').read_text(encoding='utf-8')
        match = re.search(r"/dq '([^']+)'", text)
        self.assertIsNotNone(match)
        self.assertEqual(sorted(match.group(1).split('_')),
                         sorted(MSIX[c] for c in i18n.SUPPORTED))

    @unittest.skipUnless((REPO / 'mobile' / 'lib' / 'l10n').is_dir(),
                         'poza monorepo BeatTime (repozytorium publiczne)')
    def test_same_languages_as_the_mobile_app(self):
        mobile = {p.stem.removeprefix('app_')
                  for p in (REPO / 'mobile' / 'lib' / 'l10n').glob('app_*.arb')}
        self.assertEqual(mobile, set(i18n.SUPPORTED))

    @unittest.skipUnless((REPO / 'config' / 'settings.py').is_file(),
                         'poza monorepo BeatTime (repozytorium publiczne)')
    def test_same_languages_as_the_website(self):
        text = (REPO / 'config' / 'settings.py').read_text(encoding='utf-8')
        block = text[text.index('\nLANGUAGES = ['):]
        block = block[:block.index(']')]
        site = set(re.findall(r"\('([a-z-]+)',", block))
        app = {config.SITE_LANGUAGE_PREFIX.get(c, c) for c in i18n.SUPPORTED}
        self.assertEqual(site, app)

    def test_help_links_use_the_site_prefix_for_chinese(self):
        self.assertEqual(config.site_url('proof', 'zh'), 'https://sigelith.org/zh-hans/proof/')
        self.assertEqual(config.site_url('proof', 'ar'), 'https://sigelith.org/ar/proof/')
        # Manifest ma tylko PL i EN — reszta dostaje angielski oryginal.
        self.assertEqual(config.site_url('manifesto', 'ja'), 'https://sigelith.org/manifesto/')

    def test_windows_chinese_maps_to_the_simplified_catalog(self):
        original = i18n._windows_ui_languages
        try:
            i18n._windows_ui_languages = lambda: ['zh-Hans-CN', 'en-US']
            if sys.platform == 'win32':
                self.assertEqual(i18n.system_languages()[0], 'zh')
                self.assertEqual(i18n.resolve(i18n.AUTO), 'zh')
        finally:
            i18n._windows_ui_languages = original


class FallbackFileNameTests(unittest.TestCase):
    """Awaryjne nazwy plikow sa tlumaczone, ale zostaja w ASCII.

    Nazwa pliku wedruje miedzy systemami plikow, archiwami ZIP i poczta —
    tam, gdzie kodowanie znakow bywa zgadywane. Po japonsku czy arabsku
    zostaje wiec angielska nazwa, a nie jej zapis w pismie jezyka.
    """

    FILE_NAMES = ('certificate', 'proof', 'sigelith-history.csv')

    def test_fallback_file_names_are_plain_ascii(self):
        safe = re.compile(r'^[A-Za-z0-9._-]+$')
        for code in extract_messages.CATALOGS:
            for entry in _catalog(code):
                if entry.msgid in self.FILE_NAMES:
                    with self.subTest(language=code, msgid=entry.msgid):
                        self.assertRegex(entry.msgstr[0], safe)


class TemporaryLanguageTests(unittest.TestCase):

    def tearDown(self):
        i18n.set_language('pl')

    def test_switch_is_local_to_the_thread(self):
        i18n.set_language('pl')
        seen = {}
        started = threading.Event()
        release = threading.Event()

        def worker():
            started.set()
            release.wait(5)
            seen['text'] = i18n.gettext('Copy')
            seen['language'] = i18n.current_language()

        thread = threading.Thread(target=worker)
        with i18n.temporary('en'):
            thread.start()
            started.wait(5)
            self.assertEqual(i18n.current_language(), 'en')
            self.assertEqual(i18n.gettext('Copy'), 'Copy')
            release.set()
            thread.join(5)
        self.assertEqual(seen, {'text': 'Kopiuj', 'language': 'pl'})
        self.assertEqual(i18n.current_language(), 'pl')
        self.assertEqual(i18n.gettext('Copy'), 'Kopiuj')

    def test_switch_is_undone_after_an_error(self):
        i18n.set_language('de')
        with self.assertRaises(RuntimeError):
            with i18n.temporary('en'):
                raise RuntimeError('x')
        self.assertEqual(i18n.current_language(), 'de')

    def test_right_to_left_is_only_arabic(self):
        self.assertEqual({c for c in i18n.SUPPORTED if i18n.is_rtl(c)}, {'ar'})


def _certificate_strings(language: str) -> list[str]:
    """Tlumaczenia napisow, ktore trafiaja do certyfikatu PDF."""
    out = []
    for entry in _catalog(language):
        if not entry.msgid:
            continue
        if any(ref.startswith(('beatstamp/certificate.py', 'beatstamp/plural.py'))
               for ref in entry.references):
            out.extend(s for s in entry.msgstr if s)
    return out


def _missing(texts: list[str], chars) -> list[str]:
    return sorted({ch for text in texts for ch in text
                   if not ch.isspace() and ord(ch) not in chars})


class CertificateLanguageTests(unittest.TestCase):

    def tearDown(self):
        i18n.set_language('pl')

    def test_latin_and_cyrillic_languages_keep_their_language(self):
        for code in certificate.PDF_LANGUAGES:
            self.assertEqual(certificate.certificate_language(code), code)

    def test_arabic_falls_back_to_english(self):
        self.assertEqual(certificate.certificate_language('ar'), 'en')

    def test_cjk_needs_the_system_font(self):
        for code in certificate.CJK_LANGUAGES:
            with self.subTest(language=code):
                expected = code if fonts.pdf_script_font(code) else 'en'
                self.assertEqual(certificate.certificate_language(code), expected)

    def test_certificate_font_has_every_character_of_its_language(self):
        """Brakujacy znak czytnik PDF pokazuje jako NIC — zdanie gubi slowa."""
        self.assertTrue(fonts.register_pdf_fonts())
        inter = fonts.pdf_chars(fonts.PDF_REGULAR)
        for code in sorted(certificate.PDF_LANGUAGES - {'en'}):
            with self.subTest(language=code):
                self.assertEqual(_missing(_certificate_strings(code), inter), [])
        for code in sorted(certificate.CJK_LANGUAGES):
            font = fonts.pdf_script_font(code)
            if not font:
                continue
            with self.subTest(language=code):
                self.assertEqual(_missing(_certificate_strings(code), font['chars']), [])

    def test_certificate_is_built_in_every_language(self):
        entry = Entry(digest='ab' * 32, file_name='umowa.pdf', note='notatka',
                      utc='2026-09-27T10:00:00Z', beat='@458.33')
        for code in i18n.SUPPORTED:
            with self.subTest(language=code):
                i18n.set_language(code)
                pdf = certificate.build_certificate(entry)
                self.assertTrue(pdf.startswith(b'%PDF'))
                # Jezyk interfejsu wraca po zlozeniu dokumentu.
                self.assertEqual(i18n.current_language(), code)

    def test_user_text_in_cjk_gets_a_font_that_has_it(self):
        if not fonts.pdf_script_font('ja'):
            self.skipTest('brak czcionki japonskiej w systemie')
        xml = certificate._user_text('契約書_最終版.pdf', 'pl', fonts.pdf_chars(fonts.PDF_REGULAR))
        self.assertIn('<font name="BeatStamp-CJK-', xml)
        self.assertIn('.pdf', xml)
        self.assertNotIn('?', xml)

    def test_unprintable_characters_are_marked_not_dropped(self):
        fonts.register_pdf_fonts()
        xml = certificate._user_text('عقد 2026', 'pl', fonts.pdf_chars(fonts.PDF_REGULAR))
        self.assertEqual(xml, '??? 2026')

    def test_user_text_is_still_escaped(self):
        xml = certificate._user_text('a<b>&契', 'pl', None)
        self.assertNotIn('<b>', xml)
        self.assertIn('&lt;b&gt;&amp;', xml)


class ScriptFontTests(unittest.TestCase):

    def tearDown(self):
        i18n.set_language('pl')
        theme.apply_theme(_app, 'light')

    def test_cjk_and_arabic_get_system_fallbacks_after_inter(self):
        for code in ('ja', 'ko', 'zh', 'ar'):
            with self.subTest(language=code):
                i18n.set_language(code)
                families = theme.ui_font().families()
                self.assertEqual(families[0], fonts.UI_FAMILY)
                self.assertTrue(set(theme.SCRIPT_FAMILIES[code]) <= set(families))
                self.assertIn(f'"{theme.SCRIPT_FAMILIES[code][0]}"',
                              theme.stylesheet(theme.resolve('light')))

    def test_latin_languages_add_no_fallback(self):
        i18n.set_language('pl')
        self.assertEqual(theme.script_families(), ())


class BidiIsolationTests(unittest.TestCase):
    """Po arabsku daty, tygodnie i numery czytaja sie od lewej do prawej.

    Bez izolacji algorytm bidi (UAX #9) ustawia grupy cyfr w akapicie od
    prawej do lewej w odwrotnej kolejnosci: „2026-W37" -> „W37-2026",
    „12.09 12:10" -> „12:10 12.09", „#2" -> „2#". Wartosci sa poprawne,
    tylko przeczytane od konca — w programie od dowodow czasu to blad.
    """

    FSI, PDI = '⁨', '⁩'
    TAG = re.compile(r'<[^>]*>')
    PLACEHOLDER = re.compile(r'%\([a-z_]+\)s')

    def tearDown(self):
        i18n.set_language('pl')

    def test_ltr_isolates_only_in_right_to_left_languages(self):
        i18n.set_language('ar')
        self.assertEqual(i18n.ltr('2026-W37'), '⁦2026-W37⁩')
        self.assertEqual(i18n.strip_bidi(i18n.ltr('2026-W37')), '2026-W37')
        i18n.set_language('pl')
        self.assertEqual(i18n.ltr('2026-W37'), '2026-W37')

    def test_arabic_dates_are_isolated(self):
        for key in ('date', 'date_short', 'datetime'):
            value = i18n._FORMATS['ar'][key]
            self.assertTrue(value.startswith('⁦') and value.endswith('⁩'), key)
        for code in i18n.SUPPORTED:
            if code not in i18n.RTL:
                self.assertFalse(set(''.join(i18n._FORMATS[code].values()))
                                 & i18n.BIDI_CONTROLS, code)

    def test_file_names_never_carry_direction_marks(self):
        from beatstamp import naming
        i18n.set_language('ar')
        entry = Entry(digest='ab' * 32, file_name='عقد.pdf', utc='2026-09-12T10:10:38Z',
                      beat='@424.05')
        name = naming.certificate_name(entry, moment=True, beat=True)
        self.assertFalse(set(name) & i18n.BIDI_CONTROLS, name)

    def _interface_entries(self):
        skip = ('beatstamp/bundle.py', 'beatstamp/certificate.py')
        for entry in _catalog('ar'):
            if entry.msgid and not all(r.startswith(skip) for r in entry.references):
                yield entry

    def test_every_arabic_placeholder_is_inside_an_isolate(self):
        for entry in self._interface_entries():
            for text in entry.msgstr:
                plain = self.TAG.sub('', text)
                depth, inside = 0, []
                for i, ch in enumerate(plain):
                    if ch == self.FSI:
                        depth += 1
                    elif ch == self.PDI:
                        depth -= 1
                    inside.append(depth > 0)
                for m in self.PLACEHOLDER.finditer(plain):
                    with self.subTest(msgid=entry.msgid[:60]):
                        self.assertTrue(inside[m.start()], plain)

    def test_isolates_are_balanced_and_keep_prefixes(self):
        for entry in _catalog('ar'):
            for text in entry.msgstr:
                with self.subTest(msgid=entry.msgid[:60]):
                    self.assertEqual(text.count(self.FSI), text.count(self.PDI))
                    self.assertNotIn('#' + self.FSI, text)
                    self.assertNotRegex(text, r'\d{4}-(?:W\d{2}|Q\d)(?!⁩)')

    def test_other_catalogs_have_no_direction_marks(self):
        for code in extract_messages.CATALOGS:
            if code in i18n.RTL:
                continue
            for entry in _catalog(code):
                for text in entry.msgstr:
                    with self.subTest(language=code, msgid=entry.msgid[:60]):
                        self.assertFalse(set(text) & i18n.BIDI_CONTROLS)


class RightToLeftPaintingTests(unittest.TestCase):
    """Widgety rysowane recznie czytaja kierunek pisma same."""

    @staticmethod
    def _is_ok_green(color) -> bool:
        ok = theme.color('ok')
        return (abs(color.red() - ok.red()) < 30 and abs(color.green() - ok.green()) < 30
                and abs(color.blue() - ok.blue()) < 30)

    def _journey(self, direction):
        journey = ProofJourney()
        journey.setLayoutDirection(direction)
        journey.resize(600, 70)
        journey.set_steps([JourneyStep('a', STEP_DONE), JourneyStep('b', STEP_PENDING),
                           JourneyStep('c', STEP_PENDING)])
        return journey.grab().toImage()

    def test_journey_starts_on_the_right_in_arabic(self):
        # margin = 600 / 3 / 2 = 100: pierwszy etap na x=100 (LTR) albo x=500 (RTL).
        # Probka 4 px w lewo i 3 px w gore od srodka — wewnatrz kola, obok znaczka.
        ltr = self._journey(Qt.LeftToRight)
        rtl = self._journey(Qt.RightToLeft)
        self.assertTrue(self._is_ok_green(ltr.pixelColor(96, 15)))
        self.assertFalse(self._is_ok_green(ltr.pixelColor(496, 15)))
        self.assertTrue(self._is_ok_green(rtl.pixelColor(496, 15)))
        self.assertFalse(self._is_ok_green(rtl.pixelColor(96, 15)))

    def test_badge_dot_leads_the_text(self):
        for direction in (Qt.LeftToRight, Qt.RightToLeft):
            with self.subTest(direction=direction):
                badge = StatusBadge()
                badge.setLayoutDirection(direction)
                badge.show_state('ok', 'zweryfikowano')
                badge.resize(badge.sizeHint())
                image = badge.grab().toImage()
                cy = image.height() // 2
                x = StatusBadge.PAD_X + StatusBadge.DOT // 2
                if direction == Qt.RightToLeft:
                    x = image.width() - 1 - x
                self.assertTrue(self._is_ok_green(image.pixelColor(x, cy)))


if __name__ == '__main__':
    unittest.main()
