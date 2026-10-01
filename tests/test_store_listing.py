"""
Karta w Microsoft Store (packaging/store/listing.json) i narzedzie, ktore
wpisuje ja do eksportu z Partner Center (fill_listing_csv.py).

Pilnuje limitow Partner Center (opis 10 000 znakow bez adresow URL, do 20
funkcji po 200 znakow, podpisy zrzutow do 200), jezykow zgodnych z paczka
MSIX i dyscypliny twierdzen z HANDOVER_SPEC.md §0.4.
"""
from __future__ import annotations

import csv
import importlib.util
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STORE = ROOT / 'packaging' / 'store'
LISTING = json.loads((STORE / 'listing.json').read_text(encoding='utf-8'))

# §0.4: zadnych nazw uslug pocztowych ani „qualified"/„registered delivery".
FORBIDDEN = {'en-us': ('registered', 'qualified'), 'de-de': ('einschreiben', 'qualifiziert',
                                                             'zustellung'),
             'pl-pl': ('polecon', 'kwalifikowan'), 'ru-ru': ('заказн', 'квалифицир'),
             'tr-tr': ('taahhütlü', 'nitelikli'), 'ja-jp': ('書留', '適格'), 'ko-kr': ('등기', '적격'),
             'ar-sa': ('بريد مسجل', 'مؤهل'),
             'es-es': ('correo certificad', 'entrega certificad', 'burofax', 'cualificad'),
             'fr-fr': ('recommandé', 'qualifié'), 'zh-cn': ('挂号', '合格')}


def _filler():
    spec = importlib.util.spec_from_file_location('fill_listing_csv', STORE / 'fill_listing_csv.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ListingTests(unittest.TestCase):
    def test_languages_match_the_msix_package(self):
        manifest = (ROOT / 'packaging' / 'AppxManifest.xml').read_text(encoding='utf-8')
        languages = {m.lower() for m in re.findall(r'<Resource Language="([^"]+)"', manifest)}
        self.assertEqual(set(LISTING), languages)

    def test_partner_center_limits(self):
        for locale, item in LISTING.items():
            with self.subTest(locale=locale):
                self.assertLessEqual(len(item['description']), 10000)
                self.assertTrue(0 < len(item['whats_new']) <= 1500, 'What\'s new: do 1500 znakow')
                self.assertLessEqual(len(item['short_description']), 270,
                                     'powyzej 270 znakow Sklep ucina krotki opis')
                self.assertLessEqual(len(item['features']), 20)
                for text in item['features'] + item['captions'] + item['recommended_hardware']:
                    self.assertLessEqual(len(text), 200, text)
                self.assertEqual(len(item['captions']), len(item['screenshots']))
                self.assertLessEqual(len(item['screenshots']), 10)
                self.assertNotRegex(item['description'], r'https?://|www\.|\.org\b|\.com\b',
                                    'Partner Center: bez adresow URL w opisie')
                self.assertNotIn('<', item['description'], 'zwykly tekst, bez HTML')

    def test_search_terms_fit_the_keywords_field(self):
        # Keywords: do 7 hasel po 40 znakow, razem do 21 roznych slow.
        for locale, item in LISTING.items():
            terms = item['search_terms']
            with self.subTest(locale=locale):
                self.assertLessEqual(len(terms), 7)
                self.assertEqual(len(terms), len(set(terms)))
                for term in terms:
                    self.assertTrue(0 < len(term) <= 40, term)
                self.assertLessEqual(len({w.lower() for t in terms for w in t.split()}), 21)

    def test_claims_discipline(self):
        for locale, item in LISTING.items():
            text = json.dumps(item, ensure_ascii=False).lower()
            for word in FORBIDDEN[locale]:
                with self.subTest(locale=locale, word=word):
                    self.assertNotIn(word, text)

    def test_every_language_is_translated(self):
        english = LISTING['en-us']
        for locale, item in LISTING.items():
            if locale == 'en-us':
                continue
            with self.subTest(locale=locale):
                self.assertNotEqual(item['description'], english['description'])
                self.assertNotEqual(item['whats_new'], english['whats_new'])
                self.assertNotEqual(item['features'][0], english['features'][0])
                self.assertNotEqual(item['captions'][1], english['captions'][1])


class FillCsvTests(unittest.TestCase):
    def test_fills_an_exported_template(self):
        filler = _filler()
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            fields = (['Description', 'ReleaseNotes', 'AdditionalLicenseTerms', 'ShortDescription',
                       'CopyrightTrademarkInformation', 'StoreLogo720x1080',
                       'StoreLogo300x300']
                      + [f'Feature{n}' for n in range(1, 21)]
                      + [f'DesktopScreenshot{n}' for n in range(1, 11)]
                      + [f'DesktopScreenshotCaption{n}' for n in range(1, 11)]
                      + [f'RecommendedHardwareReq{n}' for n in range(1, 12)]
                      + [f'SearchTerm{n}' for n in range(1, 8)])
            exported = tmp / 'eksport.csv'
            rows = [['Field', 'ID', 'Type (Type)', 'default', 'en-us']]
            rows += [[f, str(n), 'Text', '', 'stare' if f in ('ReleaseNotes', 'AdditionalLicenseTerms') else '']
                     for n, f in enumerate(fields, 2)]
            with open(exported, 'w', encoding='utf-8-sig', newline='') as f:
                csv.writer(f).writerows(rows)
            shots = tmp / 'zrzuty'
            for lang in filler.SHOT_DIRS.values():
                (shots / lang).mkdir(parents=True)
                for name in LISTING['en-us']['screenshots']:
                    (shots / lang / name).write_bytes(b'\x89PNG')
            out = tmp / 'wynik'
            missing = filler.fill(exported, shots, out)
            self.assertEqual(missing, [])
            raw = (out / 'listing.csv').read_bytes()
            self.assertTrue(raw.startswith(b'\xef\xbb\xbf'), 'kodowanie jak w eksporcie')
            table = list(csv.reader(io.StringIO(raw.decode('utf-8-sig'), newline='')))
            header = table[0]
            self.assertEqual(header[:5], rows[0])
            self.assertEqual(set(header[4:]), set(LISTING))
            data = {r[0]: r for r in table[1:]}
            ja = header.index('ja-jp')
            self.assertEqual(data['Description'][ja], LISTING['ja-jp']['description'])
            self.assertEqual(data['DesktopScreenshot2'][ja], 'wynik/screens/ja/02-history.png')
            self.assertEqual(data['ReleaseNotes'][header.index('en-us')], LISTING['en-us']['whats_new'])
            self.assertEqual(data['AdditionalLicenseTerms'][header.index('en-us')], 'stare',
                             'pola spoza listing.json zostaja nietkniete')
            self.assertEqual(data['Feature20'][ja], '')
            self.assertEqual(data['SearchTerm1'][ja], LISTING['ja-jp']['search_terms'][0])
            # Ikona kafelka karty (dla aplikacji jedyne logo, ktore Sklep
            # stawia przed logo z paczki) — ta sama we wszystkich jezykach.
            self.assertEqual({data['StoreLogo300x300'][header.index(lang)] for lang in LISTING},
                             {'wynik/logo/tile-300.png'})
            self.assertEqual(data['StoreLogo720x1080'][ja], '', 'plakat 2:3 jest dla gier')
            from PIL import Image
            with Image.open(out / 'logo' / 'tile-300.png') as tile:
                self.assertEqual(tile.size, (300, 300))
            self.assertTrue((out / 'screens' / 'ar' / '05-evidence.png').is_file())
            self.assertEqual([r[:3] for r in table[1:]], [r[:3] for r in rows[1:]],
                             'kolumny Field/ID/Type bez zmian')


if __name__ == '__main__':
    unittest.main()
