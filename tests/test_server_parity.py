"""
Zgodnosc z serwerem BeatTime — jedno zrodlo prawdy dla dwoch implementacji.

Sigelith Desktop mieszka w monorepo BeatTime (katalog desktop/), wiec zamiast ufac,
ze ktos przepisze zmiane w obu miejscach, porownujemy je wprost:

* keys.RETIRED_KEYS  <->  apps/tsa/signing.py: RETIRED_KEYS
  (odczyt modulem `ast` — bez Django i bez importu kodu serwera);
* beatcore           <->  apps/beat/core.py (czysty Python, ladowany ze sciezki).

Gdy desktop/ zostanie skopiowany poza monorepo, testy sa POMIJANE, a nie
oblewane. Druga strona pilnuje tego samego w apps/tsa/tests.py
(DesktopKeyMirrorTests).

Opcjonalnie, z SIGELITH_LIVE=1 (dawniej BEATSTAMP_LIVE=1), test na zywo sprawdza,
ze produkcja podpisuje
kluczem z keys.CURRENT_KEYS (aktualnego klucza nie ma w repozytorium serwera
— serwer wyprowadza go z env).
"""
from __future__ import annotations

import ast
import importlib.util
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from beatstamp import beatcore, i18n, keys, proof  # noqa: E402

# Jezyk interfejsu PRZYPIETY. Testy sprawdzaja ZNACZENIE napisu — oczekiwany
# tekst bierzemy z tego samego katalogu tlumaczen, ktorego uzywa program
# (`_('<msgid>')`), a nie z przepisanego recznie ciagu znakow. Bez przypiecia
# wynik suite zalezalby od jezyka interfejsu maszyny, na ktorej akurat sie ja
# uruchamia; bez katalogu — sprawdzalibysmy literowke, a nie tresc.
i18n.set_language('pl')
_ = i18n.gettext


REPO_ROOT = Path(__file__).resolve().parents[2]
SIGNING_PY = REPO_ROOT / 'apps' / 'tsa' / 'signing.py'
BEAT_CORE_PY = REPO_ROOT / 'apps' / 'beat' / 'core.py'

MIRRORED_FIELDS = ('public_key', 'active_from', 'retired_on')


def _server_retired_keys() -> list[dict]:
    """RETIRED_KEYS z signing.py — literal odczytany przez `ast`, bez importu."""
    tree = ast.parse(SIGNING_PY.read_text(encoding='utf-8'), filename=str(SIGNING_PY))
    for node in tree.body:
        target = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target, value = node.target.id, node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            target, value = node.targets[0].id, node.value
        if target == 'RETIRED_KEYS':
            return [dict(k) for k in ast.literal_eval(value)]
    raise AssertionError('w signing.py nie znaleziono RETIRED_KEYS')


@unittest.skipUnless(SIGNING_PY.is_file(),
                     'brak apps/tsa/signing.py — desktop/ poza monorepo BeatTime')
class RetiredKeysMirrorTests(unittest.TestCase):

    def test_retired_keys_mirror_the_server(self):
        server = [{f: k.get(f) for f in MIRRORED_FIELDS} for k in _server_retired_keys()]
        desktop = [{f: k.get(f) for f in MIRRORED_FIELDS} for k in keys.RETIRED_KEYS]
        self.assertEqual(
            desktop, server,
            'desktop/beatstamp/keys.py: RETIRED_KEYS rozjechało się z '
            'apps/tsa/signing.py — przy rotacji zmień oba miejsca.')

    def test_no_current_key_is_retired_on_the_server(self):
        retired = {k['public_key'] for k in _server_retired_keys()}
        for pub in keys.current_public_keys():
            self.assertNotIn(pub, retired,
                             f'serwer wycofał klucz {pub}, a aplikacja wciąż mu ufa')


def _load_server_core():
    spec = importlib.util.spec_from_file_location('_beattime_server_core', BEAT_CORE_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(BEAT_CORE_PY.is_file(),
                     'brak apps/beat/core.py — desktop/ poza monorepo BeatTime')
class BeatCoreParityTests(unittest.TestCase):
    """Port beatcore musi liczyc co do centibeatu to samo, co serwer."""

    @classmethod
    def setUpClass(cls):
        cls.server = _load_server_core()

    INSTANTS = [
        datetime(2026, 6, 15, 0, 0, 0, tzinfo=timezone.utc),               # polnoc
        datetime(2026, 6, 15, 0, 21, 36, tzinfo=timezone.utc),             # @015.00
        datetime(2026, 6, 15, 8, 0, 0, tzinfo=timezone.utc),               # @333.33
        datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc),              # @500
        datetime(2026, 6, 15, 23, 59, 59, 999000, tzinfo=timezone.utc),    # tuz przed polnoca
        datetime(2026, 6, 15, 23, 59, 59, 999999, tzinfo=timezone.utc),
        datetime(2026, 6, 15, 8, 21, 32, 167366, tzinfo=timezone.utc),     # LIVE_PAYLOAD
        datetime(2026, 6, 15, 0, 1, 26, 400000, tzinfo=timezone.utc),      # dokladnie @001
        datetime(2026, 6, 15, 10, 0, 0, tzinfo=timezone.utc,
                 ).astimezone(timezone(timedelta(hours=2))),               # strefa != UTC
        datetime(2026, 6, 15, 12, 0, 0),                                   # naive = UTC
    ]

    def test_known_boundaries(self):
        expected = {
            datetime(2026, 6, 15, 0, 21, 36, tzinfo=timezone.utc): '@015.00',
            datetime(2026, 6, 15, 8, 0, 0, tzinfo=timezone.utc): '@333.33',
            datetime(2026, 6, 15, 0, 0, 0, tzinfo=timezone.utc): '@000.00',
            datetime(2026, 6, 15, 23, 59, 59, 999000, tzinfo=timezone.utc): '@999.99',
        }
        for dt, beat in expected.items():
            for name, core in (('desktop', beatcore), ('serwer', self.server)):
                self.assertEqual(core.format_beat(core.beats_from_utc(dt), decimals=2),
                                 beat, f'{name}: {dt.isoformat()}')

    def test_beats_from_utc_matches(self):
        for dt in self.INSTANTS:
            self.assertEqual(beatcore.beats_from_utc(dt), self.server.beats_from_utc(dt),
                             dt.isoformat())

    def test_format_beat_matches(self):
        for dt in self.INSTANTS:
            beats = self.server.beats_from_utc(dt)
            for decimals in (0, 2, 3):
                self.assertEqual(beatcore.format_beat(beats, decimals=decimals),
                                 self.server.format_beat(beats, decimals=decimals),
                                 f'{dt.isoformat()} decimals={decimals}')
        for beats in (0.0, 999.6, 999.999, 1000.0, 1234.5, -0.5):
            self.assertEqual(beatcore.format_beat(beats, decimals=2),
                             self.server.format_beat(beats, decimals=2), beats)

    def test_unix_and_inverse_match(self):
        for unix in (0, 1_781_491_292.167366, 86_399.999, 1_781_481_600):
            self.assertEqual(beatcore.beats_from_unix(unix),
                             self.server.beats_from_unix(unix), unix)
        day = datetime(2026, 6, 15, tzinfo=timezone.utc)
        for beats in (0.0, 15.0, 333.33, 500.0, 999.99):
            self.assertEqual(beatcore.beat_to_utc(beats, day),
                             self.server.beat_to_utc(beats, day), beats)
            self.assertEqual(beatcore.beat_to_seconds_of_day(beats),
                             self.server.beat_to_seconds_of_day(beats), beats)

    def test_constants_match(self):
        for name in ('SECONDS_PER_DAY', 'BEATS_PER_DAY', 'SECONDS_PER_BEAT',
                     'MICROSECONDS_PER_BEAT'):
            self.assertEqual(getattr(beatcore, name), getattr(self.server, name), name)


@unittest.skipUnless('1' in (os.environ.get('SIGELITH_LIVE'),
                             os.environ.get('BEATSTAMP_LIVE')),
                     'test na żywo — uruchom z SIGELITH_LIVE=1')
class LiveCurrentKeyTests(unittest.TestCase):
    """Produkcja podpisuje kluczem z keys.CURRENT_KEYS — i podpis sie zgadza."""

    # Adres domyslny programu (sigelith.org) — ta sama instancja co
    # beattime.live, wiec ten sam klucz.
    URL = 'https://sigelith.org/api/proof/root/latest'

    def test_production_signs_with_a_current_key(self):
        import requests
        response = requests.get(self.URL, timeout=20, allow_redirects=False)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get('found'), data)
        self.assertIn(data['public_key'], keys.current_public_keys(),
                      'produkcja podpisuje kluczem spoza keys.CURRENT_KEYS — '
                      'rotacja? dopisz nowy klucz do keys.py')
        self.assertTrue(proof.verify_ed25519_root(
            data['week'], data['root'], data['signature'], data['public_key']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
