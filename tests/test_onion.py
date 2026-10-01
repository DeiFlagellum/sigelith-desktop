"""Adres .onion pobierany z /api/onion/ i zapamietywany (onion.py, od 3.0.0).

Serwis oglasza biezacy adres uslugi ukrytej (apps/api/views.OnionView, format
`sigelith-onion-v1`), a program w trybie Tor go pobiera — zmiana adresu nie
wymaga nowego wydania. Testy pilnuja przede wszystkim, czego program NIE
przyjmie: niepoprawnego adresu, obcego formatu, zbyt duzej odpowiedzi, drogi
z pominieciem Tora.
"""
import base64
import hashlib
import io
import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from beatstamp import config, onion

# Prawdziwe adresy v3 (suma kontrolna liczona przez Tor, nie przez nas).
OUR_OLD = 'beattimep6dfropwazgaluos7xsxxmyjeat2ddb73dxxvvbsejmp4hqd.onion'
TOR_PROJECT = '2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion'
DUCKDUCKGO = 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion'


def _address(pub: bytes, version: int = 3, *, bad_checksum: bool = False) -> str:
    """Adres zbudowany wg specyfikacji Tor (rend-spec-v3, 6. „Encoding onion addresses”)."""
    ver = bytes([version])
    checksum = hashlib.sha3_256(b'.onion checksum' + pub + ver).digest()[:2]
    if bad_checksum:
        checksum = bytes([checksum[0] ^ 1, checksum[1]])
    return base64.b32encode(pub + checksum + ver).decode().lower() + '.onion'


NEW = _address(bytes(range(32)))


class _Raw:
    """`response.raw` z urllib3 — tylko to, czego uzywa onion._fetch."""

    def __init__(self, body: bytes):
        self._stream = io.BytesIO(body)

    def read(self, n=-1, decode_content=True):  # noqa: ARG002 — podpis urllib3
        return self._stream.read(n)


class _Response:
    def __init__(self, status=200, body=b'', data=None):
        self.status_code = status
        if data is not None:
            body = json.dumps(data).encode()
        self.raw = _Raw(body)
        self.closed = False

    def close(self):
        self.closed = True


class _Session:
    """Udaje `requests`: odpowiedz (albo wyjatek) per adres, zapis wywolan."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        answer = self.answers.get(url)
        if answer is None or isinstance(answer, Exception):
            raise answer or ConnectionError('brak odpowiedzi')
        return answer


def _doc(host):
    return {'format': 'sigelith-onion-v1', 'onion': host, 'url': f'http://{host}'}


class V3AddressTests(unittest.TestCase):
    def test_real_addresses_are_valid(self):
        for host in (OUR_OLD, TOR_PROJECT, DUCKDUCKGO, NEW):
            with self.subTest(host=host):
                self.assertTrue(onion.is_v3_host(host))

    def test_everything_else_is_rejected(self):
        one_char_off = OUR_OLD[:10] + ('a' if OUR_OLD[10] != 'a' else 'b') + OUR_OLD[11:]
        for host in (
            one_char_off,                                  # zla suma kontrolna
            _address(bytes(32), bad_checksum=True),
            _address(bytes(32), version=2),                # nie v3
            OUR_OLD.upper(),                               # tylko male litery
            OUR_OLD[:-6],                                  # bez .onion
            OUR_OLD[1:],                                   # 55 znakow
            'a' + OUR_OLD,                                 # 57 znakow
            'beattime.live', '', None, 42,
            OUR_OLD.replace('b', '1', 1),                  # spoza alfabetu base32
        ):
            with self.subTest(host=host):
                self.assertFalse(onion.is_v3_host(host))

    def test_only_a_bare_http_base_url_counts(self):
        self.assertTrue(onion.is_v3_url(f'http://{NEW}'))
        self.assertTrue(onion.is_v3_url(f'http://{NEW}/'))
        for url in (f'https://{NEW}', f'http://{NEW}:8080', f'http://{NEW}/api/',
                    f'http://user@{NEW}', f'http://{NEW}/?x=1', NEW, '', None,
                    f'http://{_address(bytes(32), bad_checksum=True)}'):
            with self.subTest(url=url):
                self.assertFalse(onion.is_v3_url(url))


class ParseTests(unittest.TestCase):
    def test_accepts_the_documented_format(self):
        self.assertEqual(onion.parse(_doc(NEW)), NEW)
        self.assertEqual(onion.parse(_doc(NEW.upper().replace('.ONION', '.onion'))), NEW)

    def test_rejects_anything_else(self):
        for data in (
            {'format': 'sigelith-onion-v2', 'onion': NEW},
            {'onion': NEW},
            {'format': 'sigelith-onion-v1'},
            {'format': 'sigelith-onion-v1', 'onion': 'evil.example'},
            {'format': 'sigelith-onion-v1', 'onion': ['x']},
            [NEW], NEW, None,
        ):
            with self.subTest(data=data):
                self.assertIsNone(onion.parse(data))


class DueTests(unittest.TestCase):
    now = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)

    def test_schedule(self):
        iso = lambda d: d.isoformat()  # noqa: E731
        self.assertTrue(onion.due('', self.now))
        self.assertTrue(onion.due('nonsense', self.now))
        self.assertTrue(onion.due('2026-09-30T11:00:00', self.now))     # bez strefy
        self.assertFalse(onion.due(iso(self.now - timedelta(hours=1)), self.now))
        self.assertTrue(onion.due(iso(self.now - timedelta(hours=25)), self.now))
        # Data z przyszlosci (przestawiony zegar) nie blokuje sprawdzania.
        self.assertTrue(onion.due(iso(self.now + timedelta(days=1)), self.now))


class DiscoverTests(unittest.TestCase):
    def setUp(self):
        self.settings = config.Settings(use_tor=True)
        self.known = self.settings.onion_base_url + onion.PATH
        self.clearnet = config.DEFAULT_BASE_URL + onion.PATH

    def test_asks_the_known_onion_first_and_only_through_tor(self):
        session = _Session({self.known: _Response(data=_doc(NEW))})
        self.assertEqual(onion.discover(self.settings, session), f'http://{NEW}')
        url, kwargs = session.calls[0]
        self.assertEqual(url, f'{config.ONION_BASE_URL}/api/onion/')
        self.assertEqual(kwargs['proxies'], {'http': self.settings.tor_proxy,
                                             'https': self.settings.tor_proxy})
        self.assertFalse(kwargs['allow_redirects'])
        self.assertEqual(len(session.calls), 1)

    def test_falls_back_to_sigelith_org_through_tor_with_tls(self):
        session = _Session({self.known: ConnectionError('wycofany'),
                            self.clearnet: _Response(data=_doc(NEW))})
        self.assertEqual(onion.discover(self.settings, session), f'http://{NEW}')
        url, kwargs = session.calls[1]
        self.assertEqual(url, 'https://sigelith.org/api/onion/')
        # Takze do sigelith.org idziemy przez Tor — serwer nie pozna IP.
        self.assertEqual(kwargs['proxies']['https'], self.settings.tor_proxy)
        self.assertTrue(str(kwargs['verify']).endswith('.pem'))

    def test_uses_the_remembered_address_as_the_known_one(self):
        settings = replace(self.settings, onion_url=f'http://{TOR_PROJECT}')
        session = _Session({f'http://{TOR_PROJECT}/api/onion/': _Response(data=_doc(NEW))})
        self.assertEqual(onion.discover(settings, session), f'http://{NEW}')

    def test_bad_answers_are_skipped_and_nothing_is_invented(self):
        cases = {
            'status': _Response(status=404, data={'format': 'sigelith-onion-v1'}),
            'format': _Response(data={'format': 'other', 'onion': NEW}),
            'checksum': _Response(data=_doc(_address(bytes(32), bad_checksum=True))),
            'size': _Response(body=b' ' * (onion.MAX_BYTES + 1)),
            'json': _Response(body=b'<html>'),
        }
        for name, bad in cases.items():
            with self.subTest(case=name):
                session = _Session({self.known: bad, self.clearnet: ConnectionError()})
                self.assertIsNone(onion.discover(self.settings, session))

    def test_nothing_answers(self):
        self.assertIsNone(onion.discover(self.settings, _Session({})))


class SettingsTests(unittest.TestCase):
    def test_tor_mode_uses_the_remembered_address(self):
        settings = config.Settings(use_tor=True, onion_url=f'http://{NEW}')
        self.assertEqual(settings.effective_base_url, f'http://{NEW}')

    def test_a_broken_remembered_address_falls_back_to_the_built_in_one(self):
        for bad in ('http://evil.example', f'https://{NEW}',
                    f'http://{_address(bytes(32), bad_checksum=True)}', 'x'):
            with self.subTest(bad=bad):
                settings = config.Settings(use_tor=True, onion_url=bad)
                self.assertEqual(settings.effective_base_url, config.ONION_BASE_URL)

    def test_without_tor_the_remembered_address_changes_nothing(self):
        settings = config.Settings(onion_url=f'http://{NEW}')
        self.assertEqual(settings.effective_base_url, config.DEFAULT_BASE_URL)

    def test_the_built_in_address_is_itself_valid(self):
        self.assertTrue(onion.is_v3_url(config.ONION_BASE_URL))


if __name__ == '__main__':
    unittest.main()
