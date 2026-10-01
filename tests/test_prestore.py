"""
Poprawki z diagnostyki przed publikacja w Microsoft Store (2026-09-27).

Piec niezaleznych przegladow (gotowy program, uklad okien w 11 jezykach,
odpornosc na zle dane, paczka MSIX, serwer produkcyjny) plus Windows App
Certification Kit. Kazdy test ponizej odpowiada jednemu znalezisku — i pilnuje,
zeby nie wrocilo:

* pierwszy alarm swiadka wywracal program przy KAZDYM starcie;
* kopia checkpointu, ktorej nie da sie odczytac (migawka Internet Archive
  w kompresji zstd), byla alarmem;
* 15-minutowy cykl pytal w kolko o te same szczegoly checkpointow;
* zepsute IPv6 kosztowalo 5 s na kazdy rekord AAAA serwera;
* „Retry-After: 120" zatrzymywal jedyny watek roboczy na dwie minuty;
* 503 stanu potoku (tresc: alert) ginelo w ponawianiu;
* przekierowanie na http:// bylo sprawdzane PO wyslaniu zapytania;
* pierwszy pomiar zegara liczyl uscisk TLS i dawal falszywe ostrzezenie;
* dwie kopie programu psuly wspolny katalog danych;
* czynnosc uzytkownika czekala za kontrola w tle;
* okna wychodzily poza ekran, „O programie" bylo uciete.
"""
from __future__ import annotations

import io
import json
import os
import socket
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import requests  # noqa: E402
from PySide6.QtCore import QCoreApplication  # noqa: E402
from PySide6.QtWidgets import QApplication, QScrollArea  # noqa: E402
from urllib3.exceptions import MaxRetryError, ReadTimeoutError  # noqa: E402

from beatstamp import api, i18n, logtree, witness  # noqa: E402
from beatstamp.config import Settings  # noqa: E402
from beatstamp.instance import SingleInstance  # noqa: E402
from beatstamp.ui import theme  # noqa: E402
from test_logtree import TEST_KEY  # noqa: E402
from test_witness import ENTRIES, FakeServer  # noqa: E402

_app = QApplication.instance() or QApplication(sys.argv)
i18n.set_language('pl')
_ = i18n.gettext


def _response(status: int, body: bytes = b'', headers: dict | None = None,
              url: str = 'https://beattime.live/x') -> requests.Response:
    r = requests.Response()
    r.status_code = status
    r._content = body
    r._content_consumed = True
    r.headers.update(headers or {})
    r.url = url
    return r


class _TempDataDir(unittest.TestCase):
    """Katalog danych izolowany dla calej klasy (jak w test_gui_smoke)."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls._saved = {k: os.environ.get(k) for k in ('SIGELITH_DATA_DIR', 'LOCALAPPDATA')}
        os.environ['SIGELITH_DATA_DIR'] = cls._tmp.name
        os.environ['LOCALAPPDATA'] = cls._tmp.name
        (Path(cls._tmp.name) / '.tvs-zaimportowano').write_text('test')
        theme.apply_theme(_app, 'light')

    @classmethod
    def tearDownClass(cls):
        for key, value in cls._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        cls._tmp.cleanup()

    def _window(self):
        from beatstamp.ui.main_window import MainWindow
        window = MainWindow(Settings(background_checks=False))
        self.addCleanup(self._close, window)
        return window

    @staticmethod
    def _close(window):
        window.close()
        window.deleteLater()
        QCoreApplication.processEvents()


# --- Alarm swiadka ------------------------------------------------------------------

def _alarm(severity: str, code: str = witness.ALARM_BTC) -> dict:
    return {'code': code, 'severity': severity, 'detail': 'test', 'n': 2,
            'at': '2026-09-27T10:00:00Z', 'source': 'mempool.space', 'key': f'{code}:2:'}


class AlarmRenderingTests(_TempDataDir):

    def test_panel_renders_warning_and_critical_alarms(self):
        from beatstamp.ui.witness_panel import WitnessPanel
        panel = WitnessPanel()
        for severity in ('warning', 'critical'):
            with self.subTest(severity=severity):
                state = witness.WitnessState()
                state.alarms = [_alarm(severity)]
                panel.set_state(state)          # do 2.2.0: AttributeError
                self.assertTrue(panel.alarm_card.isVisibleTo(panel))
        panel.deleteLater()

    def test_copy_card_says_when_the_archive_did_not_answer(self):
        """2026-09-29: przy awarii indeksu Internet Archive karta mowila „jeszcze
        tam nie opublikowano”, choc migawka byla. Brak odpowiedzi to co innego."""
        from beatstamp.ui.witness_panel import WitnessPanel
        panel = WitnessPanel()
        self.addCleanup(panel.deleteLater)
        state = witness.WitnessState()
        state.copies = {'wayback': {'max_n': 0, 'weeks': {'2026-W39': {
            'status': 'unavailable', 'checked': '2026-09-29T10:00:00Z', 'url': ''}}}}
        panel.set_state(state)
        caption = panel.cards['wayback'].caption.text()
        self.assertIn('Internet Archive', caption)
        self.assertNotIn(i18n._('not published there yet — checked %(when)s; Sigelith Desktop '
                                'tries again every 3 h').split('—')[0], caption)

    def test_window_starts_with_an_alarm_saved_on_disk(self):
        """Stan z alarmem czyta KONSTRUKTOR okna — blad byl przy kazdym starcie."""
        store = witness.WitnessStore()
        state = witness.WitnessState()
        state.alarms = [_alarm('warning')]
        store.save(state)
        try:
            window = self._window()
            self.assertEqual(len(window.witness_state.alarms), 1)
        finally:
            store.save(witness.WitnessState())


# --- Kopia dziennika ------------------------------------------------------------------

class LogMirrorRepairTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'log.jsonl'

    def _lines(self) -> list[bytes]:
        return [logtree.canonical_json(logtree.parse_entry(e).to_dict()) for e in ENTRIES]

    def test_duplicated_range_is_cut_and_the_file_rewritten(self):
        """Dwie kopie programu dopisaly ten sam zakres dwa razy (380 linii, 190 wpisow)."""
        lines = self._lines()
        self.path.write_bytes(b'\n'.join(lines + lines) + b'\n')
        mirror = witness.LogMirror(self.path).load()
        self.assertEqual(mirror.size, len(lines))
        self.assertEqual(self.path.read_bytes().splitlines(), lines)
        # Ponowny odczyt: juz bez ostrzezenia i bez zmian.
        with self.assertNoLogs('beatstamp.witness', level='WARNING'):
            self.assertEqual(witness.LogMirror(self.path).load().size, len(lines))

    def test_torn_last_line_is_dropped(self):
        lines = self._lines()
        self.path.write_bytes(b'\n'.join(lines) + b'\n' + lines[0][:17])
        mirror = witness.LogMirror(self.path).load()
        self.assertEqual(mirror.size, len(lines))
        self.assertEqual(self.path.read_bytes().splitlines(), lines)


# --- Szczegoly checkpointow i kopie ------------------------------------------------------

class CountingServer(FakeServer):

    def __init__(self, ots_status='bitcoin', btc_time='2026-09-28T09:30:00Z', zenodo=''):
        super().__init__()
        self.detail_calls: list[int] = []
        self._ots_status = ots_status
        self._btc_time = btc_time
        self._zenodo = zenodo

    def checkpoint(self, n):
        self.detail_calls.append(n)
        detail = super().checkpoint(n)
        if detail:
            detail.update(ots_status=self._ots_status, btc_time=self._btc_time)
            detail['copies']['zenodo'] = self._zenodo
        return detail


class DetailsScheduleTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = witness.WitnessStore(Path(self.tmp.name))
        self.state = witness.WitnessState()

    def _run(self, server, now):
        with mock.patch.object(witness, '_now', return_value=now):
            witness.refresh(server, self.store, self.state, None, mode=witness.MODE_FAST,
                            override=TEST_KEY, third_party=False)

    def _issued(self) -> datetime:
        return max(r.utc_dt for r in self.state.checkpoints.values())

    # Wektory z LOG.md: #1 (dzienny) 2026-09-28 — ostatni III kwartalu;
    # #2 (tygodniowy) 2026-10-05 — IV kwartal.
    START = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)

    def test_immature_checkpoints_are_asked_hourly_when_fresh_daily_when_old(self):
        server = CountingServer(ots_status='pending', btc_time='')
        self._run(server, self.START)
        self.assertEqual(sorted(server.detail_calls), [1, 2],
                         'pierwszy przebieg: kazdy checkpoint dokladnie raz')
        server.detail_calls.clear()
        self._run(server, self.START + timedelta(minutes=15))
        self.assertEqual(server.detail_calls, [], 'kwadrans pozniej — nic')
        self._run(server, self.START + timedelta(minutes=61))
        self.assertEqual(server.detail_calls, [2], 'swiezy (< 2 dni) co godzine, starszy nie')
        server.detail_calls.clear()
        self._run(server, self.START + timedelta(hours=25))
        self.assertEqual(sorted(server.detail_calls), [1, 2], 'starszy raz na dobe')

    def test_mature_checkpoints_wait_for_zenodo_only_after_their_quarter(self):
        server = CountingServer()
        self._run(server, self.START)
        server.detail_calls.clear()
        self._run(server, self.START + timedelta(hours=2))
        self.assertEqual(server.detail_calls, [], 'szczegoly swieze — nic')
        # #1 zamyka III kwartal (koniec 01.10 + 48 h juz minal): raz na dobe,
        # az pojawi sie rekord Zenodo. #2 czeka na koniec IV kwartalu.
        self._run(server, self.START + timedelta(hours=25))
        self.assertEqual(server.detail_calls, [1])
        server.detail_calls.clear()
        q4_end = witness._quarter_end(self.state.checkpoints[2].utc_dt)
        self._run(server, q4_end + timedelta(hours=1))
        self.assertEqual(server.detail_calls, [1], '#2 czeka jeszcze 48 h po koncu kwartalu')
        server.detail_calls.clear()
        self._run(server, q4_end + witness.ZENODO_GRACE + timedelta(hours=2))
        self.assertEqual(sorted(server.detail_calls), [1, 2])

    def test_a_published_zenodo_record_ends_the_questions(self):
        server = CountingServer(zenodo='https://zenodo.org/records/123456')
        self._run(server, self.START)
        server.detail_calls.clear()
        self._run(server, self.START + timedelta(days=200))
        self.assertEqual(server.detail_calls, [])


class WaybackTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = witness.WitnessStore(Path(self.tmp.name))
        self.state = witness.WitnessState()
        self.server = FakeServer()
        witness.refresh(self.server, self.store, self.state, None, mode=witness.MODE_FAST,
                        override=TEST_KEY, third_party=False)
        weekly = [r for r in self.state.checkpoints.values() if r.kind == 'weekly']
        self.assertTrue(weekly)
        self.record = weekly[0]
        self.original = witness.CHECKPOINT_PUBLIC.format(
            name=logtree.checkpoint_filename(self.record.n))

    def test_cdx_is_asked_from_the_checkpoint_date_and_a_readable_capture_wins(self):
        since = self.record.utc_dt.strftime('%Y%m%d')
        cdx = witness.WAYBACK_CDX.format(url=self.original, since=since)
        self.assertIn(f'from={since}', cdx)
        self.assertIn('limit=5', cdx)
        self.assertNotIn('limit=-', cdx, 'ujemny limit kaze archiwum czytac cala historie')
        stamps = ['20261001000000', '20261002000000']
        self.server.external[cdx] = json.dumps(
            [['timestamp', 'digest']] + [[s, 'X'] for s in stamps]).encode()
        self.server.external[witness.WAYBACK_RAW.format(timestamp=stamps[0], url=self.original)] = (
            b'\x28\xb5\x2f\xfd' + b'\x00' * 50)
        self.server.external[witness.WAYBACK_RAW.format(timestamp=stamps[1], url=self.original)] = (
            self.server.files[self.record.n])
        report = witness.RefreshReport()
        witness.check_copies(self.server, self.store, self.state, report, override=TEST_KEY)
        entry = self.state.copies['wayback']['weeks'][self.record.week]
        self.assertEqual(entry['status'], 'match')
        self.assertIn(stamps[1], entry['url'])
        self.assertEqual(self.state.alarms, [])

    # --- sigelith.org i beattime.live (2026-09-27) ------------------------------

    def _url(self, template: str) -> str:
        return template.format(name=logtree.checkpoint_filename(self.record.n))

    def _cdx(self, original: str) -> str:
        return witness.WAYBACK_CDX.format(
            url=original, since=self.record.utc_dt.strftime('%Y%m%d'))

    def _snapshot(self, original: str, stamp: str) -> None:
        self.server.external[self._cdx(original)] = json.dumps(
            [['timestamp', 'digest'], [stamp, 'X']]).encode()
        self.server.external[witness.WAYBACK_RAW.format(timestamp=stamp, url=original)] = (
            self.server.files[self.record.n])

    def _check(self) -> tuple[dict, list[str]]:
        asked: list[str] = []
        real = self.server.fetch_external

        def recording(url, **kw):
            asked.append(url)
            return real(url, **kw)

        self.server.fetch_external = recording
        try:
            witness.check_copies(self.server, self.store, self.state,
                                 witness.RefreshReport(), override=TEST_KEY)
        finally:
            self.server.fetch_external = real
        return self.state.copies['wayback']['weeks'][self.record.week], asked

    def test_the_addresses_are_sigelith_first_then_beattime_live(self):
        self.assertEqual(witness.CHECKPOINT_PUBLIC_URLS, (
            'https://sigelith.org/checkpoints/{name}',
            'https://beattime.live/checkpoints/{name}'))
        self.assertEqual(self.original, self._url(witness.CHECKPOINT_PUBLIC_URLS[0]))

    def test_a_snapshot_under_sigelith_is_enough(self):
        """Migawki od 2026-W39 sa pod sigelith.org — o drugi adres nie pytamy."""
        sigelith = self._url(witness.CHECKPOINT_PUBLIC_URLS[0])
        beattime = self._url(witness.CHECKPOINT_PUBLIC_URLS[1])
        self._snapshot(sigelith, '20261005120000')

        entry, asked = self._check()

        self.assertEqual(entry['status'], 'match')
        self.assertIn('sigelith.org', entry['url'])
        self.assertIn(self._cdx(sigelith), asked)
        self.assertNotIn(self._cdx(beattime), asked)
        self.assertEqual(self.state.copy_max('wayback'), self.record.n)

    def test_a_snapshot_under_beattime_live_is_accepted_too(self):
        """To ta sama instancja — migawka pod stara domena to rownie dobra kopia."""
        sigelith = self._url(witness.CHECKPOINT_PUBLIC_URLS[0])
        beattime = self._url(witness.CHECKPOINT_PUBLIC_URLS[1])
        self._snapshot(beattime, '20260930120000')

        entry, asked = self._check()

        self.assertEqual(entry['status'], 'match')
        self.assertIn('beattime.live', entry['url'])
        self.assertLess(asked.index(self._cdx(sigelith)), asked.index(self._cdx(beattime)))
        self.assertEqual(self.state.alarms, [])

    def test_no_snapshot_under_either_address_is_missing(self):
        sigelith = self._url(witness.CHECKPOINT_PUBLIC_URLS[0])
        beattime = self._url(witness.CHECKPOINT_PUBLIC_URLS[1])

        entry, asked = self._check()

        self.assertEqual(entry['status'], 'missing')
        self.assertIn(self._cdx(sigelith), asked)
        self.assertIn(self._cdx(beattime), asked)

    def test_a_different_signed_copy_under_the_old_address_is_still_an_alarm(self):
        """Inna, POPRAWNIE podpisana wersja checkpointu o tym samym numerze to
        dowod podwojnej historii — pod kazdym z adresow."""
        from test_witness import _sign
        beattime = self._url(witness.CHECKPOINT_PUBLIC_URLS[1])
        self._snapshot(beattime, '20260930120000')
        body = json.loads(self.server.files[self.record.n])
        body.pop('sig')
        body['root'] = 'cd' * 32
        self.server.external[witness.WAYBACK_RAW.format(
            timestamp='20260930120000', url=beattime)] = _sign(body)

        entry, _asked = self._check()

        self.assertEqual(entry['status'], 'mismatch')
        codes = [a['code'] for a in self.state.alarms]
        self.assertIn(witness.ALARM_COPY_MISMATCH, codes)

    def test_another_checkpoint_number_is_unreadable_not_an_alarm(self):
        beattime = self._url(witness.CHECKPOINT_PUBLIC_URLS[1])
        self._snapshot(beattime, '20260930120000')
        other_n = next(n for n in self.server.files if n != self.record.n)
        self.server.external[witness.WAYBACK_RAW.format(
            timestamp='20260930120000', url=beattime)] = self.server.files[other_n]

        entry, _asked = self._check()

        self.assertEqual(entry['status'], 'unreadable')
        self.assertEqual(self.state.alarms, [])


# --- Siec ---------------------------------------------------------------------------------

class _FakeSocket:
    instances: list['_FakeSocket'] = []

    def __init__(self, af, socktype=None, proto=None):
        self.af = af
        self.timeouts = []
        self.closed = False
        _FakeSocket.instances.append(self)

    def settimeout(self, value):
        self.timeouts.append(value)

    def setsockopt(self, *args):
        pass

    def bind(self, address):
        pass

    def connect(self, address):
        if self.af == socket.AF_INET6:
            raise socket.timeout('timed out')

    def close(self):
        self.closed = True


class HappyEyeballsTests(unittest.TestCase):

    INFOS = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::1', 443, 0, 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::2', 443, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 443)),
    ]

    def setUp(self):
        _FakeSocket.instances = []
        api._FAMILY_THAT_WORKED.clear()
        self.addCleanup(api._FAMILY_THAT_WORKED.clear)

    def test_urllib3_uses_the_replacement(self):
        import urllib3.util.connection as connection
        self.assertIs(connection.create_connection, api._create_connection)

    def test_families_alternate_and_a_dead_ipv6_costs_one_short_attempt(self):
        with mock.patch.object(api, '_socket_factory', _FakeSocket), \
                mock.patch('socket.getaddrinfo', return_value=list(self.INFOS)):
            sock = api._create_connection(('example.test', 443), timeout=5.0)
        self.assertEqual(sock.af, socket.AF_INET)
        dead = _FakeSocket.instances[0]
        self.assertEqual(dead.af, socket.AF_INET6)
        self.assertEqual(dead.timeouts, [api.FALLBACK_CONNECT_SECONDS])
        self.assertTrue(dead.closed)
        self.assertEqual(len(_FakeSocket.instances), 2, 'drugi adres IPv6 nie byl potrzebny')
        self.assertEqual(sock.timeouts[-1], 5.0, 'po polaczeniu wraca limit wywolujacego')

    def test_the_family_that_worked_goes_first_next_time(self):
        with mock.patch.object(api, '_socket_factory', _FakeSocket), \
                mock.patch('socket.getaddrinfo', return_value=list(self.INFOS)):
            api._create_connection(('example.test', 443), timeout=5.0)
            _FakeSocket.instances = []
            api._create_connection(('example.test', 443), timeout=5.0)
        self.assertEqual([s.af for s in _FakeSocket.instances], [socket.AF_INET])


class ClientBehaviourTests(unittest.TestCase):

    def setUp(self):
        self.client = api.BeatTimeClient(Settings())
        self.addCleanup(self.client.close)

    def test_retry_after_is_capped(self):
        retry = api._Retry(total=2, respect_retry_after_header=True)
        response = SimpleNamespace(headers={'Retry-After': '120'})
        self.assertEqual(retry.get_retry_after(response), api._Retry.RETRY_AFTER_MAX)

    def test_status_503_is_content_not_an_error(self):
        body = json.dumps({'status': 'alert', 'checks': [{'name': 'ots', 'status': 'alert'}]})
        with mock.patch.object(self.client._session_once, 'request',
                               return_value=_response(503, body.encode())) as once, \
                mock.patch.object(self.client._session, 'request') as default:
            data = self.client.proof_status()
        self.assertEqual(data['status'], 'alert')
        self.assertEqual(once.call_count, 1)
        default.assert_not_called()

    def test_rate_limit_message_depends_on_the_endpoint(self):
        with mock.patch.object(self.client._session, 'request',
                               return_value=_response(429, b'{}', {'Retry-After': '7'})):
            with self.assertRaises(api.ApiError) as other:
                self.client.health()
            with self.assertRaises(api.ApiError) as stamp:
                self.client.stamp('a' * 64)
        self.assertNotIn('20', other.exception.message.split('.')[0])
        self.assertIn('20', stamp.exception.message)
        self.assertEqual(other.exception.retry_after, 7)

    def test_proxy_error_without_tor_does_not_blame_tor(self):
        with mock.patch.object(self.client._session, 'request',
                               side_effect=requests.exceptions.ProxyError('x')):
            with self.assertRaises(api.ApiError) as ctx:
                self.client.health()
        self.assertNotIn('Tor', ctx.exception.message)
        self.assertIn('HTTPS_PROXY', ctx.exception.message)

    def test_read_timeout_after_retries_is_reported_as_read_timeout(self):
        error = requests.exceptions.ConnectionError(
            MaxRetryError(None, '/api/health/', ReadTimeoutError(None, '/', 'read timed out')))
        with mock.patch.object(self.client._session, 'request', side_effect=error):
            with self.assertRaises(api.ApiError) as ctx:
                self.client.health()
        self.assertEqual(ctx.exception.message, _(
            'The server accepted the connection but sent no answer in time.'))

    def test_redirect_to_http_is_refused_before_it_is_requested(self):
        redirect = _response(302, b'', {'Location': 'http://example.com/file'},
                             url='https://example.org/file')
        with mock.patch.object(self.client._external, 'get', return_value=redirect) as get:
            with self.assertRaises(api.ApiError):
                self.client.fetch_external('https://example.org/file')
        self.assertEqual(get.call_count, 1, 'krok http:// nie mogl zostac wyslany')
        self.assertFalse(get.call_args.kwargs['allow_redirects'])

    def test_https_redirects_are_followed(self):
        responses = [_response(302, b'', {'Location': '/final'}, url='https://example.org/a'),
                     _response(200, b'payload', url='https://example.org/final')]
        with mock.patch.object(self.client._external, 'get', side_effect=responses) as get:
            self.assertEqual(self.client.fetch_external('https://example.org/a'), b'payload')
        self.assertEqual(get.call_args.args[0], 'https://example.org/final')

    def test_clock_sync_keeps_the_fastest_sample(self):
        calls = []

        def fake_request(method, path, **kwargs):
            calls.append(path)
            if len(calls) == 1:
                time.sleep(0.25)            # pierwsze zapytanie: DNS + TCP + TLS
            return 200, {'server_unix_ms': int(time.time() * 1000)}

        with mock.patch.object(self.client, '_request', side_effect=fake_request):
            result = self.client.sync()
        self.assertGreaterEqual(len(calls), 2)
        self.assertLess(result.round_trip_seconds, 0.2)
        self.assertLess(abs(result.offset_seconds), 0.2)


# --- Jedna kopia programu --------------------------------------------------------------------

class SingleInstanceTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    #: Druga kopia w OSOBNYM procesie — tak jak naprawde. Qt tworzy potok
    #: z buforem 0, wiec zapis konczy sie dopiero, gdy pierwsza kopia odczyta
    #: go w swojej petli zdarzen; w jednym watku oba konce czekalyby na siebie.
    SECOND_COPY = (
        'import sys\n'
        'from pathlib import Path\n'
        'sys.path.insert(0, ".")\n'
        'from PySide6.QtCore import QCoreApplication\n'
        'app = QCoreApplication([])\n'
        'from beatstamp.instance import SingleInstance\n'
        'copy = SingleInstance(Path(sys.argv[1]))\n'
        'if copy.acquire():\n'
        '    sys.exit(1)\n'
        'sys.exit(3 if copy.forward(sys.argv[2:]) else 2)\n'
    )

    def test_second_copy_forwards_files_and_steps_aside(self):
        import subprocess
        first = SingleInstance(self.dir)
        self.addCleanup(first.release)
        self.assertTrue(first.acquire())
        received = []
        first.activated.connect(received.append)
        document = r'C:\dokumenty\umowa.pdf'
        child = subprocess.Popen(
            [sys.executable, '-c', self.SECOND_COPY, str(self.dir), document],
            cwd=str(ROOT), env={**os.environ, 'QT_QPA_PLATFORM': 'offscreen'})
        deadline = time.monotonic() + 20
        while (not received or child.poll() is None) and time.monotonic() < deadline:
            QCoreApplication.processEvents()
            time.sleep(0.01)
        self.assertEqual(child.wait(5), 3, '3 = blokada zajeta, pliki przekazane')
        self.assertEqual(received, [[document]])

    def test_second_copy_in_the_same_process_sees_the_lock(self):
        first = SingleInstance(self.dir)
        self.addCleanup(first.release)
        self.assertTrue(first.acquire())
        self.assertFalse(SingleInstance(self.dir).acquire())

    def test_lock_is_free_again_after_release(self):
        first = SingleInstance(self.dir)
        self.assertTrue(first.acquire())
        first.release()
        again = SingleInstance(self.dir)
        self.addCleanup(again.release)
        self.assertTrue(again.acquire())

    def test_other_data_folders_do_not_see_each_other(self):
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        a, b = SingleInstance(self.dir), SingleInstance(Path(other.name))
        self.addCleanup(a.release)
        self.addCleanup(b.release)
        self.assertTrue(a.acquire())
        self.assertTrue(b.acquire())
        self.assertNotEqual(a.name, b.name)


# --- Pierwszenstwo uzytkownika i zamykanie ------------------------------------------------------

class _FakeTask:
    def __init__(self):
        self.cancelled = False

    def cancel(self):
        self.cancelled = True


class BackgroundTests(_TempDataDir):

    def test_user_action_pauses_the_background_check(self):
        window = self._window()
        task = _FakeTask()
        window._witness_task, window._witness_interactive = task, False
        window._pause_background()
        self.assertTrue(task.cancelled)
        self.assertTrue(window._background_paused)
        window._witness_task = None

    def test_a_check_started_by_hand_is_not_interrupted(self):
        window = self._window()
        task = _FakeTask()
        window._witness_task, window._witness_interactive = task, True
        window._pause_background()
        self.assertFalse(task.cancelled)
        window._witness_task = None

    def test_closing_cancels_background_work(self):
        window = self._window()
        tasks = [_FakeTask(), _FakeTask(), _FakeTask()]
        window._witness_task, window._quiet_task, window._sync_task = tasks
        window.close()
        self.assertTrue(all(t.cancelled for t in tasks))
        self.assertFalse(window.abandoned_workers)


# --- Okna ----------------------------------------------------------------------------------------

class WindowFitTests(_TempDataDir):

    def _available(self):
        from PySide6.QtGui import QGuiApplication
        return QGuiApplication.primaryScreen().availableGeometry()

    def test_main_window_default_size_fits_the_screen(self):
        window = self._window()
        window.settings.window_geometry = ''
        window.restore_geometry()
        area = self._available()
        self.assertLessEqual(window.height(), max(window.minimumHeight(), area.height() - 40))
        self.assertLessEqual(window.minimumHeight(), 600)

    def test_about_dialog_scrolls_instead_of_cutting(self):
        from beatstamp.ui.dialogs import AboutDialog
        dialog = AboutDialog()
        self.addCleanup(dialog.deleteLater)
        self.assertIsNotNone(dialog.findChild(QScrollArea))
        area = self._available()
        self.assertLessEqual(dialog.height(), max(dialog.minimumHeight(), area.height() - 40))

    def test_copy_button_fits_the_copied_text(self):
        from PySide6.QtWidgets import QPushButton
        from beatstamp.ui.widgets import CopyField
        field = CopyField()
        self.addCleanup(field.deleteLater)
        probe = QPushButton(_('Copied'))
        from beatstamp.ui import icons
        icons.apply(probe, 'copy')
        self.assertGreaterEqual(field._button.width(), probe.sizeHint().width())

    def test_combo_and_spin_boxes_have_arrows(self):
        sheet = theme.stylesheet(theme.resolve('light'))
        for rule in ('QComboBox::down-arrow', 'QSpinBox::up-arrow', 'QSpinBox::down-arrow'):
            self.assertIn(rule, sheet)
        for name in ('chevron-down', 'chevron-up'):
            path = Path(theme._tinted_icon(name, '#123456'))
            self.assertTrue(path.is_file(), name)


# --- Fuzzing: dane z pliku i z serwera ------------------------------------------------------------

class VerifiedViewTests(unittest.TestCase):
    """Okno „Szczegoly" dowodu .beatproof widzi tylko to, co sprawdzono lokalnie."""

    FORGED = {
        'level': 'anchored', 'verified_ok': True, 'trusted': True, 'week_closed': True,
        'ots_status': 'bitcoin', 'ots_bitcoin_height': 900000,
        'anchors': [{'bank': 'Swissquote', 'status': 'confirmed'}],
        'time': {'not_after': {'source': 'opentimestamps', 'height': 800000}},
        'checkpoint': {'n': 1, 'verified': True}, 'copies': {'github': 'x'},
        'digest': 'ab' * 32, 'file_name': 'umowa.pdf',
    }

    def test_a_rejected_proof_shows_nothing_it_claims(self):
        from beatstamp import bundle
        check = bundle.BundleCheck(ok=False, signature_ok=False, problems=['signature invalid'],
                                   checkpoint_ok=False, checkpoint_n=1)
        view = bundle.verified_view(self.FORGED, check)
        self.assertEqual(view['level'], 'none')
        self.assertFalse(view['verified_ok'])
        self.assertFalse(view['trusted'])
        self.assertEqual(view['ots_status'], 'none')
        self.assertNotIn('ots_bitcoin_height', view)
        self.assertEqual(view['anchors'], [])
        self.assertEqual(view['time'], {})
        self.assertNotIn('copies', view)
        self.assertEqual(view['checkpoint'], {'n': 1, 'verified': False})
        self.assertEqual(view['problems'], ['signature invalid'])
        self.assertEqual(view['file_name'], 'umowa.pdf')

    def test_a_confirmed_proof_is_at_most_signed(self):
        from beatstamp import bundle
        check = bundle.BundleCheck(ok=True, signature_ok=True, key_pinned_ok=True,
                                   checkpoint_ok=True, checkpoint_n=1)
        view = bundle.verified_view(self.FORGED, check)
        self.assertEqual(view['level'], 'signed', 'OTS i banku offline nie sprawdzimy')
        self.assertTrue(view['checkpoint']['verified'])
        self.assertEqual(view['anchors'], [])


class HostileServerTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = witness.WitnessStore(Path(self.tmp.name))
        self.state = witness.WitnessState()

    def _refresh(self, server, third_party=False):
        return witness.refresh(server, self.store, self.state, None, mode=witness.MODE_FAST,
                               override=TEST_KEY, third_party=third_party)

    def test_a_huge_checkpoint_number_does_not_allocate_memory(self):
        server = FakeServer()
        self._refresh(server)
        server.checkpoint_latest = lambda: {'n': 10 ** 12, 'hash': 'x'}
        started = time.monotonic()
        report = self._refresh(server)
        self.assertLess(time.monotonic() - started, 5)
        self.assertTrue(report.more or report.errors or self.state.last_error)

    def test_malformed_archive_answers_do_not_lose_the_run(self):
        server = FakeServer()
        self._refresh(server)
        weekly = [r for r in self.state.checkpoints.values() if r.kind == 'weekly'][0]
        original = witness.CHECKPOINT_PUBLIC.format(name=logtree.checkpoint_filename(weekly.n))
        cdx = witness.WAYBACK_CDX.format(url=original, since=weekly.utc_dt.strftime('%Y%m%d'))
        for payload in (b'{}', b'null', b'42', b'[[1,2]'):
            with self.subTest(payload=payload):
                server.external[cdx] = payload
                self.state.copies = {}
                report = self._refresh(server, third_party=True)
                self.assertEqual(self.state.last_error, '')
                self.assertTrue(self.state.checkpoints)
                self.assertTrue(any('Internet Archive' in e for e in report.errors) or
                                payload == b'[[1,2]')


class DamagedLocalFileTests(unittest.TestCase):

    def test_strict_json_rejects_non_finite_and_deep_nesting(self):
        from beatstamp.config import json_loads
        for text in ('{"a": Infinity}', '{"a": NaN}', '{"a": 1e999}', '[' * 100000 + ']' * 100000):
            with self.subTest(text=text[:20]):
                with self.assertRaises(ValueError):
                    json_loads(text)
        self.assertEqual(json_loads('{"a": 1.5}'), {'a': 1.5})

    def test_settings_with_infinity_fall_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {'SIGELITH_DATA_DIR': tmp}):
            (Path(tmp) / 'settings.json').write_text('{"timeout_seconds": 1e999}', encoding='utf-8')
            self.assertIsInstance(Settings.load(), Settings)

    def test_deeply_nested_history_is_set_aside(self):
        from beatstamp.history import History
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'history.json'
            path.write_text('[' * 100000 + ']' * 100000, encoding='utf-8')
            history = History(path).load()
            self.assertEqual(history.entries, [])
            self.assertTrue(history.load_problem)

    def test_witness_state_with_wrong_types_starts_over(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = witness.WitnessStore(Path(tmp))
            store.state_path.parent.mkdir(parents=True, exist_ok=True)
            for text in ('{"checkpoints": "x"}', '{"checkpoints": {"1": {"n": 1e999}}}',
                         '[' * 100000 + ']' * 100000):
                with self.subTest(text=text[:25]):
                    store.state_path.write_text(text, encoding='utf-8')
                    self.assertEqual(store.load().checkpoints, {})

    def test_out_of_range_dates_do_not_raise(self):
        from beatstamp import beatcore
        for year in (1000, 1969, 9999):
            with self.subTest(year=year):
                text = beatcore.local_str(datetime(year, 6, 1, tzinfo=timezone.utc))
                self.assertIn(str(year), text)

    def test_reserved_device_names_are_defused(self):
        from beatstamp import naming
        for name in ('CON', 'con.txt', 'NUL.tar', 'COM¹', 'LPT³.pdf', 'CONOUT$'):
            with self.subTest(name=name):
                self.assertTrue(naming.safe_component(name).startswith('_'))
        self.assertEqual(naming.safe_component('Contract'), 'Contract')

    def test_a_very_long_note_still_gives_a_certificate(self):
        from beatstamp import certificate
        from beatstamp.history import Entry
        entry = Entry(digest='ab' * 32, file_name='x' * 20000, note='notatka ' * 3000,
                      utc='2026-09-27T10:00:00Z', beat='@458.33')
        self.assertTrue(certificate.build_certificate(entry).startswith(b'%PDF'))


class PlainTextSinkTests(_TempDataDir):
    """Tresc od serwera trafia do etykiet jako ZWYKLY tekst (bez HTML)."""

    def test_witness_panel_lines_are_plain_text(self):
        from PySide6.QtCore import Qt
        from beatstamp.ui.witness_panel import WitnessPanel
        panel = WitnessPanel()
        self.addCleanup(panel.deleteLater)
        for widget in (panel.subline, panel.pipeline, panel.headline):
            self.assertEqual(widget.textFormat(), Qt.PlainText)
        for card in panel.cards.values():
            self.assertEqual(card.caption.textFormat(), Qt.PlainText)
            self.assertEqual(card.value.textFormat(), Qt.PlainText)

    def test_overlay_text_is_plain(self):
        from PySide6.QtCore import Qt
        window = self._window()
        self.assertEqual(window.overlay.detail.textFormat(), Qt.PlainText)
        self.assertEqual(window.status_connection.textFormat(), Qt.PlainText)


class RightToLeftBlockTests(unittest.TestCase):

    def tearDown(self):
        i18n.set_language('pl')

    def test_arabic_labels_start_with_a_right_to_left_mark(self):
        i18n.set_language('ar')
        self.assertTrue(i18n.rtl_block('#2').startswith(i18n.RLM))
        self.assertEqual(i18n.rtl_block(i18n.rtl_block('x')).count(i18n.RLM), 1)
        i18n.set_language('pl')
        self.assertEqual(i18n.rtl_block('#2'), '#2')


if __name__ == '__main__':
    unittest.main()
