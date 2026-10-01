"""
Swiadek (`beatstamp/witness.py`) na atrapie serwera — bez sieci.

Atrapa podaje wektory z LOG.md §10 (trzy wpisy, dwa checkpointy podpisane
kluczem testowym). Klucz testowy wchodzi jako WLASNY klucz z ustawien —
dzieki temu sprawdzamy prawdziwa sciezke zaufania, a nie obejscie.

Najwazniejsze testy to te, w ktorych serwer klamie: dwie rozne historie pod
jednym numerem, checkpoint nieprzedluzajacy poprzedniego, inna kopia
u osoby trzeciej, przepisany wpis w dzienniku. Kazdy z nich MUSI skonczyc
sie alarmem z materialem dowodowym na dysku.
"""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from beatstamp import logtree, witness  # noqa: E402
from beatstamp.api import ApiError  # noqa: E402
from test_logtree import (  # noqa: E402
    CHECKPOINT_1,
    CHECKPOINT_2,
    DUMP,
    TEST_KEY,
)


SEED = b'\x11' * 32
ENTRIES = [json.loads(line) for line in DUMP.splitlines()]


def _sign(body: dict) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    sig = base64.b64encode(key.sign(logtree.signing_message(body))).decode('ascii')
    return logtree.canonical_json({**body, 'sig': sig})


class FakeServer:
    """Atrapa API BeatTime + osob trzecich. Zapisuje, o co pytano."""

    def __init__(self):
        self.files = {1: CHECKPOINT_1, 2: CHECKPOINT_2}
        self.entries_list = list(ENTRIES)
        self.external: dict[str, bytes] = {}
        self.asked_verify: list[str] = []
        self.weeks: dict[str, dict] = {}
        self.consistency_override = None

    # --- API BeatTime ---
    def checkpoint_latest(self):
        n = max(self.files)
        return {'n': n, 'hash': logtree.checkpoint_hash(self.files[n])}

    def checkpoint(self, n):
        if n not in self.files:
            return None
        return {'n': n, 'hash': logtree.checkpoint_hash(self.files[n]),
                'ots_status': 'bitcoin', 'ots_height': 916010,
                'ots_time': '2026-10-05T03:00:00Z', 'btc_time': '2026-09-28T09:30:00Z',
                'copies': {'week': '2026-W40', 'github': '', 'wayback': '', 'zenodo': ''}}

    def checkpoint_file(self, n):
        if n not in self.files:
            raise ApiError('404', status=404)
        return self.files[n]

    def consistency(self, first, second):
        if self.consistency_override is not None:
            return {'proof': self.consistency_override}
        leaves = [logtree.parse_entry(e).leaf for e in self.entries_list][:second]
        return {'proof': [h.hex() for h in logtree.consistency_proof(first, leaves)]}

    def entries(self, start, limit=1000):
        rows = [e for e in self.entries_list if e['seq'] >= start][:limit]
        return {'entries': rows, 'next': None}

    def proof_status(self):
        return {'status': 'ok', 'checks': [{'name': 'x', 'status': 'ok'}]}

    def week(self, week_key):
        return self.weeks.get(week_key)

    def verify(self, digest):
        self.asked_verify.append(digest)
        return {'found': False, 'digest': digest}

    # --- Osoby trzecie ---
    def fetch_external(self, url, **_kw):
        return self.external.get(url)


class _Base(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.store = witness.WitnessStore(self.dir)
        self.state = witness.WitnessState()
        self.mirror = witness.LogMirror(self.dir / 'log.jsonl')
        self.server = FakeServer()

    def refresh(self, mode=witness.MODE_PRIVATE, third_party=False):
        return witness.refresh(self.server, self.store, self.state,
                               self.mirror if mode == witness.MODE_PRIVATE else None,
                               mode=mode, override=TEST_KEY, third_party=third_party)

    def codes(self):
        return [a['code'] for a in self.state.alarms]


class HonestLogTests(_Base):

    def test_the_chain_is_verified_and_stored(self):
        report = self.refresh()
        self.assertEqual(report.new_checkpoints, 2)
        self.assertEqual(self.state.verified_n, 2)
        self.assertTrue(self.state.checkpoints[2].consistent)
        self.assertTrue(self.state.checkpoints[1].audited)
        self.assertTrue(self.state.checkpoints[2].audited)
        self.assertEqual(self.store.read_checkpoint(2), CHECKPOINT_2)
        self.assertEqual(self.state.alarms, [])
        self.assertEqual(self.state.log_size, 3)

    def test_the_state_survives_a_restart(self):
        self.refresh()
        self.store.save(self.state)
        again = witness.WitnessStore(self.dir).load()
        self.assertEqual(again.verified_n, 2)
        self.assertEqual(again.checkpoints[2].hash, self.state.checkpoints[2].hash)

    def test_without_the_trusted_key_nothing_is_accepted(self):
        report = witness.refresh(self.server, self.store, self.state, self.mirror)
        self.assertEqual(report.new_checkpoints, 0)
        self.assertIn(witness.ALARM_SIGNATURE, self.codes())

    def test_a_second_run_asks_only_for_what_is_new(self):
        self.refresh()
        report = self.refresh()
        self.assertEqual(report.new_checkpoints, 0)
        self.assertEqual(report.new_entries, 0)
        self.assertEqual(self.state.alarms, [])


class LyingServerTests(_Base):
    """Kazde klamstwo konczy sie alarmem z dowodem na dysku."""

    def _evidence(self) -> list[Path]:
        return sorted((self.dir / 'evidence').glob('*'))

    def test_two_different_signed_files_under_one_number(self):
        self.refresh()
        body = json.loads(CHECKPOINT_2)
        body.pop('sig')
        body['utc'] = '2026-10-05T00:16:00.000000Z'
        self.server.files[2] = _sign(body)
        self.refresh()
        self.assertIn(witness.ALARM_EQUIVOCATION, self.codes())
        self.assertEqual(len(self._evidence()), 2)

    def test_a_checkpoint_that_does_not_continue_the_chain(self):
        self.server.files = {1: CHECKPOINT_1}
        self.refresh()
        body = json.loads(CHECKPOINT_2)
        body.pop('sig')
        body['prev'] = '00' * 32
        self.server.files[2] = _sign(body)
        self.refresh()
        self.assertIn(witness.ALARM_FORK, self.codes())
        self.assertEqual(self.state.verified_n, 1)

    def test_a_checkpoint_that_does_not_extend_the_previous_one(self):
        self.server.consistency_override = ['00' * 32]
        self.refresh(mode=witness.MODE_FAST)
        self.assertIn(witness.ALARM_CONSISTENCY, self.codes())
        self.assertEqual(self.state.verified_n, 1)

    def test_a_rewritten_entry_breaks_the_mirror(self):
        self.refresh()
        forged = dict(ENTRIES[2])
        forged['digest'] = 'ab' * 32
        self.mirror.path.write_text('', encoding='utf-8')
        mirror = witness.LogMirror(self.dir / 'log.jsonl')
        self.mirror = mirror
        self.server.entries_list = [ENTRIES[0], ENTRIES[1], forged]
        self.refresh()
        self.assertIn(witness.ALARM_LOG_REWRITTEN, self.codes())

    def test_a_different_signed_copy_at_github_is_proof_of_a_split_view(self):
        self.refresh()
        body = json.loads(CHECKPOINT_2)
        body.pop('sig')
        body['root'] = 'cd' * 32
        other = _sign(body)
        name = logtree.checkpoint_filename(2)
        self.server.external[witness.GITHUB_ASSET.format(
            repo=witness.GITHUB_REPO, week='2026-W40', name=logtree.checkpoint_filename(1))] = CHECKPOINT_1
        self.server.external[witness.GITHUB_ASSET.format(
            repo=witness.GITHUB_REPO, week='2026-W40', name=name)] = other
        report = witness.RefreshReport()
        witness.check_copies(self.server, self.store, self.state, report, override=TEST_KEY)
        alarms = [a for a in self.state.alarms if a['code'] == witness.ALARM_COPY_MISMATCH]
        self.assertEqual(alarms[0]['severity'], 'critical')
        self.assertEqual(self.state.copy_max('github'), 0)

    def _copy_status(self, payload: bytes) -> str:
        self.refresh()
        url = witness.GITHUB_ASSET.format(repo=witness.GITHUB_REPO, week='2026-W40',
                                          name=logtree.checkpoint_filename(1))
        self.server.external[url] = payload
        report = witness.RefreshReport()
        witness.check_copies(self.server, self.store, self.state, report, override=TEST_KEY)
        alarms = [a for a in self.state.alarms if a['code'] == witness.ALARM_COPY_MISMATCH]
        self.assertEqual(alarms, [], 'kopia bez waznego podpisu niczego nie dowodzi')
        return self.state.copies['github']['weeks']['2026-W40']['status']

    def test_a_damaged_copy_is_unreadable_not_an_alarm(self):
        """Do 2.2.0 uszkodzona kopia byla ostrzezeniem — i pierwsze ostrzezenie
        wywracalo okno przy kazdym starcie. Kopia, ktora nie jest poprawnie
        podpisanym checkpointem, nie mowi nic o BeatTime: ani za, ani przeciw."""
        self.assertEqual(self._copy_status(b'{"broken": true}'), 'unreadable')

    def test_a_zstd_snapshot_is_unreadable_not_an_alarm(self):
        """Internet Archive odtwarza migawke w kompresji, w jakiej ja zapisal —
        takze zstd (magiczne bajty 28 b5 2f fd), ktorego klient nie rozpakowuje."""
        self.assertEqual(self._copy_status(b'\x28\xb5\x2f\xfd' + b'\x00' * 40), 'unreadable')

    def test_an_unreadable_copy_is_retried_daily_not_every_three_hours(self):
        self._copy_status(b'garbage')
        entry = self.state.copies['github']['weeks']['2026-W40']
        checked = witness._parse_iso(entry['checked'])
        self.assertFalse(witness._due(entry, checked + witness.COPY_RETRY))
        self.assertTrue(witness._due(entry, checked + witness.COPY_RETRY_SLOW))


class WaybackTests(_Base):
    """Internet Archive: migawka pliku checkpointu tygodniowego (witness.check_copies)."""

    def _setup(self):
        self.refresh()
        record = next(r for r in self.state.checkpoints.values() if r.kind == 'weekly')
        original = witness.CHECKPOINT_PUBLIC.format(name=logtree.checkpoint_filename(record.n))
        return record, original, record.utc_dt.strftime('%Y%m%d')

    def _check(self):
        report = witness.RefreshReport()
        witness.check_copies(self.server, self.store, self.state, report, override=TEST_KEY)
        return report

    def _entry(self, record):
        return self.state.copies['wayback']['weeks'][record.week]

    def test_snapshot_found_through_the_index(self):
        record, original, since = self._setup()
        self.server.external[witness.WAYBACK_CDX.format(url=original, since=since)] = json.dumps(
            [['timestamp', 'digest'], ['20261005021054', 'X']]).encode()
        self.server.external[witness.WAYBACK_RAW.format(
            timestamp='20261005021054', url=original)] = self.server.files[record.n]
        self._check()
        self.assertEqual(self._entry(record)['status'], 'match')
        self.assertIn('20261005021054', self._entry(record)['url'])
        self.assertEqual(self.state.copy_max('wayback'), record.n)

    def test_snapshot_found_when_the_index_is_down(self):
        """2026-09-29: indeks CDX odpowiadal strona „Temporarily Offline” (HTML
        zamiast JSON), a migawka byla i dawala sie odtworzyc — aplikacja
        pokazywala „czeka na Internet Archive”. Adres z sama data prowadzi
        przekierowaniem do migawki; bajty i tak porownujemy z naszymi."""
        record, original, since = self._setup()
        self.server.external[witness.WAYBACK_CDX.format(url=original, since=since)] = (
            b'<html><title>Internet Archive: Temporarily Offline</title></html>')
        self.server.external[witness.WAYBACK_RAW.format(
            timestamp=f'{since}000000', url=original)] = self.server.files[record.n]
        report = self._check()
        self.assertEqual(self._entry(record)['status'], 'match')
        self.assertEqual(self.state.copy_max('wayback'), record.n)
        self.assertEqual([e for e in report.errors if 'Internet Archive' in e], [],
                         'obejscie zadzialalo — bez komunikatu o bledzie')

    def test_snapshot_newer_than_the_index(self):
        """Indeks CDX bywa o godziny spozniony wobec swiezej migawki."""
        record, original, since = self._setup()
        self.server.external[witness.WAYBACK_CDX.format(url=original, since=since)] = b'[]'
        self.server.external[witness.WAYBACK_RAW.format(
            timestamp=f'{since}000000', url=original)] = self.server.files[record.n]
        self._check()
        self.assertEqual(self._entry(record)['status'], 'match')

    def test_an_archive_that_does_not_answer_is_not_a_missing_copy(self):
        record, original, since = self._setup()
        outage = b'<html><title>Internet Archive: Temporarily Offline</title></html>'
        self.server.external[witness.WAYBACK_CDX.format(url=original, since=since)] = outage
        self.server.external[witness.WAYBACK_RAW.format(
            timestamp=f'{since}000000', url=original)] = outage
        report = self._check()
        entry = self._entry(record)
        self.assertEqual(entry['status'], 'unavailable')
        self.assertTrue(any('Internet Archive' in e for e in report.errors))
        checked = witness._parse_iso(entry['checked'])
        self.assertTrue(witness._due(entry, checked + witness.COPY_RETRY), 'ponawiane co 3 h')
        self.assertEqual(self.state.alarms, [])

    def test_really_missing_stays_missing(self):
        record, _original, _since = self._setup()
        self._check()
        self.assertEqual(self._entry(record)['status'], 'missing')

    def test_github_that_does_not_answer_is_not_a_missing_release(self):
        self.refresh()

        def down(url, **_kw):
            raise ApiError('No connection to github.com.')
        self.server.fetch_external = down
        self._check()
        self.assertEqual(self.state.copies['github']['weeks']['2026-W40']['status'],
                         'unavailable')
        self.assertEqual(self.state.alarms, [])


class CopiesTests(_Base):

    def test_an_identical_release_pins_every_earlier_checkpoint(self):
        self.refresh()
        for n in (1, 2):
            self.server.external[witness.GITHUB_ASSET.format(
                repo=witness.GITHUB_REPO, week='2026-W40',
                name=logtree.checkpoint_filename(n))] = self.server.files[n]
        report = witness.RefreshReport()
        witness.check_copies(self.server, self.store, self.state, report, override=TEST_KEY)
        self.assertEqual(self.state.copy_max('github'), 2)
        pin = witness.pinning({'n': 1, 'verified': True}, self.state)
        self.assertTrue(pin.github)
        self.assertFalse(pin.wayback)

    def test_a_missing_release_is_retried_later_not_every_run(self):
        self.refresh()
        report = witness.RefreshReport()
        witness.check_copies(self.server, self.store, self.state, report, override=TEST_KEY)
        entry = self.state.copies['github']['weeks']['2026-W40']
        self.assertEqual(entry['status'], 'missing')
        self.assertFalse(witness._due(entry, datetime.now(timezone.utc)))
        self.assertTrue(witness._due(entry, datetime.now(timezone.utc) + timedelta(hours=4)))


class PrivateVerificationTests(_Base):
    """Tryb prywatny nie mowi serwerowi, ktory wpis nas interesuje."""

    def setUp(self):
        super().setUp()
        self.refresh()
        week_leaves = [logtree.week_leaf_hash(e['digest']) for e in ENTRIES]
        self.server.weeks['2026-W40'] = {
            'week': '2026-W40', 'closed': False, 'size': 3}
        self.week_root = logtree.merkle_root(week_leaves).hex()

    def test_the_server_is_never_asked_about_our_digest(self):
        digest = ENTRIES[2]['digest']
        result = witness.verify_private(self.server, digest, self.state, self.mirror)
        self.assertTrue(result.found)
        self.assertEqual(self.server.asked_verify, [])
        self.assertTrue(result.inclusion_ok)
        self.assertEqual(result.week_root, self.week_root)
        self.assertEqual(result.checkpoint['n'], 2)
        self.assertTrue(result.checkpoint['verified'])
        self.assertEqual(result.log_index, 2)
        self.assertEqual(result.witness_mode, witness.MODE_PRIVATE)

    def test_the_lower_bound_comes_from_the_checkpoint_before_the_entry(self):
        result = witness.verify_private(self.server, ENTRIES[2]['digest'],
                                        self.state, self.mirror)
        bound = result.time_bounds['not_before']
        self.assertEqual(bound['checkpoint'], 1)
        self.assertEqual(bound['height'], 916000)

    def test_an_unknown_digest_is_not_found_after_one_sync(self):
        result = witness.verify_private(self.server, 'ef' * 32, self.state, self.mirror)
        self.assertFalse(result.found)
        self.assertEqual(self.server.asked_verify, [])

    def test_a_server_root_that_contradicts_the_log_is_a_problem(self):
        self.server.weeks['2026-W40'] = {'week': '2026-W40', 'closed': True,
                                         'week_root': 'ab' * 32}
        result = witness.verify_private(self.server, ENTRIES[0]['digest'],
                                        self.state, self.mirror)
        self.assertTrue(result.problems)
        self.assertFalse(result.trusted)


class FastVerificationTests(_Base):

    def setUp(self):
        super().setUp()
        self.refresh(mode=witness.MODE_FAST)

    def _payload(self, path):
        e = ENTRIES[2]
        return {'found': True, 'digest': e['digest'], 'seq': e['seq'], 'utc': e['utc'],
                'beat': '@500.00', 'week': e['week'],
                'checkpoint': {'n': 2, 'tree_size': 3, 'leaf_index': 2, 'audit_path': path},
                'time': {'not_before': {'source': 'bitcoin_block', 'checkpoint': 1,
                                        'height': 1, 'hash': '00' * 32}}}

    def _result(self, payload):
        from beatstamp import proof
        result = proof.verify_payload(payload, expected_digest=ENTRIES[2]['digest'])
        witness.enrich_from_payload(result, self.state, payload)
        return result

    def test_the_path_is_checked_against_our_own_checkpoint_file(self):
        leaves = [logtree.parse_entry(e).leaf for e in ENTRIES]
        path = [h.hex() for h in logtree.audit_path(2, leaves)]
        result = self._result(self._payload(path))
        self.assertTrue(result.checkpoint['verified'])
        # Blok „nie wczesniej niz" bierzemy z NASZEGO pliku #1, nie z odpowiedzi.
        self.assertEqual(result.time_bounds['not_before']['height'], 916000)

    def test_a_wrong_path_is_a_problem(self):
        result = self._result(self._payload(['00' * 32]))
        self.assertFalse(result.checkpoint['verified'])
        self.assertTrue(result.problems)


class NextEventsTests(unittest.TestCase):

    def test_events_are_in_the_future_and_sorted(self):
        now = datetime(2026, 9, 26, 19, 0, tzinfo=timezone.utc)
        events = witness.next_events(witness.WitnessState(), now)
        moments = [witness._parse_iso(e['at']) for e in events]
        self.assertEqual(moments, sorted(moments))
        self.assertTrue(all(m > now for m in moments))
        weekly = next(e for e in events if e['kind'] == 'weekly')
        self.assertEqual(weekly['week'], '2026-W39')


if __name__ == '__main__':
    unittest.main()
