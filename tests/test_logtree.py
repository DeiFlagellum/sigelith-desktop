"""
Dziennik globalny po stronie klienta (`beatstamp/logtree.py`).

Dwie niezalezne siatki:

* **wektory z LOG.md §10** — liczby przepisane z zamrozonej specyfikacji,
  znak w znak. Jesli ktorys z tych testow sie przewroci, to nie „drobna
  roznica w implementacji": aplikacja przestalaby rozumiec checkpointy,
  ktore juz leza u osob trzecich;
* **parytet z serwerem** — te same drzewa, sciezki i dowody spojnosci
  liczone kodem `apps/tsa/merkle.py` (ladowanym ze sciezki, bez Django).
  Gdy desktop/ zyje poza monorepo, test jest pomijany.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import random
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from beatstamp import logtree  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_MERKLE = REPO_ROOT / 'apps' / 'tsa' / 'merkle.py'
LOG_MD = REPO_ROOT / 'apps' / 'tsa' / 'LOG.md'

# --- Wektory z LOG.md §10 ---------------------------------------------------

TEST_KEY = '0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc='

ENTRIES = [
    (1, 'd426a3a1df05344e837b26a904177329f16f15aa4f9f934aa53d5c091a45cf0a',
     datetime(2026, 9, 28, 0, 0, 0, 0, tzinfo=timezone.utc),
     'efd38a142ae66a266850702366269e31e7b1d70ca54eb266cad2f74a09b687ec'),
    (2, 'cd53115f14511240719ef645d2cc250c84b6c8e3a3187951c9cba54fb3850436',
     datetime(2026, 9, 28, 9, 6, 3, 926713, tzinfo=timezone.utc),
     'c6e7db99f5c4fe429bd54203c35c0940ee415fa7d1aecb585cc40cd54815126a'),
    (4, '3e6f0b0a97d1c5062629486dc6c632db1a5339c3d2bc49d3634d4bfa97b6a126',
     datetime(2026, 9, 28, 12, 0, 0, 500000, tzinfo=timezone.utc),
     'e424f49b574def86c8ac3d14ec22cb8da83fac8b8a1c2f243ed71303402f5af2'),
]

LEAVES = [
    '0f57b2d73aadfbebd3812acfc7c8ecb1fec4d43f763ce42141dbb0bd248fb2fd',
    'c13ae1ced21b7446b6cf87a8a54ce3b7f220461a8594bc2568c359b1e1f530d9',
    'fb28b9655ce639c2941c3f5857cf8cd3488e8ed9ce052f345e45243851d554fa',
]

ROOT_2 = 'f636e996038a2392ee6bcd3d282a7389d87d9ae1b7c7c369c25b27e5f2537cce'
ROOT_3 = 'bda0c891af7812124648447e1402ec9a9af54ced96e5600ac017f01512d5428d'
WEEK_ROOT = '0226899a6c7e872ac110d42d2b27fda0e931c59d2c7670fccfa2a28c2eb847f9'

DUMP = (
    '{"chain_hash":"efd38a142ae66a266850702366269e31e7b1d70ca54eb266cad2f74a09b687ec","digest":"d426a3a1df05344e837b26a904177329f16f15aa4f9f934aa53d5c091a45cf0a","prev_chain":"0000000000000000000000000000000000000000000000000000000000000000","seq":1,"utc":"2026-09-28T00:00:00.000000Z","week":"2026-W40"}\n'
    '{"chain_hash":"c6e7db99f5c4fe429bd54203c35c0940ee415fa7d1aecb585cc40cd54815126a","digest":"cd53115f14511240719ef645d2cc250c84b6c8e3a3187951c9cba54fb3850436","prev_chain":"efd38a142ae66a266850702366269e31e7b1d70ca54eb266cad2f74a09b687ec","seq":2,"utc":"2026-09-28T09:06:03.926713Z","week":"2026-W40"}\n'
    '{"chain_hash":"e424f49b574def86c8ac3d14ec22cb8da83fac8b8a1c2f243ed71303402f5af2","digest":"3e6f0b0a97d1c5062629486dc6c632db1a5339c3d2bc49d3634d4bfa97b6a126","prev_chain":"c6e7db99f5c4fe429bd54203c35c0940ee415fa7d1aecb585cc40cd54815126a","seq":4,"utc":"2026-09-28T12:00:00.500000Z","week":"2026-W40"}\n'
)
DUMP_SHA = 'e73986538f8bf1eefd48ef0a1591b782e52230ad13e54ba830f9309ff6a748bf'

CHECKPOINT_1 = (
    '{"btc":{"hash":"1bf5637622b2106ff2bad6553db76afe94489326ebb36d4372e74f238cfeff17","height":916000},"format":"beattime-checkpoint-v1","key":"0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=","kind":"daily","last_chain_hash":"c6e7db99f5c4fe429bd54203c35c0940ee415fa7d1aecb585cc40cd54815126a","last_seq":2,"n":1,"prev":null,"root":"f636e996038a2392ee6bcd3d282a7389d87d9ae1b7c7c369c25b27e5f2537cce","sig":"7u5sfBIxcT2sbTAgJlgWALvI9+u/tA3E79jDGjHqnirbTyU7A/HOaV2+bQwh6zwzXvLeQZZap8VioTbMES+GCQ==","tree_size":2,"utc":"2026-09-28T10:00:00.000000Z"}'
).encode('utf-8')
CHECKPOINT_1_HASH = '277cd363f8361a589e44310b6cec12ee3c3b342ea7ecc0eacf7e30e5f4337564'

CHECKPOINT_2 = (
    '{"anchors":[{"bank":"Testbank","booked":"2026-09-29","reference":"1234567890","title":"MROOT 2026W39 3d67612c 29fad1ed 7e105292 787266e0 2432e080 67a82fbc 2d94e5c9 40e886ef","week":"2026-W39"}],"btc":null,"dump":{"file":"2026-W40.jsonl","sha256":"e73986538f8bf1eefd48ef0a1591b782e52230ad13e54ba830f9309ff6a748bf"},"format":"beattime-checkpoint-v1","key":"0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=","kind":"weekly","last_chain_hash":"e424f49b574def86c8ac3d14ec22cb8da83fac8b8a1c2f243ed71303402f5af2","last_seq":4,"n":2,"prev":"277cd363f8361a589e44310b6cec12ee3c3b342ea7ecc0eacf7e30e5f4337564","root":"bda0c891af7812124648447e1402ec9a9af54ced96e5600ac017f01512d5428d","sig":"Kt3Yo/sjsJCAlXEcvPLYyhSr+zL1x18owJ5hubOQkDtUDkHJvEkvxpAxoF5j8x9myFTIVRjgprxxPBdD9zyODQ==","tree_size":3,"utc":"2026-10-05T00:15:00.000000Z","week":"2026-W40","week_root":"0226899a6c7e872ac110d42d2b27fda0e931c59d2c7670fccfa2a28c2eb847f9","week_size":3}'
).encode('utf-8')
CHECKPOINT_2_HASH = '92f9a4209a5473ab348b7dfbfeca29333b4c572759a3db0c8015dde94523dd68'


def _vector_leaves() -> list[bytes]:
    return [logtree.entry_leaf_hash(seq, digest, dt) for seq, digest, dt, _c in ENTRIES]


class SpecVectorTests(unittest.TestCase):
    """Liczby z LOG.md §10 — zamrozone razem z formatami."""

    def test_the_vectors_are_the_ones_in_the_spec(self):
        # Wektory przepisane do tego pliku musza wciaz stac w LOG.md —
        # inaczej test pilnowalby kopii, a nie specyfikacji.
        if not LOG_MD.is_file():
            self.skipTest('desktop/ poza monorepo — brak LOG.md')
        text = LOG_MD.read_text(encoding='utf-8')
        for value in (ROOT_2, ROOT_3, WEEK_ROOT, DUMP_SHA, CHECKPOINT_1_HASH,
                      CHECKPOINT_2_HASH, *LEAVES):
            self.assertIn(value, text)
        self.assertIn(CHECKPOINT_1.decode('utf-8'), text)
        self.assertIn(CHECKPOINT_2.decode('utf-8'), text)

    def test_chain_utc_drops_the_fraction_for_zero_microseconds(self):
        self.assertEqual(logtree.chain_utc(ENTRIES[0][2]), '2026-09-28T00:00:00+00:00')
        self.assertEqual(logtree.chain_utc(ENTRIES[1][2]),
                         '2026-09-28T09:06:03.926713+00:00')
        self.assertEqual(logtree.canonical_utc(ENTRIES[0][2]),
                         '2026-09-28T00:00:00.000000Z')

    def test_chain_hashes(self):
        prev = logtree.GENESIS
        for seq, digest, dt, expected in ENTRIES:
            self.assertEqual(logtree.chain_hash(prev, digest, dt), expected, seq)
            prev = expected

    def test_global_leaves_and_roots(self):
        leaves = _vector_leaves()
        self.assertEqual([leaf.hex() for leaf in leaves], LEAVES)
        self.assertEqual(logtree.merkle_root(leaves[:2]).hex(), ROOT_2)
        self.assertEqual(logtree.merkle_root(leaves).hex(), ROOT_3)

    def test_weekly_root(self):
        leaves = [logtree.week_leaf_hash(digest) for _s, digest, _d, _c in ENTRIES]
        self.assertEqual(logtree.merkle_root(leaves).hex(), WEEK_ROOT)

    def test_audit_path_of_seq_4(self):
        leaves = _vector_leaves()
        path = logtree.audit_path(2, leaves)
        self.assertEqual([p.hex() for p in path], [ROOT_2])
        self.assertTrue(logtree.verify_inclusion(leaves[2], 2, 3, path,
                                                 bytes.fromhex(ROOT_3)))
        self.assertFalse(logtree.verify_inclusion(leaves[1], 2, 3, path,
                                                  bytes.fromhex(ROOT_3)))

    def test_consistency_between_the_two_checkpoints(self):
        leaves = _vector_leaves()
        proof = logtree.consistency_proof(2, leaves)
        self.assertTrue(logtree.verify_consistency(
            2, 3, bytes.fromhex(ROOT_2), bytes.fromhex(ROOT_3), proof))
        # Podmieniony korzen starszego drzewa = dowod przestaje przechodzic.
        self.assertFalse(logtree.verify_consistency(
            2, 3, bytes.fromhex(ROOT_3), bytes.fromhex(ROOT_3), proof))

    def test_dump_lines_parse_and_chain(self):
        entries = [logtree.parse_entry(json.loads(line))
                   for line in DUMP.splitlines()]
        logtree.check_chain(entries)
        rebuilt = ''.join(
            logtree.canonical_json(e.to_dict()).decode('utf-8') + '\n' for e in entries)
        self.assertEqual(rebuilt, DUMP)
        self.assertEqual(hashlib.sha256(rebuilt.encode('utf-8')).hexdigest(), DUMP_SHA)

    def test_a_tampered_entry_is_rejected(self):
        raw = json.loads(DUMP.splitlines()[1])
        raw['utc'] = '2026-09-28T09:06:03.926714Z'
        with self.assertRaises(ValueError):
            logtree.parse_entry(raw)

    def test_a_broken_chain_is_rejected(self):
        entries = [logtree.parse_entry(json.loads(line))
                   for line in DUMP.splitlines()]
        with self.assertRaises(ValueError):
            logtree.check_chain([entries[0], entries[2]])

    def test_checkpoint_files_verify(self):
        first = logtree.parse_checkpoint(CHECKPOINT_1)
        second = logtree.parse_checkpoint(CHECKPOINT_2)
        self.assertEqual(first.hash, CHECKPOINT_1_HASH)
        self.assertEqual(second.hash, CHECKPOINT_2_HASH)
        self.assertEqual(second.prev, first.hash)
        self.assertTrue(first.signature_ok)
        self.assertTrue(second.signature_ok)
        # Klucz testowy NIE jest kluczem BeatTime — podpis sie zgadza,
        # ale checkpoint nie jest uznany. Tak ma byc.
        self.assertFalse(first.key_ok)
        self.assertFalse(first.ok)
        self.assertEqual(first.root, ROOT_2)
        self.assertEqual(second.week, '2026-W40')
        self.assertEqual(second.release_week, '2026-W40')

    def test_the_test_key_is_accepted_as_a_personal_override(self):
        cp = logtree.parse_checkpoint(CHECKPOINT_1, override=TEST_KEY)
        self.assertTrue(cp.ok)

    def test_a_non_canonical_file_is_rejected(self):
        pretty = json.dumps(json.loads(CHECKPOINT_1), indent=1).encode('utf-8')
        cp = logtree.parse_checkpoint(pretty, override=TEST_KEY)
        self.assertFalse(cp.ok)
        self.assertIn('canonical', cp.problem)

    def test_a_changed_byte_breaks_the_signature(self):
        tampered = CHECKPOINT_1.replace(b'"tree_size":2', b'"tree_size":3')
        cp = logtree.parse_checkpoint(tampered, override=TEST_KEY)
        self.assertFalse(cp.signature_ok)
        self.assertFalse(cp.ok)

    def test_release_week_of_a_daily_checkpoint(self):
        cp = logtree.parse_checkpoint(CHECKPOINT_1)
        # 2026-09-28 to poniedzialek tygodnia 2026-W40.
        self.assertEqual(cp.release_week, '2026-W40')


class KeyValidityTests(unittest.TestCase):

    def test_current_key_after_its_start(self):
        from beatstamp import keys
        key = keys.CURRENT_KEYS[-1]['public_key']
        self.assertTrue(logtree.key_valid_at(
            key, datetime(2026, 9, 26, tzinfo=timezone.utc)))
        self.assertFalse(logtree.key_valid_at(
            key, datetime(2026, 9, 1, tzinfo=timezone.utc)))

    def test_retired_key_only_before_retirement(self):
        from beatstamp import keys
        old = keys.RETIRED_KEYS[0]
        key = old['public_key']
        self.assertTrue(logtree.key_valid_at(
            key, datetime(2026, 8, 1, tzinfo=timezone.utc)))
        self.assertFalse(logtree.key_valid_at(
            key, datetime(2026, 9, 25, tzinfo=timezone.utc)))

    def test_foreign_key(self):
        self.assertFalse(logtree.key_valid_at(
            TEST_KEY, datetime(2026, 9, 26, tzinfo=timezone.utc)))


def _load_server_merkle():
    if not SERVER_MERKLE.is_file():
        return None
    spec = importlib.util.spec_from_file_location('_server_tsa_merkle', SERVER_MERKLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ServerParityTests(unittest.TestCase):
    """Te same drzewa liczone kodem serwera i kodem aplikacji."""

    @classmethod
    def setUpClass(cls):
        cls.server = _load_server_merkle()

    def setUp(self):
        if self.server is None:
            self.skipTest('desktop/ poza monorepo — brak apps/tsa/merkle.py')

    def test_roots_paths_and_consistency_for_many_sizes(self):
        rng = random.Random(20260926)
        for size in list(range(1, 40)) + [63, 64, 65, 127, 128, 129, 171, 173]:
            leaves = [hashlib.sha256(rng.randbytes(16)).digest() for _ in range(size)]
            self.assertEqual(logtree.merkle_root(leaves),
                             self.server.merkle_root(leaves), size)
            for index in {0, size // 2, size - 1}:
                self.assertEqual(logtree.audit_path(index, leaves),
                                 self.server.audit_path(index, leaves))
                self.assertEqual(
                    logtree.weekly_proof(leaves, index),
                    [{'side': s, 'hash': h}
                     for s, h in self.server.merkle_proof(leaves, index)])
            for first in {1, size // 2 or 1, size}:
                ours = logtree.consistency_proof(first, leaves)
                self.assertEqual(ours, self.server.consistency_proof(first, leaves))
                self.assertTrue(logtree.verify_consistency(
                    first, size, logtree.merkle_root(leaves[:first]),
                    logtree.merkle_root(leaves), ours))

    def test_entry_strings_match(self):
        for seq, digest, dt, _chain in ENTRIES:
            self.assertEqual(logtree.entry_string(seq, digest, dt),
                             self.server.entry_string(seq, digest, dt))


if __name__ == '__main__':
    unittest.main()
