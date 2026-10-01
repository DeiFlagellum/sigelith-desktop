"""
Kontrakt dla programow kopii zapasowych (Sigelith Backup, dawniej Time Vault Backup; 2026-09-29).

Sigelith Backup (ten sam wydawca, repo O:\\Repo\\CleanVault) czyta katalog
danych Sigelith Desktop — nigdy w nim nie pisze — i na tej podstawie
zabezpiecza dokladne bajty ostemplowanych dokumentow razem z .beatproof.
Ten test pilnuje tego, na czym tamten program polega. Zmiana, ktora go
przewraca, jest zmiana kontraktu: najpierw uzgodnienie z Sigelith Backup
(desktop/ROZWOJ.md, „Kontrakt dla programow kopii zapasowych").

Zasada: DOPISYWAC wolno (nowe pola, nowe pliki); zmieniac nazw i usuwac — nie.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from beatstamp import bundle, config, instance, proof  # noqa: E402
from beatstamp.history import Entry, History  # noqa: E402
from test_core import DIGEST, LIVE_PAYLOAD  # noqa: E402
from test_datadir import EnvIsolatedTest  # noqa: E402

#: Pola wpisu historii, na ktorych stoi Sigelith Backup — stan 2026-09-29.
CONTRACT_FIELDS = (
    'digest', 'file_name', 'file_path', 'file_size', 'note', 'beat', 'utc', 'seq', 'week',
    'week_closed', 'week_root', 'inclusion_proof', 'root_signature', 'public_key', 'chain_hash',
    'ots_status', 'ots_height', 'anchors', 'level', 'time_bounds', 'checkpoint',
    'log_index', 'witness_mode', 'verified_ok', 'source', 'created_local', 'refreshed_utc',
    'legacy',
)


def _entry() -> Entry:
    return Entry(digest=DIGEST, file_name='umowa.pdf', file_size=12, beat='@348.28',
                 utc='2026-06-15T08:21:32.167366Z', file_path='C:/Dokumenty/umowa.pdf')


class HistoryFileContractTests(EnvIsolatedTest):

    def test_every_contract_field_is_still_written(self):
        written = set(_entry().to_dict())
        self.assertEqual(set(CONTRACT_FIELDS) - written, set(),
                         'pole kontraktu zniknelo z wpisu historii — Sigelith Backup go czyta')

    def test_history_file_is_a_json_list_of_entries(self):
        path = self.dir / 'history.json'
        history = History(path)
        history.add(_entry())
        history.save()
        raw = json.loads(path.read_text(encoding='utf-8'))
        self.assertIsInstance(raw, list)
        self.assertEqual(raw[0]['digest'], DIGEST)
        self.assertEqual(raw[0]['file_path'], 'C:/Dokumenty/umowa.pdf')

    def test_the_dict_form_with_entries_is_read_too(self):
        path = self.dir / 'history.json'
        path.write_text(json.dumps({'entries': [_entry().to_dict()]}), encoding='utf-8')
        self.assertEqual([e.digest for e in History(path).load().entries], [DIGEST])

    def test_file_names_in_the_data_folder(self):
        os.environ['SIGELITH_DATA_DIR'] = str(self.dir / 'dane')
        self.assertEqual(config.history_path().name, 'history.json')
        self.assertEqual(config.settings_path().name, 'settings.json')
        self.assertEqual(config.handover_dir().name, 'handover')
        self.assertEqual(config.LOG_NAME, 'sigelith.log')
        self.assertEqual(instance.LOCK_NAME, 'beatstamp.lock')


class DataFolderLookupContractTests(EnvIsolatedTest):
    """Kolejnosc: SIGELITH_DATA_DIR / BEATSTAMP_DATA_DIR → wskaznik → %USERPROFILE%\\Sigelith."""

    def test_pointer_file_name_place_and_format(self):
        target = self.dir / 'Gdzie indziej' / 'Sigelith'
        self.assertTrue(config.remember_data_dir(target))
        pointer = Path(os.environ['LOCALAPPDATA']) / 'Sigelith' / 'katalog-danych.json'
        self.assertEqual(config.location_file(), pointer)
        data = json.loads(pointer.read_text(encoding='utf-8'))
        self.assertEqual(set(data), {'katalog', 'zapisano_utc'})
        self.assertEqual(Path(data['katalog']), target)
        self.assertEqual(config.stored_data_dir(), target)
        self.assertEqual(config.resolved_data_dir(), target)

    def test_empty_pointer_means_the_default_folder(self):
        pointer = config.location_file()
        pointer.parent.mkdir(parents=True)
        pointer.write_text(json.dumps({'katalog': '', 'zapisano_utc': '2026-09-29T00:00:00Z'}),
                           encoding='utf-8')
        self.assertIsNone(config.stored_data_dir())
        if sys.platform == 'win32':
            self.assertEqual(config.resolved_data_dir(),
                             Path(os.environ['USERPROFILE']) / 'Sigelith')

    def test_old_beatstamp_pointer_is_read_when_there_is_no_new_one(self):
        legacy = Path(os.environ['LOCALAPPDATA']) / 'BeatStamp' / 'katalog-danych.json'
        self.assertEqual(config.legacy_location_file(), legacy)
        legacy.parent.mkdir(parents=True)
        chosen = self.dir / 'Stary wybor'
        legacy.write_text(json.dumps({'katalog': str(chosen)}), encoding='utf-8')
        self.assertEqual(config.stored_data_dir(), chosen)

    def test_environment_variable_wins_over_the_pointer(self):
        config.remember_data_dir(self.dir / 'Wskaznik')
        os.environ['SIGELITH_DATA_DIR'] = str(self.dir / 'Zmienna')
        self.assertEqual(config.resolved_data_dir(), self.dir / 'Zmienna')


class ForeignBeatproofContractTests(EnvIsolatedTest):
    """.beatproof zlozony przez Sigelith Backup z pol wpisu historii: inny
    `generator`, bez sekcji `checkpoint` (TVB nie ma plikow swiadka)."""

    def test_a_beatproof_from_time_vault_backup_verifies(self):
        data = bundle.build(proof.verify_payload(LIVE_PAYLOAD, expected_digest=DIGEST),
                            file_name='umowa.pdf')
        data['generator'] = 'Sigelith Backup 3.0.0'
        data['authority'] = 'https://sigelith.org'
        data.pop('checkpoint', None)
        data.pop('how_to_verify_checkpoint', None)
        check = bundle.check(data, document_digest=DIGEST)
        self.assertTrue(check.ok, check.problems)
        self.assertIsNone(check.checkpoint_ok, 'brak sekcji checkpoint niczego nie psuje')


if __name__ == '__main__':
    unittest.main()
