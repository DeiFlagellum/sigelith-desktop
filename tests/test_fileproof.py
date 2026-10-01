"""
Dowód pliku z kopii Sigelith Backup (`.sigelith-proof`, `sigelith-file-proof-v1`).

Wektor `data/file_proof_vector.json` wystawił KOD Sigelith Backup
(`cleanvault.fileproof`, O:\\Repo\\CleanVault) — test pilnuje, że oba programy
liczą liść, drzewo i oświadczenie pieczęci dokładnie tak samo. Korzeń tygodnia
podpisany jest kluczem testowym, więc przyjmujemy go tylko przez `key_override`
(tak jak własny klucz z ustawień); bez niego dowód MUSI zostać odrzucony.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from beatstamp import fileproof, keys, workers  # noqa: E402

VECTOR = json.loads((Path(__file__).resolve().parent / 'data' / 'file_proof_vector.json')
                    .read_text(encoding='utf-8'))
PUB = VECTOR['test_public_key']
DOCUMENT = bytes.fromhex(VECTOR['document_hex'])
PROOF = VECTOR['proof']


def _check(doc, document=DOCUMENT, *, override=PUB):
    return fileproof.check(doc, document_digest=hashlib.sha256(document).hexdigest(),
                           document_size=len(document), key_override=override)


class FileProofVectorTests(unittest.TestCase):

    def test_proof_from_sigelith_backup_verifies(self):
        r = _check(PROOF)
        self.assertTrue(r.ok, r.problems)
        self.assertEqual(r.problems, [])
        self.assertTrue(r.file_matches)
        self.assertEqual(r.digest, hashlib.sha256(DOCUMENT).hexdigest())
        self.assertTrue(r.inclusion_ok and r.signature_ok)
        self.assertEqual(r.signer_status, keys.SIGNER_OVERRIDE)

    def test_the_proof_alone_is_consistent_without_the_file(self):
        r = fileproof.check(PROOF, key_override=PUB)
        self.assertTrue(r.ok, r.problems)
        self.assertIsNone(r.file_matches)

    def test_test_key_is_not_trusted_without_override(self):
        r = _check(PROOF, override='')
        self.assertFalse(r.ok)
        self.assertEqual(r.signer_status, keys.SIGNER_UNKNOWN)

    def test_another_file_is_rejected(self):
        r = _check(PROOF, DOCUMENT + b' ')
        self.assertFalse(r.ok)
        self.assertIs(r.file_matches, False)

    def test_proof_without_path_still_verifies(self):
        hidden = VECTOR['hidden_path_proof']
        self.assertNotIn('path', hidden['file'])
        self.assertNotIn('Tajne', json.dumps(hidden))
        r = _check(hidden, bytes.fromhex(VECTOR['hidden_path_document_hex']))
        self.assertTrue(r.ok, r.problems)

    def test_no_other_file_of_the_backup_is_revealed(self):
        text = json.dumps(PROOF)
        for name in ('faktura', 'lato.jpg', 'notatka', 'plan.txt'):
            self.assertNotIn(name, text)

    def test_every_kind_of_tampering_is_rejected(self):
        def damage(what):
            doc = copy.deepcopy(PROOF)
            if what == 'path':
                doc['file']['path'] = 'Dokumenty/umowa-stara.pdf'
            elif what == 'step':
                doc['merkle_path'][0]['hash'] = '0' * 64
            elif what == 'side':
                doc['merkle_path'][0]['side'] = 'L' if doc['merkle_path'][0]['side'] == 'R' else 'R'
            elif what == 'root':
                doc['files_root'] = '1' * 64
            elif what == 'statement':
                doc['statement'] = doc['statement'].replace('files 5', 'files 6')
            elif what == 'week_root':
                doc['beatproof']['week_root'] = '2' * 64
            elif what == 'salt':
                doc['leaf']['salt'] = '3' * 64
            elif what == 'size':
                doc['file']['size'] += 1
            elif what == 'time':
                doc['beatproof']['utc'] = '2026-09-01T12:17:00Z'
            elif what == 'format':
                doc['format'] = 'beatproof-v1'
            return doc

        for what in ('path', 'step', 'side', 'root', 'statement', 'week_root', 'salt', 'size',
                     'time', 'format'):
            with self.subTest(what=what):
                r = _check(damage(what))
                self.assertFalse(r.ok, what)
                self.assertTrue(r.problems, what)

    def test_statement_parser(self):
        self.assertEqual(fileproof.parse_statement(PROOF['statement'])[2], PROOF['files'])
        for bad in ('', PROOF['statement'] + 'x', PROOF['statement'].replace('files 5', 'files 05'),
                    PROOF['statement'].replace('\n', '\r\n')):
            self.assertIsNone(fileproof.parse_statement(bad), bad)


class CheckTaskTests(unittest.TestCase):
    """Okno „Sprawdzanie” wczytuje dowód pliku tym samym zadaniem co `.beatproof`."""

    def test_task_recognises_a_file_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            proof_path = Path(tmp) / ('umowa.pdf' + fileproof.EXTENSION)
            proof_path.write_text(json.dumps(PROOF), encoding='utf-8')
            document = Path(tmp) / 'umowa.pdf'
            document.write_bytes(DOCUMENT)
            outcome = workers.CheckBundleTask(proof_path, document, key_override=PUB).work()
        self.assertTrue(outcome.check.ok, outcome.check.problems)
        self.assertEqual(outcome.data['format'], fileproof.FORMAT)
        self.assertEqual(fileproof.file_info(outcome.data)['name'], 'umowa.pdf')



class OpenedFilesTests(unittest.TestCase):
    """Dwuklik na dowodzie otwiera sprawdzanie — nigdy stemplowanie."""

    def test_proof_files_are_recognised(self):
        for name in ('dowod.beatproof', 'umowa.pdf.sigelith-proof', 'UMOWA.PDF.SIGELITH-PROOF'):
            self.assertTrue(fileproof.is_proof_file(Path(name)), name)
        for name in ('umowa.pdf', 'paczka.sigelith-handover', 'dowod.zip', 'proof.json'):
            self.assertFalse(fileproof.is_proof_file(Path(name)), name)

    def test_manifest_associates_both_proof_formats(self):
        manifest = (Path(__file__).resolve().parent.parent / 'packaging' / 'AppxManifest.xml'
                    ).read_text(encoding='utf-8')
        self.assertIn('<uap:FileType>.sigelith-proof</uap:FileType>', manifest)
        self.assertIn('<uap:FileType>.beatproof</uap:FileType>', manifest)


if __name__ == '__main__':
    unittest.main()
