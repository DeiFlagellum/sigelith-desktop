"""
Dowód pliku z kopii Sigelith Backup (`.sigelith-proof`, format `sigelith-file-proof-v1`).

Sigelith Backup (3.0+) pieczętuje każdą wersję kopii jednym wpisem w dzienniku:
skrótem czterowierszowego oświadczenia (suma spisu wersji + korzeń drzewa
Merkle'a nad plikami wersji). Dowód jednego pliku to jego liść, droga w drzewie
do korzenia, samo oświadczenie i zwykły `beatproof-v1` dla skrótu oświadczenia —
nie ujawnia żadnych innych plików kopii.

Budowa (ta sama co w Sigelith Backup, `cleanvault/fileproof.py`, i w opisie
formatu na sigelith.org/spec/#file-proof):

* liść = SHA-256(0x00 ‖ sól ‖ SHA-256 pliku ‖ rozmiar jako 8 bajtów big-endian
  ‖ SHA-256 ścieżki w UTF-8); sól to 32 bajty z dowodu;
* węzeł = SHA-256(0x01 ‖ lewy ‖ prawy), pole `side` mówi, po której stronie
  stoi sąsiad — ta sama reguła 0x00/0x01 co w drzewach tygodni;
* oświadczenie: `SIGELITH-BACKUP-SEAL 1`, `index-sha256 <hex>`,
  `files-root <hex>`, `files <n>` — każda linia zakończona LF.

Sprawdzenie jest w całości lokalne: warstwę pliku liczymy tutaj, a osadzony
`beatproof-v1` sprawdza `bundle.check` — z kluczami wbudowanymi w program,
czasem w podpisanym tygodniu i checkpointem, dokładnie jak każdy `.beatproof`.
"""
from __future__ import annotations

import hashlib
import re

from . import bundle, merkle
from .i18n import _

FORMAT = 'sigelith-file-proof-v1'
EXTENSION = '.sigelith-proof'
STATEMENT_HEADER = 'SIGELITH-BACKUP-SEAL 1'

_STATEMENT = re.compile(
    r'^SIGELITH-BACKUP-SEAL 1\nindex-sha256 ([0-9a-f]{64})\nfiles-root ([0-9a-f]{64})\n'
    r'files ([1-9][0-9]*)\n\Z')


def _leaf(salt: bytes, sha_hex: str, size: int, path_sha: bytes) -> bytes:
    return hashlib.sha256(
        b'\x00' + salt + bytes.fromhex(sha_hex) + size.to_bytes(8, 'big') + path_sha).digest()


def _fold(start: bytes, steps) -> bytes:
    current = start
    for step in steps:
        side, sibling = step['side'], bytes.fromhex(step['hash'])
        if side not in ('L', 'R') or len(sibling) != 32:
            raise ValueError('bad step')
        pair = sibling + current if side == 'L' else current + sibling
        current = hashlib.sha256(b'\x01' + pair).digest()
    return current


def is_proof_file(path) -> bool:
    """Plik dowodu (`.beatproof` albo dowód pliku z kopii) — do sprawdzenia, nigdy do stemplowania."""
    name = str(getattr(path, 'name', path)).lower()
    return name.endswith((bundle.EXTENSION, EXTENSION))


def parse_statement(text: str) -> tuple[str, str, int] | None:
    """(suma spisu, korzeń drzewa plików, liczba plików) albo None."""
    match = _STATEMENT.match(text) if isinstance(text, str) else None
    if match is None:
        return None
    return match.group(1), match.group(2), int(match.group(3))


def file_info(data: dict) -> dict:
    """Opis pliku z dowodu (nazwa, ścieżka, rozmiar, SHA-256) — do wyświetlenia."""
    info = data.get('file') if isinstance(data, dict) else None
    return dict(info) if isinstance(info, dict) else {}


def check(data: dict, *, document_digest: str = '', document_size: int | None = None,
          key_override: str = '') -> bundle.BundleCheck:
    """Sprawdza dowód pliku w całości lokalnie. Zadnej sieci, żadnego zaufania.

    `document_digest` (i `document_size`) — policzone TERAZ z pliku, którego
    dowód dotyczy; bez nich sprawdzamy tylko spójność samego dowodu.
    """
    r = bundle.BundleCheck()
    if not isinstance(data, dict) or data.get('format') != FORMAT:
        r.problems.append(_('Unknown proof format (expected "%(format)s").') % {'format': FORMAT})
        return r
    info, leaf = data.get('file'), data.get('leaf')
    try:
        sha = str(info['sha256']).strip().lower()
        size = int(info['size'])
        salt = bytes.fromhex(str(leaf['salt']))
        path_sha = bytes.fromhex(str(leaf['path_sha256']))
        root = str(data['files_root']).strip().lower()
        if not (merkle.is_digest(sha) and merkle.is_digest(root)) or size < 0 \
                or len(salt) != 32 or len(path_sha) != 32:
            raise ValueError('bad field')
        reached = _fold(_leaf(salt, sha, size, path_sha), data['merkle_path']).hex()
    except (KeyError, TypeError, ValueError):
        r.problems.append(_('The file proof is damaged — fields are missing or malformed.'))
        return r

    statement = str(data.get('statement') or '')
    statement_digest = hashlib.sha256(statement.encode('utf-8')).hexdigest()
    inner_data = data.get('beatproof')
    if not isinstance(inner_data, dict) or str(inner_data.get('digest') or '').lower() != statement_digest:
        r.problems.append(_('The Sigelith confirmation in the file proof is not about this backup seal.'))
        return r
    r = bundle.check(inner_data, document_digest=statement_digest, key_override=key_override)
    # Od tej chwili „dokument" to plik z kopii, nie oświadczenie pieczęci.
    r.digest = sha
    r.file_matches = None
    if document_digest:
        r.file_matches = (document_digest.strip().lower() == sha
                          and (document_size is None or document_size == size))
        if not r.file_matches:
            r.problems.append(_(
                'The digest of the selected file does NOT match the digest in '
                'the proof. The file was changed, or the proof is about a '
                'different document.'))
    path = info.get('path')
    if path is not None and hashlib.sha256(str(path).encode('utf-8')).digest() != path_sha:
        r.problems.append(_('The file path in the proof does not match the leaf of the backup tree.'))
    parsed = parse_statement(statement)
    if reached != root:
        r.problems.append(_('The path in the backup tree does not lead to the sealed root.'))
    if parsed is None or parsed[1] != root or parsed[2] != data.get('files'):
        r.problems.append(_('The backup seal statement does not confirm this file tree.'))
    r.ok = r.ok and not r.problems
    return r
