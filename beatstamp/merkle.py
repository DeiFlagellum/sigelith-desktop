"""
Drzewo Merkle i łańcuch hashy — strona KLIENTA.

Port `apps/tsa/merkle.py` z BeatTime, zredukowany do tego, co klientowi jest
naprawdę potrzebne: przeliczenia ścieżki inkluzji do korzenia. Konwencja jak
w RFC 6962: lisc = SHA-256(0x00 || digest), wezel = SHA-256(0x01 || L || R),
a samotny wezel na koncu poziomu jest niesiony w gore bez duplikacji.

To jest miejsce, w którym aplikacja przestaje wierzyc serwerowi na slowo:
majac digest, ścieżkę i korzeń, policzy sama, czy stempel naprawdę nalezy do
tygodnia — bez sieci i bez zaufania do tego, kto te dane dostarczył.
"""
from __future__ import annotations

import hashlib
import re

HEX64 = re.compile(r'^[0-9a-f]{64}$')


def is_digest(value: object) -> bool:
    """64 male znaki hex — jedyna forma, jaka przyjmuje i wysyla API."""
    return isinstance(value, str) and bool(HEX64.match(value.strip().lower()))


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(digest_hex: str) -> bytes:
    """Lisc drzewa z hexowego SHA-256 dokumentu."""
    return _sha(b'\x00' + bytes.fromhex(digest_hex))


def fold_proof(digest_hex: str, proof: list[dict]) -> str | None:
    """Zwija ścieżkę inkluzji do korzenia. None gdy ścieżka jest zepsuta.

    `proof` w formacie API: [{'side': 'L'|'R', 'hash': '<64 hex>'}, ...],
    gdzie 'side' mówi, po której stronie lezy RODZENSTWO.
    """
    if not is_digest(digest_hex):
        return None
    node = leaf_hash(digest_hex.strip().lower())
    for step in proof or []:
        if not isinstance(step, dict):
            return None
        side = str(step.get('side', '')).upper()
        sib_hex = str(step.get('hash', '')).strip().lower()
        if side not in ('L', 'R') or not is_digest(sib_hex):
            return None
        sib = bytes.fromhex(sib_hex)
        node = _sha(b'\x01' + (sib + node if side == 'L' else node + sib))
    return node.hex()


def verify_inclusion(digest_hex: str, proof: list[dict], root_hex: str) -> bool:
    """Czy digest naprawdę nalezy do drzewa o tym korzeniu."""
    if not is_digest(root_hex):
        return False
    folded = fold_proof(digest_hex, proof)
    return folded is not None and folded == root_hex.strip().lower()


def chain_hash(prev_hex: str, digest_hex: str, utc_iso: str) -> str:
    """Ogniwo łańcucha tamper-evident: SHA-256(prev || digest || utc).

    Odtwarzalne u klienta tylko wtedy, gdy zna `prev` (hash poprzedniego
    stempla). Pojedyncza odpowiedź API go nie zawiera, więc sluzy do
    porownywania dwoch SASIEDNICH wpisów z własnej historii.
    """
    return hashlib.sha256(
        (prev_hex + digest_hex + utc_iso).encode('utf-8')
    ).hexdigest()


GENESIS = '0' * 64
