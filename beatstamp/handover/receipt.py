"""
Podpisany kwit stempla — `sigelith-receipt-v1` (HANDOVER_SPEC.md §9.2).

Serwer (apps/tsa/receipt.py) dokleja kwit do odpowiedzi /api/proof/stamp
i /api/proof/verify:

    {"v": "sigelith-receipt-v1", "seq", "digest", "utc", "chain_hash", "key", "sig"}
    sig = Ed25519(klucz dziennika, "sigelith-receipt-v1|" ‖ JCS(kwit bez sig))

To obietnica dziennika: „wpis `seq` z tym skrotem, o tej chwili, z tym ogniwem
lancucha". Jesli dziennik potem pokaze cos innego, podpisany kwit jest dowodem.
W Handover chroni nadawce przed przesunieciem czasu zapisu czesci B.

Kto podpisal — decyduje WYLACZNIE lista przypietych kluczy, ktora podaje
wolajacy (aplikacja: keys.current_public_keys()). Klucz wycofany nie jest uznawany,
jak przy korzeniach (keys.py). Pakiet handover nie importuje keys.py, zeby
zostac czystym, samodzielnym modulem.

LUSTRO: apps/web/static/web/handover/verify.js (readReceipt) — te same reguly
i kody bledow; wektory: `receipt` w tests/vectors/handover-v1.json.
"""
from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jcs
from .errors import HandoverError
from .primitives import b64decode, hex32, parse_log_utc

RECEIPT_V1 = 'sigelith-receipt-v1'
FIELDS = frozenset({'v', 'seq', 'digest', 'utc', 'chain_hash', 'key', 'sig'})
# Serwer pisze czas zawsze z szescioma cyframi ulamka (merkle.canonical_utc) —
# inna postac to nie jest kwit tego serwera.
_UTC = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z')


@dataclass(frozen=True)
class Receipt:
    seq: int
    digest: bytes
    utc: datetime
    chain_hash: bytes
    key: str


def message(receipt: dict) -> bytes:
    body = {k: v for k, v in receipt.items() if k != 'sig'}
    return f'{RECEIPT_V1}|'.encode('ascii') + jcs.dumps(body)


def read_receipt(receipt: object, pinned_keys: Iterable[str], *,
                 expected_digest: bytes | None = None) -> Receipt:
    """Sprawdza kwit. Kody: receipt-structure, receipt-key, receipt-signature, receipt-digest."""
    if not isinstance(receipt, dict) or set(receipt) != FIELDS:
        raise HandoverError('receipt-structure', f'expected fields {sorted(FIELDS)}')
    try:
        if receipt['v'] != RECEIPT_V1:
            raise HandoverError('receipt-structure', f'not a {RECEIPT_V1} receipt')
        seq = receipt['seq']
        if type(seq) is not int or not 1 <= seq <= jcs.MAX_SAFE_INT:
            raise HandoverError('receipt-structure', 'seq: a positive integer')
        digest = hex32(receipt['digest'], 'digest')
        if not isinstance(receipt['utc'], str) or not _UTC.fullmatch(receipt['utc']):
            raise HandoverError('receipt-structure', 'utc: YYYY-MM-DDTHH:MM:SS.ffffffZ')
        utc = parse_log_utc(receipt['utc'])
        chain_hash = hex32(receipt['chain_hash'], 'chain_hash')
        key = b64decode(receipt['key'], 'key', 32)
        sig = b64decode(receipt['sig'], 'sig', 64)
        data = message(receipt)
    except HandoverError as e:
        raise (e if e.code == 'receipt-structure' else e.renamed('receipt-structure')) from None
    if receipt['key'] not in set(pinned_keys):
        raise HandoverError('receipt-key', 'the receipt is not signed by a pinned log key')
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, data)
    except InvalidSignature:
        raise HandoverError('receipt-signature', 'the receipt signature does not verify') from None
    if expected_digest is not None and not hmac.compare_digest(digest, expected_digest):
        raise HandoverError('receipt-digest', 'the receipt is for another digest')
    return Receipt(seq=seq, digest=digest, utc=utc, chain_hash=chain_hash, key=receipt['key'])
