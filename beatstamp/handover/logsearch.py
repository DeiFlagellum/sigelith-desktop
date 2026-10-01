"""
Znalezienie czesci B w publicznym dzienniku — HANDOVER_SPEC.md §8.

Nadawca publikuje B zwyklym stemplem; odbiorca nie potrzebuje od nikogo zadnej
wiadomosci. Przeglada wpisy dziennika (`/api/proof/entries?from=<seq>`, lustra
swiadkow, zrzuty tygodniowe) i dla kazdego liczy zobowiazanie
SHA-256("sigelith-handover-v1|part-b|" ‖ digest). Trafienie = B.

Wpis wyglada jak kazdy inny stempel: dziennik nie wie, ze to czesc klucza.
"""
from __future__ import annotations

import hmac
import re
from typing import Iterable

from .package import commit_b

_HEX64 = re.compile(r'[0-9a-f]{64}')


def find_part_b(entries: Iterable[object], commitment: bytes) -> tuple[bytes, object] | None:
    """(B, wpis) dla pierwszego wpisu pasujacego do zobowiazania, albo None.

    Wpis to slownik z polem `digest` (odpowiedz API, linia zrzutu) albo obiekt
    z atrybutem `digest` (np. `logtree.LogEntry`). Wpisy w innym formacie sa
    pomijane — przegladamy cudze dane, nie ufamy im.
    """
    for entry in entries:
        digest = entry.get('digest') if isinstance(entry, dict) else getattr(entry, 'digest', None)
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            continue
        b = bytes.fromhex(digest)
        if hmac.compare_digest(commit_b(b), commitment):
            return b, entry
    return None
