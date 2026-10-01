"""
Dowod z dziennika w pakiecie dowodowym — HANDOVER_SPEC.md §12.1.

Pakiet niesie dla kazdego skrotu odpowiedz `GET /api/proof/verify` — tekst
JSON, tak jak przyszedl. Tej odpowiedzi NIE podpisal nikt poza kwitem (§9.2):
przynoszacy pakiet moze w niej zmienic kazde pole. Dlatego czas liczy sie
wylacznie wtedy, gdy:

1. odpowiedz to obiekt z `found: true` i tym samym skrotem;
2. ma kwit `sigelith-receipt-v1` od PRZYPIETEGO, aktualnego klucza dziennika,
   a jej `utc`, `seq` i `chain_hash` sa rowne kwitowym;
3. `week` to prawdziwy tydzien ISO, ktory obejmuje `utc` (od 5 minut przed
   jego poczatkiem — stempel z wyscigu na granicy trafia do nastepnego
   otwartego tygodnia, proof.py: WEEK_BOUNDARY_TOLERANCE);
4. korzen tygodnia i sciezka inkluzji — jesli sa, to oba — zwijaja skrot do
   korzenia (RFC 6962: lisc 0x00, wezel 0x01);
5. podpis korzenia — jesli jest — sklada przypiety aktualny klucz, nad
   `beattime-proof-v1|<tydzien>|<korzen>`;
6. tydzien zamkniety ma korzen, sciezke i podpis.

Czas wpisu = `utc` z kwitu. Poziom: `receipt` (sam kwit), `signed` (tez
podpisany korzen tygodnia), `anchored` (podpisany, a dziennik DEKLARUJE
kotwice Bitcoin albo bankowa tego korzenia — deklaracja, nie sprawdzona tu).
Pozostale pola odpowiedzi (`beat`, `time`, `checkpoint`...) sa ignorowane:
weryfikator ich nie uzywa, wiec nie ma czego w nich sprawdzac.

Checkpointy z niezaleznych kopii (LOG.md) to kolejna warstwa aplikacji — nie
warunek werdyktu: swiezy pakiet ma kwit od razu, a checkpoint dopiero po
dobie.

LUSTRO: apps/web/static/web/handover/verify.js (readLogProof, PayloadLog) —
te same reguly, ta sama kolejnosc i te same kody; wektory `log_proofs`.
"""
from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jcs
from .errors import HandoverError
from .primitives import b64decode, hex32, parse_log_utc, sha256
from .receipt import read_receipt

ROOT_V1 = 'beattime-proof-v1'          # apps/tsa/signing.py: signing_message
WEEK_TOLERANCE = timedelta(minutes=5)
MAX_PATH = 64                          # 2^64 lisci w tygodniu — z ogromnym zapasem
LEVELS = ('receipt', 'signed', 'anchored')
_WEEK = re.compile(r'(\d{4})-W(\d{2})')


@dataclass(frozen=True)
class LogProof:
    utc: datetime
    seq: int
    week: str
    level: str


def week_start(week: object) -> datetime:
    """Poniedzialek 00:00 UTC tygodnia ISO `RRRR-Www`. Kod bledu: log-week."""
    m = _WEEK.fullmatch(week) if isinstance(week, str) else None
    if m is None:
        raise HandoverError('log-week', 'week: expected YYYY-Www')
    try:
        start = datetime.fromisocalendar(int(m.group(1)), int(m.group(2)), 1)
    except ValueError:
        raise HandoverError('log-week', 'week: not a real ISO week') from None
    return start.replace(tzinfo=timezone.utc)


def fold(digest: bytes, path: list[dict]) -> bytes:
    node = sha256(b'\x00', digest)
    for step in path:
        sibling = bytes.fromhex(step['hash'])
        node = sha256(b'\x01', sibling, node) if step['side'] == 'L' else sha256(b'\x01', node, sibling)
    return node


def _present(payload: dict, key: str) -> bool:
    """Pole jest, gdy ma wartosc — `null` znaczy to samo co brak."""
    return payload.get(key) is not None


def _read_path(path: object) -> list[dict]:
    if not isinstance(path, list) or len(path) > MAX_PATH:
        raise HandoverError('log-structure', f'inclusion_proof: a list of at most {MAX_PATH} steps')
    for i, step in enumerate(path):
        if not isinstance(step, dict) or set(step) != {'side', 'hash'} or step['side'] not in ('L', 'R'):
            raise HandoverError('log-structure', f'inclusion_proof[{i}]: {{"side": "L"|"R", "hash": hex}}')
        try:
            hex32(step['hash'], f'inclusion_proof[{i}].hash')
        except HandoverError as e:
            raise e.renamed('log-structure') from None
    return path


def _anchored(payload: dict, root: str) -> bool:
    if payload.get('ots_status') == 'bitcoin':
        return True
    anchors = payload.get('anchors')
    return isinstance(anchors, list) and any(
        isinstance(a, dict) and a.get('status') == 'confirmed' and a.get('root') == root
        and a.get('root_matches_week') is not False for a in anchors)


def read_log_proof(raw: object, digest: bytes, keys: Iterable[str]) -> LogProof:
    """Regula §12.1. Kody: log-structure, receipt-missing, receipt-*, log-mismatch,
    log-week, log-inclusion, log-key, log-signature, log-incomplete."""
    keys = list(keys)
    if not isinstance(raw, str):
        raise HandoverError('log-structure', 'the proof must be the JSON text of /api/proof/verify')
    try:
        payload = jcs.loads(raw.encode('utf-8'), canonical=False)
    except HandoverError as e:
        raise e.renamed('log-structure') from None
    if not isinstance(payload, dict) or payload.get('found') is not True:
        raise HandoverError('log-structure', 'not a "found" answer of /api/proof/verify')
    if payload.get('digest') != digest.hex():
        raise HandoverError('log-structure', 'the proof is for another digest')
    if not _present(payload, 'receipt'):
        raise HandoverError('receipt-missing', 'the proof has no signed receipt')
    receipt = read_receipt(payload['receipt'], keys, expected_digest=digest)
    try:
        utc = parse_log_utc(payload.get('utc'))
    except HandoverError:
        utc = None
    seq = payload.get('seq')
    if (utc != receipt.utc or type(seq) is not int or seq != receipt.seq
            or payload.get('chain_hash') != receipt.chain_hash.hex()):
        raise HandoverError('log-mismatch', 'utc, seq and chain_hash must equal the receipt')

    week = payload.get('week')
    start = week_start(week)
    if not start - WEEK_TOLERANCE <= receipt.utc < start + timedelta(days=7):
        raise HandoverError('log-week', f'the entry time lies outside week {week}')

    root = None
    if _present(payload, 'week_root') or _present(payload, 'inclusion_proof'):
        if not (_present(payload, 'week_root') and _present(payload, 'inclusion_proof')):
            raise HandoverError('log-structure', 'week_root and inclusion_proof come together')
        root = payload['week_root']
        try:
            hex32(root, 'week_root')
        except HandoverError as e:
            raise e.renamed('log-structure') from None
        path = _read_path(payload['inclusion_proof'])
        if not hmac.compare_digest(fold(digest, path).hex(), root):
            raise HandoverError('log-inclusion', 'the inclusion proof does not lead to the week root')

    signed = False
    if _present(payload, 'root_signature'):
        if root is None:
            raise HandoverError('log-structure', 'a root signature needs week_root')
        if payload.get('public_key') not in keys:
            raise HandoverError('log-key', 'the week root is not signed by a pinned log key')
        try:
            key = b64decode(payload['public_key'], 'public_key', 32)
            sig = b64decode(payload['root_signature'], 'root_signature', 64)
            Ed25519PublicKey.from_public_bytes(key).verify(sig, f'{ROOT_V1}|{week}|{root}'.encode('ascii'))
        except (HandoverError, InvalidSignature):
            raise HandoverError('log-signature', 'the week root signature does not verify') from None
        signed = True

    closed = payload['week_closed'] if _present(payload, 'week_closed') else False
    if type(closed) is not bool:
        raise HandoverError('log-structure', 'week_closed: true or false')
    if closed and not signed:
        raise HandoverError('log-incomplete', 'a closed week needs its root, inclusion proof and signature')

    level = 'anchored' if signed and _anchored(payload, root) else 'signed' if signed else 'receipt'
    return LogProof(utc=receipt.utc, seq=receipt.seq, week=week, level=level)
