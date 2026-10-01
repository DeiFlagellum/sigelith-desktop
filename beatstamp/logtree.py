"""
Dziennik globalny Sigelith po stronie klienta — port `apps/tsa/LOG.md`.

Po co ten modul istnieje. Do wersji 2.1 program (wtedy BeatStamp) sprawdzal JEDEN wpis:
sciezke inkluzji skrotu do korzenia tygodnia i podpis tego korzenia. To
dowodzi, ze wpis jest w drzewie, ktore Sigelith podpisal — ale nie mowi nic
o tym, czy Sigelith pokazuje wszystkim TO SAMO drzewo. Operator, ktory
chcialby wydatowac wpis wstecz albo cos wyciac, moglby pokazac jednemu
klientowi jedna historie, a drugiemu inna (tzw. split view) i kazda z nich
bylaby „poprawnie podpisana".

Dziennik globalny (LOG.md) zamyka te luke trzema rzeczami, ktore ten modul
umie sprawdzic sam, bez zaufania do serwera:

* **checkpoint** — podpisany stan CALEGO dziennika (rozmiar + korzen drzewa
  RFC 9162), zawierajacy hash poprzedniego checkpointu. Jeden zachowany
  checkpoint przypina cala historie przed nim;
* **dowod spojnosci** (RFC 9162 §2.1.4) — ze drzewo o rozmiarze n jest
  ROZSZERZENIEM drzewa o rozmiarze m: nic nie wycieto, niczego nie
  przepisano, tylko dopisano;
* **dowod inkluzji** (RFC 9162 §2.1.3) — ze wpis nr N o chwili T jest w
  drzewie zamknietym danym checkpointem.

LUSTRO SERWERA. Funkcje ponizej sa kopia `apps/tsa/merkle.py` (sekcja
„Dziennik globalny") i `apps/tsa/checkpoint.py`, z jedna roznica: tutaj nic
nie PODPISUJEMY, tylko sprawdzamy. Formaty sa ZAMROZONE (LOG.md §0) —
checkpoint raz opublikowany lezy u osob trzecich. Zgodnosc z serwerem
pilnuja wektory z LOG.md §10 w `tests/test_logtree.py` i test parytetu,
ktory laduje kod serwera obok (`tests/test_server_parity.py`).

Modul jest czystym Pythonem: bez Qt, bez sieci. Jedyna zaleznosc spoza
biblioteki standardowej to `cryptography` (Ed25519), ta sama co przy
podpisach korzeni tygodniowych.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import keys

ENTRY_V1 = 'beattime-entry-v1'
CHECKPOINT_V1 = 'beattime-checkpoint-v1'
GENESIS = '0' * 64

_MAX_INT = 2 ** 53
HEX64 = re.compile(r'^[0-9a-f]{64}$')
_WEEK = re.compile(r'^\d{4}-W\d{2}$')
_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
_UTC = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$')

FIELDS_COMMON = ('btc', 'format', 'key', 'kind', 'last_chain_hash', 'last_seq',
                 'n', 'prev', 'root', 'tree_size', 'utc')
FIELDS_WEEKLY = ('anchors', 'dump', 'week', 'week_root', 'week_size')
FIELDS_ANCHOR = ('bank', 'booked', 'reference', 'title', 'week')


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --- Czas -------------------------------------------------------------------

def parse_canonical_utc(text: object) -> datetime | None:
    """`YYYY-MM-DDTHH:MM:SS.ffffffZ` -> datetime UTC albo None.

    Przyjmujemy WYLACZNIE postac kanoniczna (szesc cyfr ulamka, `Z`). Czas
    w innym zapisie nie jest bledem skladni, tylko sygnalem, ze dane nie
    pochodza z formatow LOG v1 — a te sa zamrozone.
    """
    value = str(text or '')
    if not _UTC.match(value):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError:
        return None


def canonical_utc(dt: datetime) -> str:
    """Czas w nowych formatach: ZAWSZE szesc cyfr ulamka i `Z`."""
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def chain_utc(dt: datetime) -> str:
    """Czas, z ktorego liczony jest `chain_hash` (HISTORYCZNY, nie ruszac).

    `datetime.isoformat()` dla UTC — z pulapka opisana w LOG.md §2: czesc
    ulamkowa ZNIKA, gdy mikrosekundy wynosza dokladnie 0.
    """
    return dt.astimezone(timezone.utc).isoformat()


# --- Wpis dziennika ---------------------------------------------------------

def chain_hash(prev_hex: str, digest_hex: str, dt: datetime) -> str:
    """Ogniwo lancucha: SHA-256(prev || digest || chain_utc(utc)), hex."""
    return hashlib.sha256(
        (prev_hex + digest_hex + chain_utc(dt)).encode('utf-8')).hexdigest()


def entry_string(seq: int, digest_hex: str, dt: datetime) -> str:
    """`beattime-entry-v1|<seq>|<digest>|<canonical_utc>` — lisc globalny."""
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise ValueError('seq must be a positive integer')
    digest_hex = digest_hex.lower()
    if not HEX64.match(digest_hex):
        raise ValueError('digest must be 64 hex characters')
    return f'{ENTRY_V1}|{seq}|{digest_hex}|{canonical_utc(dt)}'


def entry_leaf_hash(seq: int, digest_hex: str, dt: datetime) -> bytes:
    """Lisc drzewa globalnego: SHA-256(0x00 || ASCII(entry_string))."""
    return _sha(b'\x00' + entry_string(seq, digest_hex, dt).encode('ascii'))


def week_leaf_hash(digest_hex: str) -> bytes:
    """Lisc drzewa TYGODNIOWEGO: SHA-256(0x00 || bajty skrotu) — sam odcisk."""
    return _sha(b'\x00' + bytes.fromhex(digest_hex))


# --- Drzewo RFC 9162 --------------------------------------------------------

def _split(n: int) -> int:
    """Najwieksza potega dwojki MNIEJSZA od n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    """MTH wg RFC 9162 §2.1.1 — iteracyjnie, samotny wezel niesiony w gore.

    Ten sam ksztalt co `apps/tsa/merkle.merkle_root` (i co drzewo
    tygodniowe). Pusta lista daje 32 zera — tak jak po stronie serwera;
    w praktyce drzewo globalne nigdy nie jest puste.
    """
    if not leaves:
        return b'\x00' * 32
    level = list(leaves)
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_sha(b'\x01' + level[i] + level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0]


def weekly_proof(leaves: list[bytes], index: int) -> list[dict]:
    """Sciezka inkluzji drzewa tygodniowego w formacie API: [{side, hash}].

    Format odpowiedzi `/api/proof/verify` (`inclusion_proof`), ktory
    rozumie `merkle.verify_inclusion` tej aplikacji i `.beatproof`.
    Potrzebna w trybie prywatnym: sciezke do korzenia tygodnia liczymy
    wtedy SAMI z pobranego dziennika, zamiast pytac serwer o nasz skrot.
    """
    proof: list[dict] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                if i == idx:
                    proof.append({'side': 'R', 'hash': level[i + 1].hex()})
                elif i + 1 == idx:
                    proof.append({'side': 'L', 'hash': level[i].hex()})
                nxt.append(_sha(b'\x01' + level[i] + level[i + 1]))
            else:
                nxt.append(level[i])
        idx //= 2
        level = nxt
    return proof


def audit_path(index: int, leaves: list[bytes]) -> list[bytes]:
    """Sciezka audytowa RFC 9162 §2.1.3.1 — od poziomu lisci w gore."""
    if not 0 <= index < len(leaves):
        raise ValueError('index outside the tree')
    return [bytes.fromhex(step['hash']) for step in weekly_proof(leaves, index)]


def verify_inclusion(leaf: bytes, index: int, size: int, path: list[bytes],
                     root: bytes) -> bool:
    """Weryfikacja inkluzji wg RFC 9162 §2.1.3.2."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _sha(b'\x01' + p + r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _sha(b'\x01' + r + p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def _subproof(m: int, leaves: list[bytes], complete: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [merkle_root(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [merkle_root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]


def consistency_proof(first: int, leaves: list[bytes]) -> list[bytes]:
    """Dowod spojnosci RFC 9162 §2.1.4.1 (tylko do testow i kontroli)."""
    if not 0 < first <= len(leaves):
        raise ValueError('0 < first <= second is required')
    return _subproof(first, leaves, True)


def verify_consistency(first: int, second: int, first_root: bytes,
                       second_root: bytes, path: list[bytes]) -> bool:
    """Weryfikacja spojnosci wg RFC 9162 §2.1.4.2."""
    if not 0 < first <= second:
        return False
    if first == second:
        return not path and first_root == second_root
    if not path:
        return False
    path = list(path)
    if first & (first - 1) == 0:          # first jest potega dwojki
        path.insert(0, first_root)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = _sha(b'\x01' + c + fr)
            sr = _sha(b'\x01' + c + sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _sha(b'\x01' + sr + c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


# --- Kanoniczny JSON (podzbior JCS, RFC 8785) -------------------------------

def _check(value, path: str = '$') -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) >= _MAX_INT:
            raise ValueError(f'{path}: integer outside 2**53')
        return
    if isinstance(value, float):
        raise ValueError(f'{path}: floating point numbers are not allowed')
    if isinstance(value, str):
        if any(ord(c) < 0x20 for c in value):
            raise ValueError(f'{path}: control character in a string')
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check(item, f'{path}[{i}]')
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ValueError(f'{path}: keys must be ASCII strings')
            _check(item, f'{path}.{key}')
        return
    raise ValueError(f'{path}: type {type(value).__name__} is not allowed')


def canonical_json(obj) -> bytes:
    """Bajty JCS (RFC 8785) dla dozwolonego podzbioru JSON."""
    _check(obj)
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode('utf-8')


# --- Wpis z dziennika (linia zrzutu / /api/proof/entries) -------------------

@dataclass(frozen=True)
class LogEntry:
    """Jeden wpis dziennika publicznego — po walidacji formatu."""

    seq: int
    digest: str
    utc: datetime
    chain_hash: str
    prev_chain: str
    week: str

    @property
    def utc_text(self) -> str:
        return canonical_utc(self.utc)

    @property
    def leaf(self) -> bytes:
        return entry_leaf_hash(self.seq, self.digest, self.utc)

    def to_dict(self) -> dict:
        """Postac linii zrzutu tygodniowego (LOG.md §6), bez LF."""
        return {'chain_hash': self.chain_hash, 'digest': self.digest,
                'prev_chain': self.prev_chain, 'seq': self.seq,
                'utc': self.utc_text, 'week': self.week}


def parse_entry(raw: object) -> LogEntry:
    """Wpis z JSON-a -> `LogEntry`. `ValueError`, gdy cokolwiek nie gra.

    Sprawdzamy format KAZDEGO pola i przeliczamy ogniwo lancucha z tego, co
    przyszlo: wpis, ktorego `chain_hash` nie wynika z jego wlasnych danych,
    jest odrzucany od razu, a nie dopiero przy liczeniu drzewa.
    """
    if not isinstance(raw, dict):
        raise ValueError('entry is not an object')
    seq = raw.get('seq')
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise ValueError('entry: seq')
    digest = str(raw.get('digest') or '')
    chain = str(raw.get('chain_hash') or '')
    prev = str(raw.get('prev_chain') or '')
    week = str(raw.get('week') or '')
    for name, value in (('digest', digest), ('chain_hash', chain),
                        ('prev_chain', prev)):
        if not HEX64.match(value):
            raise ValueError(f'entry {seq}: {name}')
    if not _WEEK.match(week):
        raise ValueError(f'entry {seq}: week')
    dt = parse_canonical_utc(raw.get('utc'))
    if dt is None:
        raise ValueError(f'entry {seq}: utc')
    if chain_hash(prev, digest, dt) != chain:
        raise ValueError(f'entry {seq}: chain_hash does not follow from its data')
    return LogEntry(seq, digest, dt, chain, prev, week)


def check_chain(entries: list[LogEntry], previous: LogEntry | None = None) -> None:
    """Czy wpisy tworza ciagly lancuch (`prev_chain` = poprzedni `chain_hash`).

    `previous` to ostatni wpis, ktory juz mamy — kolejna porcja musi sie do
    niego doczepic. Numery (`seq`) rosna scisle, ale MOGA miec dziury
    (LOG.md §2), wiec o ciaglosci swiadczy wylacznie lancuch hashy.
    """
    prev = previous
    for entry in entries:
        expected = prev.chain_hash if prev is not None else GENESIS
        if entry.prev_chain != expected:
            raise ValueError(f'entry {entry.seq}: the chain is broken')
        if prev is not None and entry.seq <= prev.seq:
            raise ValueError(f'entry {entry.seq}: numbers do not increase')
        prev = entry


# --- Checkpoint -------------------------------------------------------------

def _require(cond: bool, message: str) -> None:
    if not cond:
        raise ValueError(message)


def validate_body(body: dict) -> None:
    """Tresc checkpointu (bez `sig`) wzgledem LOG.md §5 — kopia serwera."""
    _require(isinstance(body, dict), 'checkpoint must be an object')
    _require('sig' not in body, 'the signed body must not contain `sig`')
    kind = body.get('kind')
    _require(kind in ('daily', 'weekly'), 'kind: daily or weekly')
    expected = set(FIELDS_COMMON) | (set(FIELDS_WEEKLY) if kind == 'weekly' else set())
    _require(set(body) == expected, 'unexpected set of fields')
    _require(body['format'] == CHECKPOINT_V1, f'format: {CHECKPOINT_V1}')
    for name in ('n', 'tree_size', 'last_seq'):
        _require(isinstance(body[name], int) and not isinstance(body[name], bool)
                 and body[name] >= 1, f'{name}: integer >= 1')
    _require(isinstance(body['utc'], str) and bool(_UTC.match(body['utc'])),
             'utc: YYYY-MM-DDTHH:MM:SS.ffffffZ')
    for name in ('root', 'last_chain_hash'):
        _require(isinstance(body[name], str) and bool(HEX64.match(body[name])),
                 f'{name}: 64 hex characters')
    if body['n'] == 1:
        _require(body['prev'] is None, 'prev: null only for n=1')
    else:
        _require(isinstance(body['prev'], str) and bool(HEX64.match(body['prev'])),
                 'prev: hash of the previous checkpoint file')
    btc = body['btc']
    if btc is not None:
        _require(isinstance(btc, dict) and set(btc) == {'hash', 'height'},
                 'btc: {height, hash} or null')
        _require(isinstance(btc['height'], int) and not isinstance(btc['height'], bool)
                 and btc['height'] >= 0, 'btc.height')
        _require(isinstance(btc['hash'], str) and bool(HEX64.match(btc['hash'])),
                 'btc.hash: 64 hex characters')
    _require(isinstance(body['key'], str) and len(body['key']) == 44,
             'key: Ed25519 key in base64')
    if kind == 'weekly':
        _require(isinstance(body['week'], str) and bool(_WEEK.match(body['week'])),
                 'week: YYYY-Www')
        _require(isinstance(body['week_size'], int) and not isinstance(body['week_size'], bool)
                 and body['week_size'] >= 0, 'week_size')
        if body['week_size'] == 0:
            _require(body['week_root'] is None and body['dump'] is None,
                     'empty week: week_root and dump = null')
        else:
            _require(isinstance(body['week_root'], str)
                     and bool(HEX64.match(body['week_root'])), 'week_root')
            dump = body['dump']
            _require(isinstance(dump, dict) and set(dump) == {'file', 'sha256'},
                     'dump: {file, sha256}')
            _require(dump['file'] == f"{body['week']}.jsonl", 'dump.file')
            _require(isinstance(dump['sha256'], str)
                     and bool(HEX64.match(dump['sha256'])), 'dump.sha256')
        _require(isinstance(body['anchors'], list), 'anchors: list')
        for a in body['anchors']:
            _require(isinstance(a, dict) and set(a) == set(FIELDS_ANCHOR),
                     'anchors[]: fields')
            _require(isinstance(a['week'], str) and bool(_WEEK.match(a['week'])),
                     'anchors[].week')
            _require(isinstance(a['booked'], str) and bool(_DATE.match(a['booked'])),
                     'anchors[].booked')
            _require(isinstance(a['title'], str) and a['title'].startswith('MROOT ')
                     and len(a['title']) == 85, 'anchors[].title')
    canonical_json(body)


def signing_message(body: dict) -> bytes:
    """Wiadomosc podpisywana: `beattime-checkpoint-v1|` + JCS(tresc bez sig)."""
    validate_body(body)
    return CHECKPOINT_V1.encode('ascii') + b'|' + canonical_json(body)


def checkpoint_hash(data: bytes) -> str:
    """Hash checkpointu = SHA-256 BAJTOW PLIKU (to trafia do `prev`)."""
    return hashlib.sha256(data).hexdigest()


def verify_ed25519(message: bytes, sig_b64: str, pub_b64: str) -> bool:
    """Podpis Ed25519. Kazdy blad (zly base64, zla dlugosc) to False."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        pub = base64.b64decode(pub_b64, validate=True)
        Ed25519PublicKey.from_public_bytes(pub).verify(
            base64.b64decode(sig_b64, validate=True), message)
        return True
    except Exception:              # noqa: BLE001 — kazda porazka = „niepodpisane"
        return False


def key_valid_at(pub: object, when: datetime, override: str = '') -> bool:
    """Czy checkpoint podpisany kluczem `pub` w chwili `when` wolno uznac.

    Inaczej niz przy korzeniach tygodniowych: korzen tygodnia Sigelith
    podpisuje ponownie po kazdej rotacji, wiec podpis kluczem wycofanym
    nigdy nie jest ostatnim slowem. Checkpointu nie da sie podpisac
    ponownie — lezy u osob trzecich z bajtami z chwili publikacji. Uznajemy
    wiec klucz, ktory BYL wazny w chwili checkpointu: aktualny od swojego
    `active_from`, a wycofany — tylko przed data wycofania.
    """
    canonical = keys.canonical(pub)
    if not canonical:
        return False
    day = when.astimezone(timezone.utc).date().isoformat()
    for k in keys.CURRENT_KEYS:
        if k['public_key'] == canonical:
            return day >= str(k.get('active_from') or '')
    for k in keys.RETIRED_KEYS:
        if k['public_key'] == canonical:
            return str(k.get('active_from') or '') <= day < str(k['retired_on'])
    return keys.classify(canonical, override) == keys.SIGNER_OVERRIDE


@dataclass
class Checkpoint:
    """Checkpoint po sprawdzeniu bajtow pliku.

    `ok` znaczy: plik jest w postaci kanonicznej, tresc spelnia LOG.md §5,
    podpis Ed25519 sie zgadza, a klucz byl kluczem Sigelith w chwili
    checkpointu. Powiazania z innymi checkpointami (`prev`, spojnosc)
    sprawdza `witness.py` — ten obiekt opisuje jeden plik.
    """

    data: bytes = b''
    body: dict = field(default_factory=dict)
    sig: str = ''
    hash: str = ''
    ok: bool = False
    signature_ok: bool = False
    key_ok: bool = False
    problem: str = ''

    @property
    def n(self) -> int:
        return int(self.body.get('n') or 0)

    @property
    def kind(self) -> str:
        return str(self.body.get('kind') or '')

    @property
    def tree_size(self) -> int:
        return int(self.body.get('tree_size') or 0)

    @property
    def root(self) -> str:
        return str(self.body.get('root') or '')

    @property
    def prev(self) -> str:
        return str(self.body.get('prev') or '')

    @property
    def utc(self) -> datetime | None:
        return parse_canonical_utc(self.body.get('utc'))

    @property
    def week(self) -> str:
        return str(self.body.get('week') or '')

    @property
    def btc(self) -> dict | None:
        value = self.body.get('btc')
        return value if isinstance(value, dict) else None

    @property
    def release_week(self) -> str:
        """Tag wydania na GitHubie, w ktorym lezy ten checkpoint (LOG.md §7).

        Tygodniowy — tydzien, ktory zamyka. Dzienny — tydzien ISO swojej
        doby UTC (dzienny z poniedzialku nalezy juz do nowego tygodnia).
        """
        if self.kind == 'weekly' and self.week:
            return self.week
        dt = self.utc
        if dt is None:
            return ''
        year, week, _day = dt.isocalendar()
        return f'{year}-W{week:02d}'


def parse_checkpoint(data: bytes, *, override: str = '') -> Checkpoint:
    """Sprawdza plik checkpointu (BAJTY, nie rozpakowana tresc).

    Podpis i hash sprawdza sie na bajtach pliku (LOG.md §7) — dlatego
    najpierw odtwarzamy postac kanoniczna i porownujemy ja z tym, co
    przyszlo. Plik, ktory nie jest swoja wlasna postacia kanoniczna, nie
    jest checkpointem v1, nawet jesli podpis by sie zgadzal.
    """
    cp = Checkpoint(data=bytes(data), hash=checkpoint_hash(bytes(data)))
    try:
        raw = json.loads(bytes(data).decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        cp.problem = 'not a JSON document'
        return cp
    if not isinstance(raw, dict) or not isinstance(raw.get('sig'), str):
        cp.problem = 'no signature in the file'
        return cp
    try:
        if canonical_json(raw) != bytes(data):
            cp.problem = 'the file is not in canonical form'
            return cp
        body = {k: v for k, v in raw.items() if k != 'sig'}
        message = signing_message(body)
    except ValueError as e:
        cp.problem = str(e)
        return cp
    cp.body = body
    cp.sig = raw['sig']
    cp.signature_ok = verify_ed25519(message, cp.sig, str(body.get('key') or ''))
    moment = cp.utc
    cp.key_ok = moment is not None and key_valid_at(body.get('key'), moment, override)
    if not cp.signature_ok:
        cp.problem = 'the Ed25519 signature is invalid'
    elif not cp.key_ok:
        cp.problem = 'the key is not a Sigelith key valid at that time'
    cp.ok = cp.signature_ok and cp.key_ok
    return cp


def checkpoint_filename(n: int) -> str:
    """`000123.json` — nazwa pliku checkpointu w archiwum (LOG.md §7)."""
    return f'{int(n):06d}.json'
