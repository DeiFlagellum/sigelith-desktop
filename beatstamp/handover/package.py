"""
Paczka — HANDOVER_SPEC.md §4-5, §7.1-7.2, §7.5 i §11.3.

Nadawca: manifest i kontener -> szyfrogram (klucz z czesci A i B) -> podglad
-> oferta podpisana kluczem z karty. Odbiorca: odczyt oferty -> czesc A
i podglad (PRZED pytaniem czlowieka) -> sprawdzenie szyfrogramu -> po
opublikowaniu B: odszyfrowanie, kontrola kazdego skrotu, porownanie podgladu
z manifestem.

Wszystko strumieniowo: paczka moze miec gigabajty, a zaden plik nie jest
wydawany, zanim jego skrot sie nie zgodzi.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import BinaryIO, Callable

from cryptography.exceptions import InvalidTag

from . import jcs, stream
from .errors import HandoverError
from .identity import Card, Signer, read_card
from .primitives import (
    D_CONTAINER, D_CONTENT_KEY, D_OFFER, D_PART_A, D_PART_B, D_PREVIEW_KEY, D_SEAL_A,
    HPKE_OVERHEAD, VERSION, EncKey, b64decode, b64encode, format_ts, hex32, hkdf,
    hpke_seal, parse_ts, preview_open, preview_seal, sha256, signed_message,
    verify_signature)
from .rules import check_file_name, check_mime, check_text

MAX_FILES = 1000
TITLE_MAX = 200
NOTE_MAX = 2000
SENDER_NAME_MAX = 100
PREVIEW_FILES = 50
MANIFEST_MAX_BYTES = 1024 * 1024
PREVIEW_MAX_BYTES = 48 * 1024
AEAD_NAME = 'AES-256-GCM-STREAM'
SEGMENT = stream.SEGMENT

DEFAULT_EXPIRES = timedelta(days=30)
MAX_EXPIRES = timedelta(days=90)
DEFAULT_COMPLETE_WITHIN = 14 * 24 * 3600
MIN_COMPLETE_WITHIN = 3600
MAX_COMPLETE_WITHIN = 30 * 24 * 3600
CREATED_TOLERANCE = timedelta(minutes=5)

MANIFEST_FIELDS = frozenset({'v', 'type', 'salt', 'title', 'note', 'files'})
FILE_FIELDS = frozenset({'name', 'size', 'sha256', 'type'})
PREVIEW_FIELDS = frozenset({'title', 'note', 'sender_name', 'files', 'file_count',
                            'total_size'})
PREVIEW_FILE_FIELDS = frozenset({'name', 'size', 'type'})
OFFER_FIELDS = frozenset({'v', 'type', 'nonce', 'created', 'expires', 'complete_within',
                          'sender_card', 'recipient_card', 'content', 'ciphertext',
                          'part_a', 'part_b', 'preview', 'sig'})


def _fields(obj: object, fields: frozenset, code: str, what: str) -> dict:
    if not isinstance(obj, dict) or set(obj) != fields:
        raise HandoverError(code, f'{what}: expected fields {sorted(fields)}')
    return obj


def _int(value: object, field: str, code: str, lo: int = 0, hi: int = jcs.MAX_SAFE_INT) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise HandoverError(code, f'{field}: integer {lo}..{hi}')
    return value


# --- pliki wejsciowe, manifest, kontener -------------------------------------

@dataclass(frozen=True)
class InputFile:
    """Plik do wyslania: bajty w pamieci albo sciezka na dysku."""

    name: str
    source: bytes | str | Path
    type: str = 'application/octet-stream'

    def open(self) -> BinaryIO:
        if isinstance(self.source, (bytes, bytearray)):
            return io.BytesIO(bytes(self.source))
        return open(self.source, 'rb')


def _digest_file(f: InputFile) -> tuple[int, str]:
    h = hashlib.sha256()
    size = 0
    with f.open() as src:
        for chunk in iter(lambda: src.read(1 << 20), b''):
            h.update(chunk)
            size += len(chunk)
    return size, h.hexdigest()


def check_manifest(manifest: object) -> dict:
    """Struktura i reguly manifestu. Kod bledu zawsze `manifest-rules`."""
    try:
        _fields(manifest, MANIFEST_FIELDS, 'manifest-rules', 'manifest')
        if manifest['v'] != VERSION or manifest['type'] != 'manifest':
            raise HandoverError('manifest-rules', 'not a sigelith-handover-v1 manifest')
        b64decode(manifest['salt'], 'salt', 16)
        check_text(manifest['title'], 'title', TITLE_MAX)
        check_text(manifest['note'], 'note', NOTE_MAX, allow_lf=True)
        files = manifest['files']
        if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
            raise HandoverError('manifest-rules', f'files: 1..{MAX_FILES} entries')
        seen: set[str] = set()
        for i, entry in enumerate(files):
            _fields(entry, FILE_FIELDS, 'manifest-rules', f'files[{i}]')
            check_file_name(entry['name'], f'files[{i}].name')
            # upper(), nie casefold(): pelne mapowanie wielkich liter Unicode jest
            # takie samo w Pythonie i w JS (toUpperCase) — casefold() JS nie ma.
            folded = entry['name'].upper()
            if folded in seen:
                raise HandoverError('manifest-rules', f'files[{i}]: duplicate name '
                                    '(names must be unique ignoring case)')
            seen.add(folded)
            _int(entry['size'], f'files[{i}].size', 'manifest-rules')
            hex32(entry['sha256'], f'files[{i}].sha256')
            check_mime(entry['type'], f'files[{i}].type')
    except HandoverError as e:
        raise (e if e.code == 'manifest-rules' else e.renamed('manifest-rules')) from None
    return manifest


def build_manifest(files: list[InputFile], *, title: str, note: str, salt: bytes) -> dict:
    entries = []
    for f in files:
        size, digest = _digest_file(f)
        entries.append({'name': f.name, 'size': size, 'sha256': digest, 'type': f.type})
    manifest = {'v': VERSION, 'type': 'manifest', 'salt': b64encode(salt),
                'title': title, 'note': note, 'files': entries}
    return check_manifest(manifest)


class _ContainerSource:
    """Czyta kontener (linia manifestu + pliki) i przy okazji liczy skroty.

    Plik zmieniony po zbudowaniu manifestu (edytor zapisal go w trakcie
    pakowania) konczy sie bledem `file-changed` — inaczej nadawca wyslalby
    paczke, ktora odbiorca udowodni jako wadliwa.
    """

    def __init__(self, manifest: dict, files: list[InputFile]) -> None:
        self._entries = list(zip(manifest['files'], files))
        self._index = -1
        self._current: BinaryIO | None = io.BytesIO(jcs.dumps(manifest) + b'\n')
        self._file_hash = hashlib.sha256()
        self._file_size = 0
        self.hash = hashlib.sha256()
        self.size = 0

    def _advance(self) -> None:
        if self._current is not None:
            self._current.close()
        if self._index >= 0:
            entry = self._entries[self._index][0]
            if (self._file_size != entry['size']
                    or self._file_hash.hexdigest() != entry['sha256']):
                raise HandoverError('file-changed', f'{entry["name"]}: the file changed '
                                    'while the package was being made')
        self._index += 1
        if self._index >= len(self._entries):
            self._current = None
            return
        self._current = self._entries[self._index][1].open()
        self._file_hash = hashlib.sha256()
        self._file_size = 0

    def read(self, n: int = -1) -> bytes:
        while self._current is not None:
            chunk = self._current.read(n if n and n > 0 else 1 << 20)
            if chunk:
                if self._index >= 0:
                    self._file_hash.update(chunk)
                    self._file_size += len(chunk)
                self.hash.update(chunk)
                self.size += len(chunk)
                return chunk
            self._advance()
        return b''


class _HashingWriter:
    def __init__(self, dst: BinaryIO | None) -> None:
        self._dst = dst
        self.hash = hashlib.sha256()
        self.size = 0

    def write(self, data: bytes) -> int:
        if self._dst is not None:
            self._dst.write(data)
        self.hash.update(data)
        self.size += len(data)
        return len(data)


def _walk_container(src: BinaryIO, size: int,
                    open_sink: Callable[[int, dict], BinaryIO | None],
                    close_sink: Callable[[int, dict, BinaryIO | None], None]) -> dict:
    """Czyta kontener: manifest, potem pliki; kazdy plik sprawdza przed wydaniem."""
    line = src.readline(MANIFEST_MAX_BYTES + 1)
    if not line.endswith(b'\n'):
        raise HandoverError('manifest-rules', 'no manifest line within the size limit')
    try:
        manifest = jcs.loads(line[:-1], max_bytes=MANIFEST_MAX_BYTES, max_depth=4)
    except HandoverError as e:
        raise e.renamed('manifest-rules') from None
    check_manifest(manifest)
    if len(line) + sum(e['size'] for e in manifest['files']) != size:
        raise HandoverError('container-size', 'the file sizes do not add up to the container')
    for index, entry in enumerate(manifest['files']):
        sink = open_sink(index, entry)
        h = hashlib.sha256()
        left = entry['size']
        while left:
            chunk = src.read(min(left, 1 << 20))
            if not chunk:
                raise HandoverError('container-size', 'the container ends too early')
            h.update(chunk)
            if sink is not None:
                sink.write(chunk)
            left -= len(chunk)
        if h.hexdigest() != entry['sha256']:
            if sink is not None:
                sink.close()
            raise HandoverError('file-hash', f'{entry["name"]}: content does not match '
                                'its hash in the manifest')
        close_sink(index, entry, sink)
    if src.read(1):
        raise HandoverError('container-size', 'bytes after the last file')
    return manifest


def container_files(container: bytes) -> tuple[dict, list[bytes]]:
    """Kontener z pamieci -> (manifest, tresci plikow). Testy i male paczki."""
    buffers: list[io.BytesIO] = []

    def open_sink(_i: int, _e: dict) -> BinaryIO:
        buffers.append(io.BytesIO())
        return buffers[-1]

    manifest = _walk_container(io.BytesIO(container), len(container), open_sink,
                               lambda *_: None)
    return manifest, [b.getvalue() for b in buffers]


def check_container(src: BinaryIO, size: int) -> dict:
    """Sprawdza kontener bez zapisywania plikow (rozstrzyganie wady, weryfikator)."""
    return _walk_container(src, size, lambda *_: None, lambda *_: None)


def _free_name(folder: Path, name: str) -> Path:
    target = folder / name
    if not target.exists():
        return target
    stem, dot, ext = name.rpartition('.') if '.' in name else (name, '', '')
    for n in range(2, 10_000):
        candidate = folder / (f'{stem} ({n}).{ext}' if dot else f'{name} ({n})')
        if not candidate.exists():
            return candidate
    raise HandoverError('file-name', f'{name}: no free name in the folder')


def mark_of_the_web(path: Path) -> None:
    """Oznacza plik jako pobrany z internetu (Windows: strumien Zone.Identifier).

    Dzieki temu SmartScreen i Widok chroniony w Office traktuja otrzymany plik
    jak zalacznik z sieci. Na dyskach bez strumieni NTFS (FAT, exFAT, czesc
    udzialow sieciowych) oznaczenie sie nie uda — aplikacja ostrzega wtedy
    przed otwarciem niezaleznie od tego znacznika.
    """
    if os.name != 'nt':
        return
    try:
        with open(f'{path}:Zone.Identifier', 'w', encoding='ascii', newline='') as f:
            f.write('[ZoneTransfer]\r\nZoneId=3\r\n')
    except OSError:
        pass


def extract_container(src: BinaryIO, size: int, folder: Path) -> tuple[dict, list[Path]]:
    """Wypakowuje kontener do `folder`. Plik trafia pod swoja nazwe dopiero po
    zgodnosci skrotu; nazwy juz zajete dostaja „ (2)". Nic nie jest otwierane.
    """
    folder.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []
    partials: dict[int, Path] = {}

    def open_sink(index: int, _entry: dict) -> BinaryIO:
        partial = folder / f'.sigelith-partial-{index}'
        partials[index] = partial
        return open(partial, 'wb')

    def close_sink(index: int, entry: dict, sink: BinaryIO | None) -> None:
        assert sink is not None
        sink.close()
        target = _free_name(folder, entry['name'])
        os.replace(partials.pop(index), target)
        mark_of_the_web(target)
        saved.append(target)

    try:
        manifest = _walk_container(src, size, open_sink, close_sink)
    finally:
        for partial in partials.values():
            try:
                partial.unlink()
            except OSError:
                pass
    return manifest, saved


# --- czesci klucza, zobowiazania, podglad -------------------------------------

@dataclass(frozen=True)
class Parts:
    """Losowe elementy jednej oferty — kazda oferta MUSI miec nowe (§4.2)."""

    nonce: bytes
    a: bytes
    b: bytes
    nonce_prefix: bytes

    @classmethod
    def generate(cls, rng: Callable[[int], bytes] = os.urandom) -> 'Parts':
        return cls(nonce=rng(16), a=rng(32), b=rng(32), nonce_prefix=rng(7))


def content_key(a: bytes, b: bytes, nonce: bytes) -> bytes:
    return hkdf(a + b, nonce, D_CONTENT_KEY)


def preview_key(a: bytes, nonce: bytes) -> bytes:
    return hkdf(a, nonce, D_PREVIEW_KEY)


def commit_a(a: bytes) -> bytes:
    return sha256(D_PART_A, a)


def commit_b(b: bytes) -> bytes:
    return sha256(D_PART_B, b)


def container_aad(nonce: bytes) -> bytes:
    return sha256(D_CONTAINER, nonce)


def build_preview(manifest: dict, sender_name: str) -> dict:
    files = manifest['files']
    return {'title': manifest['title'], 'note': manifest['note'], 'sender_name': sender_name,
            'files': [{'name': e['name'], 'size': e['size'], 'type': e['type']}
                      for e in files[:PREVIEW_FILES]],
            'file_count': len(files), 'total_size': sum(e['size'] for e in files)}


def check_preview(preview: object) -> dict:
    try:
        _fields(preview, PREVIEW_FIELDS, 'preview-rules', 'preview')
        check_text(preview['title'], 'title', TITLE_MAX)
        check_text(preview['note'], 'note', NOTE_MAX, allow_lf=True)
        check_text(preview['sender_name'], 'sender_name', SENDER_NAME_MAX)
        count = _int(preview['file_count'], 'file_count', 'preview-rules', 1, MAX_FILES)
        _int(preview['total_size'], 'total_size', 'preview-rules')
        files = preview['files']
        if not isinstance(files, list) or len(files) != min(count, PREVIEW_FILES):
            raise HandoverError('preview-rules', 'files: the first min(file_count, 50) entries')
        for i, entry in enumerate(files):
            _fields(entry, PREVIEW_FILE_FIELDS, 'preview-rules', f'files[{i}]')
            check_file_name(entry['name'], f'files[{i}].name')
            _int(entry['size'], f'files[{i}].size', 'preview-rules')
            check_mime(entry['type'], f'files[{i}].type')
    except HandoverError as e:
        raise (e if e.code == 'preview-rules' else e.renamed('preview-rules')) from None
    return preview


def preview_differences(preview: dict, manifest: dict) -> list[str]:
    """Czym podglad (to, co odbiorca widzial przed przyjeciem) rozni sie od tresci."""
    expected = build_preview(manifest, preview.get('sender_name', ''))
    return [key for key in ('title', 'note', 'file_count', 'total_size', 'files')
            if preview.get(key) != expected[key]]


# --- oferta --------------------------------------------------------------------

@dataclass(frozen=True)
class Offer:
    """Oferta po sprawdzeniu struktury, kart, limitow i podpisu nadawcy."""

    raw: dict
    digest: bytes
    sender: Card
    recipient: Card
    nonce: bytes
    created: datetime
    expires: datetime
    complete_within: int
    content_sha256: bytes
    content_size: int
    nonce_prefix: bytes
    ciphertext_sha256: bytes
    ciphertext_size: int
    commit_a: bytes
    sealed_a: bytes
    commit_b: bytes
    preview_ct: bytes

    @property
    def answer_bound(self) -> datetime:
        """Najpozniejsze dopuszczalne `valid_until` odpowiedzi (§6)."""
        return self.expires + timedelta(seconds=self.complete_within)


def _check_window(created: datetime, expires: datetime, complete_within: int) -> None:
    if not created < expires <= created + MAX_EXPIRES:
        raise HandoverError('offer-limits', 'expires must be after created and at most '
                            '90 days later')
    _int(complete_within, 'complete_within', 'offer-limits', MIN_COMPLETE_WITHIN,
         MAX_COMPLETE_WITHIN)


def read_offer(offer: object) -> Offer:
    """Sprawdza oferte bez kluczy odbiorcy: struktura, karty, limity, podpis."""
    _fields(offer, OFFER_FIELDS, 'offer-structure', 'offer')
    try:
        if offer['v'] != VERSION or offer['type'] != 'offer':
            raise HandoverError('offer-structure', 'not a sigelith-handover-v1 offer')
        nonce = b64decode(offer['nonce'], 'nonce', 16)
        created = parse_ts(offer['created'], 'created')
        expires = parse_ts(offer['expires'], 'expires')
        content = _fields(offer['content'], frozenset({'sha256', 'size'}),
                          'offer-structure', 'content')
        content_sha256 = hex32(content['sha256'], 'content.sha256')
        cipher = _fields(offer['ciphertext'], frozenset({'aead', 'segment', 'nonce_prefix',
                                                         'sha256', 'size'}),
                         'offer-structure', 'ciphertext')
        nonce_prefix = b64decode(cipher['nonce_prefix'], 'ciphertext.nonce_prefix',
                                 stream.NONCE_PREFIX_LEN)
        ciphertext_sha256 = hex32(cipher['sha256'], 'ciphertext.sha256')
        part_a = _fields(offer['part_a'], frozenset({'commit', 'sealed'}),
                         'offer-structure', 'part_a')
        commit_a_ = hex32(part_a['commit'], 'part_a.commit')
        sealed_a = b64decode(part_a['sealed'], 'part_a.sealed', HPKE_OVERHEAD + 32)
        part_b = _fields(offer['part_b'], frozenset({'commit'}), 'offer-structure', 'part_b')
        commit_b_ = hex32(part_b['commit'], 'part_b.commit')
        preview_ct = b64decode(offer['preview'], 'preview')
        message = signed_message(D_OFFER, offer)
    except HandoverError as e:
        raise (e if e.code == 'offer-structure' else e.renamed('offer-structure')) from None
    try:
        sender = read_card(offer['sender_card'])
        recipient = read_card(offer['recipient_card'])
    except HandoverError as e:
        raise e.renamed('offer-card') from None
    if hmac.compare_digest(sender.fingerprint, recipient.fingerprint):
        raise HandoverError('offer-limits', 'sender and recipient are the same card')
    _check_window(created, expires, offer['complete_within'])
    content_size = _int(content['size'], 'content.size', 'offer-limits')
    if cipher['aead'] != AEAD_NAME or cipher['segment'] != SEGMENT:
        raise HandoverError('offer-limits', f'ciphertext: {AEAD_NAME} with {SEGMENT}-byte '
                            'segments')
    ciphertext_size = _int(cipher['size'], 'ciphertext.size', 'offer-limits')
    if ciphertext_size != stream.ciphertext_size(content_size):
        raise HandoverError('offer-limits', 'ciphertext.size does not match content.size')
    if not 16 <= len(preview_ct) <= PREVIEW_MAX_BYTES:
        raise HandoverError('offer-limits', 'preview size out of range')
    try:
        verify_signature(sender.sig_alg, sender.sig_key, message, offer['sig'])
    except HandoverError as e:
        raise e.renamed('offer-signature') from None
    return Offer(raw=offer, digest=sha256(message), sender=sender, recipient=recipient,
                 nonce=nonce, created=created, expires=expires,
                 complete_within=offer['complete_within'], content_sha256=content_sha256,
                 content_size=content_size, nonce_prefix=nonce_prefix,
                 ciphertext_sha256=ciphertext_sha256, ciphertext_size=ciphertext_size,
                 commit_a=commit_a_, sealed_a=sealed_a, commit_b=commit_b_,
                 preview_ct=preview_ct)


def check_offer_times(offer: Offer, log_now: datetime) -> None:
    """Czas oferty wzgledem czasu DZIENNIKA (nie zegara komputera)."""
    if offer.created > log_now + CREATED_TOLERANCE:
        raise HandoverError('offer-created-future', 'the offer was created in the future')
    if log_now >= offer.expires:
        raise HandoverError('offer-expired', 'the offer has expired')


@dataclass
class Outgoing:
    """Wynik pakowania po stronie nadawcy. `parts.b` to sekret do czasu publikacji."""

    offer: dict
    info: Offer
    parts: Parts
    manifest: dict


def create_offer(*, signer: Signer, sender_card: dict, recipient_card: dict,
                 files: list[InputFile], ciphertext_out: BinaryIO, created: datetime,
                 title: str = '', note: str = '', sender_name: str = '',
                 expires: datetime | None = None,
                 complete_within: int = DEFAULT_COMPLETE_WITHIN,
                 rng: Callable[[int], bytes] = os.urandom) -> Outgoing:
    """Pakuje pliki, szyfruje je do `ciphertext_out` i zwraca podpisana oferte."""
    sender = read_card(sender_card)
    recipient = read_card(recipient_card)
    if signer.public_bytes != sender.sig_key or signer.alg != sender.sig_alg:
        raise HandoverError('signer', 'the signer does not match the sender card')
    check_text(sender_name, 'sender_name', SENDER_NAME_MAX)
    created = created.replace(microsecond=0)
    expires = (expires or created + DEFAULT_EXPIRES).replace(microsecond=0)
    _check_window(created, expires, complete_within)

    parts = Parts.generate(rng)
    manifest = build_manifest(files, title=title, note=note, salt=rng(16))
    source = _ContainerSource(manifest, files)
    sink = _HashingWriter(ciphertext_out)
    stream.encrypt(content_key(parts.a, parts.b, parts.nonce), parts.nonce_prefix,
                   container_aad(parts.nonce), source, sink)
    preview = check_preview(build_preview(manifest, sender_name))
    offer = {
        'v': VERSION, 'type': 'offer', 'nonce': b64encode(parts.nonce),
        'created': format_ts(created), 'expires': format_ts(expires),
        'complete_within': complete_within,
        'sender_card': sender_card, 'recipient_card': recipient_card,
        'content': {'sha256': source.hash.hexdigest(), 'size': source.size},
        'ciphertext': {'aead': AEAD_NAME, 'segment': SEGMENT,
                       'nonce_prefix': b64encode(parts.nonce_prefix),
                       'sha256': sink.hash.hexdigest(), 'size': sink.size},
        'part_a': {'commit': commit_a(parts.a).hex(),
                   'sealed': b64encode(hpke_seal(recipient.enc_key, parts.a,
                                                 D_SEAL_A + parts.nonce))},
        'part_b': {'commit': commit_b(parts.b).hex()},
        'preview': b64encode(preview_seal(preview_key(parts.a, parts.nonce),
                                          jcs.dumps(preview))),
    }
    offer['sig'] = signer.sign(signed_message(D_OFFER, offer))
    return Outgoing(offer=offer, info=read_offer(offer), parts=parts, manifest=manifest)


# --- odbiorca: przed pytaniem czlowieka (§7.2) -------------------------------

def open_preview(offer: Offer, a: bytes) -> dict:
    raw = preview_open(preview_key(a, offer.nonce), offer.preview_ct)
    try:
        preview = jcs.loads(raw, max_bytes=PREVIEW_MAX_BYTES)
    except HandoverError as e:
        raise e.renamed('preview-rules') from None
    return check_preview(preview)


def open_offer(offer: Offer, enc_key: EncKey, my_card: Card) -> tuple[bytes, dict]:
    """Czesc A i podglad. Kazdy blad = oferta wadliwa, NIGDY pytanie do czlowieka."""
    if (not hmac.compare_digest(offer.recipient.fingerprint, my_card.fingerprint)
            or enc_key.public_bytes != offer.recipient.enc_key):
        raise HandoverError('offer-not-mine', 'the offer is addressed to another card')
    try:
        a = enc_key.open(offer.sealed_a, D_SEAL_A + offer.nonce)
    except HandoverError as e:
        raise e.renamed('part-a-open') from None
    if len(a) != 32 or not hmac.compare_digest(commit_a(a), offer.commit_a):
        raise HandoverError('part-a-commit', 'part A does not match its commitment')
    return a, open_preview(offer, a)


def copy_ciphertext(offer: Offer, src: BinaryIO, dst: BinaryIO | None = None) -> None:
    """Kopiuje szyfrogram (albo tylko liczy skrot) i sprawdza go z oferta."""
    sink = _HashingWriter(dst)
    for chunk in iter(lambda: src.read(1 << 20), b''):
        sink.write(chunk)
        if sink.size > offer.ciphertext_size:
            raise HandoverError('ciphertext-size', 'the ciphertext is longer than offered')
    if sink.size != offer.ciphertext_size:
        raise HandoverError('ciphertext-size', 'the ciphertext is shorter than offered')
    if sink.hash.digest() != offer.ciphertext_sha256:
        raise HandoverError('ciphertext-hash', 'the ciphertext is not the offered one')


# --- odbiorca: po opublikowaniu B (§7.5) --------------------------------------

def decrypt_package(offer: Offer, a: bytes, b: bytes, ciphertext: BinaryIO,
                    container_out: BinaryIO) -> None:
    """Odszyfrowuje szyfrogram do `container_out` i sprawdza skrot kontenera."""
    if len(a) != 32 or not hmac.compare_digest(commit_a(a), offer.commit_a):
        raise HandoverError('part-a-commit', 'part A does not match its commitment')
    if len(b) != 32 or not hmac.compare_digest(commit_b(b), offer.commit_b):
        raise HandoverError('part-b-commit', 'part B does not match its commitment')
    sink = _HashingWriter(container_out)
    try:
        stream.decrypt(content_key(a, b, offer.nonce), offer.nonce_prefix,
                       container_aad(offer.nonce), ciphertext, sink)
    except (InvalidTag, ValueError):
        raise HandoverError('ciphertext-tag', 'the ciphertext does not decrypt with the '
                            'committed key') from None
    if sink.size != offer.content_size or sink.hash.digest() != offer.content_sha256:
        raise HandoverError('content-hash', 'the content is not the committed one')


def open_package(offer: Offer, a: bytes, b: bytes, ciphertext: BinaryIO, preview: dict,
                 folder: Path) -> tuple[dict, list[Path], list[str]]:
    """Pelne otwarcie: odszyfrowanie, kontrola, wypakowanie, porownanie z podgladem.

    Zwraca (manifest, zapisane pliki, roznice podglad/manifest). Niepusta lista
    roznic oznacza wade oferty (§11.3) — pliki i tak sa zapisane, bo odbiorca
    ma do nich prawo, ale aplikacja musi pokazac, ze podglad klamal.
    """
    with tempfile.TemporaryFile() as container:
        decrypt_package(offer, a, b, ciphertext, container)
        container.seek(0)
        manifest, saved = extract_container(container, offer.content_size, folder)
    return manifest, saved, preview_differences(preview, manifest)


# --- rozstrzygniecie zarzutu wady (§11.3) -------------------------------------

@dataclass(frozen=True)
class DefectFinding:
    """Co wyszlo z przeliczenia zarzutu. `code` None = paczka otwiera sie dobrze.
    Podglad i manifest sa, o ile daly sie odczytac — do pokazania roznic."""

    code: str | None
    offer: Offer
    preview: dict | None = None
    manifest: dict | None = None
    differences: tuple[str, ...] = ()


def examine_defect(offer_raw: dict, a: bytes, b: bytes, ciphertext: BinaryIO) -> DefectFinding:
    """Przeliczenie zarzutu wady: A, B i szyfrogram z oferta, potem odszyfrowanie.

    `HandoverError('defect-claim')`, gdy falszywy jest sam zarzut: A, B albo
    szyfrogram nie sa tymi z oferty. Odbiorca nie moze wiec uniewaznic dobrej
    dostawy, podajac cos innego — kazdy przeliczy to samo.
    """
    offer = read_offer(offer_raw)
    if len(a) != 32 or not hmac.compare_digest(commit_a(a), offer.commit_a):
        raise HandoverError('defect-claim', 'A is not the part committed in the offer')
    if len(b) != 32 or not hmac.compare_digest(commit_b(b), offer.commit_b):
        raise HandoverError('defect-claim', 'B is not the part committed in the offer')
    with tempfile.SpooledTemporaryFile(max_size=64 << 20) as held:
        try:
            copy_ciphertext(offer, ciphertext, held)
        except HandoverError as e:
            raise HandoverError('defect-claim', f'not the offered ciphertext ({e.code})') from None
        held.seek(0)
        try:
            preview = open_preview(offer, a)
        except HandoverError as e:
            return DefectFinding(e.code, offer)
        with tempfile.SpooledTemporaryFile(max_size=64 << 20) as container:
            try:
                decrypt_package(offer, a, b, held, container)
                container.seek(0)
                manifest = check_container(container, offer.content_size)
            except HandoverError as e:
                return DefectFinding(e.code, offer, preview)
    differences = tuple(preview_differences(preview, manifest))
    return DefectFinding('preview-mismatch' if differences else None, offer, preview, manifest,
                         differences)


def check_defect(offer_raw: dict, a: bytes, b: bytes, ciphertext: BinaryIO) -> str | None:
    """Czy oferta jest wadliwa. Zwraca kod wady albo None (paczka otwiera sie dobrze)."""
    return examine_defect(offer_raw, a, b, ciphertext).code
