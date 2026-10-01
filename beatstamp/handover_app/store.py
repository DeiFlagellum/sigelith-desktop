"""
Stan Sigelith Handover na dysku: tozsamosc (karta i klucze), kontakty oraz
przesylki wyslane i odebrane.

    <katalog>/identity.json            karty uzytkownika (aktywna + archiwalne)
    <katalog>/contacts.json            karty innych osob z moim zapisem powiazania
    <katalog>/outgoing/<skrot>.json    przesylka wyslana (+ .ciphertext)
    <katalog>/incoming/<skrot>.json    przesylka odebrana (+ .ciphertext)

Sekrety — klucz szyfrujacy karty, klucz programowy (gdy nie ma Windows Hello),
czesci A i B — leza WYLACZNIE jako bloby DPAPI (dpapi.py) z celem przypisanym
do rodzaju sekretu. Reszta to dane publiczne protokolu (karty, oferty,
odpowiedzi) albo wlasne dane uzytkownika (tytuly, nazwy plikow), jak w
historii stempli.

Karty archiwalne zostaja: ich klucze szyfrujace otwieraja przesylki wyslane
na stara karte. Nic nie jest kasowane po cichu.

Zapis atomowy (plik tymczasowy + os.replace): przerwany zapis zostawia stara,
cala wersje, nigdy pol pliku.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import TypeVar

from ..handover.identity import read_card

FORMAT = 1
_HEX64 = re.compile(r'[0-9a-f]{64}')
T = TypeVar('T')


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _dump(obj: object) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=True) + '\n').encode('utf-8')


def _load(cls: type[T], data: dict) -> T:
    """Rekord z JSON — pola nieznane pomijamy (nowsza wersja programu), brakujace
    biora wartosc domyslna."""
    names = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in names})


# --- rekordy -----------------------------------------------------------------

@dataclass
class Identity:
    """Moja karta. `cred_id` = klucz Windows Hello; `signing_blob` = zapasowy
    klucz programowy (DPAPI), gdy Windows Hello nie ma."""

    fingerprint: str
    card: dict
    enc_blob: str                          # b64 DPAPI(klucz szyfrujacy 96 B)
    created: str
    attestation: dict | None = None        # zalacznik §3.6 (tylko TPM)
    attestation_raw: dict | None = None    # atestacja w innym formacie — do zachowania
    cred_id: str | None = None             # b64
    signing_blob: str | None = None        # b64 DPAPI(klucz P-256)
    archived: bool = False


@dataclass
class Contact:
    fingerprint: str
    card: dict
    label: str                             # moja nazwa kontaktu — poza protokolem
    binding: dict                          # moj podpisany zapis powiazania (§3.4)
    added: str
    attestation: dict | None = None
    binding_stamped: bool = False


@dataclass
class Outgoing:
    offer_digest: str
    offer: dict
    contact: str                           # odcisk odbiorcy
    title: str
    files: list[str]
    total_size: int
    part_a_blob: str                       # b64 DPAPI — do ujawnienia tresci w dowodzie
    part_b_blob: str                       # b64 DPAPI — sekret do chwili publikacji
    created: str
    status: str = 'sent'                   # sent|delivered|refused|expired|failed
    offer_stamped: bool = False
    answers: list[dict] = field(default_factory=list)
    # B wyszlo do dziennika co najmniej raz (moglo zostac zapisane mimo bledu
    # sieci) — tylko wtedy wolno o B pytac, zanim sie je opublikuje (§13 p. 4).
    publish_attempted: bool = False
    delivered_at: str | None = None
    refused_at: str | None = None
    package_path: str | None = None
    evidence_path: str | None = None
    note: str = ''
    error: str | None = None


@dataclass
class Incoming:
    offer_digest: str
    offer: dict
    sender: str                            # odcisk nadawcy
    my_card: str                           # odcisk mojej karty, na ktora przyszla
    preview: dict
    part_a_blob: str                       # b64 DPAPI
    received: str
    status: str = 'new'                    # new|accepted|refused|opened|expired|defective
    offer_stamped_at: str | None = None    # T0 z dziennika (§7.2.4), jesli jest
    answer: dict | None = None
    answer_seq: int | None = None          # seq stempla odpowiedzi — B szukamy od niego
    search_seq: int | None = None          # dokad dziennik juz przejrzany (nastepny seq)
    answer_file: str | None = None         # b64 pliku odpowiedzi (do ponownego wyslania)
    part_b: str | None = None
    opened_at: str | None = None
    folder: str | None = None
    saved: list[str] = field(default_factory=list)
    preview_differences: list[str] = field(default_factory=list)
    evidence_path: str | None = None
    error: str | None = None


class HandoverStore:
    """Magazyn stanu w jednym katalogu (zwykle <dane aplikacji>/handover)."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    # --- pliki ---------------------------------------------------------------

    def _read(self, path: Path, default):
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            return default
        if not isinstance(data, dict) or data.get('format') != FORMAT:
            raise ValueError(f'{path.name}: unknown format')
        return data

    def _write(self, path: Path, payload: dict) -> None:
        _atomic_write(path, _dump({'format': FORMAT, **payload}))

    @staticmethod
    def _digest(value: str) -> str:
        if not isinstance(value, str) or not _HEX64.fullmatch(value):
            raise ValueError('digest: 64 lowercase hex characters')
        return value

    # --- tozsamosc -----------------------------------------------------------

    def identities(self) -> list[Identity]:
        data = self._read(self.root / 'identity.json', {'cards': []})
        return [_load(Identity, x) for x in data.get('cards', [])]

    def active_identity(self) -> Identity | None:
        """Najnowsza niezarchiwizowana karta."""
        live = [i for i in self.identities() if not i.archived]
        return live[-1] if live else None

    def save_identity(self, ident: Identity) -> None:
        read_card(ident.card)                     # do magazynu trafia tylko poprawna karta
        cards = [i for i in self.identities() if i.fingerprint != ident.fingerprint]
        cards.append(ident)
        self._write(self.root / 'identity.json', {'cards': [asdict(card) for card in cards]})

    # --- kontakty ------------------------------------------------------------

    def contacts(self) -> list[Contact]:
        data = self._read(self.root / 'contacts.json', {'contacts': []})
        return [_load(Contact, x) for x in data.get('contacts', [])]

    def contact(self, fingerprint: str) -> Contact | None:
        return next((c for c in self.contacts() if c.fingerprint == fingerprint), None)

    def save_contact(self, contact: Contact) -> None:
        read_card(contact.card)
        rest = [c for c in self.contacts() if c.fingerprint != contact.fingerprint]
        rest.append(contact)
        rest.sort(key=lambda c: c.label.casefold())
        self._write(self.root / 'contacts.json', {'contacts': [asdict(c) for c in rest]})

    def remove_contact(self, fingerprint: str) -> None:
        rest = [c for c in self.contacts() if c.fingerprint != fingerprint]
        self._write(self.root / 'contacts.json', {'contacts': [asdict(c) for c in rest]})

    # --- przesylki -----------------------------------------------------------

    def _items(self, kind: str, cls: type[T]) -> list[T]:
        folder = self.root / kind
        out = []
        for path in sorted(folder.glob('*.json')) if folder.is_dir() else []:
            data = self._read(path, None)
            if data is not None:
                out.append(_load(cls, data['item']))
        return out

    def _get(self, kind: str, cls: type[T], digest: str) -> T | None:
        data = self._read(self.root / kind / f'{self._digest(digest)}.json', None)
        return _load(cls, data['item']) if data else None

    def _put(self, kind: str, digest: str, item: object) -> None:
        self._write(self.root / kind / f'{self._digest(digest)}.json', {'item': asdict(item)})

    def outgoing(self) -> list[Outgoing]:
        return sorted(self._items('outgoing', Outgoing), key=lambda r: r.created, reverse=True)

    def get_outgoing(self, digest: str) -> Outgoing | None:
        return self._get('outgoing', Outgoing, digest)

    def save_outgoing(self, record: Outgoing) -> None:
        self._put('outgoing', record.offer_digest, record)

    def incoming(self) -> list[Incoming]:
        return sorted(self._items('incoming', Incoming), key=lambda r: r.received, reverse=True)

    def get_incoming(self, digest: str) -> Incoming | None:
        return self._get('incoming', Incoming, digest)

    def save_incoming(self, record: Incoming) -> None:
        self._put('incoming', record.offer_digest, record)

    def ciphertext_path(self, kind: str, digest: str) -> Path:
        if kind not in ('outgoing', 'incoming'):
            raise ValueError('kind: outgoing or incoming')
        return self.root / kind / f'{self._digest(digest)}.ciphertext'
