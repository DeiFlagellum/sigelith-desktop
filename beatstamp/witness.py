"""
Swiadkowie — Sigelith Desktop jako niezalezny audytor dziennika Sigelith.

Co ten modul robi, kiedy aplikacja jest otwarta
-----------------------------------------------
Zasada z LOG.md brzmi: **audytor jest swiadkiem**. Nie potrzeba wyznaczonych
obserwatorow — wystarczy, ze KAZDY, kto ma interes, moze policzyc. Sigelith
Desktop liczy sam, w tle, przy kazdym uruchomieniu i co kwadrans:

1. **Checkpointy.** Pobiera kazdy nowy checkpoint jako BAJTY pliku, sprawdza
   postac kanoniczna, podpis Ed25519 i klucz (lista wbudowana w program),
   a potem lancuch `prev` — hash poprzedniego pliku. Checkpoint o numerze,
   ktory juz widzielismy, ale z inna trescia, to dowod, ze Sigelith pokazuje
   rozne historie roznym ludziom. Oba pliki zostaja wtedy na dysku jako
   material dowodowy (`witness/evidence/`).
2. **Spojnosc.** Miedzy kolejnymi checkpointami sprawdza dowod RFC 9162, ze
   nowe drzewo jest rozszerzeniem starego — nic nie wycieto, nic nie
   przepisano. W trybie prywatnym robi wiecej: przelicza korzen KAZDEGO
   checkpointu od zera z wlasnej kopii dziennika.
3. **Osoby trzecie.** Porownuje checkpointy z kopiami, ktore Sigelith
   publikuje u innych: niezmienne wydania na GitHubie, migawki Internet
   Archive, wersje kwartalne w Zenodo. Kopie leza poza kontrola Sigelith,
   wiec zgodnosc przypina cala historie przed nimi. Niezgodnosc z poprawnie
   podpisana kopia jest dowodem nieuczciwosci, a nie usterka.
4. **Bitcoin.** Blok nazwany w checkpoincie sprawdza u niezaleznego
   eksploratora (mempool.space, zapasowo blockstream.info) — czy o tej
   wysokosci naprawde jest blok o tym hashu i kiedy zostal wydobyty.

Dwa tryby sprawdzania dowodow
-----------------------------
* **Prywatny (domyslny)** — aplikacja trzyma kopie CALEGO publicznego
  dziennika (`witness/log.jsonl`) i wszystko liczy sama: sciezke do korzenia
  tygodnia, sciezke do checkpointu, trzy czasy. Od serwera bierze tylko to,
  co jest wspolne dla calego tygodnia (`/api/proof/weeks/<week>`). Serwer
  nie dowiaduje sie, KTORE wpisy dotycza uzytkownika — ani przy odswiezaniu
  historii, ani przy sprawdzaniu cudzego pliku.
* **Szybki** — pyta serwer o kazdy skrot osobno (`/api/proof/verify`), jak
  wersja 2.1. Mniej danych, ale serwer widzi, o co pytamy. Sciezke do
  checkpointu sprawdzamy i tak lokalnie, wzgledem pliku checkpointu
  zweryfikowanego w punkcie 1.

Stemplowanie z definicji wysyla skrot — to jest jego jedyny cel.

Watki
-----
Nic tu nie dotyka Qt. Funkcje sieciowe wolaja wylacznie zadania z puli
`workers.py`, a pula ma JEDEN watek, wiec kopia dziennika i stan swiadkow
nigdy nie sa zmieniane z dwoch watkow naraz. Stan zapisuje watek GUI po
powrocie zadania.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import beatcore, logtree, merkle, proof
from .api import ApiError
from .config import app_data_dir, json_loads, write_atomic
from .i18n import _

log = logging.getLogger(__name__)

STATE_VERSION = 1

MODE_PRIVATE = 'private'
MODE_FAST = 'fast'
MODES = (MODE_PRIVATE, MODE_FAST)

#: Gdzie Sigelith publikuje kopie (LOG.md §7). Adresy GitHuba i Internet
#: Archive sa STALE, wpisane w program — nie pytamy Sigelith, gdzie szukac
#: jego wlasnych kopii. Zenodo nie ma stalego adresu przed pierwsza wersja,
#: wiec jego rekord wskazuje serwer; tresc plikow i tak sprawdzamy sami.
#:
#: Repozytorium nazywalo sie `DeiFlagellum/beattime-log` — przemianowane
#: 2026-09-27, PRZED pierwszym wydaniem (2026-W39); GitHub przekierowuje
#: stara nazwe, a `fetch_external` przechodzi przekierowania GitHuba.
GITHUB_REPO = 'DeiFlagellum/sigelith-log'
GITHUB_ASSET = 'https://github.com/{repo}/releases/download/{week}/{name}'
GITHUB_RELEASE = 'https://github.com/{repo}/releases/tag/{week}'
#: Zapytanie o migawki pliku checkpointu: od dnia jego wydania, piec
#: NAJWCZESNIEJSZYCH. `limit=-5` (piec ostatnich) kaze indeksowi CDX przejsc
#: cala historie adresu i w pomiarach 2026-09-27 trwalo 9–48 s albo konczylo
#: sie przekroczeniem czasu; `from=` + dodatni `limit` odpowiada od razu
#: (tak pyta serwer: apps/tsa/wayback.py, `snapshot_since`). Plik checkpointu
#: sie nie zmienia, wiec kazda poprawna migawka jest rownie dobra.
WAYBACK_CDX = ('https://web.archive.org/cdx/search/cdx?url={url}&output=json'
               '&filter=statuscode:200&fl=timestamp,digest&from={since}&limit=5')
WAYBACK_RAW = 'https://web.archive.org/web/{timestamp}id_/{url}'
WAYBACK_VIEW = 'https://web.archive.org/web/{timestamp}/{url}'
ZENODO_FILE = 'https://zenodo.org/records/{record}/files/{name}?download=1'
#: Publiczny adres pliku checkpointu — ten, pod ktorym serwer zamawia migawke
#: w Internet Archive (apps/tsa/archival.py). Od 2026-W39 migawki powstaja
#: pod sigelith.org; pod beattime.live nie ma zadnej, ale PYTAMY tez o ten
#: adres — to ta sama instancja, wiec migawka pod ktorymkolwiek z nich jest
#: rownie dobra kopia (porownujemy BAJTY podpisanego pliku, nie adres).
#: Kolejnosc = kolejnosc zapytan: najpierw adres, pod ktorym migawki SA.
CHECKPOINT_PUBLIC = 'https://sigelith.org/checkpoints/{name}'
CHECKPOINT_PUBLIC_URLS = (CHECKPOINT_PUBLIC,
                          'https://beattime.live/checkpoints/{name}')
EXPLORERS = ('https://mempool.space/api', 'https://blockstream.info/api')

SOURCES = ('github', 'wayback', 'zenodo')

#: Co ile sprawdzac kopie, ktorych jeszcze nie ma (wydania wychodza w swoim
#: rytmie — GitHub najpozniej dobe po checkpoincie tygodniowym).
COPY_RETRY = timedelta(hours=3)
#: Kopia, ktorej nie da sie odczytac (albo podpisana inaczej): raz na dobe.
#: Migawka w Internet Archive jest wieczna — sprawdzanie jej co 3 h u kazdego
#: uzytkownika nic nie zmienia, a obciaza archiwum.
COPY_RETRY_SLOW = timedelta(hours=24)
#: Szczegoly checkpointu (stan OTS, czas bloku, rekord Zenodo) dojrzewaja po
#: jego wydaniu. Ile checkpointow dociagamy w jednym przebiegu i jak czesto
#: pytamy o ten sam: swiezy (< 2 dni) co godzine, starszy raz na dobe.
DETAILS_PER_RUN = 8
DETAILS_RETRY = timedelta(hours=1)
DETAILS_RETRY_OLD = timedelta(hours=24)
#: Wersja kwartalna w Zenodo wychodzi po koncu kwartalu (LOG.md §7) — wczesniej
#: nie ma o co pytac.
ZENODO_GRACE = timedelta(hours=48)
#: Ile nowych checkpointow na jeden przebieg. Pula ma jeden watek, a limit
#: API to 120 zapytan na minute — przy pierwszym uruchomieniu po roku bylo by
#: ich kilkaset, wiec reszta idzie w kolejnych przebiegach, a stemplowanie
#: nie czeka minutami za audytem.
MAX_CHECKPOINTS_PER_RUN = 40
#: Ile wpisow dziennika najwyzej dociagamy w jednym przebiegu.
MAX_MIRROR_ENTRIES_PER_SYNC = 200_000

# Alarmy — `critical` znaczy „dowod nieuczciwosci albo uszkodzenia", nie
# „cos nie odpowiada".
ALARM_SIGNATURE = 'checkpoint_signature'
ALARM_FORK = 'checkpoint_fork'
ALARM_EQUIVOCATION = 'checkpoint_equivocation'
ALARM_CONSISTENCY = 'consistency'
ALARM_LOG_ROOT = 'log_root'
ALARM_LOG_REWRITTEN = 'log_rewritten'
ALARM_COPY_MISMATCH = 'copy_mismatch'
ALARM_BTC = 'btc_block'

_RECORD_ID = re.compile(r'(?:records?/|zenodo\.)(\d{3,12})')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_ISO_Z = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$')


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str:
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') if dt else ''


def _parse_iso(text: object) -> datetime | None:
    value = str(text or '')
    if not _ISO_Z.match(value):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError:
        return None


def witness_dir() -> Path:
    return app_data_dir() / 'witness'


# --- Stan ---------------------------------------------------------------------

@dataclass
class CheckpointRecord:
    """Checkpoint, ktory aplikacja sama sprawdzila (plik lezy obok)."""

    n: int
    hash: str
    kind: str
    tree_size: int
    root: str
    prev: str
    utc: str
    week: str
    release_week: str
    btc: dict | None = None
    btc_time: str = ''
    ots_status: str = 'none'
    ots_height: int | None = None
    ots_time: str = ''
    zenodo: str = ''                     # adres rekordu wskazany przez serwer
    consistent: bool | None = None       # dowod spojnosci z poprzednim
    audited: bool | None = None          # korzen przeliczony z kopii dziennika
    details_checked: str = ''            # kiedy ostatnio pytano o szczegoly

    @property
    def utc_dt(self) -> datetime | None:
        return logtree.parse_canonical_utc(self.utc)

    @classmethod
    def from_dict(cls, raw: dict) -> 'CheckpointRecord | None':
        try:
            return cls(
                n=int(raw['n']), hash=str(raw['hash']), kind=str(raw['kind']),
                tree_size=int(raw['tree_size']), root=str(raw['root']),
                prev=str(raw.get('prev') or ''), utc=str(raw['utc']),
                week=str(raw.get('week') or ''),
                release_week=str(raw.get('release_week') or ''),
                btc=raw.get('btc') if isinstance(raw.get('btc'), dict) else None,
                btc_time=str(raw.get('btc_time') or ''),
                ots_status=str(raw.get('ots_status') or 'none'),
                ots_height=raw.get('ots_height') if isinstance(raw.get('ots_height'), int) else None,
                ots_time=str(raw.get('ots_time') or ''),
                zenodo=str(raw.get('zenodo') or ''),
                consistent=raw.get('consistent') if isinstance(raw.get('consistent'), bool) else None,
                audited=raw.get('audited') if isinstance(raw.get('audited'), bool) else None,
                details_checked=str(raw.get('details_checked') or ''),
            )
        except (KeyError, TypeError, ValueError, OverflowError):
            return None


@dataclass
class WitnessState:
    """Wszystko, co aplikacja wie o dzienniku — zapisywane w `state.json`."""

    checkpoints: dict[int, CheckpointRecord] = field(default_factory=dict)
    log_size: int = 0
    log_last_seq: int = 0
    copies: dict = field(default_factory=dict)       # zrodlo -> {max_n, weeks}
    weeks: dict = field(default_factory=dict)        # tydzien -> dane tygodnia
    blocks: dict = field(default_factory=dict)       # wysokosc -> {hash, time, source, ok}
    pipeline: dict = field(default_factory=dict)     # /api/proof/status
    alarms: list = field(default_factory=list)
    last_refresh: str = ''
    last_success: str = ''
    last_error: str = ''

    # --- Pochodne -----------------------------------------------------------

    @property
    def latest(self) -> CheckpointRecord | None:
        return self.checkpoints[max(self.checkpoints)] if self.checkpoints else None

    @property
    def verified_n(self) -> int:
        """Najwyzszy numer, do ktorego lancuch jest ciagly i sprawdzony."""
        n = 0
        while (n + 1) in self.checkpoints:
            n += 1
        return n

    @property
    def critical_alarms(self) -> list[dict]:
        return [a for a in self.alarms if a.get('severity') == 'critical']

    def copy_max(self, source: str) -> int:
        return int((self.copies.get(source) or {}).get('max_n') or 0)

    def covering(self, index: int) -> CheckpointRecord | None:
        """Pierwszy sprawdzony checkpoint, ktory zawiera wpis na pozycji `index`."""
        for n in sorted(self.checkpoints):
            record = self.checkpoints[n]
            if record.tree_size > index:
                return record
        return None

    def before(self, index: int) -> CheckpointRecord | None:
        """Ostatni checkpoint wystawiony PRZED wpisem (tree_size <= index)."""
        found = None
        for n in sorted(self.checkpoints):
            record = self.checkpoints[n]
            if record.tree_size <= index:
                found = record
        return found

    def to_dict(self) -> dict:
        return {
            'version': STATE_VERSION,
            'checkpoints': {str(n): asdict(r) for n, r in sorted(self.checkpoints.items())},
            'log_size': self.log_size, 'log_last_seq': self.log_last_seq,
            'copies': self.copies, 'weeks': self.weeks, 'blocks': self.blocks,
            'pipeline': self.pipeline, 'alarms': self.alarms,
            'last_refresh': self.last_refresh, 'last_success': self.last_success,
            'last_error': self.last_error,
        }

    @classmethod
    def from_dict(cls, raw: object) -> 'WitnessState':
        state = cls()
        if not isinstance(raw, dict):
            return state
        checkpoints = raw.get('checkpoints')
        for key, value in (checkpoints.items() if isinstance(checkpoints, dict) else ()):
            record = CheckpointRecord.from_dict(value) if isinstance(value, dict) else None
            if record is not None and str(record.n) == str(key):
                state.checkpoints[record.n] = record
        for name in ('copies', 'weeks', 'blocks', 'pipeline'):
            value = raw.get(name)
            if isinstance(value, dict):
                setattr(state, name, value)
        if isinstance(raw.get('alarms'), list):
            state.alarms = [a for a in raw['alarms'] if isinstance(a, dict)]
        for name in ('log_size', 'log_last_seq'):
            if isinstance(raw.get(name), int):
                setattr(state, name, raw[name])
        for name in ('last_refresh', 'last_success', 'last_error'):
            setattr(state, name, str(raw.get(name) or ''))
        return state

    def copy(self) -> 'WitnessState':
        return WitnessState.from_dict(json.loads(json.dumps(self.to_dict())))


class WitnessStore:
    """Pliki swiadka w katalogu danych: stan, checkpointy, material dowodowy."""

    def __init__(self, directory: Path | None = None):
        self.directory = Path(directory) if directory else witness_dir()

    @property
    def state_path(self) -> Path:
        return self.directory / 'state.json'

    def checkpoint_path(self, n: int) -> Path:
        return self.directory / 'checkpoints' / logtree.checkpoint_filename(n)

    def load(self) -> WitnessState:
        try:
            raw = json_loads(self.state_path.read_text(encoding='utf-8'))
            state = WitnessState.from_dict(raw)
        except (OSError, ValueError, TypeError, AttributeError, KeyError, OverflowError) as e:
            # Stan swiadka to pamiec podreczna: zepsuty plik nie moze blokowac
            # startu — nastepny przebieg odbuduje go od zera.
            if not isinstance(e, FileNotFoundError):
                log.warning('stan swiadka nieczytelny (%s) — zaczynam od nowa', e)
            return WitnessState()
        # Stan bez pliku checkpointu jest bez pokrycia — zapominamy go, a
        # nastepny przebieg pobierze i sprawdzi plik od nowa.
        for n in list(state.checkpoints):
            if not self.checkpoint_path(n).is_file():
                del state.checkpoints[n]
        return state

    def save(self, state: WitnessState) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        write_atomic(self.state_path, json.dumps(
            state.to_dict(), indent=1, ensure_ascii=False).encode('utf-8'))

    def read_checkpoint(self, n: int) -> bytes | None:
        try:
            return self.checkpoint_path(n).read_bytes()
        except OSError:
            return None

    def write_checkpoint(self, n: int, data: bytes) -> None:
        path = self.checkpoint_path(n)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_atomic(path, data)

    def keep_evidence(self, name: str, data: bytes) -> Path:
        """Odklada plik jako material dowodowy — nigdy go nie nadpisuje."""
        folder = self.directory / 'evidence'
        folder.mkdir(parents=True, exist_ok=True)
        stamp = _now().strftime('%Y%m%dT%H%M%SZ')
        target = folder / f'{stamp}-{name}'
        i = 1
        while target.exists():
            i += 1
            target = folder / f'{stamp}-{i}-{name}'
        write_atomic(target, data)
        return target


# --- Kopia dziennika ------------------------------------------------------------

class LogMirror:
    """Kopia calego publicznego dziennika, dopisywana przyrostowo.

    Plik ma postac linii zrzutu tygodniowego (LOG.md §6), wiec kazde
    narzedzie, ktore rozumie zrzuty, rozumie tez te kopie. Kazdy wpis
    przechodzi `logtree.parse_entry` (format + przeliczone ogniwo) i
    `check_chain` (ciaglosc) — kopia nie zawiera niczego, czego aplikacja
    sama nie sprawdzila.
    """

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else witness_dir() / 'log.jsonl'
        self.entries: list[logtree.LogEntry] = []
        self._by_digest: dict[str, int] = {}
        self._loaded = False
        self._leaves: list[bytes] = []

    def load(self) -> 'LogMirror':
        self.entries, self._by_digest, self._leaves = [], {}, []
        self._loaded = True
        try:
            lines = self.path.read_text(encoding='utf-8').splitlines()
        except OSError:
            return self
        good: list[logtree.LogEntry] = []
        damaged = False
        for line in lines:
            try:
                entry = logtree.parse_entry(json.loads(line))
                logtree.check_chain([entry], good[-1] if good else None)
            except ValueError:
                # Uszkodzona kopia: zostawiamy to, co spojne, reszte pobierzemy
                # jeszcze raz. Kopia to pamiec podreczna, nie zrodlo prawdy.
                log.warning('kopia dziennika: przerwana na wpisie po %s',
                            good[-1].seq if good else 0)
                damaged = True
                break
            good.append(entry)
        for entry in good:
            self._append_memory(entry)
        if damaged:
            self._rewrite()
        return self

    def _rewrite(self) -> None:
        """Zapisuje od nowa sama spojna czesc kopii.

        Bez tego `sync` dopisywal nowe wpisy ZA uszkodzonym fragmentem (plik
        otwierany w trybie 'ab'), a ostrzezenie wracalo przy kazdym starcie —
        np. po dwoch rownoczesnych kopiach programu, ktore dopisaly ten sam
        zakres dwa razy (diagnostyka przed Sklepem, 2026-09-27).
        """
        data = b''.join(logtree.canonical_json(e.to_dict()) + b'\n' for e in self.entries)
        try:
            write_atomic(self.path, data)
        except OSError:
            log.warning('kopia dziennika: nie udalo sie zapisac naprawionej kopii',
                        exc_info=True)
            return
        log.warning('kopia dziennika: uszkodzony koniec usuniety, zostaje %s wpisow',
                    len(self.entries))

    def _append_memory(self, entry: logtree.LogEntry) -> None:
        self._by_digest.setdefault(entry.digest, len(self.entries))
        self.entries.append(entry)
        self._leaves.append(entry.leaf)

    def ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    @property
    def size(self) -> int:
        return len(self.entries)

    @property
    def last(self) -> logtree.LogEntry | None:
        return self.entries[-1] if self.entries else None

    def position(self, digest: str) -> int | None:
        self.ensure_loaded()
        return self._by_digest.get(str(digest or '').lower())

    def leaves(self, size: int | None = None) -> list[bytes]:
        return self._leaves[:size] if size is not None else list(self._leaves)

    def week_entries(self, week: str) -> list[logtree.LogEntry]:
        return sorted((e for e in self.entries if e.week == week), key=lambda e: e.seq)

    def sync(self, client, *, cancelled=lambda: False) -> int:
        """Dociaga nowe wpisy. Zwraca ich liczbe; `ValueError` = przepisana historia."""
        self.ensure_loaded()
        added: list[logtree.LogEntry] = []
        start = (self.last.seq + 1) if self.last else 1
        # Serwer moglby podawac strony bez konca; reszta przyjdzie w kolejnym
        # przebiegu (dziennik rosnie o setki wpisow na tydzien, nie miliony).
        while not cancelled() and len(added) < MAX_MIRROR_ENTRIES_PER_SYNC:
            page = client.entries(start, 1000)
            batch = [logtree.parse_entry(raw) for raw in page.get('entries') or []]
            logtree.check_chain(batch, added[-1] if added else self.last)
            added.extend(batch)
            nxt = page.get('next')
            if not batch or not isinstance(nxt, int):
                break
            start = nxt
        if added:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, 'ab') as fh:
                for entry in added:
                    fh.write(logtree.canonical_json(entry.to_dict()) + b'\n')
            for entry in added:
                self._append_memory(entry)
        return len(added)


# --- Przebieg swiadka -------------------------------------------------------------

@dataclass
class RefreshReport:
    """Co sie wydarzylo w jednym przebiegu — dla paska stanu i dziennika."""

    new_checkpoints: int = 0
    new_entries: int = 0
    copies_confirmed: list[str] = field(default_factory=list)
    new_alarms: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    more: bool = False                    # zostaly checkpointy na nastepny przebieg


def _add_alarm(state: WitnessState, report: RefreshReport, code: str, severity: str,
               detail: str, *, n: int | None = None, source: str = '',
               evidence: list[str] | None = None) -> None:
    key = f'{code}:{n}:{source}'
    for alarm in state.alarms:
        if alarm.get('key') == key:
            return
    alarm = {'key': key, 'code': code, 'severity': severity, 'detail': detail,
             'n': n, 'source': source, 'at': _iso(_now()),
             'evidence': evidence or []}
    state.alarms.append(alarm)
    report.new_alarms.append(alarm)
    log.error('SWIADEK — alarm %s (n=%s, zrodlo=%s): %s', code, n, source, detail)


def _record_from(cp: logtree.Checkpoint, detail: dict | None) -> CheckpointRecord:
    detail = detail if isinstance(detail, dict) else {}
    height = detail.get('ots_height')
    copies = detail.get('copies') if isinstance(detail.get('copies'), dict) else {}
    zenodo = str(copies.get('zenodo') or '')
    return CheckpointRecord(
        n=cp.n, hash=cp.hash, kind=cp.kind, tree_size=cp.tree_size, root=cp.root,
        prev=cp.prev, utc=str(cp.body.get('utc') or ''), week=cp.week,
        release_week=cp.release_week, btc=cp.btc,
        btc_time=_iso(_parse_iso(detail.get('btc_time'))),
        ots_status=str(detail.get('ots_status') or 'none')
        if str(detail.get('ots_status') or 'none') in ('none', 'pending', 'bitcoin') else 'none',
        ots_height=height if isinstance(height, int) and not isinstance(height, bool) else None,
        ots_time=_iso(_parse_iso(detail.get('ots_time'))),
        zenodo=zenodo if zenodo.startswith('https://') else '',
    )


def refresh_checkpoints(client, store: WitnessStore, state: WitnessState,
                        report: RefreshReport, *, override: str = '',
                        cancelled=lambda: False) -> None:
    """Punkt 1 i 2: nowe checkpointy, ich podpisy, lancuch `prev` i spojnosc."""
    latest = client.checkpoint_latest()
    if not latest:
        return
    latest_n = latest.get('n')
    if not isinstance(latest_n, int) or latest_n < 1:
        return
    have = state.verified_n
    if have and not cancelled():
        # Czy serwer nadal podaje TE SAME bajty ostatniego checkpointu, ktory
        # juz widzielismy. Inny, poprawnie podpisany plik pod tym samym
        # numerem to podwojna historia (equivocation) — najciezszy zarzut.
        again = client.checkpoint_file(have)
        known = store.read_checkpoint(have) or b''
        if again != known:
            other = logtree.parse_checkpoint(again, override=override)
            if other.ok:
                paths = [str(store.keep_evidence(f'old-{logtree.checkpoint_filename(have)}', known)),
                         str(store.keep_evidence(f'new-{logtree.checkpoint_filename(have)}', again))]
                _add_alarm(state, report, ALARM_EQUIVOCATION, 'critical',
                           f'#{have}: two different signed files', n=have,
                           evidence=paths)
                return
    # Numer ostatniego checkpointu podaje SERWER. Lista byla budowana cala
    # przed przycieciem — n = 10**9 to ~40 GB pamieci (fuzzing 2026-09-27).
    end = min(latest_n, have + MAX_CHECKPOINTS_PER_RUN)
    todo = list(range(have + 1, end + 1))
    report.more = latest_n > end

    for n in todo:
        if cancelled():
            return
        data = client.checkpoint_file(n)
        cp = logtree.parse_checkpoint(data, override=override)
        if not cp.ok or cp.n != n:
            path = store.keep_evidence(logtree.checkpoint_filename(n), data)
            _add_alarm(state, report, ALARM_SIGNATURE, 'critical',
                       cp.problem or 'number mismatch', n=n, evidence=[str(path)])
            return
        previous = state.checkpoints.get(n - 1)
        if n > 1 and previous is not None and cp.prev != previous.hash:
            path = store.keep_evidence(logtree.checkpoint_filename(n), data)
            _add_alarm(state, report, ALARM_FORK, 'critical',
                       f'prev {cp.prev} != hash of #{n - 1} {previous.hash}',
                       n=n, evidence=[str(path)])
            return
        detail = client.checkpoint(n) if n == latest_n or n > latest_n - 3 else None
        record = _record_from(cp, detail)
        if detail:
            # Szczegoly juz sa — petla dojrzewania nizej nie pyta o nie drugi
            # raz w tym samym przebiegu.
            record.details_checked = _iso(_now())
        if previous is not None:
            if previous.tree_size == cp.tree_size:
                record.consistent = previous.root == cp.root
            elif previous.tree_size > cp.tree_size:
                record.consistent = False
            else:
                answer = client.consistency(previous.tree_size, cp.tree_size)
                try:
                    path = [bytes.fromhex(h) for h in answer.get('proof') or []]
                except (TypeError, ValueError):
                    path = []
                record.consistent = logtree.verify_consistency(
                    previous.tree_size, cp.tree_size, bytes.fromhex(previous.root),
                    bytes.fromhex(cp.root), path)
            if record.consistent is False:
                evidence = store.keep_evidence(logtree.checkpoint_filename(n), data)
                _add_alarm(state, report, ALARM_CONSISTENCY, 'critical',
                           f'#{n} does not extend #{n - 1}', n=n,
                           evidence=[str(evidence)])
                return
        store.write_checkpoint(n, data)
        state.checkpoints[n] = record
        report.new_checkpoints += 1

    # Stan OTS, czasy blokow i rekord Zenodo dojrzewaja po wydaniu checkpointu
    # (tresc pliku sie nie zmienia). Dociagamy je dla KAZDEGO checkpointu,
    # ktory jeszcze na cos czeka — takze starszych niz ostatnie szesc, ktore
    # przy pierwszym uruchomieniu dostaja tylko sam plik — ale nie czesciej niz
    # `_details_due` pozwala. Wczesniej 15-minutowy cykl pytal w kolko o szesc
    # ostatnich, dopoki nie mialy rekordu Zenodo, czyli do konca kwartalu.
    now = _now()
    last_of_quarter = _last_of_quarter(state)
    due = [n for n in sorted(state.checkpoints, reverse=True)
           if _details_due(state.checkpoints[n], now, n in last_of_quarter)]
    for n in due[:DETAILS_PER_RUN]:
        record = state.checkpoints[n]
        if cancelled():
            return
        record.details_checked = _iso(now)
        detail = client.checkpoint(n)
        if not detail or detail.get('hash') != record.hash:
            continue
        fresh = _record_from(logtree.parse_checkpoint(
            store.read_checkpoint(n) or b'', override=override), detail)
        record.ots_status, record.ots_height = fresh.ots_status, fresh.ots_height
        record.ots_time = fresh.ots_time or record.ots_time
        record.btc_time = fresh.btc_time or record.btc_time
        record.zenodo = fresh.zenodo or record.zenodo


def _quarter_end(moment: datetime | None) -> datetime | None:
    """Poczatek kwartalu NASTEPUJACEGO po `moment` (UTC)."""
    if moment is None:
        return None
    month = ((moment.month - 1) // 3 + 1) * 3 + 1
    year = moment.year + (1 if month > 12 else 0)
    return datetime(year, (month - 1) % 12 + 1, 1, tzinfo=timezone.utc)


def _last_of_quarter(state: WitnessState) -> set[int]:
    """Numery ostatnich checkpointow kazdego kwartalu.

    Adres rekordu Zenodo wystarczy znac z JEDNEGO checkpointu kwartalu
    (`check_copies` bierze najnowszy znany), wiec tylko o te pytamy po jego
    koncu — nie o kazdy z ~90 dziennych.
    """
    last: dict[datetime, int] = {}
    for n, record in state.checkpoints.items():
        end = _quarter_end(record.utc_dt)
        if end is not None and n > last.get(end, 0):
            last[end] = n
    return set(last.values())


def _details_due(record: CheckpointRecord, now: datetime, zenodo_candidate: bool) -> bool:
    """Czy pytac serwer o szczegoly checkpointu w tym przebiegu."""
    ots_final = record.ots_status == 'bitcoin' and bool(record.btc_time)
    checked = _parse_iso(record.details_checked)
    if not ots_final:
        issued = record.utc_dt
        fresh = issued is not None and now - issued < timedelta(days=2)
        wait = DETAILS_RETRY if fresh else DETAILS_RETRY_OLD
        return checked is None or now - checked >= wait
    if record.zenodo or not zenodo_candidate:
        return False
    end = _quarter_end(record.utc_dt)
    if end is None or now < end + ZENODO_GRACE:
        return False
    return checked is None or now - checked >= DETAILS_RETRY_OLD


def audit_log(client, mirror: LogMirror, store: WitnessStore, state: WitnessState,
              report: RefreshReport, *, cancelled=lambda: False) -> None:
    """Tryb prywatny: kopia dziennika + korzen kazdego checkpointu od zera."""
    try:
        report.new_entries = mirror.sync(client, cancelled=cancelled)
    except ValueError as e:
        _add_alarm(state, report, ALARM_LOG_REWRITTEN, 'critical', str(e))
        return
    state.log_size = mirror.size
    state.log_last_seq = mirror.last.seq if mirror.last else 0
    leaves = mirror.leaves()
    for n in sorted(state.checkpoints):
        record = state.checkpoints[n]
        if record.audited or record.tree_size > len(leaves):
            continue
        root = logtree.merkle_root(leaves[:record.tree_size]).hex()
        data = store.read_checkpoint(n) or b''
        body = logtree.parse_checkpoint(data).body
        last = mirror.entries[record.tree_size - 1]
        record.audited = (root == record.root and body.get('last_seq') == last.seq
                          and body.get('last_chain_hash') == last.chain_hash)
        if not record.audited:
            evidence = store.keep_evidence(logtree.checkpoint_filename(n), data)
            _add_alarm(state, report, ALARM_LOG_ROOT, 'critical',
                       f'#{n}: root from the log {root} != {record.root}', n=n,
                       evidence=[str(evidence)])


def _copy_state(state: WitnessState, source: str) -> dict:
    return state.copies.setdefault(source, {'max_n': 0, 'weeks': {}})


#: Ktory stan kopii przesadza, gdy jest ich kilka (dwa adresy, kilka plikow):
#: zgodna albo ROZNA podpisana kopia > nieczytelna > archiwum nie odpowiedzialo
#: > brak. 'unavailable' ponawiamy jak brak — co 3 h.
_COPY_RANK = {'missing': 0, 'unavailable': 1, 'unreadable': 2, 'match': 3, 'mismatch': 3}


def _due(entry: dict | None, now: datetime) -> bool:
    if not entry:
        return True
    if entry.get('status') == 'match':
        return False
    checked = _parse_iso(entry.get('checked'))
    wait = COPY_RETRY_SLOW if entry.get('status') in ('unreadable', 'mismatch') else COPY_RETRY
    return checked is None or now - checked >= wait


def _compare_copy(store: WitnessStore, state: WitnessState, report: RefreshReport,
                  source: str, record: CheckpointRecord, copy: bytes | None,
                  url: str, *, override: str = '') -> str:
    """'match' | 'missing' | 'unreadable' | 'mismatch' — alarm tylko przy 'mismatch'.

    'unreadable' = kopia jest, ale nie jest poprawnie podpisanym checkpointem
    o tym numerze: uszkodzona, obca albo w postaci, ktorej nie umiemy
    odczytac (Internet Archive odtwarza migawke w kompresji, w jakiej ja
    zapisal — takze zstd, ktorego klient celowo nie rozpakowuje). Taka kopia
    NICZEGO o Sigelith nie dowodzi — ani za, ani przeciw — wiec nie jest
    alarmem. Do 2.2.0 byla ostrzezeniem, ktore dodatkowo wywracalo okno.
    """
    if copy is None:
        return 'missing'
    ours = store.read_checkpoint(record.n) or b''
    if copy == ours:
        return 'match'
    theirs = logtree.parse_checkpoint(copy, override=override)
    if not theirs.ok or theirs.n != record.n:
        why = ('zstd' if copy[:4] == b'\x28\xb5\x2f\xfd'
               else theirs.problem or f'#{theirs.n}')
        log.info('swiadek: kopia %s checkpointu #%s nieczytelna (%s): %s',
                 source, record.n, why, url)
        return 'unreadable'
    # Rozna, ale POPRAWNIE PODPISANA kopia tego samego numeru = Sigelith
    # podpisal dwie rozne historie. To jest dowod — zostaje w katalogu.
    path = store.keep_evidence(f'{source}-{logtree.checkpoint_filename(record.n)}', copy)
    ours_path = store.keep_evidence(f'sigelith-{logtree.checkpoint_filename(record.n)}', ours)
    _add_alarm(state, report, ALARM_COPY_MISMATCH, 'critical',
               f'{source}: {url} — signed copy differs',
               n=record.n, source=source, evidence=[str(path), str(ours_path)])
    return 'mismatch'


def _wayback_lookup(client, store: WitnessStore, state: WitnessState,
                    report: RefreshReport, record: CheckpointRecord, original: str,
                    since: str, *, override: str = '') -> tuple[str, str]:
    """Migawki JEDNEGO adresu pliku checkpointu: (status, adres migawki).

    Status jak w `_compare_copy`: 'match' | 'missing' | 'unreadable' |
    'mismatch' — oraz 'unavailable', gdy migawki nie znalezlismy, bo archiwum
    nie odpowiedzialo (blad polaczenia, strona awarii zamiast danych). To NIE
    jest „jeszcze nie opublikowano”: nastepny przebieg pyta znowu za 3 h.
    """
    status, view = 'missing', ''
    problem = ''
    stamps: list[str] = []
    try:
        raw = client.fetch_external(WAYBACK_CDX.format(url=original, since=since),
                                    accept='application/json')
        rows = json.loads(raw.decode('utf-8')) if raw else []
        stamps = [row[0] for row in rows[1:] if isinstance(row, list) and row
                  and re.fullmatch(r'\d{14}', str(row[0]))]
    except (ApiError, ValueError, UnicodeDecodeError, TypeError, KeyError,
            AttributeError, IndexError) as e:
        problem = f'CDX: {e}'
        log.info('swiadek: indeks CDX Internet Archive nie odpowiada: %s', e)
    # Na koncu adres z SAMA data: Internet Archive przekierowuje go do
    # najblizszej migawki. Indeks CDX bywa wylaczony („Temporarily Offline”,
    # 2026-09-29) albo o godziny spozniony wobec swiezej migawki, a samo
    # odtwarzanie dziala. Plik checkpointu sie nie zmienia, a bajty
    # porownujemy z naszymi — pasuje kazda zgodna migawka, niczyje slowo.
    for timestamp in [*stamps, f'{since}000000']:
        try:
            copy = client.fetch_external(WAYBACK_RAW.format(timestamp=timestamp,
                                                            url=original))
        except ApiError as e:
            problem = str(e)
            continue
        if copy is not None and copy.lstrip()[:1] == b'<':
            # Strona archiwum (np. „Temporarily Offline”), nie migawka pliku JSON.
            problem = problem or 'HTML instead of a snapshot'
            continue
        result = _compare_copy(store, state, report, 'wayback', record,
                               copy, original, override=override)
        if result == 'missing':
            continue
        view = WAYBACK_VIEW.format(timestamp=timestamp, url=original)
        status = result
        # Nieczytelna migawka nie przesadza sprawy: kolejna moze byc
        # zapisana bez kompresji (albo gzipem, ktory umiemy).
        if result != 'unreadable':
            break
    if status == 'missing' and problem:
        report.errors.append(f'Internet Archive: {problem}')
        status = 'unavailable'
    return status, view


def check_copies(client, store: WitnessStore, state: WitnessState,
                 report: RefreshReport, *, override: str = '', now: datetime | None = None,
                 cancelled=lambda: False) -> None:
    """Punkt 3: kopie u osob trzecich — GitHub, Internet Archive, Zenodo."""
    now = now or _now()
    by_week: dict[str, list[CheckpointRecord]] = {}
    for record in state.checkpoints.values():
        by_week.setdefault(record.release_week, []).append(record)
    weekly = {r.week: r for r in state.checkpoints.values() if r.kind == 'weekly'}

    # GitHub: wydanie tygodnia wychodzi po jego checkpoincie tygodniowym.
    github = _copy_state(state, 'github')
    for week in sorted(weekly):
        if cancelled():
            return
        entry = github['weeks'].get(week)
        if not _due(entry, now):
            continue
        status, confirmed = 'match', 0
        for record in sorted(by_week.get(week, []), key=lambda r: r.n):
            name = logtree.checkpoint_filename(record.n)
            url = GITHUB_ASSET.format(repo=GITHUB_REPO, week=week, name=name)
            try:
                result = _compare_copy(store, state, report, 'github', record,
                                       client.fetch_external(url), url, override=override)
            except ApiError as e:
                report.errors.append(str(e))
                result = 'unavailable'
            if result != 'match':
                status = result
                break
            confirmed = max(confirmed, record.n)
        github['weeks'][week] = {'status': status, 'checked': _iso(now),
                                 'url': GITHUB_RELEASE.format(repo=GITHUB_REPO, week=week)}
        if status == 'match':
            github['max_n'] = max(int(github.get('max_n') or 0), confirmed)
            report.copies_confirmed.append(f'GitHub {week}')

    # Internet Archive: migawka pliku checkpointu tygodniowego — pod
    # sigelith.org, a gdy jej tam nie ma, pod beattime.live (CHECKPOINT_PUBLIC_URLS).
    wayback = _copy_state(state, 'wayback')
    for week, record in sorted(weekly.items()):
        if cancelled():
            return
        entry = wayback['weeks'].get(week)
        if not _due(entry, now):
            continue
        name = logtree.checkpoint_filename(record.n)
        since = (record.utc_dt or now).strftime('%Y%m%d')
        status, view = 'missing', ''
        for template in CHECKPOINT_PUBLIC_URLS:
            if cancelled():
                return
            found, found_view = _wayback_lookup(
                client, store, state, report, record, template.format(name=name),
                since, override=override)
            if _COPY_RANK[found] > _COPY_RANK[status]:
                status, view = found, found_view
            # Zgodna albo ROZNA podpisana kopia przesadza sprawe; brak migawki
            # i migawka nieczytelna — nie, wtedy pytamy o drugi adres.
            if found in ('match', 'mismatch'):
                break
        wayback['weeks'][week] = {'status': status, 'checked': _iso(now), 'url': view}
        if status == 'match':
            wayback['max_n'] = max(int(wayback.get('max_n') or 0), record.n)
            report.copies_confirmed.append(f'Internet Archive {week}')

    # Zenodo: rekord kwartalny; adres wskazuje serwer, tresc sprawdzamy sami.
    zenodo = _copy_state(state, 'zenodo')
    record_url = next((r.zenodo for n, r in sorted(state.checkpoints.items(), reverse=True)
                       if r.zenodo), '')
    match = _RECORD_ID.search(record_url)
    if match and weekly:
        key = match.group(1)
        entry = zenodo['weeks'].get(key)
        if _due(entry, now) and not cancelled():
            status, confirmed = 'missing', 0
            for week, record in sorted(weekly.items(), reverse=True):
                name = logtree.checkpoint_filename(record.n)
                url = ZENODO_FILE.format(record=key, name=name)
                try:
                    result = _compare_copy(store, state, report, 'zenodo', record,
                                           client.fetch_external(url), url,
                                           override=override)
                except ApiError as e:
                    report.errors.append(str(e))
                    result = 'unavailable'
                if result == 'match':
                    status, confirmed = 'match', record.n
                    break
                if result == 'mismatch':
                    status = 'mismatch'
                    break
                if _COPY_RANK[result] > _COPY_RANK[status]:
                    status = result
            zenodo['weeks'][key] = {'status': status, 'checked': _iso(now),
                                    'url': record_url}
            if status == 'match':
                zenodo['max_n'] = max(int(zenodo.get('max_n') or 0), confirmed)
                report.copies_confirmed.append('Zenodo')


def check_blocks(client, state: WitnessState, report: RefreshReport, *,
                 limit: int = 8, cancelled=lambda: False) -> None:
    """Punkt 4: blok Bitcoina z checkpointu u niezaleznego eksploratora."""
    done = 0
    for n in sorted(state.checkpoints, reverse=True):
        record = state.checkpoints[n]
        btc = record.btc or {}
        height, expected = btc.get('height'), str(btc.get('hash') or '')
        if not isinstance(height, int) or not _HEX64.match(expected):
            continue
        known = state.blocks.get(str(height))
        if known and known.get('ok') is not None:
            continue
        if done >= limit or cancelled():
            return
        done += 1
        for base in EXPLORERS:
            try:
                raw = client.fetch_external(f'{base}/block-height/{height}',
                                            accept='text/plain', max_bytes=256)
                found = (raw or b'').decode('ascii', 'replace').strip().lower()
                if not _HEX64.match(found):
                    continue
                info = client.fetch_external(f'{base}/block/{found}',
                                             accept='application/json', max_bytes=64 * 1024)
                stamp = json.loads(info.decode('utf-8')).get('timestamp') if info else None
                when = (_iso(datetime.fromtimestamp(stamp, tz=timezone.utc))
                        if isinstance(stamp, int) else '')
                host = base.split('/')[2]
                state.blocks[str(height)] = {'hash': found, 'time': when,
                                             'source': host, 'ok': found == expected}
                if found != expected:
                    _add_alarm(state, report, ALARM_BTC, 'warning',
                               f'{host}: block {height} is {found}, the checkpoint '
                               f'names {expected}', n=n, source=host)
                break
            except (ApiError, ValueError, UnicodeDecodeError, TypeError, KeyError,
                    AttributeError, OSError, OverflowError) as e:
                report.errors.append(f'{base.split("/")[2]}: {e}')
                continue


def refresh(client, store: WitnessStore, state: WitnessState, mirror: LogMirror | None,
            *, mode: str = MODE_PRIVATE, override: str = '', third_party: bool = True,
            cancelled=lambda: False) -> RefreshReport:
    """Jeden pelny przebieg swiadka. Zmienia `state` w miejscu."""
    report = RefreshReport()
    state.last_refresh = _iso(_now())
    try:
        refresh_checkpoints(client, store, state, report, override=override,
                            cancelled=cancelled)
        if mode == MODE_PRIVATE and mirror is not None and not cancelled():
            audit_log(client, mirror, store, state, report, cancelled=cancelled)
        try:
            state.pipeline = {'checked': _iso(_now()), **client.proof_status()}
        except ApiError as e:
            report.errors.append(str(e))
        if third_party and not cancelled():
            # Osoby trzecie to dodatek: nieoczekiwana odpowiedz ktorejs z nich
            # nie moze wyrzucic wynikow calego przebiegu (sprawdzone
            # checkpointy przepadaly razem z kopia stanu).
            try:
                check_copies(client, store, state, report, override=override,
                             cancelled=cancelled)
                check_blocks(client, state, report, cancelled=cancelled)
            except Exception as e:           # noqa: BLE001 — dane z zewnatrz
                log.warning('swiadek: kontrola osob trzecich przerwana', exc_info=True)
                report.errors.append(f'{type(e).__name__}: {e}')
        state.last_success = state.last_refresh
        state.last_error = ''
    except ApiError as e:
        state.last_error = str(e)
        report.errors.append(str(e))
    return report


# --- Wpis a swiadkowie --------------------------------------------------------------

def _valid_bound(raw: object) -> dict | None:
    """Granica czasu z odpowiedzi serwera — tylko znane pola o znanym formacie."""
    if not isinstance(raw, dict):
        return None
    out: dict = {}
    source = str(raw.get('source') or '')
    if source not in ('bitcoin_block', 'opentimestamps', 'bank'):
        return None
    out['source'] = source
    for name in ('checkpoint', 'height'):
        value = raw.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            out[name] = value
    for name in ('week',):
        value = str(raw.get(name) or '')
        if re.fullmatch(r'\d{4}-W\d{2}', value):
            out[name] = value
    when = _parse_iso(raw.get('time'))
    if when is not None:
        out['time'] = _iso(when)
    date = str(raw.get('date') or '')[:10]
    if re.fullmatch(r'\d{4}-\d{2}-\d{2}', date):
        out['date'] = date
    bank = str(raw.get('bank') or '')
    if bank and re.fullmatch(r'[^<>\x00-\x1f\x7f]{1,120}', bank):
        out['bank'] = bank
    block = str(raw.get('hash') or '').lower()
    if _HEX64.match(block):
        out['hash'] = block
    return out


def bound_moment(bound: dict | None) -> datetime | None:
    """Chwila granicy: czas bloku albo koniec dnia ksiegowania przelewu."""
    if not bound:
        return None
    if bound.get('time'):
        return _parse_iso(bound['time'])
    if bound.get('date'):
        try:
            day = datetime.fromisoformat(bound['date']).replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        return day + timedelta(days=1) - timedelta(seconds=1)
    return None


def time_bounds_from(recorded: str, not_before: dict | None,
                     uppers: list[dict]) -> dict:
    uppers = [u for u in uppers if u]
    uppers.sort(key=lambda u: bound_moment(u) or datetime.max.replace(tzinfo=timezone.utc))
    return {'recorded': recorded, 'not_before': not_before,
            'not_after': uppers[0] if uppers else None, 'upper_bounds': uppers}


def _block_bound(record: CheckpointRecord, state: WitnessState) -> dict | None:
    """„Nie wczesniej niz" z checkpointu sprawdzonego przez aplikacje."""
    btc = record.btc or {}
    if not isinstance(btc.get('height'), int):
        return None
    bound = {'source': 'bitcoin_block', 'checkpoint': record.n,
             'height': btc['height'], 'hash': str(btc.get('hash') or '')}
    block = state.blocks.get(str(btc['height'])) or {}
    when = (block.get('time') if block.get('ok') else '') or record.btc_time
    if when:
        bound['time'] = when
    if block.get('ok'):
        bound['confirmed_by'] = block.get('source')
    return bound


def attach_checkpoint(result: proof.VerificationResult, state: WitnessState,
                      *, index: int | None, path: list[str] | None,
                      tree_size: int | None, n: int | None) -> None:
    """Sprawdza sciezke wpisu do checkpointu WZGLEDEM PLIKU, ktory mamy.

    Korzen bierzemy z naszego, zweryfikowanego checkpointu — nie z tej samej
    odpowiedzi, ktora niesie sciezke. Inaczej serwer podawalby oba konce
    dowodu sam.
    """
    if index is None or not result.found:
        return
    result.log_index = index
    record = state.checkpoints.get(n) if n else state.covering(index)
    if record is None:
        return
    if tree_size is not None and tree_size != record.tree_size:
        result.problems.append(_(
            'The server describes checkpoint #%(n)s with a different tree size '
            'than the signed checkpoint file this application verified.')
            % {'n': record.n})
        return
    dt = beatcore.parse_iso_utc(result.utc)
    try:
        leaf = logtree.entry_leaf_hash(int(result.seq or 0), result.digest, dt)
        steps = [bytes.fromhex(h) for h in (path or [])]
        ok = logtree.verify_inclusion(leaf, index, record.tree_size, steps,
                                      bytes.fromhex(record.root))
    except (ValueError, TypeError, AttributeError):
        ok = False
    result.checkpoint = {
        'n': record.n, 'hash': record.hash, 'tree_size': record.tree_size,
        'root': record.root, 'leaf_index': index, 'audit_path': list(path or []),
        'verified': ok, 'release_week': record.release_week,
    }
    if not ok:
        result.problems.append(_(
            'The path of this entry does NOT lead to the root of checkpoint '
            '#%(n)s, which this application verified itself.') % {'n': record.n})


def private_times(result: proof.VerificationResult, state: WitnessState,
                  week: dict | None) -> None:
    """Trzy czasy liczone lokalnie (tryb prywatny)."""
    if result.log_index is None:
        return
    before = state.before(result.log_index)
    not_before = _block_bound(before, state) if before else None
    uppers: list[dict] = []
    covering = state.covering(result.log_index)
    if covering is not None and covering.ots_status == 'bitcoin':
        uppers.append({'source': 'opentimestamps', 'checkpoint': covering.n,
                       'height': covering.ots_height, 'time': covering.ots_time})
    for raw in (week or {}).get('upper_bounds') or []:
        bound = _valid_bound(raw)
        if bound:
            uppers.append(bound)
    result.time_bounds = time_bounds_from(result.utc, not_before, uppers)


def fast_times(result: proof.VerificationResult, state: WitnessState,
               payload: dict) -> None:
    """Trzy czasy z odpowiedzi serwera — po walidacji formatu.

    Blok „nie wczesniej niz" podmieniamy na ten z NASZEGO checkpointu, jesli
    go mamy: jego wysokosc i hash sa podpisane w pliku, ktory sprawdzilismy.
    """
    raw = payload.get('time') if isinstance(payload.get('time'), dict) else {}
    not_before = _valid_bound(raw.get('not_before'))
    if not_before and isinstance(not_before.get('checkpoint'), int):
        record = state.checkpoints.get(not_before['checkpoint'])
        if record is not None:
            not_before = _block_bound(record, state)
    uppers = [b for b in (_valid_bound(u) for u in raw.get('upper_bounds') or []) if b]
    result.time_bounds = time_bounds_from(result.utc, not_before, uppers)


def verify_fast(client, digest: str, state: WitnessState, *,
                key_override: str = '') -> proof.VerificationResult:
    """Tryb szybki: jedno zapytanie o skrot, sciezka do checkpointu lokalnie."""
    payload = client.verify(digest)
    result = proof.verify_payload(payload, expected_digest=digest,
                                  key_override=key_override)
    enrich_from_payload(result, state, payload)
    return result


def enrich_from_payload(result: proof.VerificationResult, state: WitnessState,
                        payload: dict) -> None:
    """Sciezka do checkpointu i trzy czasy z odpowiedzi `/verify` albo `/stamp`."""
    result.witness_mode = MODE_FAST
    if not result.found or not isinstance(payload, dict):
        return
    cp = payload.get('checkpoint') if isinstance(payload.get('checkpoint'), dict) else None
    if cp:
        index = cp.get('leaf_index')
        path = cp.get('audit_path')
        if (isinstance(index, int) and not isinstance(index, bool) and index >= 0
                and isinstance(path, list)
                and all(isinstance(h, str) and _HEX64.match(h) for h in path)):
            attach_checkpoint(result, state, index=index, path=path,
                              tree_size=cp.get('tree_size') if isinstance(cp.get('tree_size'), int) else None,
                              n=cp.get('n') if isinstance(cp.get('n'), int) else None)
    fast_times(result, state, payload)


def _week_data(client, week: str, mirror: LogMirror, digest: str,
               cache: dict) -> dict | None:
    """Dane tygodnia — bez pytania o NASZ skrot.

    Najpierw `/api/proof/weeks/<week>`. Serwer sprzed 2026-09-26 go nie ma —
    wtedy pytamy `/api/proof/verify` o INNY wpis tego samego tygodnia
    (odciski sa publiczne, wiec to nie zdradza niczego o naszym). Tydzien
    z jednym wpisem nie ma kogo zapytac zamiast nas — wtedy i tak wiadomo,
    ktory wpis jest nasz.
    """
    if week in cache:
        return cache[week]
    data = client.week(week)
    if data is None:
        others = [e.digest for e in mirror.week_entries(week) if e.digest != digest]
        proxy = others[0] if others else digest
        raw = client.verify(proxy)
        data = {'week': week, 'closed': bool(raw.get('week_closed'))}
        for name in ('week_root', 'root_signature', 'public_key', 'ots_status',
                     'ots_bitcoin_height', 'anchors'):
            if name in raw:
                data[name] = raw[name]
        time = raw.get('time') if isinstance(raw.get('time'), dict) else {}
        data['upper_bounds'] = [u for u in time.get('upper_bounds') or []
                                if isinstance(u, dict) and u.get('week') == week]
        data['via'] = 'proxy'
    cache[week] = data
    return data


def verify_private(client, digest: str, state: WitnessState, mirror: LogMirror, *,
                   key_override: str = '', week_cache: dict | None = None,
                   synced: list | None = None,
                   cancelled=lambda: False) -> proof.VerificationResult:
    """Tryb prywatny: wszystko z kopii dziennika, od serwera tylko tydzien."""
    digest = str(digest or '').strip().lower()
    mirror.ensure_loaded()
    index = mirror.position(digest)
    if index is None and not (synced and synced[0]):
        mirror.sync(client, cancelled=cancelled)
        if synced is not None:
            synced[:] = [True]
        index = mirror.position(digest)
    if index is None:
        result = proof.VerificationResult(found=False, digest=digest)
        result.witness_mode = MODE_PRIVATE
        return result
    entry = mirror.entries[index]
    week_entries = mirror.week_entries(entry.week)
    leaves = [logtree.week_leaf_hash(e.digest) for e in week_entries]
    position = next(i for i, e in enumerate(week_entries) if e.seq == entry.seq)
    local_root = logtree.merkle_root(leaves).hex()
    data = _week_data(client, entry.week, mirror, digest,
                      week_cache if week_cache is not None else {}) or {}
    closed = bool(data.get('closed'))
    server_root = str(data.get('week_root') or '').lower()
    utc_text = logtree.canonical_utc(entry.utc)
    payload = {
        'found': True, 'digest': digest, 'seq': entry.seq, 'week': entry.week,
        'beat': beatcore.format_beat(beatcore.beats_from_utc(entry.utc), decimals=2),
        'utc': utc_text, 'chain_hash': entry.chain_hash,
        'week_closed': closed,
        'week_root': server_root if closed and server_root else local_root,
        'inclusion_proof': logtree.weekly_proof(leaves, position),
    }
    if closed:
        for name in ('root_signature', 'public_key', 'ots_status',
                     'ots_bitcoin_height', 'anchors'):
            if name in data:
                payload[name] = data[name]
    result = proof.verify_payload(payload, expected_digest=digest,
                                  key_override=key_override)
    result.witness_mode = MODE_PRIVATE
    if closed and server_root and server_root != local_root:
        result.problems.append(_(
            'The week root given by the server does not match the root computed '
            'from the public log itself — the server presents two different '
            'versions of week %(week)s.') % {'week': entry.week})
    covering = state.covering(index)
    if covering is not None and covering.tree_size <= mirror.size:
        path = [h.hex() for h in logtree.audit_path(
            index, mirror.leaves(covering.tree_size))]
        attach_checkpoint(result, state, index=index, path=path,
                          tree_size=covering.tree_size, n=covering.n)
    else:
        result.log_index = index
    private_times(result, state, data if closed else None)
    return result


# --- Stan wpisu dla interfejsu ----------------------------------------------------

@dataclass
class Pinning:
    """Kto — poza Sigelith — ma kopie checkpointu obejmujacego wpis."""

    checkpoint: int | None = None
    verified: bool = False
    github: bool = False
    wayback: bool = False
    zenodo: bool = False

    @property
    def sources(self) -> list[str]:
        return [name for name in SOURCES if getattr(self, name)]


def pinning(entry_checkpoint: dict | None, state: WitnessState) -> Pinning:
    """Wpis jest przypiety u zrodla S, gdy S ma zgodna kopie checkpointu >= n.

    Lancuch `prev` sprawdzilismy sami, wiec zgodna kopia checkpointu m
    przypina kazdy wczesniejszy checkpoint — w tym ten, ktory zawiera wpis.
    """
    cp = entry_checkpoint or {}
    n = cp.get('n') if isinstance(cp.get('n'), int) else None
    pin = Pinning(checkpoint=n, verified=bool(cp.get('verified')))
    if n is None or not pin.verified or n > state.verified_n:
        return pin
    for source in SOURCES:
        setattr(pin, source, state.copy_max(source) >= n)
    return pin


# --- Najblizsze zdarzenia -----------------------------------------------------------

def next_events(state: WitnessState, now: datetime | None = None) -> list[dict]:
    """Co wydarzy sie samo, bez udzialu kogokolwiek (LOG.md §5 i §7)."""
    now = now or _now()
    events: list[dict] = []
    tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=10, second=0, microsecond=0)
    events.append({'kind': 'daily', 'at': _iso(tomorrow)})
    monday = (now + timedelta(days=(7 - now.weekday()) or 7)).replace(
        hour=0, minute=15, second=0, microsecond=0)
    closing = monday - timedelta(days=7)
    year, week, _d = closing.isocalendar()
    events.append({'kind': 'weekly', 'at': _iso(monday), 'week': f'{year}-W{week:02d}'})
    events.append({'kind': 'github', 'at': _iso(monday + timedelta(days=1)),
                   'week': f'{year}-W{week:02d}'})
    quarter_month = ((now.month - 1) // 3 + 1) * 3 + 1
    q_year = now.year + (1 if quarter_month > 12 else 0)
    q_start = datetime(q_year, (quarter_month - 1) % 12 + 1, 1, tzinfo=timezone.utc)
    events.append({'kind': 'zenodo', 'at': _iso(q_start + timedelta(days=2)),
                   'quarter': f'{(q_start - timedelta(days=1)).year}-Q'
                              f'{((q_start - timedelta(days=1)).month - 1) // 3 + 1}'})
    events.sort(key=lambda e: e['at'])
    return events
