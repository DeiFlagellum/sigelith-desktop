"""
Zadania w tle — `QRunnable` w puli `QThreadPool`.

Poprzednik mieszal dwa swiaty watkow i robil to niebezpiecznie:

    self.worker = ApiWorker(...)                 # QObject w watku GUI
    self.worker.finished.connect(...)
    self.executor.submit(self.worker.run)        # ThreadPoolExecutor

Skutki: (1) `self.worker` był NADPISYWANY przy każdym kolejnym pliku, więc
poprzedni obiekt mogl zostac zwolniony przez odsmiecacz w trakcie pracy
swojego watku — to uzycie zwolnionego obiektu C++, czyli twarde wywalenie
procesu, nie wyjątek Pythona; (2) `ThreadPoolExecutor` polykal każdy wyjątek
w niesprawdzanym `Future`, więc awaria była po prostu niewidoczna; (3) pula
nie była nigdy zamykana, więc przy wyjsciu proces potrafil zostac w pamieci.

Tutaj: jedna pula Qt, wlascicielem zadan jest `QThreadPool`, sygnaly zyja
w obiekcie tworzonym w watku GUI (więc połączenia sa kolejkowane i dochodza
do interfejsu bezpiecznie), a kazde zadanie da się przerwać.
"""
from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, Signal

from . import bundle, fileproof, hashing, history, keys, onion, proof, supporters, witness
from .api import ApiError, BeatTimeClient
from .hashing import HashCancelled, HashError
from .i18n import _

log = logging.getLogger(__name__)


class TaskSignals(QObject):
    """Sygnaly zadania. Tworzone w watku GUI — stad kolejkowana dostawa."""

    progress = Signal(int, int, str)     # (zrobione, calosc, opis etapu)
    message = Signal(str)               # komunikat posredni dla paska stanu
    finished = Signal(object)           # wynik (typ zalezy od zadania)
    failed = Signal(str)                # komunikat bledu w jezyku interfejsu
    done = Signal()                     # zawsze na koncu, takze po bledzie


class Task(QRunnable):
    """Wspolna podstawa: obsluga przerwania i siatka bezpieczeństwa na wyjatki."""

    def __init__(self):
        super().__init__()
        self.signals = TaskSignals()
        self._cancelled = False
        # `setAutoDelete(False)` + twarda referencja w `launch()` — patrz
        # komentarz przy `_RUNNING`. Przy `True` obiektem zarzadza C++ i
        # kasuje go po `run()`, co przy referencji trzymanej po stronie
        # Pythona konczy sie sciganiem sie dwoch wlascicieli o ten sam obiekt.
        self.setAutoDelete(False)

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def work(self):
        raise NotImplementedError

    def run(self) -> None:
        # Zaden wyjatek nie ma prawa wyjsc z watku puli: w Qt nieobsluzony
        # wyjatek w `QRunnable.run` konczy sie przerwaniem calego procesu.
        try:
            result = self.work()
            if not self._cancelled:
                self.signals.finished.emit(result)
        except HashCancelled:
            pass                         # przerwanie to nie blad
        except (ApiError, HashError, ValueError) as e:
            if not self._cancelled:
                self.signals.failed.emit(str(e))
        except Exception:                # noqa: BLE001 — celowo szeroko
            log.error('zadanie w tle:\n%s', traceback.format_exc())
            if not self._cancelled:
                self.signals.failed.emit(_(
                    'An unexpected error occurred. The details were written to '
                    'the log (Help -> Show event log).'))
        finally:
            self.signals.done.emit()


# --- Uruchamianie -----------------------------------------------------------

# Zadania AKTUALNIE pracujace. Zbior istnieje po to, zeby po stronie Pythona
# byla twarda referencja do zadania przez caly czas jego zycia.
#
# Bez niego zdarza sie dokladnie to, co w poprzedniej wersji programu:
# wywolujacy tworzy zadanie w zmiennej lokalnej, oddaje je do puli i wychodzi
# z metody. Zmienna znika, licznik referencji spada do zera, odsmiecacz
# niszczy obiekt `Task` — a razem z nim `TaskSignals`, ktory byl jego jedynym
# wlascicielem. Watek roboczy nadal pracuje i przy probie `emit` dostaje
# „Signal source has been deleted". Blad jest przy tym LOSOWY: pojawia sie
# tylko wtedy, gdy odsmiecacz zdazy zadzialac przed koncem zadania.
_RUNNING: dict[int, Task] = {}


def _release(key: int) -> None:
    _RUNNING.pop(key, None)


#: Priorytety w puli: czynnosc uzytkownika wyprzedza w kolejce prace w tle.
PRIORITY_BACKGROUND = 0
PRIORITY_USER = 10


def launch(pool, task: Task, priority: int = PRIORITY_BACKGROUND) -> Task:
    """Uruchamia zadanie w puli, pilnujac jego czasu zycia.

    Referencje zwalniamy dopiero po sygnale `done`, który zawsze przychodzi
    (jest w bloku `finally`) i dociera do watku GUI kolejka zdarzeń —
    usuwanie ze slownika dzieje się więc w jednym watku.

    Slot jest `partial` po SAMEJ LICZBIE, nigdy domknieciem po `task`.
    Domkniecie tworzyloby cykl `task -> signals -> połączenie -> domkniecie
    -> task`. Cykl sam w sobie nie jest błędem — Python go rozpozna — ale
    zbiera go odsmiecacz, który zwalnia obiekty w dowolnej kolejnosci. Gdy
    w cyklu sa obiekty Qt, potrafi zniszczyc `QObject` z sygnalami przed
    obiektem, który te sygnaly trzyma, i proces konczy się uszkodzeniem
    sterty (0xC0000374) — bez żadnego wyjatku w Pythonie. Klucz liczbowy
    nie odwoluje się do niczego, więc cykl w ogole nie powstaje.
    """
    key = id(task)
    _RUNNING[key] = task
    task.signals.done.connect(partial(_release, key))
    pool.start(task, priority)
    return task


def running_count() -> int:
    """Ile zadan jeszcze zyje — uzywane przez testy."""
    return len(_RUNNING)


# --- Wyniki -----------------------------------------------------------------


@dataclass
class StampOutcome:
    entry: history.Entry
    result: proof.VerificationResult
    newly_created: bool          # False = ten skrot juz byl w rejestrze
    file_digest: hashing.FileDigest | None = None


@dataclass
class BatchOutcome:
    successes: list[StampOutcome]
    failures: list[tuple[str, str]]      # (nazwa pliku, powod)


@dataclass
class BundleOutcome:
    path: Path
    check: bundle.BundleCheck
    data: dict


# --- Zadania ----------------------------------------------------------------


class StampFilesTask(Task):
    """Liczy skróty wskazanych plików i rejestruje je w Sigelith.

    Pliki ida po kolei jednym polaczeniem HTTP — nie rownolegle. Serwer
    limituje stemplowanie do 20 zapytań na minutę na adres IP, więc rownoleglosc
    nie przyspieszylaby niczego, a wygenerowalaby lawine błędów 429. Wąskim
    gardlem przy duzych plikach jest i tak dysk, a nie sieć.
    """

    def __init__(self, paths: list[Path], client: BeatTimeClient,
                 note: str = '', key_override: str = '',
                 witness_state: 'witness.WitnessState | None' = None):
        super().__init__()
        self.paths = list(paths)
        self.client = client
        self.note = note
        self.key_override = key_override
        # Migawka stanu swiadka: przy ponownym stemplu starego dokumentu
        # serwer oddaje jego checkpoint — sciezke sprawdzamy wzgledem pliku
        # checkpointu, ktory aplikacja sama zweryfikowala.
        self.witness_state = witness_state

    def work(self) -> BatchOutcome:
        successes: list[StampOutcome] = []
        failures: list[tuple[str, str]] = []
        total = len(self.paths)

        for index, path in enumerate(self.paths, start=1):
            if self.cancelled:
                break
            prefix = f'({index}/{total}) ' if total > 1 else ''
            try:
                self.signals.message.emit(
                    prefix + _('Computing digest: %(name)s') % {'name': path.name})
                file_digest = hashing.sha256_file(
                    path,
                    progress=lambda done, size, p=prefix, n=path.name: self.signals.progress.emit(
                        done, size, p + _('Computing SHA-256: %(name)s') % {'name': n}),
                    cancelled=lambda: self.cancelled,
                )
                if self.cancelled:
                    break

                self.signals.message.emit(
                    prefix + _('Registering in Sigelith: %(name)s') % {'name': path.name})
                self.signals.progress.emit(
                    0, 0, prefix + _('Connecting to sigelith.org…'))
                payload, created = self.client.stamp(file_digest.digest)

                result = proof.verify_payload(
                    payload, expected_digest=file_digest.digest,
                    key_override=self.key_override)
                if self.witness_state is not None:
                    witness.enrich_from_payload(result, self.witness_state, payload)
                entry = history.entry_from_verification(
                    result, file_name=path.name, file_path=str(path),
                    file_size=file_digest.size, note=self.note)
                successes.append(StampOutcome(entry, result, created, file_digest))
            except HashCancelled:
                break
            except (ApiError, HashError) as e:
                log.warning('stempel %s: %s', path.name, e)
                failures.append((path.name, str(e)))
            except Exception as e:          # noqa: BLE001
                log.error('stemplowanie %s:\n%s', path, traceback.format_exc())
                failures.append((path.name, _('Unexpected error: %(kind)s.')
                                 % {'kind': type(e).__name__}))

        return BatchOutcome(successes, failures)


class VerifyDigestTask(Task):
    """Sprawdza pojedynczy skrót w rejestrze i weryfikuje odpowiedź lokalnie."""

    def __init__(self, digest: str, client: BeatTimeClient,
                 key_override: str = '',
                 file_path: Path | None = None, *,
                 mode: str = witness.MODE_FAST,
                 witness_state: 'witness.WitnessState | None' = None,
                 mirror: 'witness.LogMirror | None' = None):
        super().__init__()
        self.digest = digest
        self.client = client
        self.key_override = key_override
        self.file_path = file_path
        self.mode = mode
        self.witness_state = witness_state
        self.mirror = mirror

    def work(self) -> proof.VerificationResult:
        state = self.witness_state or witness.WitnessState()
        if self.mode == witness.MODE_PRIVATE and self.mirror is not None:
            # Tryb prywatny: skrot szukamy w NASZEJ kopii dziennika — serwer
            # nie dowiaduje sie, jaki plik sprawdzamy.
            self.signals.message.emit(_('Checking against your copy of the public '
                                        'log…'))
            return witness.verify_private(self.client, self.digest, state,
                                          self.mirror, key_override=self.key_override,
                                          cancelled=lambda: self.cancelled)
        self.signals.message.emit(_('Querying the Sigelith register…'))
        return witness.verify_fast(self.client, self.digest, state,
                                   key_override=self.key_override)


class HashFileTask(Task):
    """Sam skrót pliku, bez kontaktu z siecia (tryb weryfikacji i podgladu)."""

    def __init__(self, path: Path):
        super().__init__()
        self.path = path

    def work(self) -> hashing.FileDigest:
        return hashing.sha256_file(
            self.path,
            progress=lambda done, size: self.signals.progress.emit(
                done, size,
                _('Computing SHA-256: %(name)s') % {'name': self.path.name}),
            cancelled=lambda: self.cancelled,
        )


class RefreshEntriesTask(Task):
    """Odswieza status wpisów historii (czy tydzień zamknięty, czy już w BTC).

    Ma sens uruchamiac cyklicznie: dowód DOJRZEWA. Stempel zalozony w srode
    dostaje podpis w poniedziałek, a atestacje Bitcoina kilka godzin później.
    Bez odswiezania historia pokazywalaby na zawsze stan z chwili zalozenia.

    Pomijamy wpisy, które osiagnely już najwyższy poziom — one się nie zmienia,
    a kazde zapytanie to zuzycie limitu 120/min.
    """

    def __init__(self, entries: list[history.Entry], client: BeatTimeClient,
                 key_override: str = '', *, mode: str = witness.MODE_FAST,
                 witness_state: 'witness.WitnessState | None' = None,
                 mirror: 'witness.LogMirror | None' = None, quiet: bool = False):
        super().__init__()
        self.entries = list(entries)
        self.client = client
        self.key_override = key_override
        self.mode = mode
        self.witness_state = witness_state
        self.mirror = mirror
        # Odswiezanie w tle (co kwadrans) nie pokazuje paska postepu.
        self.quiet = quiet

    def _needs_refresh(self, entry: history.Entry) -> bool:
        """Czy wpis moze sie jeszcze zmienic.

        Oprocz wpisow niezakotwiczonych odswiezamy tez te, ktorych podpis
        pochodzi z klucza spoza aktualnej listy (np. sprzed rotacji) —
        serwer ma ich korzen podpisany ponownie aktualnym kluczem.
        """
        if entry.source != history.SOURCE_BEATTIME:
            return False
        if entry.level != proof.Level.ANCHORED.value:
            return True
        if bool(entry.root_signature) and not keys.is_trusted(
                entry.public_key, self.key_override):
            return True
        return self._waits_for_checkpoint(entry)

    def _waits_for_checkpoint(self, entry: history.Entry) -> bool:
        """Zakotwiczony wpis bez sciezki do checkpointu, ktory JUZ go obejmuje.

        Dowod dojrzewa dalej niz do kotwicy: checkpoint dzienny wiaze wpis
        z blokiem Bitcoina i z kopiami u osob trzecich. Pytamy tylko wtedy,
        gdy sprawdzony checkpoint jest pozniejszy niz wpis — wczesniej nie
        ma czego dociagac, a kazde zapytanie w trybie szybkim zdradza skrot.
        """
        if self.witness_state is None or (entry.checkpoint or {}).get('verified'):
            return False
        latest = self.witness_state.latest
        stamp = history.beatcore.parse_iso_utc(entry.utc)
        return bool(latest and latest.utc_dt and stamp and latest.utc_dt > stamp)

    def work(self) -> list[history.Entry]:
        pending = [e for e in self.entries if self._needs_refresh(e)]
        updated: list[history.Entry] = []
        total = len(pending)
        if not total:
            self.signals.message.emit(_(
                'Every entry is already anchored — there is nothing to refresh.'))
            return updated

        state = self.witness_state or witness.WitnessState()
        private = self.mode == witness.MODE_PRIVATE and self.mirror is not None
        week_cache: dict = {}
        synced: list = [False]
        for index, entry in enumerate(pending, start=1):
            if self.cancelled:
                break
            if not self.quiet:
                self.signals.progress.emit(
                    index, total,
                    _('Refreshing %(index)s of %(total)s…') % {'index': index,
                                                               'total': total})
            try:
                if private:
                    result = witness.verify_private(
                        self.client, entry.digest, state, self.mirror,
                        key_override=self.key_override, week_cache=week_cache,
                        synced=synced, cancelled=lambda: self.cancelled)
                else:
                    result = witness.verify_fast(self.client, entry.digest, state,
                                                 key_override=self.key_override)
            except ApiError as e:
                log.info('odświeżanie %s: %s', entry.short_digest, e)
                continue
            except ValueError as e:
                # Przepisana historia dziennika — alarm podnosi swiadek, tu
                # tylko nie udajemy, ze wpis sie odswiezyl.
                log.warning('odświeżanie %s: %s', entry.short_digest, e)
                continue
            if not result.found:
                continue
            fresh = history.entry_from_verification(
                result, file_name=entry.file_name, file_path=entry.file_path,
                file_size=entry.file_size, note=entry.note)
            if (fresh.level != entry.level or fresh.ots_status != entry.ots_status
                    or fresh.public_key != entry.public_key
                    or fresh.root_signature != entry.root_signature
                    or fresh.verified_ok != entry.verified_ok
                    or fresh.checkpoint != entry.checkpoint
                    or fresh.time_bounds != entry.time_bounds):
                updated.append(fresh)
        return updated


class WitnessRefreshTask(Task):
    """Jeden przebieg swiadka (`witness.refresh`) na KOPII stanu.

    Zadanie zmienia kopie; watek GUI podmienia stan i zapisuje go po
    powrocie. Dzieki temu okno nigdy nie czyta stanu, ktory w tej samej
    chwili zmienia watek roboczy.
    """

    def __init__(self, client: BeatTimeClient, store: 'witness.WitnessStore',
                 state: 'witness.WitnessState', mirror: 'witness.LogMirror | None', *,
                 mode: str = witness.MODE_PRIVATE, key_override: str = '',
                 third_party: bool = True):
        super().__init__()
        self.client = client
        self.store = store
        self.state = state.copy()
        self.mirror = mirror
        self.mode = mode
        self.key_override = key_override
        self.third_party = third_party

    def work(self):
        # Przerwane, zanim doszlo do glosu (np. czeka w kolejce za czynnoscia
        # uzytkownika) — nie zaczynamy nawet pierwszego zapytania.
        if self.cancelled:
            return self.state, witness.RefreshReport()
        report = witness.refresh(
            self.client, self.store, self.state, self.mirror, mode=self.mode,
            override=self.key_override, third_party=self.third_party,
            cancelled=lambda: self.cancelled)
        return self.state, report


class CheckBundleTask(Task):
    """Sprawdza plik `.beatproof` — opcjonalnie razem z dokumentem zrodlowym."""

    def __init__(self, bundle_path: Path, document: Path | None = None,
                 key_override: str = ''):
        super().__init__()
        self.bundle_path = bundle_path
        self.document = document
        self.key_override = key_override

    def work(self) -> BundleOutcome:
        self.signals.message.emit(
            _('Loading proof: %(name)s') % {'name': self.bundle_path.name})
        data = bundle.load(self.bundle_path)
        document_digest = ''
        document_size = None
        if self.document is not None:
            self.signals.message.emit(
                _('Computing the document digest: %(name)s')
                % {'name': self.document.name})
            document_digest = hashing.sha256_file(
                self.document,
                progress=lambda done, size: self.signals.progress.emit(
                    done, size,
                    _('Computing SHA-256: %(name)s') % {'name': self.document.name}),
                cancelled=lambda: self.cancelled,
            ).digest
            document_size = self.document.stat().st_size
        if data.get('format') == fileproof.FORMAT:  # plik z kopii Sigelith Backup (3.0+)
            check = fileproof.check(data, document_digest=document_digest,
                                    document_size=document_size,
                                    key_override=self.key_override)
        else:
            check = bundle.check(data, document_digest=document_digest,
                                 key_override=self.key_override)
        return BundleOutcome(self.bundle_path, check, data)


class OnionRefreshTask(Task):
    """Biezacy adres .onion z `/api/onion/` (onion.discover) — tylko w trybie Tor.

    Wynik: `http://<adres>.onion` albo None (Tor nie dziala, brak sieci,
    niepoprawna odpowiedz) — wtedy program zostaje przy dotychczasowym adresie.
    """

    def __init__(self, settings):
        super().__init__()
        self._settings = settings

    def work(self):
        return onion.discover(self._settings)


class ClockSyncTask(Task):
    """Mierzy dryf zegara systemowego względem serwera Sigelith.

    Znaczenie praktyczne: aplikacja pokazuje zegar @beat liczony LOKALNIE.
    Zle ustawiony zegar systemowy sprawilby, ze uzytkownik widzi inny beat niż
    reszta swiata — i nie mialby jak się o tym dowiedziec. Jedno zapytanie na
    starcie zamyka te dziure.
    """

    def __init__(self, client: BeatTimeClient):
        super().__init__()
        self.client = client

    def work(self):
        return self.client.sync()


class ServerCertificateTask(Task):
    """Pobiera oficjalny certyfikat PDF wystawiony przez serwer."""

    def __init__(self, digest: str, client: BeatTimeClient):
        super().__init__()
        self.digest = digest
        self.client = client

    def work(self) -> bytes:
        self.signals.message.emit(_('Downloading the certificate from sigelith.org…'))
        return self.client.certificate_pdf(self.digest)


class HealthTask(Task):
    """Stan usługi Sigelith: baza, cache, dryf zegara serwera względem NTP."""

    def __init__(self, client: BeatTimeClient):
        super().__init__()
        self.client = client

    def work(self) -> dict:
        self.signals.message.emit(_('Checking the service status…'))
        return self.client.health()


class SupportersTask(Task):
    """Pobiera liste podziekowan i sprawdza jej ksztalt — zawsze w tle.

    Nigdy w watku interfejsu, i to z dwoch niezaleznych powodow. Pierwszy jest
    wspolny z reszta zadan: kazde zapytanie HTTP ma limit czasu liczony
    w sekundach, a przy wlaczonym trybie Tor takze droge przez proxy —
    wywolane z watku GUI zamrozilyby okno na ten czas. Drugi jest wlasny:
    to jedyne zapytanie, ktorego rozmiar odpowiedzi zalezy od danych po
    stronie serwera, a nie od naszego zapytania.

    Walidacja (`supporters.parse`) dzieje sie JUZ TUTAJ, w watku roboczym —
    do interfejsu wraca gotowa, obcieta i oczyszczona lista, a nie surowy
    slownik z sieci.
    """

    def __init__(self, client: BeatTimeClient):
        super().__init__()
        self.client = client

    def work(self) -> supporters.ThanksList:
        self.signals.message.emit(_('Loading the list of supporters…'))
        return supporters.parse(self.client.supporters_thanks())


class OtsDownloadTask(Task):
    """Pobiera dowód OpenTimestamps (.ots) tygodnia do niezaleznej kontroli."""

    def __init__(self, week_key: str, client: BeatTimeClient):
        super().__init__()
        self.week_key = week_key
        self.client = client

    def work(self) -> bytes:
        self.signals.message.emit(
            _('Downloading the .ots proof for %(week)s…') % {'week': self.week_key})
        return self.client.ots_proof(self.week_key)
