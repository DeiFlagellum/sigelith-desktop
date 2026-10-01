"""
Jedna kopia programu na jeden katalog danych.

Dwie rownoczesne kopie programu na tym samym katalogu psuly dane
(diagnostyka przed Sklepem, 2026-09-27): obie dopisywaly ten sam zakres kopii
publicznego dziennika (`witness/log.jsonl` z kazdym wpisem dwa razy), a zapis
historii „ostatni wygrywa" potrafil zgubic stempel zrobiony w drugiej kopii.
Wystarczalo dwa razy kliknac skrot albo otworzyc plik przez „Otworz za pomoca"
przy dzialajacym programie.

Mechanizm, dwa elementy Qt:

* `QLockFile` w katalogu danych — kto go ma, ten jest JEDYNA kopia. Blokada
  po kopii, ktora sie wysypala, jest rozpoznawana po numerze procesu (Qt
  sprawdza, czy proces o tym PID jeszcze zyje), wiec awaria nie zamyka
  programu na zawsze;
* `QLocalServer` (nazwany potok, dostep TYLKO dla tego samego uzytkownika) —
  druga kopia przekazuje nim pierwszej pliki z wiersza polecen i konczy sie.
  Pierwsza wychodzi na wierzch i stempluje przekazane pliki.

Nazwa potoku pochodzi ze sciezki katalogu danych: kopie na roznych katalogach
(np. testy z `SIGELITH_DATA_DIR`) nie widza sie nawzajem, tak jak nie dziela
danych.

Nazwy blokady i potoku zostaja z czasow BeatStampa CELOWO. Sigelith Desktop
honoruje katalog wybrany w BeatStampie i jego zmienna `BEATSTAMP_DATA_DIR`,
wiec wersja 2.x i 3.x moga trafic na TEN SAM katalog danych — a wtedy maja
sie wykluczac tak samo jak dwie kopie jednej wersji. Inna nazwa blokady
wpuscilaby obie naraz.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sys
import time
from pathlib import Path

from PySide6.QtCore import QLockFile, QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket

log = logging.getLogger(__name__)

LOCK_NAME = 'beatstamp.lock'          # wspolna z 2.x — patrz naglowek
#: Wiecej niz wystarczy na liste plikow z Eksploratora; chroni przed zalewem.
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_FILES = 10_000
#: Ile najwyzej czekamy na tresc od drugiej kopii (pisze od razu po polaczeniu).
READ_TIMEOUT_S = 1.5


def server_name(data_dir: Path) -> str:
    key = str(Path(data_dir).resolve()).lower().encode('utf-8', 'replace')
    # Prefiks wspolny z 2.x — patrz naglowek modulu.
    return 'BeatStamp-' + hashlib.sha256(key).hexdigest()[:24]


def _allow_foreground(pid: int) -> None:
    """Pozwala pierwszej kopii wyjsc na wierzch (Windows).

    System oddaje pierwszy plan tylko procesowi, ktory wlasnie dostal
    klikniecie uzytkownika — czyli tej, drugiej kopii. Bez tego okno
    pierwszej tylko mrugaloby na pasku zadan.
    """
    if sys.platform != 'win32' or not pid:
        return
    try:
        import ctypes
        ctypes.windll.user32.AllowSetForegroundWindow(int(pid))
    except (AttributeError, OSError, ValueError):
        pass


class SingleInstance(QObject):
    """Straznik jednej kopii. `activated(list[str])` = druga kopia przekazala pliki.

    `handover_requested(list[str])` — pliki do WYSLANIA przez Sigelith Handover
    (`--handover`, np. z Sigelith Backup: „Przekaz…” przy pliku z kopii).
    """

    activated = Signal(list)
    handover_requested = Signal(list)

    def __init__(self, data_dir: Path, parent: QObject | None = None):
        super().__init__(parent)
        self.data_dir = Path(data_dir)
        self.name = server_name(self.data_dir)
        self._lock = QLockFile(str(self.data_dir / LOCK_NAME))
        # Tylko po numerze procesu, nie po wieku: program otwarty od tygodnia
        # nadal jest ta jedyna kopia.
        self._lock.setStaleLockTime(0)
        self._server: QLocalServer | None = None

    # --- Pierwsza kopia -------------------------------------------------------

    def acquire(self) -> bool:
        """True = to jest jedyna kopia (blokada nasza, serwer nasluchuje)."""
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            # Bez katalogu danych nie ma czego chronic — program pokaze swoj
            # komunikat o niedostepnym katalogu.
            log.warning('jedna kopia: katalog danych niedostepny — bez blokady')
            return True
        if not self._lock.tryLock(300):
            if self._lock.error() == QLockFile.LockFailedError:
                return False
            # Brak prawa zapisu itp. — nie blokujemy startu przez sama blokade.
            log.warning('jedna kopia: nie udalo sie zalozyc blokady (%s)', self._lock.error())
            return True
        server = QLocalServer(self)
        server.setSocketOptions(QLocalServer.UserAccessOption)
        QLocalServer.removeServer(self.name)
        if server.listen(self.name):
            server.newConnection.connect(self._on_connection)
            self._server = server
        else:
            log.warning('jedna kopia: potok %s niedostepny: %s', self.name,
                        server.errorString())
        return True

    def release(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None
        if self._lock.isLocked():
            self._lock.unlock()

    def _on_connection(self) -> None:
        """Odbior wiadomosci od drugiej kopii — BEZ sygnalow na gniezdzie.

        Pierwsza wersja czytala przez `readyRead`/`disconnected` z funkcjami
        Pythona i kasowala gniazdo `deleteLater()`. Qt emituje jednak
        `disconnected` takze Z DESTRUKTORA gniazda — funkcja siegala wtedy do
        niszczonego obiektu i proces padal chwile pozniej (test
        `test_prestore.SingleInstanceTests`). Druga kopia pisze od razu po
        polaczeniu i czeka na odbior, wiec krotki odczyt blokujacy (najwyzej
        `READ_TIMEOUT_S`) jest tu prostszy i bezpieczny; gniazdo kasuje juz
        tylko Qt.
        """
        while self._server is not None and self._server.hasPendingConnections():
            connection = self._server.nextPendingConnection()
            data = bytearray()
            deadline = time.monotonic() + READ_TIMEOUT_S
            while (b'\n' not in data and len(data) <= MAX_MESSAGE_BYTES
                   and time.monotonic() < deadline):
                if connection.bytesAvailable() or connection.waitForReadyRead(100):
                    data.extend(bytes(connection.readAll()))
                elif connection.state() != QLocalSocket.ConnectedState:
                    break
            connection.abort()
            connection.deleteLater()
            if len(data) > MAX_MESSAGE_BYTES:
                log.warning('jedna kopia: za dluga wiadomosc — odrzucona')
                continue
            self._deliver(bytes(data))

    def _deliver(self, data: bytes) -> None:
        files: list[str] = []
        handover: list[str] = []
        try:
            message = json.loads(data.split(b'\n', 1)[0].decode('utf-8')) if data else {}
            if isinstance(message, dict):
                files = _strings(message.get('files'))
                handover = _strings(message.get('handover'))
        except (UnicodeDecodeError, ValueError):
            log.warning('jedna kopia: nieczytelna wiadomosc od drugiej kopii')
        log.info('jedna kopia: pliki od drugiej kopii: %s (do wyslania: %s)', len(files), len(handover))
        self.activated.emit(files)
        if handover:
            self.handover_requested.emit(handover)

    # --- Druga kopia ------------------------------------------------------------

    def forward(self, files: list[str], timeout_ms: int = 2000, *,
                handover: list[str] | None = None) -> bool:
        """Przekazuje pliki pierwszej kopii. False = nie dalo sie z nia polaczyc."""
        # PySide6 zwraca (pid, host, aplikacja); dokumentacja C++ ma jeszcze
        # wynik bool na poczatku — przyjmujemy obie postacie.
        info = self._lock.getLockInfo()
        values = [v for v in (info if isinstance(info, tuple) else ()) if not isinstance(v, bool)]
        if values and isinstance(values[0], int):
            _allow_foreground(values[0])
        socket = QLocalSocket()
        socket.connectToServer(self.name)
        if not socket.waitForConnected(timeout_ms):
            log.warning('jedna kopia: brak polaczenia z dzialajaca kopia: %s',
                        socket.errorString())
            return False
        message: dict = {'files': list(files)[:MAX_FILES]}
        if handover:  # starsze wersje programu pomijaja nieznany klucz
            message['handover'] = list(handover)[:MAX_FILES]
        payload = json.dumps(message, ensure_ascii=False).encode('utf-8') + b'\n'
        socket.write(payload)
        socket.flush()
        written = socket.waitForBytesWritten(timeout_ms) or socket.bytesToWrite() == 0
        socket.disconnectFromServer()
        if socket.state() != QLocalSocket.UnconnectedState:
            socket.waitForDisconnected(500)
        return bool(written)

#: Parametr, z ktorym Sigelith Backup (i kazdy inny program) prosi o WYSLANIE
#: pliku przez Sigelith Handover: `sigelith-desktop.exe --handover <plik>`.
HANDOVER_FLAG = '--handover'


def _strings(raw) -> list[str]:
    return [f for f in raw if isinstance(f, str) and f][:MAX_FILES] if isinstance(raw, list) else []


def split_arguments(argv: list[str]) -> tuple[list[str], list[str]]:
    """(pliki do otwarcia, pliki do wyslania przez Handover) z wiersza polecen.

    Wszystko po `--handover` to pliki do wyslania; tylko istniejace pliki —
    reszte (np. `--background`, literowki) pomijamy, jak dotad.
    """
    files: list[str] = []
    handover: list[str] = []
    target = files
    for arg in argv:
        if arg == HANDOVER_FLAG:
            target = handover
        elif Path(arg).is_file():
            target.append(str(Path(arg)))
    return files[:MAX_FILES], handover[:MAX_FILES]
