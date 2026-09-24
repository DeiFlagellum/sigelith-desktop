"""
Liczenie SHA-256 z pliku: strumieniowo, z postepem i mozliwoscia przerwania.

Poprzednik robil to tak:

    for chunk in iter(lambda: f.read(4096), b""):

w watku GUI. Trzy osobne problemy w jednej linii:

1. 4 KiB na odczyt to kilkaset tysiecy wywolan systemowych na plik 1 GB —
   narzut dominuje nad samym liczeniem skrótu.
2. Każdy odczyt alokuje nowy obiekt `bytes`; `readinto` do jednego,
   wielokrotnie uzywanego bufora nie alokuje nic.
3. Praca szla w watku interfejsu, więc okno zamarzalo na cały czas liczenia,
   bez paska postepu i bez mozliwosci rezygnacji. Przy pliku wideo wygladalo
   to jak zawieszenie programu.

Tutaj: bufor 1 MiB, `readinto`, raport postepu i sprawdzanie flagi przerwania.
Sam modul nie wie nic o Qt — watkami zarzadza `workers.py`.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .i18n import _, decimal_separator

# 1 MiB: powyzej tej wartosci zysk jest juz pomijalny, a zuzycie pamieci
# rosnie liniowo razem z liczba rownoleglych zadan.
CHUNK_SIZE = 1024 * 1024

ProgressFn = Callable[[int, int], None]      # (przeczytano, rozmiar_calkowity)
CancelFn = Callable[[], bool]                # True => przerwij


class HashCancelled(Exception):
    """Uzytkownik przerwal liczenie skrótu."""


class HashError(Exception):
    """Nie udalo sie przeczytac pliku — z komunikatem w jezyku interfejsu."""


@dataclass(frozen=True)
class FileDigest:
    path: Path
    digest: str
    size: int
    modified_unix: float

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def size_human(self) -> str:
        return human_size(self.size)


def human_size(size: int) -> str:
    """Rozmiar po ludzku, z separatorem dziesietnym wedlug jezyka interfejsu.

    Przecinek po polsku i niemiecku, kropka po angielsku. Zaden katalog
    komunikatow tego nie zalatwia — separator nie jest napisem, tylko regula
    zapisu liczby (`i18n.decimal_separator`).
    """
    step = 1024.0
    value = float(size)
    separator = decimal_separator()
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if value < step or unit == 'TB':
            if unit == 'B':
                return f'{int(value)} B'
            return f'{value:.1f}'.replace('.', separator) + f' {unit}'
        value /= step
    return f'{value:.1f} TB'


def sha256_file(path: str | os.PathLike[str], *,
                progress: ProgressFn | None = None,
                cancelled: CancelFn | None = None) -> FileDigest:
    """Liczy SHA-256 pliku. Podnosi `HashCancelled` gdy przerwano.

    Postep raportujemy nie czesciej niż co ~64 MiB LUB co 1% rozmiaru — pasek
    postepu odswiezany przy każdym megabajcie kosztowalby wiecej sygnalow Qt
    niż samego liczenia.
    """
    file_path = Path(path)
    try:
        stat = file_path.stat()
    except OSError as e:
        raise HashError(_os_error_message(file_path, e)) from e
    if not file_path.is_file():
        raise HashError(_('"%(name)s" is not a file.') % {'name': file_path.name})

    total = stat.st_size
    digest = hashlib.sha256()
    buffer = bytearray(CHUNK_SIZE)
    view = memoryview(buffer)
    read_bytes = 0
    next_report = 0
    report_step = max(CHUNK_SIZE, total // 100)

    if progress:
        progress(0, total)

    try:
        with open(file_path, 'rb', buffering=0) as fh:
            while True:
                if cancelled and cancelled():
                    raise HashCancelled()
                count = fh.readinto(buffer)
                if not count:
                    break
                digest.update(view[:count])
                read_bytes += count
                if progress and read_bytes >= next_report:
                    progress(read_bytes, total)
                    next_report = read_bytes + report_step
    except HashCancelled:
        raise
    except OSError as e:
        raise HashError(_os_error_message(file_path, e)) from e

    if progress:
        progress(read_bytes, total)

    return FileDigest(
        path=file_path,
        digest=digest.hexdigest(),
        size=read_bytes,
        modified_unix=stat.st_mtime,
    )


def _os_error_message(path: Path, error: OSError) -> str:
    """Blad systemu plikow w jezyku interfejsu — bez surowego komunikatu
    z biblioteki.

    Uzytkownik ma wiedziec, co zrobic. "Errno 13 Permission denied" tego nie
    mowi; "plik jest otwarty w innym programie" — mowi.
    """
    import errno
    name = path.name or str(path)
    mapping = {
        errno.ENOENT: _('The file "%(name)s" does not exist or has been moved.'),
        errno.EACCES: _('No permission to read the file "%(name)s".'),
        errno.EISDIR: _('"%(name)s" is a folder, not a file.'),
        errno.ENAMETOOLONG: _('The path to the file "%(name)s" is too long.'),
        errno.EBUSY: _('The file "%(name)s" is in use by another program.'),
    }
    # Windows: 32 = ERROR_SHARING_VIOLATION (plik zablokowany przez inny proces)
    winerror = getattr(error, 'winerror', None)
    if winerror in (32, 33):
        return _('The file "%(name)s" is open in another program and locked '
                 'for reading. Close it and try again.') % {'name': name}
    return mapping.get(
        error.errno, _('The file "%(name)s" could not be read.')) % {'name': name}
