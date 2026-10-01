"""
Nazwy zapisywanych plikow: certyfikatu PDF i dowodu `.beatproof`.

Z czego sklada sie nazwa. Z trzech czesci, kazda do wlaczenia w Ustawieniach:

    Umowa najmu_2026-09-12_12-10-38_@424.05_sigelith.pdf
    └ plik zrodlowy └ data i godzina stempla └ @beat

Po co. Certyfikat nazwany wylacznie po pliku zrodlowym (`Umowa_sigelith.pdf`)
mial dwie wady: dwa stemple tego samego dokumentu w roznych wersjach dostaja
te sama nazwe, a przy zapisie do tego samego folderu drugi certyfikat
zastepowal pierwszy, jesli ktos nie przeczytal pytania o nadpisanie. Data,
godzina i @beat w nazwie porzadkuja folder same — sortowanie po nazwie jest
sortowaniem po czasie, a dwa certyfikaty prawie nigdy nie maja tej samej
nazwy.

Data i godzina sa w czasie LOKALNYM uzytkownika (tak, jak widzi je w
programie i w Eksploratorze), w zapisie, ktory sortuje sie poprawnie
i nie zawiera dwukropka — ten jest w nazwach plikow Windows zakazany.

A gdy nazwa i tak jest zajeta, `unique_path` dokleja „(2)", „(3)"... —
proponowana nazwa NIGDY nie wskazuje istniejacego pliku.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import beatcore, merkle

#: Znaki zakazane w nazwach plikow Windows (plus znaki sterujace).
_FORBIDDEN = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
#: Nazwy zarezerwowane przez Windows — plik o takiej nazwie nie powstanie.
#: Nazwy urzadzen Windows. Liczy sie CZESC PRZED PIERWSZA KROPKA („CON.txt"
#: to w Windows 10 nadal urzadzenie CON) oraz warianty z cyframi w indeksie
#: gornym (COM¹, LPT³) i CONIN$/CONOUT$ — fuzzing 2026-09-27.
_RESERVED = {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$',
             *(f'COM{i}' for i in (*range(1, 10), '¹', '²', '³')),
             *(f'LPT{i}' for i in (*range(1, 10), '¹', '²', '³'))}

#: Koncowka nazwy certyfikatu: kto go wystawil. Do 2.2.0 `_beattime`
#: (certyfikaty zapisane wczesniej zostaja pod stara nazwa — to tylko
#: propozycja nazwy przy zapisie, nic jej nie czyta).
PDF_SUFFIX = '_sigelith'


def safe_component(text: str, limit: int = 80) -> str:
    """Czesc nazwy pliku bez znakow zakazanych, spacji na brzegach i kropek na koncu."""
    value = _FORBIDDEN.sub('_', str(text or '')).strip().rstrip('.')
    value = re.sub(r'_{2,}', '_', value)
    if len(value) > limit:
        value = value[:limit].rstrip(' ._')
    if value.split('.', 1)[0].rstrip().upper() in _RESERVED:
        value = f'_{value}'
    return value


def stamp_moment_text(utc: str) -> str:
    """'2026-09-12_12-10-38' w czasie lokalnym albo '' dla zlego czasu."""
    dt = beatcore.parse_iso_utc(utc)
    return beatcore.local_str(dt, '%Y-%m-%d_%H-%M-%S') if dt else ''


def stem_for(entry, *, source: bool = True, moment: bool = True, beat: bool = True,
             fallback: str = 'certificate') -> str:
    """Rdzen nazwy z wybranych czesci. Nigdy pusty."""
    parts: list[str] = []
    file_name = str(getattr(entry, 'file_name', '') or '')
    if source and file_name:
        stem = safe_component(Path(file_name).stem)
        if stem:
            parts.append(stem)
    if moment:
        when = stamp_moment_text(str(getattr(entry, 'utc', '') or ''))
        if when:
            parts.append(when)
    if beat:
        value = str(getattr(entry, 'beat', '') or '')
        if re.fullmatch(r'@\d{3}(?:\.\d{1,3})?', value):
            parts.append(value)
    if not parts:
        digest = str(getattr(entry, 'digest', '') or '')
        parts.append(digest[:16] if merkle.is_digest(digest) else fallback)
    return '_'.join(parts)


def certificate_name(entry, **parts) -> str:
    return f'{stem_for(entry, **parts)}{PDF_SUFFIX}.pdf'


def bundle_name(entry, **parts) -> str:
    return f"{stem_for(entry, fallback='proof', **parts)}.beatproof"


def unique_path(path: Path) -> Path:
    """`path`, a gdy zajete — `nazwa (2).ext`, `nazwa (3).ext`..."""
    path = Path(path)
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for i in range(2, 10_000):
        candidate = path.with_name(f'{stem} ({i}){suffix}')
        if not candidate.exists():
            return candidate
    return path
