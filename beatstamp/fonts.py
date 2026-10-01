"""
Czcionki dostarczane z programem — Inter (tekst) i JetBrains Mono (skroty, zegar).

Po co wlasne czcionki, skoro Windows ma swoje. Dwa powody, oba konkretne:

* **Certyfikat PDF zamienial polskie litery na kwadraty.** reportlab bez
  wlasnej czcionki uzywa czternastu czcionek bazowych PDF (Helvetica,
  Courier...), ktore znaja tylko kodowanie WinAnsi: „ą", „ę", „ś", „ł" nie
  maja tam znakow. Czcionka TrueType osadzona w dokumencie niesie komplet
  znakow ze soba — certyfikat wyglada tak samo na kazdym komputerze
  i w kazdym czytniku, takze za dziesiec lat.
* **Ten sam wyglad wszedzie.** Interfejs ma wygladac jak jeden produkt na
  Windows 10 i 11, niezaleznie od tego, jakie czcionki ktos ma
  zainstalowane.

Obie czcionki sa na SIL Open Font License 1.1 (tekst w `licenses/`, wpis
w `NOTICE`): wolno je dolaczac do programow i osadzac w dokumentach.

PISMA CJK W CERTYFIKACIE

Inter nie ma znakow japonskich, koreanskich ani chinskich. Czcionka CJK to
13-19 MB, wiec NIE jedzie z programem: certyfikat bierze czcionke systemowa
Windows (Yu Gothic, Malgun Gothic, Microsoft YaHei — sa w kazdej instalacji
Windows 10 i 11) i osadza w PDF-ie tylko PODZBIOR uzytych znakow, tak samo
jak „Zapisz jako PDF" w Office. reportlab odmawia czcionek, ktorych flagi
licencyjne zabraniaja osadzania, wiec zakazana czcionka nie przejdzie.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from .config import resource_path

log = logging.getLogger(__name__)

UI_FAMILY = 'Inter'
MONO_FAMILY = 'JetBrains Mono'

#: Pliki w katalogu `fonts/` (ze zrodel: desktop/fonts, w paczce: _internal/fonts).
UI_FILES = ('Inter-Regular.ttf', 'Inter-Medium.ttf', 'Inter-SemiBold.ttf',
            'Inter-Bold.ttf')
MONO_FILES = ('JetBrainsMono-Regular.ttf', 'JetBrainsMono-Medium.ttf',
              'JetBrainsMono-Bold.ttf')

#: Nazwy czcionek w reportlabie (certyfikat PDF).
PDF_REGULAR = 'BeatStamp-Inter'
PDF_MEDIUM = 'BeatStamp-Inter-Medium'
PDF_BOLD = 'BeatStamp-Inter-Bold'
PDF_MONO = 'BeatStamp-Mono'
PDF_MONO_BOLD = 'BeatStamp-Mono-Bold'

#: Czcionki systemowe dla pism CJK: (zwykla, pogrubiona), w kolejnosci proby.
SYSTEM_CJK = {
    'ja': (('YuGothR.ttc', 'YuGothB.ttc'), ('msgothic.ttc', 'msgothic.ttc')),
    'ko': (('malgun.ttf', 'malgunbd.ttf'), ('gulim.ttc', 'gulim.ttc')),
    'zh': (('msyh.ttc', 'msyhbd.ttc'), ('simsun.ttc', 'simsun.ttc')),
}

_qt_done = False
_pdf_done: bool | None = None
_cjk: dict[str, dict | None] = {}


def font_path(name: str) -> Path:
    return resource_path(f'fonts/{name}')


def register_qt_fonts() -> bool:
    """Dodaje czcionki do bazy Qt. Idempotentne; False = czegos brakuje."""
    global _qt_done
    if _qt_done:
        return True
    from PySide6.QtGui import QFontDatabase
    ok = True
    for name in UI_FILES + MONO_FILES:
        path = font_path(name)
        if not path.is_file() or QFontDatabase.addApplicationFont(str(path)) < 0:
            log.warning('czcionka %s niedostepna (%s)', name, path)
            ok = False
    _qt_done = ok
    return ok


def register_pdf_fonts() -> bool:
    """Rejestruje czcionki w reportlabie. False = uzyj czcionek bazowych.

    Brak pliku nie przerywa wystawienia certyfikatu — ale w dzienniku
    zostaje slad, bo taki certyfikat znow zgubi polskie litery. Samokontrola
    paczki (`selftest.py`) sprawdza, ze pliki sa na miejscu.
    """
    global _pdf_done
    if _pdf_done is not None:
        return _pdf_done
    try:
        from reportlab.lib.fonts import addMapping
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        pairs = ((PDF_REGULAR, 'Inter-Regular.ttf'), (PDF_MEDIUM, 'Inter-Medium.ttf'),
                 (PDF_BOLD, 'Inter-Bold.ttf'), (PDF_MONO, 'JetBrainsMono-Regular.ttf'),
                 (PDF_MONO_BOLD, 'JetBrainsMono-Bold.ttf'))
        for alias, name in pairs:
            pdfmetrics.registerFont(TTFont(alias, str(font_path(name))))
        # `<b>` w akapicie reportlaba szuka pogrubionej odmiany TEJ rodziny.
        addMapping(PDF_REGULAR, 0, 0, PDF_REGULAR)
        addMapping(PDF_REGULAR, 1, 0, PDF_BOLD)
        addMapping(PDF_REGULAR, 0, 1, PDF_REGULAR)
        addMapping(PDF_REGULAR, 1, 1, PDF_BOLD)
        addMapping(PDF_MONO, 0, 0, PDF_MONO)
        addMapping(PDF_MONO, 1, 0, PDF_MONO_BOLD)
        addMapping(PDF_MONO, 0, 1, PDF_MONO)
        addMapping(PDF_MONO, 1, 1, PDF_MONO_BOLD)
        _pdf_done = True
    except Exception:                  # noqa: BLE001 — certyfikat ma powstac zawsze
        log.error('czcionki certyfikatu PDF niedostepne', exc_info=True)
        _pdf_done = False
    return _pdf_done


def system_fonts_dir() -> Path:
    return Path(os.environ.get('WINDIR') or r'C:\Windows') / 'Fonts'


def pdf_script_font(script: str) -> dict | None:
    """Czcionka systemowa dla pisma CJK (`ja`/`ko`/`zh`) albo None.

    Zwraca {'regular', 'bold', 'chars'} — `chars` to zbior kodow znakow,
    ktore czcionka naprawde ma. Wynik (takze brak) jest zapamietywany:
    wczytanie pliku 13-19 MB trwa, a certyfikat moze powstawac seriami.
    """
    if script in _cjk:
        return _cjk[script]
    result = None
    folder = system_fonts_dir()
    try:
        from reportlab.lib.fonts import addMapping
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
    except ImportError:                    # pragma: no cover — reportlab jest w paczce
        return None
    for regular_file, bold_file in SYSTEM_CJK.get(script, ()):
        regular_path, bold_path = folder / regular_file, folder / bold_file
        if not regular_path.is_file():
            continue
        alias = f'BeatStamp-CJK-{script}'
        try:
            regular = TTFont(alias, str(regular_path), subfontIndex=0)
            pdfmetrics.registerFont(regular)
            bold_alias = alias
            if bold_file != regular_file and bold_path.is_file():
                try:
                    pdfmetrics.registerFont(TTFont(alias + '-Bold', str(bold_path),
                                                   subfontIndex=0))
                    bold_alias = alias + '-Bold'
                except Exception:          # noqa: BLE001 — pogrubienie jest opcjonalne
                    log.info('brak pogrubionej odmiany %s', bold_path, exc_info=True)
            addMapping(alias, 0, 0, alias)
            addMapping(alias, 1, 0, bold_alias)
            addMapping(alias, 0, 1, alias)
            addMapping(alias, 1, 1, bold_alias)
            result = {'regular': alias, 'bold': bold_alias,
                      'chars': frozenset(regular.face.charToGlyph)}
            break
        except Exception:                  # noqa: BLE001 — certyfikat ma powstac zawsze
            log.warning('czcionka %s nie nadaje sie do certyfikatu', regular_path,
                        exc_info=True)
    _cjk[script] = result
    return result


def pdf_chars(font_name: str):
    """Kody znakow, ktore ma czcionka TrueType z reportlaba; None = nie wiadomo."""
    try:
        from reportlab.pdfbase import pdfmetrics
        face = getattr(pdfmetrics.getFont(font_name), 'face', None)
        return frozenset(face.charToGlyph) if face is not None else None
    except Exception:                      # noqa: BLE001 — czcionka bazowa PDF
        return None


def pdf_fonts() -> dict[str, str]:
    """Nazwy czcionek do stylow certyfikatu (TrueType albo bazowe PDF)."""
    if register_pdf_fonts():
        return {'regular': PDF_REGULAR, 'medium': PDF_MEDIUM, 'bold': PDF_BOLD,
                'mono': PDF_MONO, 'mono_bold': PDF_MONO_BOLD}
    return {'regular': 'Helvetica', 'medium': 'Helvetica', 'bold': 'Helvetica-Bold',
            'mono': 'Courier', 'mono_bold': 'Courier-Bold'}
