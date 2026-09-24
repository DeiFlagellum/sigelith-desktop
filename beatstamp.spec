# -*- mode: python ; coding: utf-8 -*-
"""
Przepis kompilacji BeatStampa do KATALOGU (`dist/BeatStamp/`).

Do wersji 2.1.0 budowalismy tryb jednoplikowy (`onefile`). Zmiana na tryb
katalogowy (`onedir`) nie jest kwestia gustu — wymusza ja sposob dystrybucji:

0. **Tryb katalogowy zamiast jednoplikowego.** Plik jednoplikowy jest
   samorozpakowujacym sie archiwum: przy KAZDYM starcie wysypuje kilkaset
   plikow (caly Python i caly Qt) do katalogu tymczasowego i dopiero stamtad
   je laduje. W paczce ze Sklepu (MSIX) podpisana jest ZAWARTOSC PACZKI —
   a nie to, co program wypakuje sobie potem do `%TEMP%`. Smart App Control
   w Windows 11 blokuje uruchamianie niepodpisanych plikow wykonywalnych,
   wiec aplikacja poprawnie podpisana i zainstalowana ze Sklepu i tak mogla
   zostac zatrzymana na wlasnym rozpakowanym ladunku.
   Tryb katalogowy nie rozpakowuje niczego: kazdy plik lezy na dysku
   w `_internal/`, jest objety podpisem paczki i widoczny dla systemu.
   Przy okazji znika kilkusekundowe opoznienie przy kazdym starcie
   i podwojne zuzycie miejsca na dysku.

1. **`upx=False`.** Kompresja UPX jest jedna z najczestszych przyczyn
   FALSZYWYCH ALARMOW antywirusowych — spakowany nia plik wyglada dla
   heurystyk jak upakowane szkodliwe oprogramowanie, bo realne zagrozenia
   uzywaja jej do ukrywania kodu. Zysk to kilkanascie procent rozmiaru;
   koszt to program, ktorego czesc uzytkownikow nie moze uruchomic.

2. **Zasob wersji.** `version_info.txt` daje plikowi tozsamosc we
   wlasciwosciach Windows. Poprzednik nie mial jej wcale.

3. **Twarde wykluczenia.** PySide6 ciagnie za soba Qt WebEngine, Qt 3D,
   QML/Quick, multimedia i wykresy. Nie uzywamy z tego NICZEGO — aplikacja
   stoi na QtCore, QtGui i QtWidgets. Bez wykluczen katalog urosl by
   o kilkaset megabajtow, a kazdy zbedny modul to dodatkowa powierzchnia
   ataku i dodatkowy czas startu. W paczce ze Sklepu rozmiar jest tez
   rozmiarem pobierania u kazdego uzytkownika.

4. **Jawnie dolaczony magazyn CA `certifi`.** Weryfikacja TLS jest tu
   warunkiem bezpieczenstwa, a nie detalem — bundle musi trafic do paczki
   niezaleznie od tego, czy zadzialaja automatyczne haki.

5. **Katalogi tlumaczen (`locale/`) i ikona.** Aplikacja czyta je przez
   `config.resource_path(...)`, czyli przez `sys._MEIPASS`. W trybie
   katalogowym `sys._MEIPASS` wskazuje `_internal/` obok pliku .exe — kod
   aplikacji nie wymaga z tego powodu zadnej zmiany. Bez tych wpisow wersja
   skompilowana startowalaby po angielsku niezaleznie od ustawien — i to jest
   awaria niewidoczna w testach, bo one dzialaja na kodzie zrodlowym, gdzie
   `locale/` lezy obok pakietu.
   Do paczki ida WYLACZNIE pliki `.mo`: `.po` sa zrodlem dla tlumacza,
   waza tyle samo i nikomu w gotowym programie nie sa potrzebne.

6. **Wykluczenia licencyjne i „sieroty" (`tools/licenses.py`).** `excludes`
   Analizy dziala na MODULACH PYTHONA i nie widzi bibliotek, ktore Qt
   wciaga jako WTYCZKI: `PySide6.QtQml` i `PySide6.QtQuick` byly wykluczone
   od poczatku, a `Qt6Qml.dll` i `Qt6Quick.dll` i tak lezaly w paczce —
   przyszly jako zaleznosc wtyczki klawiatury ekranowej. Ta klawiatura
   (Qt Virtual Keyboard) jest dostepna WYLACZNIE na GPLv3 albo komercyjnie,
   wiec w wydaniu na Apache-2.0 nie ma dla niej miejsca. Odsiewamy ja na
   listach zbieranych przez PyInstallera (`a.binaries`/`a.datas`), czyli
   ZANIM cokolwiek zostanie skopiowane — kasowanie plikow po kompilacji
   wraca przy kazdej nastepnej i nikt tego nie zauwaza.
   Lista jest w `tools/licenses.py`, a nie tutaj, bo czyta ja takze test
   (`tests/test_licensing.py`) i generator not (`tools/make_notice.py`).
"""
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

sys.path.insert(0, str(Path(SPECPATH) / 'tools'))

import licenses as _licenses          # noqa: E402  (sciezka ustawiona wyzej)

datas = [('beatstamp.ico', '.')]
datas += collect_data_files('certifi')          # cacert.pem — kotwica zaufania TLS

# Skompilowane katalogi tlumaczen. Sciezka docelowa odtwarza uklad
# `locale/<jezyk>/LC_MESSAGES/beatstamp.mo`, bo dokladnie tego szuka
# biblioteka `gettext`.
_LOCALE = Path(SPECPATH) / 'locale'
datas += [(str(mo), str(mo.relative_to(Path(SPECPATH)).parent))
          for mo in sorted(_LOCALE.rglob('*.mo'))]

# Dokumenty prawne DO SAMEJ PACZKI. LGPLv3 par. 4(c) mowi o DOSTARCZENIU
# kopii GNU GPL i LGPL razem z programem — nie o odnosniku do nich. Odnosnik
# wymaga sieci i cudzego serwera; katalog obok pliku .exe jest u uzytkownika
# zawsze, takze za trzy lata i bez internetu. Otwiera go przycisk w oknie
# „O programie" (`ui/dialogs.py: AboutDialog`).
_LEGAL = _licenses.LEGAL_DIR_IN_PACKAGE.split('/')[-1]
datas += [(str(Path(SPECPATH) / name), _LEGAL) for name in ('LICENSE', 'NOTICE')]
datas += [(str(text), _LEGAL)
          for text in sorted((Path(SPECPATH) / 'licenses').glob('*.txt'))]

# reportlab laduje czesc wlasnych modulow DYNAMICZNIE — `barcode/widgets.py`
# sklada nazwy klas w tekscie i wykonuje je przez `exec`. Analiza statyczna
# PyInstallera takich importow nie widzi z zasady, wiec pakiet budowal sie
# bez bledu i dopiero uruchomienie konczylo sie
# `ModuleNotFoundError: reportlab.graphics.barcode.code128`.
# Zbieramy caly pakiet zamiast wyliczac nazwy recznie: lista zaleznosci
# ukrytych, ktora trzeba pamietac o aktualizowaniu, zepsulaby sie przy
# pierwszej zmianie w reportlabie — i znowu dopiero w gotowej paczce.
hiddenimports = collect_submodules('reportlab')

# Qt, ktorego nie uzywamy. Kazda pozycja to realne megabajty i realny kod,
# ktory inaczej wladowalby sie do procesu.
EXCLUDED_QT = [
    'PySide6.QtWebEngineCore', 'PySide6.QtWebEngineWidgets', 'PySide6.QtWebEngineQuick',
    'PySide6.QtWebChannel', 'PySide6.QtWebSockets',
    'PySide6.QtQml', 'PySide6.QtQuick', 'PySide6.QtQuickWidgets', 'PySide6.QtQuick3D',
    'PySide6.Qt3DCore', 'PySide6.Qt3DRender', 'PySide6.Qt3DInput',
    'PySide6.Qt3DLogic', 'PySide6.Qt3DAnimation', 'PySide6.Qt3DExtras',
    'PySide6.QtCharts', 'PySide6.QtDataVisualization', 'PySide6.QtGraphs',
    'PySide6.QtMultimedia', 'PySide6.QtMultimediaWidgets', 'PySide6.QtSpatialAudio',
    'PySide6.QtBluetooth', 'PySide6.QtNfc', 'PySide6.QtPositioning',
    'PySide6.QtSerialPort', 'PySide6.QtSerialBus', 'PySide6.QtRemoteObjects',
    'PySide6.QtSql', 'PySide6.QtTest', 'PySide6.QtHelp', 'PySide6.QtDesigner',
    'PySide6.QtUiTools', 'PySide6.QtOpenGL', 'PySide6.QtOpenGLWidgets',
    'PySide6.QtPdf', 'PySide6.QtPdfWidgets', 'PySide6.QtNetworkAuth',
    'PySide6.QtTextToSpeech', 'PySide6.QtSensors', 'PySide6.QtScxml',
    'PySide6.QtStateMachine', 'PySide6.QtSvgWidgets', 'PySide6.QtConcurrent',
    'PySide6.QtHttpServer', 'PySide6.QtLocation',
]

# UWAGA: `PIL` (Pillow) NIE MOZE tu trafic. Kod QR rysujemy wprawdzie
# wektorowo, ale `reportlab.lib.utils` importuje PIL BEZWARUNKOWO, juz na
# poziomie modulu — wykluczenie go konczy sie `ModuleNotFoundError` przy
# starcie i to WYLACZNIE w wersji skompilowanej (ze zrodel Pillow jest
# w srodowisku, wiec bez uruchomienia gotowej paczki blad jest niewidoczny).
EXCLUDED_PY = [
    'tkinter',          # drugi zestaw narzedzi GUI — nieuzywany
    'numpy', 'scipy', 'pandas', 'matplotlib',
    'pytest', 'setuptools', 'pip', 'wheel',
    'pydoc', 'doctest', 'lib2to3',
]

a = Analysis(
    ['beatstamp_main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports + ['beatstamp.ui.main_window'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDED_QT + EXCLUDED_PY,
    noarchive=False,
    optimize=1,          # -O: usuwa assercje z kodu produkcyjnego
)


def _sift(entries, what):
    """Wyrzuca z listy zbieranej przez PyInstallera to, czego w paczce byc nie ma.

    Wpis to krotka `(nazwa_docelowa, zrodlo, typ)`. Decyduje NAZWA DOCELOWA,
    a nie sciezka zrodlowa: to ona mowi, co uzytkownik dostanie na dysk,
    i to ja sprawdza pozniej test na gotowej paczce.
    """
    kept = []
    for entry in entries:
        reason = _licenses.excluded_reason(entry[0])
        if reason is None:
            kept.append(entry)
            continue
        print(f'beatstamp.spec: {what} - wykluczam {entry[0]} '
              f'[{reason.kind}] {reason.subject}: {reason.reason}')
    return kept


a.binaries = _sift(a.binaries, 'biblioteki')
a.datas = _sift(a.datas, 'zasoby')

pyz = PYZ(a.pure)

# `exclude_binaries=True` to roznica miedzy trybem jednoplikowym a katalogowym:
# .exe jest wylacznie programem rozruchowym, a biblioteki i zasoby zbiera
# ponizej COLLECT. Nic nie laduje do `%TEMP%` — patrz punkt 0 w naglowku.
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='BeatStamp',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                       # patrz punkt 1 w naglowku
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['beatstamp.ico'],
    version='version_info.txt',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,                       # patrz punkt 1 w naglowku
    upx_exclude=[],
    # Nazwa katalogu na zaleznosci. PyInstaller 6 domyslnie uzywa `_internal`
    # i zostajemy przy tym: obok pliku .exe widac wtedy JEDEN podkatalog,
    # a nie kilkaset plikow, ktore uzytkownik moglby uznac za smieci
    # i skasowac. Nazwa jest tez zapisana w kodzie rozruchowym — zmiana
    # wymaga przebudowy, nie przeniesienia katalogu.
    contents_directory='_internal',
    name='BeatStamp',
)
