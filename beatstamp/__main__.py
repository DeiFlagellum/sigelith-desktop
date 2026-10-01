"""
Punkt wejscia aplikacji.

Poprzednik miał tu piec linii: `QApplication`, okno, `exec()`. Bez dziennika
zdarzeń, bez obslugi nieprzechwyconych wyjatkow (w wersji okienkowej taki
wyjątek gasil program BEZ SLADU — okno po prostu znikalo) i bez przygotowania
pod ekrany o duzej gestosci pikseli.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import traceback
from pathlib import Path

from . import __app_name__, __version__, selftest
from .i18n import _, current_language, is_rtl, set_language
from .config import (
    CRASH_LOG_NAME,
    MigrationReport,
    Settings,
    app_data_dir,
    is_frozen,
    is_packaged,
    log_path,
    migrate_legacy_data,
    probe_write,
)


def setup_logging() -> None:
    """Dziennik obrotowy w katalogu danych + echo na konsole w wersji zrodlowej.

    Obrotowy, bo dziennik bez limitu rosnie w nieskonczonosc: 1 MB x 3 pliki
    wystarcza, żeby dojsc do przyczyny awarii, i nigdy nie zaskoczy
    uzytkownika zajetym dyskiem.
    """
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)-7s %(name)s: %(message)s', '%Y-%m-%d %H:%M:%S')

    try:
        handler = logging.handlers.RotatingFileHandler(
            log_path(), maxBytes=1_000_000, backupCount=3, encoding='utf-8')
        handler.setFormatter(formatter)
        root.addHandler(handler)
    except OSError:
        pass          # brak prawa zapisu nie moze blokowac startu programu

    if not getattr(sys, 'frozen', False):
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        root.addHandler(console)

    # urllib3 na poziomie DEBUG wypisuje pelne adresy zapytan — czyli takze
    # skroty dokumentow uzytkownika. Do dziennika trafiaja tylko ostrzezenia.
    logging.getLogger('urllib3').setLevel(logging.WARNING)


#: Plik, do ktorego `faulthandler` wypisze stos WSZYSTKICH watkow, gdy proces
#: padnie na poziomie C (Qt, sterownik, pamiec). Wersja okienkowa nie ma
#: konsoli ani stderr, wiec bez tego awaria natywna nie zostawiala sladu —
#: ani w dzienniku, ani nigdzie indziej. Obiekt trzymamy do konca procesu.
_CRASH_FILE = None
CRASH_FILE_MAX_BYTES = 256 * 1024


def enable_crash_dump(log: logging.Logger) -> None:
    global _CRASH_FILE
    import faulthandler
    from datetime import datetime
    try:
        path = log_path().with_name(CRASH_LOG_NAME)
        if path.is_file() and path.stat().st_size > CRASH_FILE_MAX_BYTES:
            path.replace(path.with_name(Path(CRASH_LOG_NAME).stem + '.1.log'))
        handle = open(path, 'a', encoding='utf-8')
        handle.write(f'--- start {datetime.now().isoformat(timespec="seconds")} '
                     f'{__app_name__} {__version__} pid {os.getpid()} ---\n')
        handle.flush()
        faulthandler.enable(file=handle, all_threads=True)
        _CRASH_FILE = handle
    except (OSError, RuntimeError, ValueError) as e:
        log.info('zrzut awaryjny niedostepny: %s', e)


def _log_environment(log: logging.Logger) -> None:
    """Zapisuje w dzienniku warunki startu — to, co rozni sie miedzy wersja
    zrodlowa a skompilowana i najczesciej decyduje o awarii TYLKO w tej drugiej.

    Trzy rzeczy, ktore trzeba widziec bez zgadywania:

    * argumenty wiersza polecen — plik przeciagniety na ikone albo otwarty
      przez „Otworz za pomoca" przychodzi wlasnie tedy;
    * czy proces jest zamrozony, czy dziala z paczki MSIX i gdzie rozpakowal
      zasoby (`sys._MEIPASS`) — wersja ze Sklepu i zwykly `.exe` to dwa rozne
      swiaty uprawnien, a zgloszenie bledu nie mowi, ktory to;
    * KATALOG DANYCH. Historia „znikla" niemal zawsze znaczy, ze program
      zapisuje ja gdzie indziej, niz uzytkownik patrzy;
    * SCIEZKA DO MAGAZYNU CA. Jesli `certifi` nie znajdzie `cacert.pem`
      wewnatrz paczki, kazde zapytanie HTTPS konczy sie bledem weryfikacji
      certyfikatu — a uzytkownik widzi tylko „nie udalo sie polaczyc".
    """
    log.info('argumenty: %r', sys.argv[1:])
    log.info('zamrozony: %s, spakowany (MSIX): %s, katalog zasobow: %s',
             is_frozen(), is_packaged(), getattr(sys, '_MEIPASS', '(brak)'))
    log.info('katalog danych: %s', app_data_dir())
    # Proba zapisu JUZ TERAZ, zanim ruszy interfejs. Zgloszenie „historia
    # znikla" prawie zawsze znaczy, ze zapis sie nie udal — a bez tego wiersza
    # dziennik milczy az do pierwszego stempla. Uzytkownikowi mowi o tym okno
    # (`MainWindow._check_data_dir`); tu chodzi o slad dla zglaszajacego blad.
    problem = probe_write()
    if problem is not None:
        log.error('katalog danych NIE PRZYJMUJE ZAPISU (blokada systemowa: %s): %s',
                  problem.protected, problem.reason)
    try:
        import certifi
        bundle = certifi.where()
        log.info('magazyn CA: %s (istnieje: %s)', bundle, os.path.exists(bundle))
    except Exception as e:                       # noqa: BLE001
        log.error('magazyn CA NIEDOSTEPNY: %s', e)


def install_excepthook(app) -> None:
    """Nieprzechwycony wyjątek: do dziennika i do okienka, zamiast cichej smierci."""
    from PySide6.QtWidgets import QMessageBox

    def hook(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        text = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
        logging.getLogger('beatstamp').critical('nieprzechwycony wyjątek:\n%s', text)
        try:
            box = QMessageBox()
            box.setIcon(QMessageBox.Critical)
            box.setWindowTitle(_('Application error — Sigelith Desktop'))
            box.setText(_('An unexpected error occurred.'))
            box.setInformativeText(
                _('The application will try to carry on. The details were '
                  'written to the event log:\n%(path)s') % {'path': log_path()})
            box.setDetailedText(text)
            box.exec()
        except Exception:            # noqa: BLE001
            pass                     # okienko o bledzie nie moze wywolac bledu

    sys.excepthook = hook
    # NIE `_ = app`. `_` jest funkcja tlumaczaca, a przypisanie w tym ciele
    # czyni ja ZMIENNA LOKALNA takze dla domkniecia `hook` — okno awarii
    # probowaloby wtedy wywolac `QApplication`, a jego wlasny `except`
    # polknalby blad. Efekt: program gasnie po cichu dokladnie tam, gdzie
    # ten kod mial temu zapobiec.
    _unused = app


def _log_migration(log: logging.Logger, report: MigrationReport) -> None:
    """Zapisuje wynik przeprowadzki danych. Nic nie wyswietla."""
    if not report.sources:
        log.info('przeprowadzka danych: nie ma czego przenosic (znacznik: %s)',
                 report.done)
        return
    log.info('przeprowadzka danych z %s do %s: skopiowano %s, było już na '
             'miejscu %s, odłożono obok %s, nie udało się %s, znacznik: %s',
             [str(s) for s in report.sources], report.target, report.copied,
             report.already_there, report.kept_aside, report.failed, report.done)
    if report.failed:
        log.warning('przeprowadzka danych NIE zakończona — zostanie powtórzona '
                    'przy następnym starcie')


def _install_qt_translations(app) -> None:
    """Tlumaczenia SAMEGO Qt: przyciski `QMessageBox`, `QFileDialog`, `QDialogButtonBox`.

    Ich tekstow nie ma w naszym katalogu i nigdy nie bedzie — nalezą do Qt.
    Bez tego okno „Zapisz plik" mialoby polski interfejs aplikacji i
    angielskie przyciski systemowe. Brak pliku `.qm` nie jest bledem:
    aplikacja dziala dalej, tyle ze z angielskimi przyciskami Qt.
    """
    from PySide6.QtCore import QLibraryInfo, QLocale, QTranslator
    language = current_language()
    directory = QLibraryInfo.path(QLibraryInfo.TranslationsPath)
    for name in ('qtbase', 'qt'):
        translator = QTranslator(app)
        if translator.load(QLocale(language), name, '_', directory):
            app.installTranslator(translator)
            # Referencje trzyma `app` (rodzic), wiec obiekt nie zniknie.
            break


def main() -> int:
    setup_logging()
    log = logging.getLogger('beatstamp')
    log.info('--- start %s %s (python %s) ---', __app_name__, __version__,
             sys.version.split()[0])

    # Jezyk ustawiamy PRZED czymkolwiek, co produkuje tekst dla czlowieka —
    # przeprowadzka danych zostawia notatke w starym katalogu, a jej tresc
    # ma byc w jezyku uzytkownika, nie w jezyku zrodlowym kodu. Wybor
    # zapisany w ustawieniach dokladamy nizej, gdy ustawienia sa juz wczytane.
    log.info('jezyk interfejsu (system): %s', set_language())
    _log_environment(log)

    # Samokontrola paczki. Musi wyprzedzic wszystko, co dotyka interfejsu:
    # sprawdza, czy ZBUDOWANA aplikacja ma komplet zasobow (trzy katalogi
    # tlumaczen, magazyn CA, moduly `reportlab` potrzebne do certyfikatu),
    # a nie czy dziala kod zrodlowy — to drugie sprawdzaja testy. Wywoluje ja
    # `tools/verify_exe.py`, czyli trzeci krok `build.ps1`.
    if selftest.requested(sys.argv[1:]):
        return selftest.main()
    enable_crash_dump(log)

    # Skalowanie na ekranach HiDPI. Qt 6 wlacza je samo, ale zaokraglenie w
    # gore przy skali 125%/150% daje rozmyte krawedzie — `PassThrough` zostawia
    # ulamkowa skale i tekst jest ostry.
    os.environ.setdefault('QT_ENABLE_HIGHDPI_SCALING', '1')
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QGuiApplication
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

    from PySide6.QtWidgets import QApplication, QMessageBox
    from .instance import SingleInstance, split_arguments
    from .ui import theme
    from .ui.main_window import MainWindow

    app = QApplication(sys.argv)
    # Nazwa wyswietlana konczy KAZDY tytul okna (Qt dokleja ja do tytulow,
    # ktore sie nia nie koncza) — patrz `ui/main_window`. Program nie uzywa
    # QSettings ani QStandardPaths, wiec nazwy aplikacji i organizacji nie
    # decyduja o zadnej sciezce danych.
    app.setApplicationName(__app_name__)
    app.setApplicationDisplayName(__app_name__)
    app.setApplicationVersion(__version__)
    app.setOrganizationName('Sigelith')
    app.setDesktopFileName('sigelith-desktop')
    install_excepthook(app)

    # Jedna kopia na katalog danych — PRZED przeprowadzka i przed pierwszym
    # odczytem danych: druga kopia nie moze ruszyc katalogu, na ktorym
    # pracuje pierwsza (patrz `instance.py`).
    files, handover = split_arguments(sys.argv[1:])
    instance = SingleInstance(app_data_dir())
    if not instance.acquire():
        if instance.forward(files, handover=handover):
            log.info('%s juz dziala — przekazane pliki: %s, do Handover: %s, koniec tej kopii',
                     __app_name__, len(files), len(handover))
        else:
            QMessageBox.information(None, __app_name__, _(
                'Sigelith Desktop is already running. Switch to its window — '
                'a second copy would work on the same data folder.'))
        return 0

    # Przeprowadzka danych ze starych lokalizacji z czasow BeatStampa
    # (`%USERPROFILE%\BeatStamp`, `Dokumenty\BeatStamp`, `%LOCALAPPDATA%\BeatStamp`
    # — `config.legacy_locations`) MUSI wyprzedzic pierwszy odczyt ustawien
    # i historii — inaczej program wczytalby pusty komplet z nowej lokalizacji,
    # a przy pierwszym zapisie utrwalil go na miejscu danych, ktore dopiero
    # czekaja na przeniesienie.
    migration = migrate_legacy_data()
    _log_migration(log, migration)

    settings = Settings.load()
    # Jawny wybor z Ustawien ma pierwszenstwo przed jezykiem systemu.
    log.info('jezyk interfejsu (ustawienia %r): %s', settings.language,
             set_language(settings.language))
    _install_qt_translations(app)
    # Arabski: cale okno od prawej do lewej (menu, uklady, tabele).
    if is_rtl():
        app.setLayoutDirection(Qt.RightToLeft)
    theme.apply_theme(app, settings.theme)

    window = MainWindow(settings, migration=migration)
    window.restore_geometry()
    window.show()

    # Pliki podane w wierszu polecen (takze przez „Otworz za pomoca" w
    # Eksploratorze) trafiaja od razu do stemplowania — poza plikami Handover,
    # ktore otwiera zakladka Handover (`open_paths`).
    from PySide6.QtCore import QTimer
    if files:
        QTimer.singleShot(400, lambda: window.open_paths([Path(f) for f in files]))
    # `--handover <plik>` (np. „Przekaz…” w Sigelith Backup): okno wysylki Handover.
    if handover:
        QTimer.singleShot(600, lambda: window.handover_send(handover))
    # ...a pliki z KOLEJNYCH uruchomien przekazuje druga kopia.
    instance.activated.connect(window.activate_from_other_instance)
    instance.handover_requested.connect(window.handover_send)

    code = app.exec()
    log.info('--- koniec (kod %s) ---', code)
    if window.abandoned_workers or window.pool.activeThreadCount():
        # Watek w tle wisi na zapytaniu, ktorego nie da sie przerwac. Bez tego
        # proces zostawal w pamieci niewidoczny, az zapytanie skonczy sie
        # samo (71 s w pomiarze 2026-09-27). Ustawienia, historia i stan
        # swiadka sa juz zapisane (zapis atomowy), wiec niczego nie tracimy.
        log.warning('koniec bez czekania na watek roboczy')
        instance.release()
        logging.shutdown()
        os._exit(code)
    instance.release()
    return code


if __name__ == '__main__':
    sys.exit(main())
