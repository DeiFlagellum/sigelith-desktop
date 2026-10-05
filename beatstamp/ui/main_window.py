"""
Glowne okno Sigelith Desktop.

Uklad wyrasta z czterech rzeczy, ktore uzytkownik faktycznie robi albo chce
widziec:

    Stemplowanie — nadaj plikowi znacznik czasu
    Weryfikacja  — sprawdz plik, skrot albo dowod .beatproof
    Historia     — co juz ostemplowalem i na jakim etapie jest dowod
    Swiadkowie   — co aplikacja sama sprawdza w publicznym dzienniku (2.2)

Zasady, ktorych trzyma sie caly ten plik:

* nic dlugotrwalego nie dzieje sie w watku GUI — liczenie skrotu i siec ida
  przez `QThreadPool` (`workers.py`), zawsze z widocznym znakiem pracy;
* kazdy komunikat idzie przez katalog tlumaczen i mowi, CO ZROBIC, a nie
  tylko co sie stalo;
* stan dowodu nie jest lukrowany: swiezy stempel jest opisany jako swiezy,
  a nie jako "zweryfikowany";
* kazdy element sterujacy ma podpowiedz — program ma sie tlumaczyc sam.
"""
from __future__ import annotations

import html
import logging
import random
import sys
import webbrowser
from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import QThreadPool, QTimer, QUrl, Qt
from PySide6.QtGui import QAction, QDesktopServices, QGuiApplication, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import __app_name__, __version__, beatcore, bundle, certificate, keys, merkle, naming, plural, proof
from .. import fileproof, onion, witness
from ..api import ApiError, BeatTimeClient
from ..config import (
    IMPRESSUM_URL,
    MigrationReport,
    Settings,
    WriteProblem,
    app_data_dir,
    describe_write_problem,
    history_path,
    privacy_policy_url,
    probe_write,
    resource_path,
    site_url,
    verify_url,
    write_atomic,
)
from ..history import SOURCE_TVS_LEGACY, History, entry_from_verification
from ..i18n import _, current_language, ltr, rtl_block, set_language
from ..proof import Level, VerificationResult
from .. import workers
from . import icons, journey, theme
from .dialogs import (
    AboutDialog,
    DetailsDialog,
    LogDialog,
    SettingsDialog,
    ThanksDialog,
    data_dir_button_text,
    data_dir_tooltip,
    open_data_dir,
    open_url,
    resolve_data_dir_problem,
)
from .history_model import COL_DIGEST, HistoryFilter, HistoryModel
from .widgets import (
    BeatClock,
    BusyOverlay,
    CopyField,
    DropZone,
    ElidedButton,
    ElidedLabel,
    ProofJourney,
    PulseDot,
    StatusBadge,
    action_row,
    card,
    divider,
    fit_to_screen,
    label,
    section_label,
)
from .witness_panel import WitnessPanel
from .handover_controller import HandoverController, is_handover_file

log = logging.getLogger(__name__)

#: Co ile swiadek sprawdza dziennik, gdy okno jest otwarte.
WITNESS_INTERVAL_MS = 15 * 60 * 1000
#: Rozrzut cyklu swiadka (+/-). Bez niego wszystkie instalacje uruchomione
#: o pelnej godzinie pytalyby serwer w tej samej sekundzie co kwadrans.
WITNESS_JITTER = 0.15
#: Kolejna porcja checkpointow po przebiegu przycietym do limitu. 3 s przy
#: pierwszym uruchomieniu po dluzszej przerwie wpadalo w limit API (120/min).
WITNESS_CONTINUE_MS = 60 * 1000
#: Ile czekamy przy zamykaniu na prace w tle, zanim proces skonczy sie bez niej.
CLOSE_WAIT_MS = 4000


def _DROP_TEXTS() -> tuple[str, str]:
    """Napisy strefy upuszczania. Funkcja, bo uzywamy ich w dwoch miejscach
    (budowa okna i powrot po zadaniu) i nie moga sie rozjechac."""
    return (
        _('Drag files here'),
        _('or click to pick them from disk · you can drop many files and whole '
          'folders'),
    )


def _key_line(signer_status: str) -> str:
    """Wiersz listy kontroli o tozsamosci klucza — rozroznia przypadki."""
    if signer_status == keys.SIGNER_CURRENT:
        return '✓ ' + _('Sigelith key from the list built into the application')
    if signer_status == keys.SIGNER_OVERRIDE:
        return '⚠ ' + _('key accepted thanks to YOUR OWN key from the settings')
    if signer_status == keys.SIGNER_RETIRED:
        return '✗ ' + _('Sigelith key RETIRED — the proof needs refreshing')
    return '✗ ' + _('FOREIGN key — outside the Sigelith keys built into the '
                    'application')


def _retired_html(warnings: list[str]) -> str:
    """Opis stanu „podpis wycofanym kluczem" — tekst z escapowaniem."""
    return ('<b>' + _('The signature comes from a retired Sigelith key.')
            + '</b><br>' + '<br>'.join(html.escape(w) for w in warnings))


def _problems_html(problems: list[str]) -> str:
    """Zastrzezenia jako tekst etykiety — kazde przez `html.escape`."""
    return '<br>'.join(html.escape(p) for p in problems)


def _week_note(week: str, confirmed: bool) -> str:
    """Dopisek pod czasem: co podpis NAPRAWDE obejmuje (tekst zwykly).

    Podpis korzenia obejmuje tydzien, nie dokladna chwile — `utc` i `beat`
    to deklaracja rejestru. Dlatego granica potwierdzona podpisem jest tu
    pokazana osobno od samego czasu.
    """
    if not week:
        return ''
    if confirmed:
        return _('the signature covers week %(week)s (%(range)s UTC) — the '
                 'document existed no later than %(end)s; the exact moment is '
                 'given by the register') % {
                     'week': week, 'range': proof.week_range_text(week),
                     'end': proof.week_end_text(week)}
    return _('time according to the register — week %(week)s without a '
             'confirmed signature') % {'week': week}


def _time_html(obj, note: str = '', *, with_bounds: bool = True) -> str:
    """Wiersz czasu: @beat · czas lokalny (strefa) · UTC, pod nim granice.

    Kazda wartosc przechodzi przez `html.escape` (`journey.moment_html`).
    Etykiety Qt maja `Qt::AutoText`: tekst wygladajacy na HTML trafia do
    parsera tekstu wzbogaconego razem z wartosciami ze srodka, a ten rozumie
    `<img src=...>` — takze ze sciezki UNC. Wystarczyloby `"beat": "<img
    src='//host/x.png'>"` w pliku `.beatproof`, zeby samo WYSWIETLENIE wyniku
    odpytalo serwer atakujacego.
    """
    text = journey.moment_html(obj)
    if note:
        text += (f'<br><span style="color:{theme.MUTED_INK}">'
                 f'{html.escape(note)}</span>')
    if with_bounds:
        bounds = journey.bounds_html(obj)
        if bounds:
            text += '<br>' + bounds
    # Tekst wzbogacony bierze kierunek akapitu z pierwszej mocnej litery —
    # tu z izolowanego „@424.05". Po arabsku caly blok szedl od lewej.
    return rtl_block(text)


class _DictView:
    """Slownik `.beatproof` z atrybutami jak `Entry` — do `_time_html`."""

    def __init__(self, data: dict):
        self.beat = str(data.get('beat') or '')
        self.utc = str(data.get('utc') or '')
        self.time_bounds = data.get('time') if isinstance(data.get('time'), dict) else {}


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings, migration: MigrationReport | None = None):
        super().__init__()
        self.settings = settings
        # Wynik przeprowadzki danych z `%LOCALAPPDATA%`. Domyslnie `None`,
        # bo okno da sie zbudowac bez niej (testy, wywolanie z biblioteki).
        self._migration = migration
        self.client = BeatTimeClient(settings)
        self.history = History(limit=settings.history_limit).load(
            key_override=settings.key_override)
        self.current_result: VerificationResult | None = None
        self.current_entry = None
        self._current_batch: list = []
        # Wpisy serii, dla ktorych wolno wystawic certyfikat i .beatproof:
        # dowod bez zastrzezen kontroli lokalnej (jak przy jednym pliku).
        self._current_batch_exportable: list = []
        self.verify_result: VerificationResult | None = None
        self._verify_source_name = ''
        self._active_task: workers.Task | None = None
        self._pending_files: list[Path] = []
        # Od chwili zamkniecia okna zadne odlozone wywolanie nie ma prawa
        # niczego uruchamiac. Timery z konstruktora sa zaplanowane na 0-300 ms;
        # zamkniecie programu w tym oknie czasu trafialoby w okno, ktorego
        # pula watkow jest juz sprzatana.
        self._closing = False

        # Swiadek (witness.py). Stan wczytujemy od razu — to jeden plik JSON —
        # a kopie dziennika dopiero w watku roboczym, przy pierwszej potrzebie.
        self.witness_store = witness.WitnessStore()
        self.witness_state = self.witness_store.load()
        self.log_mirror = witness.LogMirror()
        self._witness_running = False
        self._witness_interactive = False
        self._background_started = False
        # Zadania w tle, ktore trzeba umiec przerwac: przy czynnosci
        # uzytkownika (pierwszenstwo) i przy zamykaniu okna.
        self._witness_task: workers.Task | None = None
        self._quiet_task: workers.Task | None = None
        self._sync_task: workers.Task | None = None
        self._onion_task: workers.Task | None = None
        self._background_paused = False
        #: True = przy zamknieciu watek w tle nie skonczyl w `CLOSE_WAIT_MS`;
        #: `__main__` konczy wtedy proces bez czekania na niego.
        self.abandoned_workers = False
        self._witness_timer = QTimer(self)
        self._witness_timer.setInterval(WITNESS_INTERVAL_MS)
        self._witness_timer.timeout.connect(self._background_cycle)
        self._note_timer = QTimer(self)
        self._note_timer.setSingleShot(True)
        self._note_timer.setInterval(900)
        self._note_timer.timeout.connect(self._save_note_to_current)

        # Jeden watek roboczy: zadania i tak ida sekwencyjnie (limit serwera
        # to 20 stempli/min), a jeden watek znaczy, ze nie ma dwoch zapisow
        # historii ani dwoch zmian kopii dziennika naraz — bez blokad.
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(1)

        # Tytul KONCZY SIE nazwa programu — `setApplicationDisplayName` kaze
        # Qt dokleic „ - Sigelith Desktop" do kazdego tytulu, ktory ta nazwa
        # sie nie konczy (`QPlatformWindow::formatWindowTitle`).
        self.setWindowTitle(_('@beat timestamps %(version)s — Sigelith Desktop')
                            % {'version': __version__})
        # 560, nie 680: przy 1920x1080 ze skala 150% (1280x720 logicznie)
        # zostaje ~640 px na okno — 680 nie miescilo sie nawet po
        # zmaksymalizowaniu. Tresc zakladek i tak jest przewijana.
        self.setMinimumSize(980, 560)
        self.setAcceptDrops(True)
        self._load_icon()

        self._build_ui()
        self._build_menu()
        self._refresh_history_view()
        self._render_witnesses()

        # Wszystko, co moze wyswietlic okienko, odkladamy na PO starcie petli
        # zdarzen. Modalny komunikat wywolany jeszcze w konstruktorze
        # zatrzymuje program zanim glowne okno sie pokaze.
        QTimer.singleShot(0, self._check_data_dir)
        QTimer.singleShot(0, self._report_migration)
        QTimer.singleShot(0, self._report_history_problem)
        QTimer.singleShot(50, self._migrate_legacy_history)
        QTimer.singleShot(300, self._sync_clock)
        # Adres .onion (tylko w trybie Tor, raz na dobe) — po starcie, zeby
        # nie wyprzedzic synchronizacji zegara w jednowatkowej puli.
        QTimer.singleShot(8000, self._refresh_onion)

    # --- Budowa interfejsu --------------------------------------------------

    def _load_icon(self) -> None:
        # Swiadomie BEZ awaryjnego siegania po `tvs_icon.ico` — ikona starej
        # marki na nowej aplikacji myli co do tego, ktory program jest otwarty.
        path = resource_path('beatstamp.ico')
        if path.exists():
            self.setWindowIcon(QIcon(str(path)))

    @staticmethod
    def _scrolled(page: QWidget) -> QScrollArea:
        """Zakladka w obszarze przewijania.

        Przy malym oknie uklad nie ma prawa sciskac tresci ponizej jej
        minimum — wtedy napisy z zawijaniem wchodzily na sasiednie wiersze
        (napis „Uwaga: ..." chowal sie pod polem skrotu). W obszarze
        przewijania tresc zachowuje swoja wysokosc, a okno dostaje pasek.
        """
        page.setObjectName('scrollBody')
        area = QScrollArea()
        area.setWidgetResizable(True)
        # Przewijanie tylko w pionie: tresc ma sie ukladac do szerokosci okna.
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        area.setFrameShape(QFrame.NoFrame)
        area.setWidget(page)
        return area

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(18, 14, 18, 8)
        layout.setSpacing(12)
        layout.addWidget(self._build_header())

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.tabBar().setDrawBase(False)
        self.tabs.addTab(self._scrolled(self._build_stamp_tab()), _('Stamping'))
        self.tabs.addTab(self._scrolled(self._build_verify_tab()), _('Verification'))
        self.tabs.addTab(self._build_history_tab(), _('History'))
        self.witness_panel = WitnessPanel()
        self.witness_panel.checkRequested.connect(lambda: self.check_witnesses(True))
        self.witness_panel.modeChanged.connect(self._set_witness_mode)
        self.witness_panel.evidenceRequested.connect(self._open_evidence)
        self.tabs.addTab(self._scrolled(self.witness_panel), _('Witnesses'))
        # Sigelith Handover (3.0): przekazanie plikow z dowodem doreczenia.
        # Ostatnia zakladka — indeksy 0-3 sa zaszyte w wielu miejscach.
        self.handover = HandoverController(self)
        self.handover_scroll = self._scrolled(self.handover.panel)
        self.tabs.addTab(self.handover_scroll, _('Handover'))
        self.tabs.setTabToolTip(
            0, _('Give files a timestamp in the Sigelith register'))
        self.tabs.setTabToolTip(
            1, _('Check a file, a SHA-256 digest or a .beatproof proof'))
        self.tabs.setTabToolTip(
            2, _('Your stamps and the stage their proof has reached'))
        self.tabs.setTabToolTip(
            3, _('What this application checks in the public log by itself'))
        self.tabs.setTabToolTip(
            4, _('Hand over files with proof of delivery'))
        for index, name in enumerate(('fingerprint', 'shield-check', 'clock-history',
                                      'people', 'file-earmark-lock')):
            icons.apply_tab(self.tabs, index, name, 'text_muted', 16)
        layout.addWidget(self.tabs, 1)

        layout.addWidget(self._build_progress())
        self.setCentralWidget(root)
        self.overlay = BusyOverlay(root)

        status = self.statusBar()
        self.status_lock = QLabel()
        icons.apply_label(self.status_lock, 'lock-fill', 'text_faint', 12)
        status.addPermanentWidget(self.status_lock)
        self.status_connection = QLabel()
        self.status_connection.setTextFormat(Qt.PlainText)
        self.status_connection.setObjectName('faint')
        status.addPermanentWidget(self.status_connection)
        self._update_connection_label()
        status.showMessage(_('Ready. Drag files in to give them a timestamp.'))

    def _build_header(self) -> QWidget:
        header = QFrame()
        header.setObjectName('header')
        self._header = header
        row = QHBoxLayout(header)
        row.setContentsMargins(20, 12, 18, 12)
        row.setSpacing(18)

        left = QVBoxLayout()
        left.setSpacing(1)
        # Izolacja: po arabsku nazwa lacinska w bloku od prawej ma zostac
        # w jednym kawalku (do 2.2.0 „@" z poczatku „@ BeatStamp" ladowal
        # na jej koncu). Marka NIE jest tlumaczona.
        title = label(rtl_block(ltr(__app_name__)), role='brand')
        left.addWidget(title)
        # Podpis i pastylka skracaja sie przy waskim oknie; zegar nie — patrz
        # `ElidedLabel`. W 2.2.0 przy minimalnej szerokosci Qt obcinal
        # wszystko naraz: poczatek pastylki i koncowke zegara.
        tagline = ElidedLabel(
            _('Proof that a file existed in time — without sending the file'))
        tagline.setObjectName('hint')
        tagline.set_hint(_('Only the SHA-256 digest, computed on this computer, '
                           'reaches the Sigelith register.'))
        left.addWidget(tagline)
        row.addLayout(left, 1)

        # Pastylka swiadkow: jedno spojrzenie mowi, czy dziennik sie zgadza.
        pill = QHBoxLayout()
        pill.setSpacing(6)
        self.witness_dot = PulseDot()
        # Skracany SRODEK: przy waskim oknie zostaje poczatek („Dziennik
        # sprawdzony") i koniec (numer punktu kontrolnego).
        self.witness_button = ElidedButton(elide=Qt.ElideMiddle)
        self.witness_button.setObjectName('ghost')
        self.witness_button.setCursor(Qt.PointingHandCursor)
        self.witness_button.set_hint(_(
            'The state of the public log as checked by this application. Click '
            'to see\nthe witnesses: checkpoints, Bitcoin, the bank and the '
            'independent copies.'))
        self.witness_button.clicked.connect(lambda: self.tabs.setCurrentIndex(3))
        pill.addWidget(self.witness_dot, 0, Qt.AlignVCenter)
        pill.addWidget(self.witness_button, 1, Qt.AlignVCenter)
        row.addLayout(pill, 1)
        row.addSpacing(8)

        self.clock = BeatClock()
        self.clock.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.clock.syncRequested.connect(self.sync_clock_interactive)
        row.addWidget(self.clock)
        return header

    def _build_progress(self) -> QWidget:
        wrapper = QWidget()
        row = QHBoxLayout(wrapper)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)

        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        self.progress.setFormat('%p%')
        self.progress.hide()

        self.progress_label = QLabel()
        self.progress_label.setObjectName('hint')
        self.progress_label.hide()

        self.cancel_button = QPushButton(_('Stop'))
        icons.apply(self.cancel_button, 'x-circle')
        self.cancel_button.setToolTip(_('Stops the current task (Esc)'))
        self.cancel_button.clicked.connect(self._cancel_task)
        self.cancel_button.hide()

        row.addWidget(self.progress_label)
        row.addWidget(self.progress, 1)
        row.addWidget(self.cancel_button)
        return wrapper

    # --- Karta wyniku --------------------------------------------------------

    def _result_card(self, *, with_note: bool) -> dict:
        """Karta wyniku — wspolna dla stemplowania i weryfikacji."""
        frame = card()
        outer = QVBoxLayout(frame)
        outer.setContentsMargins(20, 16, 20, 16)
        outer.setSpacing(10)

        top = QHBoxLayout()
        top.setSpacing(12)
        title = label(_('No result'), role='h2')
        title.setWordWrap(True)
        badge = StatusBadge()
        top.addWidget(title, 1)
        top.addWidget(badge, 0, Qt.AlignTop)
        outer.addLayout(top)

        description = label('', role='hint', wrap=True)
        outer.addWidget(description)

        path = ProofJourney()
        path.hide()
        outer.addWidget(path)
        outer.addWidget(divider())

        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(10)
        grid.setColumnMinimumWidth(0, 140)
        grid.setColumnStretch(1, 1)

        def key(text, tip=''):
            widget = label(text, role='hint', tooltip=tip)
            widget.setAlignment(Qt.AlignLeft | Qt.AlignTop)
            return widget

        digest = CopyField(
            _('not computed yet'),
            tooltip=_('The only information that reaches the Sigelith register'))
        grid.addWidget(key(_('SHA-256 digest:')), 0, 0)
        grid.addWidget(digest, 0, 1)

        moment = label('—', wrap=True, selectable=True)
        moment.setTextFormat(Qt.RichText)
        grid.addWidget(key(_('Timestamp:'), _(
            'Your local time, UTC and @beat — the same moment. Below: the two '
            'bounds\nthat do not depend on the Sigelith clock at all.')), 1, 0)
        grid.addWidget(moment, 1, 1)

        checks = label('—', role='hint', wrap=True)
        checks.setTextFormat(Qt.RichText)
        grid.addWidget(key(_('Local check:'), _(
            'What the application computed ITSELF, without trusting the server')), 2, 0)
        grid.addWidget(checks, 2, 1)

        widgets = {'frame': frame, 'title': title, 'badge': badge,
                   'description': description, 'journey': path, 'digest': digest,
                   'time': moment, 'checks': checks, 'grid': grid}
        if with_note:
            note = QLineEdit()
            note.setPlaceholderText(_('Add a note to this stamp — e.g. "client '
                                      'contract, signed version"'))
            note.setToolTip(_(
                'The note stays ONLY on this computer, in the local history.\n'
                'It is not sent to the register and does not reach the server.\n'
                'You can add or change it at any time — also later, in the '
                'History.'))
            note.setEnabled(False)
            note.editingFinished.connect(self._save_note_to_current)
            note.textEdited.connect(lambda _text: self._note_timer.start())
            note_hint = label('', role='faint')
            # Notatka ZARAZ pod wynikiem, nie na dole karty: dopisuje sie ja
            # tuz po stemplu, a przy mniejszym oknie dolna czesc karty jest
            # juz pod krawedzia.
            row = QHBoxLayout()
            row.setSpacing(18)
            note_key = key(_('Note:'), _('A description visible only to you'))
            note_key.setFixedWidth(140)
            row.addWidget(note_key, 0, Qt.AlignTop)
            box = QVBoxLayout()
            box.setSpacing(3)
            box.addWidget(note)
            box.addWidget(note_hint)
            row.addLayout(box, 1)
            outer.insertLayout(2, row)
            widgets['note'] = note
            widgets['note_hint'] = note_hint
        outer.addLayout(grid)
        return widgets

    # --- Zakladka: Stemplowanie ---------------------------------------------

    def _build_stamp_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 6, 4, 6)
        layout.setSpacing(14)

        self.drop_zone = DropZone(*_DROP_TEXTS(), icon_name='fingerprint')
        self.drop_zone.setMinimumHeight(170)
        self.drop_zone.setMaximumHeight(250)
        self.drop_zone.filesDropped.connect(self.stamp_files)
        self.drop_zone.browseRequested.connect(self.browse_files_to_stamp)
        layout.addWidget(self.drop_zone, 2)

        parts = self._result_card(with_note=True)
        self.stamp_result = parts['frame']
        self.result_title = parts['title']
        self.result_badge = parts['badge']
        self.result_description = parts['description']
        self.result_description.setText(
            _('Drag a file into the area above to give it a timestamp.'))
        self.result_journey = parts['journey']
        self.result_digest = parts['digest']
        self.result_time = parts['time']
        self.result_checks = parts['checks']
        self.note_input = parts['note']
        self.note_hint = parts['note_hint']

        self.button_pdf = self._action_button(
            _('PDF certificate'), self.save_certificate,
            _('Builds the certificate on this computer — it works without the '
              'internet too.\n'
              'It contains the digest, the time, the week root and a QR code '
              'for verification.'))
        self.button_bundle = self._action_button(
            _('Offline proof (.beatproof)'), self.save_bundle,
            _('Saves the proof in a form that can be checked WITHOUT this '
              'application\n'
              'and without access to sigelith.org: the digest, the inclusion '
              'path, the\nweek root and the Ed25519 signature in one JSON '
              'file.'))
        self.button_browser = self._action_button(
            _('Check in the browser'), self.open_in_browser,
            _('Opens the public verification page sigelith.org/proof\n'
              'with the digest filled in — an independent confirmation.'))
        self.button_details = self._action_button(
            _('Details…'), self.show_details,
            _('Everything about this proof: when, how far it has come and who '
              'confirms it'))
        for button in (self.button_pdf, self.button_bundle,
                       self.button_browser, self.button_details):
            button.setEnabled(False)
        self.button_pdf.setObjectName('primary')
        icons.apply(self.button_pdf, 'file-earmark-pdf', icons.ON_ACCENT)
        icons.apply(self.button_bundle, 'file-earmark-lock')
        icons.apply(self.button_browser, 'globe2')
        icons.apply(self.button_details, 'info-circle')
        parts['frame'].layout().addLayout(action_row(
            [self.button_pdf, self.button_bundle, self.button_browser,
             self.button_details]))
        layout.addWidget(self.stamp_result)
        layout.addStretch(1)
        return page

    @staticmethod
    def _action_button(text: str, slot, tooltip: str, *, elide: bool = False) -> QPushButton:
        """Przycisk czynnosci. `elide` — skraca tekst, gdy rzad sie nie miesci.

        Rzad pod Historia ma szesc przyciskow; po niemiecku przy minimalnej
        szerokosci okna ostatni z nich wychodzil poza okno.
        """
        if elide:
            button = ElidedButton(text)
            button.set_hint(tooltip)
        else:
            button = QPushButton(text)
            button.setToolTip(tooltip)
        button.clicked.connect(slot)
        return button

    # --- Zakladka: Weryfikacja ---------------------------------------------

    def _build_verify_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 6, 4, 6)
        layout.setSpacing(14)

        intro = label(
            _('Check whether a document already has a timestamp — and whether '
              'the proof is consistent. Verification records nothing and '
              'changes nothing.'),
            role='hint', wrap=True)
        layout.addWidget(intro)

        self.verify_drop = DropZone(
            _('Drag a file here to check it'),
            _('the digest will be computed locally and looked up in the '
              'register'), icon_name='shield-check')
        self.verify_drop.setMinimumHeight(130)
        self.verify_drop.filesDropped.connect(self._verify_dropped)
        self.verify_drop.browseRequested.connect(self.browse_file_to_verify)
        layout.addWidget(self.verify_drop)

        hash_row = QHBoxLayout()
        hash_row.setSpacing(10)
        self.verify_input = QLineEdit()
        self.verify_input.setObjectName('mono')
        self.verify_input.setPlaceholderText(
            _('…or paste a SHA-256 digest here (64 hex characters)'))
        self.verify_input.setToolTip(_(
            'You can check any digest — including one you did not stamp\n'
            'from this computer. Enter starts the check.'))
        self.verify_input.returnPressed.connect(self.verify_typed_hash)
        self.verify_input.textChanged.connect(self._update_verify_button)
        self.verify_button = QPushButton(_('Check digest'))
        self.verify_button.setObjectName('primary')
        self.verify_button.setToolTip(_(
            'Checks this digest and the answer locally: the inclusion path, '
            'the root\nsignature, the identity of the key and the path to the '
            'signed checkpoint.\nIn private mode the server is not even told '
            'which digest you check.'))
        self.verify_button.setEnabled(False)
        icons.apply(self.verify_button, 'search', icons.ON_ACCENT)
        self.verify_button.clicked.connect(self.verify_typed_hash)
        bundle_button = QPushButton(_('Load a .beatproof proof…'))
        bundle_button.setToolTip(_(
            'Checks a stand-alone proof file. The verification happens\n'
            'entirely locally — without connecting to anything.'))
        bundle_button.clicked.connect(self.check_bundle_file)
        icons.apply(bundle_button, 'folder2-open')
        hash_row.addWidget(self.verify_input, 1)
        hash_row.addWidget(self.verify_button)
        hash_row.addWidget(bundle_button)
        layout.addLayout(hash_row)

        parts = self._result_card(with_note=False)
        self.verify_title = parts['title']
        self.verify_badge = parts['badge']
        self.verify_description = parts['description']
        self.verify_description.setText(
            _('Drag a file in, paste a digest, or load a .beatproof file.'))
        self.verify_journey = parts['journey']
        self.verify_digest = parts['digest']
        self.verify_digest.set_value('')
        self.verify_time = parts['time']
        self.verify_checks = parts['checks']

        self.verify_pdf_button = self._action_button(
            _('PDF certificate'), self.save_verify_certificate,
            _('Builds a certificate for the checked digest'))
        self.verify_bundle_button = self._action_button(
            _('Offline proof (.beatproof)'), self.save_verify_bundle,
            _('Saves a stand-alone proof for the checked digest'))
        self.verify_ots_button = self._action_button(
            _('Download the .ots proof'), self.download_ots,
            _('The OpenTimestamps proof of the week — to be checked with an\n'
              'OpenTimestamps client, entirely outside Sigelith and outside '
              'this application.'))
        self.verify_details_button = self._action_button(
            _('Details…'), self.show_verify_details,
            _('Everything about this proof: when, how far it has come and who '
              'confirms it'))
        for button in (self.verify_pdf_button, self.verify_bundle_button,
                       self.verify_ots_button, self.verify_details_button):
            button.setEnabled(False)
        icons.apply(self.verify_pdf_button, 'file-earmark-pdf')
        icons.apply(self.verify_bundle_button, 'file-earmark-lock')
        icons.apply(self.verify_ots_button, 'currency-bitcoin')
        icons.apply(self.verify_details_button, 'info-circle')
        parts['frame'].layout().addLayout(action_row(
            [self.verify_pdf_button, self.verify_bundle_button,
             self.verify_ots_button, self.verify_details_button]))
        layout.addWidget(parts['frame'])
        layout.addStretch(1)
        return page

    # --- Zakladka: Historia -------------------------------------------------

    def _build_history_tab(self) -> QWidget:
        page = QWidget()
        page.setObjectName('page')
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 6, 4, 6)
        layout.setSpacing(12)

        controls = QHBoxLayout()
        controls.setSpacing(10)
        self.history_search = QLineEdit()
        self.history_search.setPlaceholderText(
            _('Search: file name, digest, note, week…'))
        self.history_search.setClearButtonEnabled(True)
        self.history_search.setToolTip(_(
            'Filters entries as you type. It also searches the full digest,\n'
            'so you can paste a whole hash.'))
        controls.addWidget(self.history_search, 1)

        self.history_level = QComboBox()
        self.history_level.addItem(_('All levels'), '')
        for level in (Level.ANCHORED, Level.SIGNED, Level.RECORDED):
            self.history_level.addItem(level.label, level.value)
        self.history_level.setToolTip(
            _('Show only entries at the selected proof stage'))
        controls.addWidget(self.history_level)

        refresh = QPushButton(_('Refresh statuses'))
        refresh.setToolTip(_(
            'A proof MATURES: a stamp from this week gets its signature once '
            'the\nweek closes, and the Bitcoin attestation a few hours later.\n'
            'While the program is open this happens by itself every 15 minutes;\n'
            'this button does it right now. (F5)'))
        refresh.clicked.connect(self.refresh_history_statuses)
        icons.apply(refresh, 'arrow-repeat')
        controls.addWidget(refresh)
        layout.addLayout(controls)

        self.history_model = HistoryModel()
        self.history_proxy = HistoryFilter()
        self.history_proxy.setSourceModel(self.history_model)
        self.history_search.textChanged.connect(self.history_proxy.set_text)
        self.history_level.currentIndexChanged.connect(
            lambda: self.history_proxy.set_level(str(self.history_level.currentData())))

        self.history_table = QTableView()
        self.history_table.setModel(self.history_proxy)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.history_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.history_table.setSortingEnabled(True)
        self.history_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.history_table.setShowGrid(False)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.verticalHeader().setDefaultSectionSize(34)
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents)
        self.history_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self._history_menu)
        self.history_table.doubleClicked.connect(lambda _: self.history_details())
        self.history_table.selectionModel().selectionChanged.connect(
            self._update_history_buttons)
        layout.addWidget(self.history_table, 1)

        self.history_buttons = {
            'pdf': self._action_button(
                _('PDF certificate'), self.history_certificate,
                _('Issues a certificate for the selected entry')),
            'bundle': self._action_button(
                _('Offline proof'), self.history_bundle,
                _('Saves a stand-alone .beatproof proof')),
            'details': self._action_button(
                _('Details…'), self.history_details,
                _('Everything about the selected entry, in plain words — and the '
                  'note to edit')),
            'copy': self._action_button(
                _('Copy digest'), self.history_copy_digest,
                _('Copies the full SHA-256 digest to the clipboard')),
            'delete': self._action_button(
                _('Remove from history'), self.history_delete,
                _('Removes the entry from this list ONLY.\n'
                  'The stamp in the public Sigelith register\n'
                  'stays — it cannot be undone.')),
        }
        for button in self.history_buttons.values():
            button.setEnabled(False)
            # Szesc przyciskow w jednym rzedzie: nieco mniejsze marginesy,
            # zeby po niemiecku miescily sie przy minimalnej szerokosci okna.
            button.setObjectName('compact')
        for key, name in (('pdf', 'file-earmark-pdf'), ('bundle', 'file-earmark-lock'),
                          ('details', 'info-circle'), ('copy', 'copy'),
                          ('delete', 'trash3')):
            icons.apply(self.history_buttons[key], name)
        export = QPushButton(_('Export…'))
        export.setObjectName('compact')
        icons.apply(export, 'download')
        export.setToolTip(_('Saves the history to a CSV (Excel) or JSON file'))
        export.clicked.connect(self.export_history)
        buttons = action_row(list(self.history_buttons.values()))
        buttons.addWidget(export)
        layout.addLayout(buttons)

        self.history_summary = label('', role='faint')
        layout.addWidget(self.history_summary)
        return page

    # --- Menu ---------------------------------------------------------------

    def _site(self, path: str) -> str:
        """Adres strony serwisu (sigelith.org) w jezyku interfejsu (jesli taka jest)."""
        return site_url(path, current_language())

    def _build_menu(self) -> None:
        bar = self.menuBar()

        # Akcelerator (`&`) jest CZESCIA tlumaczenia: kazdy jezyk musi
        # postawic go przy innej literze i nie moze go zgubic.
        file_menu = bar.addMenu(_('&File'))
        self._add_action(file_menu, _('Stamp files…'), self.browse_files_to_stamp,
                         QKeySequence.Open, _('Choose files to stamp'), 'fingerprint')
        self._add_action(file_menu, _('Verify a file…'), self.browse_file_to_verify,
                         QKeySequence('Ctrl+Shift+O'),
                         _('Check whether a file already has a stamp'), 'shield-check')
        self._add_action(file_menu, _('Load a .beatproof proof…'),
                         self.check_bundle_file, QKeySequence('Ctrl+B'),
                         _('Check a stand-alone proof — without the network'),
                         'folder2-open')
        file_menu.addSeparator()
        self._add_action(file_menu, _('Send files with proof of delivery…'),
                         lambda: self.handover.send(), QKeySequence('Ctrl+Shift+H'),
                         _('Sigelith Handover: the recipient confirms receipt with their key'),
                         'file-earmark-lock')
        self._add_action(file_menu, _('Open a Handover package…'),
                         lambda: self.handover.open_package(), QKeySequence(),
                         _('A .sigelith-handover file someone sent you'), 'download')
        file_menu.addSeparator()
        self._add_action(file_menu, _('Export history…'), self.export_history,
                         QKeySequence('Ctrl+E'),
                         _('Save the history to CSV or JSON'), 'download')
        file_menu.addSeparator()
        self._add_action(file_menu, _('Quit'), self.close, QKeySequence.Quit, '',
                         'box-arrow-right')

        tools_menu = bar.addMenu(_('&Tools'))
        self._add_action(tools_menu, _('Refresh proof statuses'),
                         self.refresh_history_statuses, QKeySequence('F5'),
                         _('Check whether the proofs have matured'), 'arrow-repeat')
        self._add_action(tools_menu, _('Synchronise the clock'),
                         self.sync_clock_interactive, QKeySequence('F6'),
                         _('Measure the clock drift of this computer'),
                         'arrow-clockwise')
        self._add_action(tools_menu, _('Check the service status'), self.check_health,
                         QKeySequence('F7'), _('State of the Sigelith server'),
                         'activity')
        self._add_action(tools_menu, _('Check the witnesses now'),
                         lambda: self.check_witnesses(True), QKeySequence('F8'),
                         _('Checkpoints, their chain and the independent copies'),
                         'people')
        tools_menu.addSeparator()
        self._add_action(tools_menu, _('Settings…'), self.open_settings,
                         QKeySequence('Ctrl+,'),
                         _('Connection, witnesses, trust, behaviour'), 'gear')

        help_menu = bar.addMenu(_('Hel&p'))
        self._add_action(help_menu, _('About'), self.show_about,
                         QKeySequence('F1'), '', 'info-circle')
        # Strony w jezyku interfejsu — do 2.1 „Jak to dziala" prowadzilo na
        # angielska strone, choc program mowil po polsku.
        self._site_action(help_menu, _('How it works — sigelith.org'), 'proof',
                          _('The public verification page'))
        self._site_action(help_menu, _('What a timestamp proves'), 'evidence',
                          _('What the proof says in a dispute — and what it does '
                            'not'), 'patch-question')
        self._site_action(help_menu, _('The public log and its checkpoints'),
                          'checkpoints', _('The archive of signed checkpoints'),
                          'journal-check')
        # Manifest w wersji 2 (Sigelith, 2026-09-28); wersja 1 („The BeatTime
        # Manifesto”, ostemplowana #174) zostaje dostepna na stronie manifestu.
        self._site_action(help_menu, _('The Sigelith manifesto'), 'manifesto',
                          _('Why Sigelith exists'), 'file-earmark-text')
        self._add_action(help_menu, _('Thank you to the supporters…'),
                         self.show_thanks, None,
                         # Wspierajacy wspieraja Sigelith (warunki wsparcia
                         # od 2026-09-27); liste podaje serwer Sigelith.
                         _('People who support Sigelith — the list is loaded '
                           'from sigelith.org'), 'heart')
        help_menu.addSeparator()
        # Impressum i ochrona danych sa TUTAJ, a nie tylko w oknie
        # „O programie": § 5 DDG wymaga, zeby impressum bylo osiagalne
        # bezposrednio, w najwyzej dwoch kliknieciach.
        self._legal_action(help_menu, _('Legal notice (Impressum)'), IMPRESSUM_URL,
                           'building')
        self._legal_action(help_menu, _('Privacy policy'),
                           privacy_policy_url(current_language()), 'shield-lock')
        help_menu.addSeparator()
        self._add_action(help_menu, _('Show the event log'), self.show_log,
                         None, _('A record of errors — useful when reporting a '
                                 'problem'), 'list-ul')
        self._add_action(help_menu, data_dir_button_text(), lambda: open_data_dir(),
                         None, data_dir_tooltip(), 'folder')

        escape = QAction(self)
        escape.setShortcut(QKeySequence('Esc'))
        escape.triggered.connect(self._cancel_task)
        self.addAction(escape)

    def _site_action(self, menu: QMenu, text: str, page: str, tip: str,
                     icon_name: str = 'globe2') -> QAction:
        url = self._site(page)
        action = self._add_action(menu, text, lambda: open_url(url), None, tip,
                                  icon_name)
        action.setData(url)
        return action

    def _legal_action(self, menu: QMenu, text: str, url: str,
                      icon_name: str = '') -> QAction:
        """Pozycja menu otwierajaca dokument prawny w przegladarce.

        Adres siedzi takze w `QAction.data()` — dzieki temu da sie sprawdzic
        testem, DOKAD naprawde prowadzi pozycja menu.
        """
        action = self._add_action(
            menu, text, lambda: open_url(url), None,
            _('Opens in the browser: %(url)s') % {'url': url}, icon_name)
        action.setData(url)
        return action

    def _add_action(self, menu: QMenu, text: str, slot, shortcut, tip: str,
                    icon_name: str = '') -> QAction:
        action = QAction(text, self)
        if icon_name:
            icons.apply(action, icon_name)
        if shortcut is not None:
            action.setShortcut(shortcut)
        if tip:
            action.setStatusTip(tip)
            action.setToolTip(tip)
        action.triggered.connect(slot)
        menu.addAction(action)
        return action

    # --- Uruchamianie zadan -------------------------------------------------

    def _busy(self) -> bool:
        return self._active_task is not None

    def _start(self, task: workers.Task, on_result, *, label_text: str = '') -> bool:
        """Uruchamia zadanie, o ile zadne inne nie trwa."""
        if self._closing:
            return False
        if self._busy():
            self.statusBar().showMessage(_(
                'Wait for the current task to finish, or stop it (Esc).'), 4000)
            return False
        self._active_task = task
        self._set_busy_ui(True, label_text)
        task.signals.progress.connect(self._on_progress)
        task.signals.message.connect(self._on_message)
        task.signals.failed.connect(self._on_failed)
        task.signals.finished.connect(on_result)
        task.signals.done.connect(self._on_task_done)
        self._pause_background()
        workers.launch(self.pool, task, workers.PRIORITY_USER)
        return True

    def _set_busy_ui(self, busy: bool, label_text: str = '') -> None:
        self.drop_zone.set_busy(busy)
        self.verify_drop.set_busy(busy)
        self.progress.setVisible(busy)
        self.progress_label.setVisible(busy)
        self.cancel_button.setVisible(busy)
        if busy:
            self.progress.setRange(0, 0)      # nieokreslony do pierwszego raportu
            self.progress_label.setText(label_text or _('Working…'))
        else:
            self.progress.reset()

    def _on_progress(self, done: int, total: int, text: str) -> None:
        if total > 0:
            self.progress.setRange(0, 100)
            self.progress.setValue(int(done * 100 / total))
        else:
            self.progress.setRange(0, 0)
        if text:
            self.progress_label.setText(text)

    def _on_message(self, text: str) -> None:
        self.progress_label.setText(text)
        self.statusBar().showMessage(text, 6000)

    def _on_failed(self, message: str) -> None:
        # Do dziennika trafia KAZDE niepowodzenie — przy uruchomieniu bez
        # konsoli (wersja .exe) okienko bylo jedynym, ulotnym sladem.
        log.warning('zadanie nieudane: %s', message)
        self.statusBar().showMessage(_('The task ended with an error.'), 6000)
        # Zwykly tekst: komunikat bywa trescia odpowiedzi serwera (pole
        # `error`/`detail`), a QMessageBox domyslnie zgaduje HTML.
        box = QMessageBox(QMessageBox.Warning, _('It did not work'), message,
                          QMessageBox.Ok, self)
        box.setTextFormat(Qt.PlainText)
        box.exec()

    def _on_task_done(self) -> None:
        self._active_task = None
        self._set_busy_ui(False)
        self._resume_background()

    # --- Praca w tle a czynnosci uzytkownika ---------------------------------

    def _background_tasks(self) -> list[workers.Task]:
        return [t for t in (self._witness_task, self._quiet_task, self._sync_task,
                            self._onion_task,
                            self.handover.background_task())
                if t is not None]

    def _pause_background(self) -> None:
        """Czynnosc uzytkownika ma pierwszenstwo przed kontrola w tle.

        Pula ma jeden watek (patrz konstruktor), wiec plik upuszczony tuz po
        starcie czekal za calym przebiegiem swiadka — w sieci z zepsutym IPv6
        ponad 40 s „Pracuje…" (diagnostyka 2026-09-27). Przebieg w tle
        przerywamy: zatrzymuje sie przy najblizszym sprawdzeniu `cancelled`,
        a po czynnosci uzytkownika rusza od nowa (`_resume_background`).
        Kontroli uruchomionej recznie („Sprawdz teraz") nie ruszamy.
        """
        paused = False
        if self._witness_task is not None and not self._witness_interactive:
            self._witness_task.cancel()
            paused = True
        if self._quiet_task is not None:
            self._quiet_task.cancel()
            paused = True
        if paused:
            self._background_paused = True
            log.info('kontrola w tle wstrzymana — pierwszenstwo ma czynnosc uzytkownika')

    def _resume_background(self) -> None:
        if not self._background_paused or self._closing:
            return
        self._background_paused = False
        QTimer.singleShot(5000, self._background_cycle)

    def _next_witness_interval(self) -> int:
        return int(WITNESS_INTERVAL_MS * random.uniform(1 - WITNESS_JITTER, 1 + WITNESS_JITTER))

    def _cancel_task(self) -> None:
        if self._active_task is not None:
            self._active_task.cancel()
            self.progress_label.setText(_('Stopping…'))
            self.statusBar().showMessage(_('Task stopped.'), 4000)

    # --- Znakowanie ---------------------------------------------------------

    def browse_files_to_stamp(self) -> None:
        paths, _filter = QFileDialog.getOpenFileNames(
            self, _('Choose files to stamp'),
            self.settings.last_directory or str(Path.home()))
        if paths:
            self.stamp_files([Path(p) for p in paths])

    def stamp_files(self, paths: list[Path]) -> None:
        paths = [Path(p) for p in paths if Path(p).is_file()]
        if not paths:
            QMessageBox.information(
                self, _('Nothing to stamp'),
                _('No file was found. Folders are expanded automatically — '
                  'perhaps the chosen folder is empty.'))
            return
        if len(paths) > 20 and QMessageBox.question(
                self, _('A large number of files'),
                _('You are about to stamp <b>%(files)s</b>.<br><br>'
                  'The server accepts 20 stamps per minute, so the operation '
                  'will take about %(minutes)s. Continue?')
                % {'files': plural.files(len(paths)),
                   'minutes': plural.minutes(len(paths) // 20 + 1)},
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes) != QMessageBox.Yes:
            return

        # Notatka poprzedniego stempla, jesli ktos ja jeszcze pisal.
        self._save_note_to_current()
        self.settings.last_directory = str(paths[0].parent)
        self.tabs.setCurrentIndex(0)
        self.drop_zone.set_texts(
            _('Working…'),
            _('%(files)s queued') % {'files': plural.files(len(paths))})
        task = workers.StampFilesTask(
            paths, self.client, key_override=self.settings.key_override,
            witness_state=self.witness_state)
        if not self._start(task, self._on_stamped, label_text=_('Preparing…')):
            self._reset_drop_texts()

    def _on_stamped(self, outcome: workers.BatchOutcome) -> None:
        self._reset_drop_texts()

        # `merge`, a nie petla `add`/`replace`: KOMPLET stempli ma wejsc do
        # pamieci, zanim cokolwiek dotknie dysku (patrz `History.merge`).
        self._store(lambda: self.history.merge(
            [item.entry for item in outcome.successes]), self.history.save)
        self._refresh_history_view()

        if outcome.successes:
            last = outcome.successes[-1]
            self.current_result = last.result
            self.current_entry = self.history.find(last.entry.digest) or last.entry
            self._current_batch = [self.history.find(item.entry.digest) or item.entry
                                   for item in outcome.successes]
            self._current_batch_exportable = [
                self.history.find(item.entry.digest) or item.entry
                for item in outcome.successes if not item.result.problems]
            self._show_result(last.result, self.current_entry,
                              newly_created=last.newly_created,
                              count=len(outcome.successes))
            self._show_note_for_current()
        if outcome.failures:
            self._report_failures(outcome.failures)
        elif outcome.successes:
            count = len(outcome.successes)
            self.statusBar().showMessage(
                _('Done — %(files)s stamped.') % {'files': plural.files(count)}
                if count > 1 else _('Done — the file has a timestamp.'), 8000)

    def _reset_drop_texts(self) -> None:
        self.drop_zone.set_texts(*_DROP_TEXTS())

    def _report_failures(self, failures: list[tuple[str, str]]) -> None:
        for name, reason in failures:
            log.warning('nie ostemplowano %s: %s', name, reason)
        shown = failures[:8]
        lines = '<br>'.join(f'• <b>{html.escape(name)}</b> — {html.escape(reason)}'
                            for name, reason in shown)
        if len(failures) > len(shown):
            lines += '<br>' + _('…and %(count)s more.') % {
                'count': len(failures) - len(shown)}
        QMessageBox.warning(
            self, _('Some files did not work out'),
            _('%(files)s could not be stamped:<br><br>%(list)s')
            % {'files': plural.files(len(failures)), 'list': lines})

    def _show_result(self, result: VerificationResult, entry, *,
                     newly_created: bool, count: int = 1) -> None:
        if not result.found:
            self.result_title.setText(_('Not registered'))
            self.result_badge.show_state('error', _('Error'))
            self.result_description.setText(
                _('The register did not confirm the write. Try again.'))
            self.result_journey.hide()
            return

        if result.problems:
            self.result_title.setText(_('Inconsistent proof'))
            self.result_badge.show_state('error', _('Warning'),
                                         '\n'.join(result.problems))
            self.result_description.setText(
                '<b>' + _('The server answer did not pass the local check.')
                + '</b><br>' + _problems_html(result.problems))
        elif result.needs_refresh:
            self.result_title.setText(_('The proof needs refreshing'))
            self.result_badge.show_state('warn', _('Retired key'),
                                         '\n'.join(result.warnings))
            self.result_description.setText(_retired_html(result.warnings))
        else:
            headline = (_('Timestamp granted') if newly_created
                        else _('This file had already been stamped'))
            if count > 1:
                headline += ' ' + _('(%(count)s files in this batch)') % {
                    'count': count}
            self.result_title.setText(headline)
            kind = 'ok' if result.level.order >= Level.SIGNED.order else 'info'
            self.result_badge.show_state(kind, result.level.label,
                                         result.level.description)
            # NIE `_('Note:')`: ten sam msgid jest etykieta POLA notatki.
            # Po niemiecku „Notiz:" to pole uzytkownika, a tu potrzebne
            # jest „Hinweis:".
            extra = ('' if newly_created else
                     '<br><br><b>' + _('Please note:') + '</b> '
                     + _('the ORIGINAL timestamp was returned. The first stamp '
                         'wins — the date on an already registered document '
                         'cannot be refreshed.'))
            if count > 1:
                # Szczegoly ponizej (skrot, czas, kontrole) sa jednego pliku —
                # ostatniego. Przyciski obejmuja kazdy plik serii.
                name = html.escape(str(getattr(entry, 'file_name', '') or ''))
                extra += '<br><br>' + _(
                    'The details below are for the last file of this batch, '
                    '<b>%(name)s</b>. The buttons save a certificate and a proof '
                    'for each file.') % {'name': name}
            self.result_description.setText(result.level.description + extra)

        self.result_digest.set_value(result.digest)
        self.result_time.setText(_time_html(result, self._result_week_note(result)))
        self.result_checks.setText(self._checks_text(result))
        self.result_journey.set_steps(journey.journey_steps(result, self.witness_state))
        self.result_journey.show()
        # Certyfikat i .beatproof tylko dla dowodu bez zastrzezen — dokument
        # wystawiony z odpowiedzi odrzuconej przez kontrole lokalna
        # wygladalby jak dowod, a nim nie jest. Przy serii: dla kazdego pliku,
        # ktorego dowod przeszedl kontrole.
        batch = self._batch_targets() if count > 1 else []
        self._label_result_buttons(len(batch))
        self._enable_result_buttons(
            True, exportable=bool(batch) if count > 1 else not result.problems)

    def _batch_targets(self) -> list:
        """Wpisy serii do certyfikatow i .beatproof — pusta lista przy jednym pliku."""
        return self._current_batch_exportable if len(self._current_batch) > 1 else []

    def _label_result_buttons(self, count: int) -> None:
        """Przy serii plikow przyciski mowia, ze obejmuja KAZDY plik.

        Do 3.0.1 po upuszczeniu np. pieciu plikow certyfikat powstawal tylko
        dla ostatniego — nic nie mowilo, ze pozostale cztery trzeba wystawic
        z Historii.
        """
        if count > 1:
            self.button_pdf.setText(_('PDF certificates (%(count)s)') % {'count': count})
            self.button_bundle.setText(_('Offline proofs (%(count)s)') % {'count': count})
        else:
            self.button_pdf.setText(_('PDF certificate'))
            self.button_bundle.setText(_('Offline proof (.beatproof)'))

    @staticmethod
    def _result_week_note(result: VerificationResult) -> str:
        """Dopisek o tygodniu: potwierdzony tylko przy pelnej kontroli."""
        if result.problems:
            return ''
        return _week_note(result.week, result.level.order >= Level.SIGNED.order)

    @staticmethod
    def _checks_text(result: VerificationResult) -> str:
        parts = []
        if result.inclusion_checked:
            parts.append('✓ ' + _('the inclusion path matches the week root')
                         if result.inclusion_ok else
                         '✗ ' + _('the inclusion path does NOT lead to the root'))
        else:
            parts.append('• ' + _('inclusion path — the week is still open'))
        if result.signature_checked:
            parts.append('✓ ' + _('the Ed25519 root signature is valid')
                         if result.signature_ok
                         else '✗ ' + _('the Ed25519 signature is invalid'))
            parts.append(_key_line(result.signer_status))
        else:
            parts.append('• ' + _('root signature — it arrives once the week '
                                  'closes'))
        cp = result.checkpoint or {}
        if cp.get('verified'):
            parts.append('✓ ' + _('the path to signed checkpoint #%(n)s checks out '
                                  '— against the checkpoint file this application '
                                  'verified') % {'n': cp.get('n')})
        elif cp.get('n'):
            parts.append('✗ ' + _('the path to checkpoint #%(n)s does NOT check out')
                         % {'n': cp.get('n')})
        else:
            parts.append('• ' + _('log checkpoint — the next daily one will contain '
                                  'this entry'))
        # Nazwa banku przychodzi z sieci, a etykieta interpretuje HTML —
        # escapujemy KAZDA wartosc, takze nasze wlasne ostrzezenia.
        parts.append('• ' + _('anchor (according to the register): %(anchors)s')
                     % {'anchors': html.escape(result.anchor_summary)})
        if result.witness_mode == witness.MODE_PRIVATE:
            parts.append('• ' + _('checked privately — the server was not told which '
                                  'digest this is'))
        for warning in result.warnings:
            parts.append(f'⚠ {html.escape(warning)}')
        return '<br>'.join(parts)

    def _enable_result_buttons(self, enabled: bool, *, exportable: bool = True) -> None:
        for button in (self.button_browser, self.button_details):
            button.setEnabled(enabled)
        for button in (self.button_pdf, self.button_bundle):
            button.setEnabled(enabled and exportable)

    # --- Notatka --------------------------------------------------------------

    def _show_note_for_current(self) -> None:
        """Pole notatki po stemplu: aktywne, z tym, co juz jest w historii.

        Do 2.1 pole stalo NAD wynikiem i dzialalo tylko wtedy, gdy wpisalo sie
        notatke PRZED przeciagnieciem pliku — a przeciaga sie od razu. Teraz
        notatke dopisuje sie po stemplu, w karcie wyniku, a w Historii mozna
        ja zmienic w kazdej chwili.
        """
        entry = self.current_entry
        self.note_input.setEnabled(entry is not None)
        self.note_input.setText(str(getattr(entry, 'note', '') or ''))
        count = len(self._current_batch)
        if entry is None:
            self.note_hint.setText('')
        elif count > 1:
            self.note_hint.setText(_('The note applies to all %(count)s files of '
                                     'this batch.') % {'count': count})
        else:
            self.note_hint.setText(_('Saved automatically · visible only on this '
                                     'computer'))

    def _save_note_to_current(self) -> None:
        """Notatka zapisuje sie sama — bez osobnego przycisku "Zapisz"."""
        self._note_timer.stop()
        targets = self._current_batch or ([self.current_entry] if self.current_entry else [])
        if not targets:
            return
        note = self.note_input.text().strip()
        changed = False
        for entry in targets:
            existing = self.history.find(entry.digest)
            for item in {id(x): x for x in (entry, existing) if x is not None}.values():
                if item.note != note:
                    item.note = note
                    changed = True
        if not changed:
            return
        if not self._store(self.history.save):
            return
        self._refresh_history_view()
        self.statusBar().showMessage(_('Note saved.'), 3000)

    def _set_note(self, entry, note: str) -> None:
        """Notatka zmieniona w oknie szczegolow."""
        if entry is None or entry.note == note:
            return
        entry.note = note
        existing = self.history.find(entry.digest)
        if existing is not None and existing is not entry:
            existing.note = note
        if self._store(self.history.save):
            self._refresh_history_view()
            if self.current_entry is not None and self.current_entry.digest == entry.digest:
                self.note_input.setText(note)
            self.statusBar().showMessage(_('Note saved.'), 3000)

    # --- Weryfikacja --------------------------------------------------------

    def _update_verify_button(self, text: str) -> None:
        self.verify_button.setEnabled(merkle.is_digest(text))

    def browse_file_to_verify(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self, _('Choose a file to check'),
            self.settings.last_directory or str(Path.home()))
        if path:
            self._verify_dropped([Path(path)])

    def _verify_dropped(self, paths: list[Path]) -> None:
        if not paths:
            return
        if len(paths) > 1:
            self.statusBar().showMessage(
                _('Checking the first of %(count)s files — verification works '
                  'on one file at a time.') % {'count': len(paths)}, 6000)
        path = Path(paths[0])
        self.tabs.setCurrentIndex(1)
        task = workers.HashFileTask(path)
        self._start(task, lambda fd: self._verify_digest(fd.digest, source=path.name),
                    label_text=_('Computing digest: %(name)s') % {'name': path.name})

    def verify_typed_hash(self) -> None:
        digest = self.verify_input.text().strip().lower()
        if not merkle.is_digest(digest):
            QMessageBox.information(
                self, _('Invalid digest'),
                _('A SHA-256 digest is exactly <b>64 hexadecimal characters</b> '
                  '(digits 0-9 and letters a-f).<br><br>'
                  '%(typed)s were entered.')
                % {'typed': plural.characters(len(digest))})
            return
        self._verify_digest(digest)

    def _verify_digest(self, digest: str, source: str = '') -> None:
        self.verify_input.setText(digest)
        self._verify_source_name = source
        task = workers.VerifyDigestTask(
            digest, self.client, key_override=self.settings.key_override,
            mode=self.settings.witness_mode, witness_state=self.witness_state,
            mirror=self.log_mirror)
        self._start(task, self._on_verified,
                    label_text=_('Querying the register…'))

    def _on_verified(self, result: VerificationResult) -> None:
        self.verify_result = result
        self.verify_digest.set_value(result.digest)
        source = getattr(self, '_verify_source_name', '')

        if not result.found:
            self.verify_title.setText(_('No stamp'))
            self.verify_badge.show_state('warn', _('Not found'))
            self.verify_description.setText(
                _('This digest <b>does not appear</b> in the Sigelith '
                  'register.<br><br>')
                + (_('The file was never stamped, or it was changed after '
                     'stamping — even a single changed byte gives a completely '
                     'different digest.')
                   if source else
                   _('Check that the digest was pasted in full.')))
            self.verify_time.setText('—')
            self.verify_checks.setText('—')
            self.verify_journey.hide()
            self._enable_verify_buttons(False)
            return

        if result.problems:
            self.verify_title.setText(_('Inconsistent proof'))
            self.verify_badge.show_state('error', _('Warning'),
                                         '\n'.join(result.problems))
            self.verify_description.setText(
                '<b>' + _('The proof data did not pass the local check:')
                + '</b><br>' + _problems_html(result.problems))
        elif result.needs_refresh:
            self.verify_title.setText(_('The proof needs refreshing')
                                      + (f' — {source}' if source else ''))
            self.verify_badge.show_state('warn', _('Retired key'),
                                         '\n'.join(result.warnings))
            self.verify_description.setText(_retired_html(result.warnings))
        else:
            self.verify_title.setText(
                _('Confirmed') + (f' — {source}' if source else ''))
            kind = 'ok' if result.level.order >= Level.SIGNED.order else 'info'
            self.verify_badge.show_state(kind, result.level.label, result.level.description)
            self.verify_description.setText(result.level.description)

        self.verify_time.setText(_time_html(result, self._result_week_note(result)))
        self.verify_checks.setText(self._checks_text(result))
        self.verify_journey.set_steps(journey.journey_steps(result, self.witness_state))
        self.verify_journey.show()
        self._enable_verify_buttons(True, exportable=not result.problems)
        self.verify_ots_button.setEnabled(bool(result.week) and result.ots_status != 'none')

    def _enable_verify_buttons(self, enabled: bool, *, exportable: bool = True) -> None:
        self.verify_details_button.setEnabled(enabled)
        for button in (self.verify_pdf_button, self.verify_bundle_button):
            button.setEnabled(enabled and exportable)
        self.verify_ots_button.setEnabled(False)

    def check_bundle_file(self) -> None:
        # Dowody plików z kopii Sigelith Backup (.sigelith-proof) w tym samym filtrze —
        # dopisane do wzorca, żeby nie zmieniać przetłumaczonego napisu.
        filters = _('Sigelith proof (*.beatproof);;JSON files (*.json);;All files (*)').replace(
            '*.beatproof)', f'*.beatproof *{fileproof.EXTENSION})', 1)
        path, _filter = QFileDialog.getOpenFileName(
            self, _('Choose a proof file'),
            self.settings.last_directory or str(Path.home()), filters)
        if path:
            self.check_bundle_path(Path(path))

    def check_bundle_path(self, path: Path) -> None:
        """Sprawdza wskazany plik dowodu — z przycisku, z menu albo z dwukliku w Eksploratorze."""
        answer = QMessageBox.question(
            self, _('Point to the document?'),
            _('Do you also want to point to the <b>document</b> this proof is '
              'about?<br><br>'
              'Without the document we check only whether the proof itself is '
              'consistent. With the document we additionally check whether the '
              'proof really is about <i>this</i> file and whether the file has '
              'been changed.'),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        document = None
        if answer == QMessageBox.Yes:
            doc_path, _selected = QFileDialog.getOpenFileName(
                self, _('Choose the document'), str(Path(path).parent))
            if doc_path:
                document = Path(doc_path)
        self.tabs.setCurrentIndex(1)
        task = workers.CheckBundleTask(
            path, document, key_override=self.settings.key_override)
        self._start(task, self._on_bundle_checked,
                    label_text=_('Checking the proof…'))

    def _on_bundle_checked(self, outcome: workers.BundleOutcome) -> None:
        check = outcome.check
        self.verify_result = None
        data = outcome.data
        backup_file = None
        if data.get('format') == fileproof.FORMAT:
            # Dowód pliku z kopii: czas i pola zaufania niesie osadzony beatproof-v1.
            backup_file = fileproof.file_info(data)
            inner = data.get('beatproof')
            data = inner if isinstance(inner, dict) else {}
        # Do okna „Szczegoly" idzie widok z polami zaufania z TEGO sprawdzenia,
        # a nie surowy plik — patrz `bundle.verified_view`.
        self._bundle_data = bundle.verified_view(data, check)
        if backup_file is not None:
            self._bundle_data['file_name'] = str(backup_file.get('name') or '')
            self._bundle_data['digest'] = check.digest
        self.verify_digest.set_value(check.digest)
        self.verify_input.setText(check.digest)
        self.verify_journey.hide()

        lines = []
        if check.file_matches is True:
            lines.append('✓ ' + _('the document digest matches the proof'))
        elif check.file_matches is False:
            lines.append('✗ ' + _('the document digest does NOT match the proof'))
        else:
            lines.append('• ' + _('no document was pointed to — only the proof '
                                  'itself was checked'))
        lines.append('✓ ' + _('the inclusion path leads to the week root')
                     if check.inclusion_ok
                     else '✗ ' + _('the inclusion path does not match'))
        lines.append('✓ ' + _('the Ed25519 root signature is valid')
                     if check.signature_ok
                     else '✗ ' + _('no valid root signature'))
        if check.signer_status:
            lines.append(_key_line(check.signer_status))
        if check.checkpoint_ok is True:
            lines.append('✓ ' + _('the proof carries signed checkpoint #%(n)s and the '
                                  'path of the entry to its root checks out')
                         % {'n': check.checkpoint_n})
        elif check.checkpoint_ok is False:
            lines.append('✗ ' + _('the checkpoint in the proof does not check out'))
        for warning in check.warnings:
            lines.append(f'⚠ {html.escape(warning)}')
        if backup_file is not None and not check.problems:
            lines.append('✓ ' + html.escape(_(
                'Sigelith Backup file proof: %(name)s — the path in the backup tree '
                'leads to the sealed root.') % {'name': str(backup_file.get('path')
                                                          or backup_file.get('name') or '')}))
        for note in check.notes:
            lines.append(f'• {html.escape(note)}')
        self.verify_checks.setText('<br>'.join(lines))

        # Tresc pliku .beatproof pochodzi OD KOGOS INNEGO — idzie przez ten
        # sam bezpieczny skladacz co reszta.
        # Bez granic czasu: w pliku .beatproof to niepodpisane twierdzenie,
        # a stalo obok „Zweryfikowano offline" (fuzzing 2026-09-27).
        self.verify_time.setText(_time_html(
            _DictView(data), '' if check.problems else _week_note(check.week, check.ok),
            with_bounds=False))

        if check.ok:
            self.verify_title.setText(_('Proof confirmed — %(name)s')
                                      % {'name': outcome.path.name})
            self.verify_badge.show_state('ok', _('Verified offline'))
            self.verify_description.setText(_(
                'The proof was checked <b>entirely locally</b> — without '
                'connecting to sigelith.org and without trusting anyone. The '
                'inclusion path, the root signature, the identity of the key '
                'and the week of the stamp all add up. The signature confirms '
                'that the document existed no later than the end of the week; '
                'the exact moment is given by the register.'))
        elif check.problems:
            self.verify_title.setText(_('Inconsistent proof'))
            self.verify_badge.show_state('error', _('Rejected'),
                                         '\n'.join(check.problems))
            self.verify_description.setText(_problems_html(check.problems))
        elif check.needs_refresh:
            self.verify_title.setText(_('The proof needs refreshing — %(name)s')
                                      % {'name': outcome.path.name})
            self.verify_badge.show_state('warn', _('Retired key'),
                                         '\n'.join(check.warnings))
            self.verify_description.setText(_retired_html(check.warnings))
        else:
            self.verify_title.setText(_('Incomplete proof'))
            self.verify_badge.show_state('warn', _('Incomplete'))
            self.verify_description.setText(_(
                'The proof is consistent but not closed yet — it was exported '
                'before the week ended. Check the digest in the register (the '
                '<b>Check digest</b> button) and export the proof again.'))
        self._enable_verify_buttons(False)
        self.verify_details_button.setEnabled(True)

    # --- Zapis wynikow ------------------------------------------------------

    def _choose_save_path(self, title: str, default_name: str, filters: str) -> Path | None:
        # Proponowana nazwa NIGDY nie wskazuje istniejacego pliku: przy
        # zajetej nazwie dostaje „(2)". Do 2.1 drugi certyfikat tego samego
        # dokumentu zastepowal pierwszy, jesli ktos przeoczyl pytanie.
        start = naming.unique_path(
            Path(self.settings.last_directory or str(Path.home())) / default_name)
        path, _filter = QFileDialog.getSaveFileName(self, title, str(start), filters)
        if not path:
            return None
        target = Path(path)
        # QFileDialog pyta o nadpisanie samo, ale tylko gdy uzytkownik wpisze
        # nazwe recznie. Sprawdzamy jeszcze raz.
        if self.settings.confirm_overwrite and target.exists():
            if QMessageBox.question(
                    self, _('The file already exists'),
                    _('The file <b>%(name)s</b> already exists in this '
                      'folder.<br><br>Overwrite it?') % {'name': html.escape(target.name)},
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No) != QMessageBox.Yes:
                return None
        self.settings.last_directory = str(target.parent)
        return target

    def _name_parts(self) -> dict:
        return {'source': self.settings.name_cert_after_source,
                'moment': self.settings.cert_name_moment,
                'beat': self.settings.cert_name_beat}

    def _write_certificate(self, entry) -> None:
        if entry is None:
            return
        target = self._choose_save_path(
            _('Save the PDF certificate'),
            naming.certificate_name(entry, **self._name_parts()),
            _('PDF document (*.pdf)'))
        if target is None:
            return
        try:
            write_atomic(target, certificate.build_certificate(
                entry, key_override=self.settings.key_override,
                witness_state=self.witness_state))
        except OSError as e:
            QMessageBox.warning(
                self, _('It could not be saved'),
                _('The certificate could not be saved:<br>%(reason)s')
                % {'reason': html.escape(str(e.strerror or e))})
            return
        except Exception as e:     # noqa: BLE001 — np. LayoutError reportlaba
            log.error('certyfikat PDF', exc_info=True)
            QMessageBox.warning(
                self, _('It could not be saved'),
                _('The certificate could not be saved:<br>%(reason)s')
                % {'reason': html.escape(type(e).__name__)})
            return
        note = ''
        if certificate.certificate_language() != current_language():
            note = _('The certificate is in English: a PDF cannot reproduce this '
                     'script faithfully.')
        self._offer_open(target, _('Certificate saved'), note=note)

    def _choose_folder(self, title: str) -> Path | None:
        path = QFileDialog.getExistingDirectory(
            self, title, self.settings.last_directory or str(Path.home()))
        if not path:
            return None
        self.settings.last_directory = path
        return Path(path)

    def _write_certificates(self, entries: list) -> None:
        """Certyfikat dla KAZDEGO wpisu, do jednego folderu.

        Nazwy jak przy pojedynczym certyfikacie; zajeta nazwa dostaje „(2)”,
        wiec nic nie nadpisuje innego pliku — takze dwa pliki o tej samej
        nazwie z roznych folderow w jednej serii.
        """
        folder = self._choose_folder(_('Choose a folder for the PDF certificates'))
        if folder is None:
            return
        saved, failed = 0, []
        for entry in entries:
            target = naming.unique_path(
                folder / naming.certificate_name(entry, **self._name_parts()))
            try:
                write_atomic(target, certificate.build_certificate(
                    entry, key_override=self.settings.key_override,
                    witness_state=self.witness_state))
                saved += 1
            except Exception:     # noqa: BLE001 — OSError, LayoutError reportlaba
                log.error('certyfikat PDF (seria)', exc_info=True)
                failed.append(entry)
        notes = []
        if saved and certificate.certificate_language() != current_language():
            notes.append(_('The certificate is in English: a PDF cannot reproduce this '
                           'script faithfully.'))
        self._report_saved(folder, saved, len(entries), failed,
                           _('Certificates saved'), notes)

    def _write_bundles(self, entries: list) -> None:
        """Dowod .beatproof dla KAZDEGO wpisu, do jednego folderu."""
        folder = self._choose_folder(_('Choose a folder for the offline proofs'))
        if folder is None:
            return
        saved, failed, open_week, retired = 0, [], 0, 0
        for entry in entries:
            try:
                data = bundle.build(entry, checkpoint_file=self._checkpoint_file(entry))
                bundle.save(data, naming.unique_path(
                    folder / naming.bundle_name(entry, **self._name_parts())))
            except Exception:     # noqa: BLE001
                log.error('dowod .beatproof (seria)', exc_info=True)
                failed.append(entry)
                continue
            saved += 1
            if data.get('root_signature') and keys.is_retired(data.get('public_key')):
                retired += 1
            elif str(data.get('level') or '') == Level.RECORDED.value:
                open_week += 1
        notes = []
        if retired:
            notes.append(_('Some proofs are signed with a retired key, so the recipient '
                           'will not accept them. Refresh the statuses (History -> '
                           'Refresh statuses, F5) and export them again.'))
        if open_week:
            notes.append(_('Some proofs are not closed yet: their week is still running, '
                           'so they cannot be verified offline for now. Export them '
                           'again once the week has closed (the coming Monday, 00:00 UTC).'))
        self._report_saved(folder, saved, len(entries), failed, _('Proofs saved'), notes)

    def _report_saved(self, folder: Path, saved: int, total: int, failed: list,
                      title: str, notes: list[str]) -> None:
        """Jedno okno na cala serie: ile zapisano, gdzie, czego nie i dlaczego."""
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning if failed else QMessageBox.Information)
        box.setWindowTitle(title if saved else _('It could not be saved'))
        box.setTextFormat(Qt.RichText)
        box.setText(rtl_block('<b>' + _('Saved: %(saved)s of %(total)s.')
                              % {'saved': saved, 'total': total} + '</b>'))
        lines = [html.escape(ltr(str(folder)))]
        if failed:
            names = ', '.join(html.escape(str(getattr(e, 'file_name', '') or e.digest[:16]))
                              for e in failed)
            lines.append(_('These could not be saved: %(names)s') % {'names': names})
        lines += [html.escape(n) for n in notes]
        box.setInformativeText(rtl_block('<br><br>'.join(lines)))
        folder_button = box.addButton(_('Show in folder'), QMessageBox.ActionRole) if saved else None
        box.addButton(_('Close'), QMessageBox.RejectRole)
        box.exec()
        if folder_button is not None and box.clickedButton() is folder_button:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def _checkpoint_file(self, entry) -> bytes | None:
        cp = getattr(entry, 'checkpoint', None) or {}
        if not cp.get('verified') or not isinstance(cp.get('n'), int):
            return None
        return self.witness_store.read_checkpoint(cp['n'])

    def _write_bundle(self, entry) -> None:
        if entry is None:
            return
        data = bundle.build(entry, checkpoint_file=self._checkpoint_file(entry))
        target = self._choose_save_path(
            _('Save the offline proof'),
            naming.bundle_name(entry, **self._name_parts()),
            _('Sigelith proof (*.beatproof)'))
        if target is None:
            return
        try:
            saved = bundle.save(data, target)
        except OSError as e:
            QMessageBox.warning(
                self, _('It could not be saved'),
                _('The proof could not be saved:<br>%(reason)s')
                % {'reason': html.escape(str(e.strerror or e))})
            return
        level = str(data.get('level') or '')
        if data.get('root_signature') and keys.is_retired(data.get('public_key')):
            QMessageBox.warning(
                self, _('Proof saved — it needs refreshing'),
                _('<b>%(name)s</b> was saved.<br><br>'
                  'The root of this week is signed with a <b>retired</b> key, '
                  'so the recipient will not accept this proof. Refresh the '
                  'statuses (History -> Refresh statuses, F5) and export the '
                  'proof again — it will get a signature made with the current '
                  'Sigelith key.') % {'name': html.escape(saved.name)})
        elif level == Level.RECORDED.value:
            QMessageBox.information(
                self, _('Proof saved — not closed yet'),
                _('<b>%(name)s</b> was saved.<br><br>'
                  'The week is still running, so the proof contains no root '
                  'signature and <b>cannot be verified offline for now</b>. '
                  'Export it again once the week has closed (the coming Monday, '
                  '00:00 UTC) — then it will be complete.')
                % {'name': html.escape(saved.name)})
        else:
            self._offer_open(saved, _('Proof saved'))

    def _offer_open(self, path: Path, title: str, *, note: str = '') -> None:
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setTextFormat(Qt.RichText)
        box.setText(rtl_block(_('<b>%(name)s</b> was saved.')
                              % {'name': html.escape(ltr(path.name))}))
        # Pole informacyjne dziedziczy tekst wzbogacony: nowe linie jako <br>,
        # sciezka escapowana (w nazwie folderu moze byc „&").
        box.setInformativeText(rtl_block(
            html.escape(ltr(str(path.parent)))
            + (f'<br><br>{html.escape(note)}' if note else '')))
        open_button = box.addButton(_('Open the file'), QMessageBox.AcceptRole)
        folder_button = box.addButton(_('Show in folder'), QMessageBox.ActionRole)
        box.addButton(_('Close'), QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is open_button:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        elif box.clickedButton() is folder_button:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))

    def save_certificate(self) -> None:
        batch = self._batch_targets()
        if len(batch) > 1:
            self._write_certificates(batch)
        elif batch:
            self._write_certificate(batch[0])
        else:
            self._write_certificate(self.current_entry)

    def save_bundle(self) -> None:
        batch = self._batch_targets()
        if len(batch) > 1:
            self._write_bundles(batch)
        elif batch:
            self._write_bundle(batch[0])
        else:
            self._write_bundle(self.current_entry)

    def save_verify_certificate(self) -> None:
        if self.verify_result is None:
            return
        self._write_certificate(entry_from_verification(
            self.verify_result, file_name=getattr(self, '_verify_source_name', '')))

    def save_verify_bundle(self) -> None:
        if self.verify_result is None:
            return
        self._write_bundle(entry_from_verification(
            self.verify_result, file_name=getattr(self, '_verify_source_name', '')))

    def download_ots(self) -> None:
        if self.verify_result is None or not self.verify_result.week:
            return
        week = self.verify_result.week
        task = workers.OtsDownloadTask(week, self.client)
        self._start(task, lambda data: self._save_ots(week, data),
                    label_text=_('Downloading the .ots proof for %(week)s…')
                    % {'week': week})

    def _save_ots(self, week: str, data: bytes) -> None:
        target = self._choose_save_path(
            _('Save the OpenTimestamps proof'), f'sigelith-{week}.ots',
            _('OpenTimestamps proof (*.ots)'))
        if target is None:
            return
        try:
            write_atomic(target, data)
        except OSError as e:
            QMessageBox.warning(self, _('It could not be saved'), str(e))
            return
        QMessageBox.information(
            self, _('.ots proof saved'),
            _('<b>%(name)s</b> was saved.<br><br>'
              'You can check it with an OpenTimestamps client:<br>'
              '<code>ots verify %(command)s</code><br><br>'
              'That verification goes through the Bitcoin chain — entirely '
              'outside Sigelith and outside this application.')
            % {'name': html.escape(target.name),
               'command': html.escape(target.name)})

    def _verify_page(self, digest: str) -> str:
        return verify_url(digest, current_language())

    def open_in_browser(self) -> None:
        if self.current_result is None:
            return
        webbrowser.open(self._verify_page(self.current_result.digest))

    def _details(self, title: str, entry, data: dict | None = None) -> None:
        actions = []
        if entry is not None and getattr(entry, 'source', '') != SOURCE_TVS_LEGACY:
            actions = [
                (_('PDF certificate'), _('Issues a certificate for this entry'),
                 lambda: self._write_certificate(entry)),
                (_('Offline proof'), _('Saves a stand-alone .beatproof proof'),
                 lambda: self._write_bundle(entry)),
                (_('Check in the browser'), _('Opens sigelith.org/proof with this '
                                              'digest'),
                 lambda: webbrowser.open(self._verify_page(entry.digest))),
            ]
        in_history = entry is not None and self.history.find(entry.digest) is not None
        DetailsDialog(
            title, data if data is not None else bundle.build(
                entry, checkpoint_file=self._checkpoint_file(entry)),
            self, entry=entry, witness_state=self.witness_state,
            on_note=(lambda text: self._set_note(entry, text)) if in_history else None,
            actions=actions).exec()

    def show_details(self) -> None:
        if self.current_entry is None:
            return
        self._details(_('Proof details'), self.current_entry)

    def show_verify_details(self) -> None:
        if self.verify_result is not None:
            entry = self.history.find(self.verify_result.digest) or entry_from_verification(
                self.verify_result, file_name=getattr(self, '_verify_source_name', ''))
            self._details(_('Proof details'), entry)
            return
        data = getattr(self, '_bundle_data', None)
        if data:
            DetailsDialog(_('Proof details'), data, self,
                          witness_state=self.witness_state).exec()

    # --- Historia -----------------------------------------------------------

    def _refresh_history_view(self) -> None:
        self.history_model.set_entries(self.history.entries)
        total = len(self.history.entries)
        anchored = sum(1 for e in self.history.entries if e.level == Level.ANCHORED.value)
        legacy = sum(1 for e in self.history.entries if e.source == SOURCE_TVS_LEGACY)
        parts = [plural.entries(total),
                 _('%(count)s anchored') % {'count': anchored}]
        pinned = sum(1 for e in self.history.entries
                     if witness.pinning(e.checkpoint, self.witness_state).sources)
        if pinned:
            parts.append(_('%(count)s with independent copies') % {'count': pinned})
        if legacy:
            parts.append(_('%(count)s from the TVS archive') % {'count': legacy})
        self.history_summary.setText(' · '.join(parts))
        self._update_history_buttons()
        panel = getattr(self, 'witness_panel', None)
        if panel is not None:
            panel.set_history(self.history.entries)

    # --- Katalog danych -----------------------------------------------------

    def _check_data_dir(self) -> None:
        """Sprawdza PRZY STARCIE, czy program ma gdzie zapisac dane."""
        if self._closing:
            return
        problem = probe_write()
        if problem is not None:
            self._resolve_data_dir(problem)

    def _resolve_data_dir(self, problem: WriteProblem) -> bool:
        """Okno blokady + przyjecie nowego katalogu. `True` = da sie pisac."""
        chosen = resolve_data_dir_problem(problem, self)
        if chosen is None:
            self.statusBar().showMessage(
                _('Sigelith Desktop cannot save data in %(path)s — new stamps will '
                  'not be recorded in the history until the folder is changed '
                  '(Settings -> Data).') % {'path': problem.directory})
            return False
        self._adopt_data_dir()
        return True

    def _adopt_data_dir(self) -> None:
        """Po zmianie katalogu danych: historia i swiadek pisza w NOWYM miejscu."""
        self.history.path = history_path()
        self.witness_store = witness.WitnessStore()
        self.witness_state = self.witness_store.load()
        self.log_mirror = witness.LogMirror()
        self._render_witnesses()
        self.handover.adopt_data_dir()
        self.statusBar().showMessage(
            _('Data folder: %(path)s') % {'path': app_data_dir()}, 20_000)

    def _store(self, action, save=None) -> bool:
        """Zapis danych programu z obsluga blokady. `True` = zapisane.

        Po zmianie katalogu powtarzamy SAM ZAPIS, a nie cala czynnosc —
        ponowienie `History.add` dolozyloby ten sam stempel po raz drugi.
        """
        save = save or action
        try:
            action()
            return True
        except OSError as e:
            problem = describe_write_problem(app_data_dir(), e)
        if not self._resolve_data_dir(problem):
            return False
        try:
            save()
        except OSError as e:
            problem = describe_write_problem(app_data_dir(), e)
            QMessageBox.warning(self, problem.title, problem.message)
            return False
        return True

    def _report_migration(self) -> None:
        """Mowi o przeprowadzce danych — na pasku stanu, nie okienkiem."""
        if self._closing or self._migration is None:
            return
        message = self._migration.message
        if message:
            self.statusBar().showMessage(message, 20_000)

    def _report_history_problem(self) -> None:
        if self._closing or not self.history.load_problem:
            return
        QMessageBox.warning(self, _('Local history'), self.history.load_problem)
        self.history.load_problem = ''

    @staticmethod
    def _find_legacy_history() -> Path | None:
        """Szuka `history.json` starego klienta TVS (katalog programu, zrodla, cwd)."""
        candidates = [Path(sys.executable).resolve().parent,
                      Path(__file__).resolve().parent.parent.parent,
                      Path.cwd()]
        for directory in candidates:
            candidate = directory / 'history.json'
            try:
                if candidate.is_file() and candidate != history_path():
                    return candidate
            except OSError:
                continue
        return None

    def _migrate_legacy_history(self) -> None:
        """Jednorazowo wciaga historie starego klienta TVS."""
        if self._closing:
            return
        marker = app_data_dir() / '.tvs-zaimportowano'
        if marker.exists():
            return
        legacy = self._find_legacy_history()
        if legacy is None:
            return
        before = len(self.history.entries)
        if not self._store(lambda: self.history.import_legacy_tvs(legacy),
                           self.history.save):
            return
        added = len(self.history.entries) - before
        try:
            (app_data_dir() / '.tvs-zaimportowano').write_text(
                'ok', encoding='utf-8')
        except OSError:
            pass
        if added:
            self._refresh_history_view()
            QMessageBox.information(
                self, _('History carried over from TVS'),
                _('<b>%(entries)s</b> from the old TVS client were added to the '
                  'history.<br><br>They are marked as an <b>archive</b>: their '
                  'former "signature" is a concatenation of a time and a digest '
                  'that cannot be verified. To get a proof that can be checked '
                  'independently, stamp those files again — Sigelith will write '
                  'a new entry and the old one will stay in the history.')
                % {'entries': plural.entries(added)})

    def _selected_entries(self) -> list:
        rows = self.history_table.selectionModel().selectedRows()
        entries = []
        for index in rows:
            source = self.history_proxy.mapToSource(index)
            entry = self.history_model.entry_at(source.row())
            if entry is not None:
                entries.append(entry)
        return entries

    def _update_history_buttons(self, *_args) -> None:
        entries = self._selected_entries()
        one = len(entries) == 1
        # Certyfikat i .beatproof takze dla kilku zaznaczonych wpisow — kazdy osobno.
        usable = bool(entries) and all(e.source != SOURCE_TVS_LEGACY for e in entries)
        self.history_buttons['pdf'].setEnabled(bool(entries))
        self.history_buttons['bundle'].setEnabled(usable)
        self.history_buttons['details'].setEnabled(one)
        self.history_buttons['copy'].setEnabled(one)
        self.history_buttons['delete'].setEnabled(bool(entries))

    def _history_menu(self, position) -> None:
        entries = self._selected_entries()
        if not entries:
            return
        menu = QMenu(self)
        menu.addAction(_('Copy the SHA-256 digest'), self.history_copy_digest)
        menu.addAction(_('PDF certificate…'), self.history_certificate)
        if all(e.source != SOURCE_TVS_LEGACY for e in entries):
            menu.addAction(_('Offline proof (.beatproof)…'), self.history_bundle)
            menu.addAction(_('Check in the browser'), self.history_open_browser)
        menu.addSeparator()
        menu.addAction(_('Details…'), self.history_details)
        menu.addSeparator()
        menu.addAction(_('Remove from history'), self.history_delete)
        menu.exec(self.history_table.viewport().mapToGlobal(position))

    def history_certificate(self) -> None:
        entries = self._selected_entries()
        if len(entries) > 1:
            self._write_certificates(entries)
        elif entries:
            self._write_certificate(entries[0])

    def history_bundle(self) -> None:
        entries = [e for e in self._selected_entries() if e.source != SOURCE_TVS_LEGACY]
        if len(entries) > 1:
            self._write_bundles(entries)
        elif entries:
            self._write_bundle(entries[0])

    def history_details(self) -> None:
        entries = self._selected_entries()
        if entries:
            self._details(_('Entry details'), entries[0])

    def history_copy_digest(self) -> None:
        entries = self._selected_entries()
        if entries:
            QGuiApplication.clipboard().setText(entries[0].digest)
            self.statusBar().showMessage(_('Digest copied to the clipboard.'), 3000)

    def history_open_browser(self) -> None:
        entries = self._selected_entries()
        if entries:
            entry = entries[0]
            url = (entry.verify_url if entry.source == SOURCE_TVS_LEGACY
                   else self._verify_page(entry.digest))
            if url:
                webbrowser.open(url)

    def history_delete(self) -> None:
        entries = self._selected_entries()
        if not entries:
            return
        if QMessageBox.question(
                self, _('Remove from history?'),
                _('Remove <b>%(entries)s</b> from the local history?<br><br>'
                  'The stamp <b>stays in the public Sigelith register</b> — the '
                  'register is append-only and nothing can be removed from it. '
                  'Only this list on this computer changes.')
                % {'entries': plural.entries(len(entries))},
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        digests = [e.digest for e in entries]
        before = len(self.history.entries)
        if not self._store(lambda: self.history.remove(digests),
                           self.history.save):
            return
        removed = before - len(self.history.entries)
        self._refresh_history_view()
        self.statusBar().showMessage(
            _('%(entries)s removed from the history.')
            % {'entries': plural.entries(removed)}, 4000)

    def refresh_history_statuses(self) -> None:
        if not self.history.entries:
            self.statusBar().showMessage(
                _('The history is empty — there is nothing to refresh.'), 4000)
            return
        self.tabs.setCurrentIndex(2)
        task = workers.RefreshEntriesTask(
            self.history.entries, self.client,
            key_override=self.settings.key_override,
            mode=self.settings.witness_mode, witness_state=self.witness_state,
            mirror=self.log_mirror)
        self._start(task, self._on_refreshed,
                    label_text=_('Refreshing statuses…'))

    def _on_refreshed(self, updated: list, *, quiet: bool = False) -> None:
        # Ten sam powod co w `_on_stamped`: przerwana w polowie petla zapisow
        # utrwalilaby czesc odswiezonych statusow i zgubila reszte.
        if updated:
            self._store(lambda: self.history.merge(updated), self.history.save)
        self._refresh_history_view()
        if quiet:
            if updated:
                self.statusBar().showMessage(
                    _('%(entries)s matured in the background.')
                    % {'entries': plural.entries(len(updated))}, 8000)
            return
        if updated:
            QMessageBox.information(
                self, _('Statuses refreshed'),
                _('<b>%(entries)s</b> updated — the proofs have matured.')
                % {'entries': plural.entries(len(updated))})
        else:
            self.statusBar().showMessage(
                _('No change — none of the proofs has moved to another stage '
                  'yet.'), 6000)

    def export_history(self) -> None:
        if not self.history.entries:
            QMessageBox.information(self, _('The history is empty'),
                                    _('There is nothing to export yet.'))
            return
        path, selected = QFileDialog.getSaveFileName(
            self, _('Export the history'),
            str(Path(self.settings.last_directory or Path.home())
                / _('sigelith-history.csv')),
            _('CSV sheet for Excel (*.csv);;JSON file (*.json)'))
        if not path:
            return
        target = Path(path)
        self.settings.last_directory = str(target.parent)
        try:
            if 'json' in selected.lower() or target.suffix.lower() == '.json':
                count = self.history.export_json(target)
            else:
                count = self.history.export_csv(target)
        except OSError as e:
            QMessageBox.warning(
                self, _('It could not be saved'),
                _('File write error:<br>%(reason)s')
                % {'reason': html.escape(str(e.strerror or e))})
            return
        self._offer_open(target, _('%(entries)s exported')
                         % {'entries': plural.entries(count)})

    # --- Swiadkowie -------------------------------------------------------------

    def _render_witnesses(self) -> None:
        panel = getattr(self, 'witness_panel', None)
        if panel is None:
            return
        panel.set_mode(self.settings.witness_mode)
        panel.set_third_party(self.settings.third_party_checks)
        panel.set_state(self.witness_state)
        panel.set_running(self._witness_running)
        role, text = panel.summary()
        self.witness_dot.set_state(role, self._witness_running)
        self.witness_button.setText(text)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        # Praca w tle rusza dopiero, gdy okno jest NA EKRANIE — nie w
        # konstruktorze. Okno budowane w testach (albo przez kod
        # biblioteczny) nie laczy sie wtedy z niczym samo z siebie.
        if not self._background_started and not self._closing:
            self._background_started = True
            if self.settings.background_checks:
                QTimer.singleShot(2500, self._background_cycle)
                self._witness_timer.start()
            # Handover czeka tylko wtedy, gdy jest na co (folder wymiany albo
            # zaakceptowana paczka) — niezaleznie od kontroli swiadka.
            self.handover.start_background()

    def _background_cycle(self) -> None:
        if self._closing or not self.settings.background_checks:
            return
        if self._busy():
            # Uzytkownik cos wlasnie robi — wracamy po jego zadaniu.
            self._background_paused = True
            return
        self.check_witnesses(False)

    def check_witnesses(self, interactive: bool = True) -> None:
        """Jeden przebieg swiadka; `interactive` = nakladka z wynikiem."""
        if self._closing:
            return
        if self._witness_running:
            if interactive:
                self.tabs.setCurrentIndex(3)
            return
        self._witness_running = True
        self._witness_interactive = interactive
        if interactive:
            self.overlay.begin(_('Checking the public log…'), _(
                'Downloading new checkpoints and checking the signature, the chain, '
                'consistency and the independent copies'))
        task = workers.WitnessRefreshTask(
            self.client, self.witness_store, self.witness_state,
            self.log_mirror if self.settings.witness_mode == witness.MODE_PRIVATE else None,
            mode=self.settings.witness_mode, key_override=self.settings.key_override,
            third_party=self.settings.third_party_checks)
        task.signals.finished.connect(self._on_witness_refreshed)
        task.signals.failed.connect(self._on_witness_failed)
        task.signals.done.connect(self._on_witness_done)
        self._witness_task = task
        self._render_witnesses()
        workers.launch(self.pool, task)

    def _on_witness_refreshed(self, outcome) -> None:
        state, report = outcome
        # Jedna linia na przebieg: do 2.2.0 udany przebieg nie zostawial
        # w dzienniku NIC — wynik byl tylko w state.json.
        log.info('swiadek: %s nowych checkpointow, %s nowych wpisow, kopie: %s, '
                 'alarmy: %s, bledy: %s%s', report.new_checkpoints, report.new_entries,
                 ', '.join(report.copies_confirmed) or '—', len(report.new_alarms),
                 len(report.errors), ' (ciag dalszy)' if report.more else '')
        for error in report.errors[:5]:
            log.info('swiadek: %s', error)
        self.witness_state = state
        try:
            self.witness_store.save(state)
        except OSError:
            log.warning('swiadek: nie udalo sie zapisac stanu', exc_info=True)
        self._render_witnesses()
        self._refresh_history_view()
        critical = [a for a in report.new_alarms if a.get('severity') == 'critical']
        if critical:
            self.tabs.setCurrentIndex(3)
            QMessageBox.critical(
                self, _('The witnesses raised an alarm'),
                _('Sigelith Desktop found something in the public log that must not '
                  'happen: <b>%(what)s</b>.<br><br>The conflicting files were '
                  'kept as evidence in the data folder. Details are in the '
                  'Witnesses tab.') % {'what': html.escape(critical[0].get('detail', ''))})
        if self._witness_interactive:
            if state.critical_alarms:
                self.overlay.finish(_('Alarm'), _('See the Witnesses tab'), ok=False)
            elif report.errors and not report.new_checkpoints and state.last_error:
                self.overlay.finish(_('No connection'), state.last_error, ok=False)
            else:
                latest = state.latest
                self.overlay.finish(
                    _('The log checks out'),
                    (_('checkpoint #%(n)s · %(new)s new · %(copies)s independent '
                       'copies confirmed') % {
                        'n': latest.n, 'new': report.new_checkpoints,
                        'copies': sum(1 for s in witness.SOURCES if state.copy_max(s))})
                    if latest else _('no checkpoint has been issued yet'))
        if report.new_checkpoints or report.copies_confirmed:
            self.statusBar().showMessage(
                _('Witnesses: %(n)s new checkpoints checked') % {'n': report.new_checkpoints}
                + (' · ' + ', '.join(report.copies_confirmed) if report.copies_confirmed
                   else ''), 8000)
        if report.more:
            QTimer.singleShot(WITNESS_CONTINUE_MS, self._background_cycle)
        elif self.settings.background_checks and not self._witness_interactive:
            self._refresh_quietly()

    def _on_witness_failed(self, message: str) -> None:
        log.warning('swiadek: %s', message)
        self.witness_state.last_error = message
        if self._witness_interactive:
            self.overlay.finish(_('The check did not work'), message, ok=False)

    def _on_witness_done(self) -> None:
        self._witness_running = False
        self._witness_task = None
        # Nastepny przebieg liczy sie od konca tego, z rozrzutem.
        if self._witness_timer.isActive():
            self._witness_timer.setInterval(self._next_witness_interval())
        self._render_witnesses()

    def _refresh_quietly(self) -> None:
        """Dojrzewanie dowodow w tle — bez paska postepu i bez okienek."""
        if self._closing or not self.history.entries:
            return
        task = workers.RefreshEntriesTask(
            self.history.entries, self.client,
            key_override=self.settings.key_override,
            mode=self.settings.witness_mode, witness_state=self.witness_state,
            mirror=self.log_mirror, quiet=True)
        if not any(task._needs_refresh(e) for e in self.history.entries):
            return
        task.signals.finished.connect(lambda updated: self._on_refreshed(updated, quiet=True))
        task.signals.failed.connect(lambda message: log.info('odswiezanie w tle: %s', message))
        task.signals.done.connect(self._on_quiet_done)
        self._quiet_task = task
        workers.launch(self.pool, task)

    def _on_quiet_done(self) -> None:
        self._quiet_task = None

    def _set_witness_mode(self, mode: str) -> None:
        if mode not in witness.MODES or mode == self.settings.verification_mode:
            return
        self.settings.verification_mode = mode
        self._store(self.settings.save)
        self._render_witnesses()
        self.statusBar().showMessage(
            _('Private mode: Sigelith Desktop keeps a copy of the whole public log.')
            if mode == witness.MODE_PRIVATE else
            _('Fast mode: the server is asked about each digest.'), 6000)
        if mode == witness.MODE_PRIVATE:
            QTimer.singleShot(200, lambda: self.check_witnesses(False))

    def _open_evidence(self) -> None:
        folder = self.witness_store.directory / 'evidence'
        folder.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    # --- Narzedzia ----------------------------------------------------------

    def _sync_clock(self, interactive: bool = False) -> None:
        if self._closing:
            return
        if interactive:
            self.overlay.begin(_('Synchronising the clock…'), _(
                'Measuring the difference between this computer and the Sigelith '
                'server'))
        self.clock.set_syncing(True)
        task = workers.ClockSyncTask(self.client)
        task.signals.finished.connect(lambda result: self._on_synced(result, interactive))
        # Synchronizacja przy starcie jest czynnoscia tla — blad tylko na
        # pasku stanu: brak sieci przy starcie nie powinien witac okienkiem.
        task.signals.failed.connect(lambda message: self._on_sync_failed(message, interactive))
        task.signals.done.connect(lambda: self.clock.set_syncing(False))
        task.signals.done.connect(self._on_sync_done)
        self._sync_task = task
        workers.launch(self.pool, task)

    def _on_sync_done(self) -> None:
        self._sync_task = None

    # --- Adres .onion (onion.py) --------------------------------------------

    def _refresh_onion(self, force: bool = False) -> None:
        """Biezacy adres .onion z serwisu — raz na dobe, tylko w trybie Tor.

        Dzieki temu zmiana adresu uslugi ukrytej nie wymaga nowego wydania
        programu. Blad (Tor nie dziala, brak sieci, zla odpowiedz) zostawia
        dotychczasowy adres i nic nie pokazuje — sprobujemy przy nastepnym
        uruchomieniu. Zadanie dostaje KOPIE ustawien (inny watek).
        """
        if self._closing or not self.settings.use_tor or self._onion_task is not None:
            return
        if not force and not onion.due(self.settings.onion_checked):
            return
        task = workers.OnionRefreshTask(replace(self.settings))
        task.signals.finished.connect(self._on_onion)
        task.signals.done.connect(self._on_onion_done)
        self._onion_task = task
        workers.launch(self.pool, task)

    def _on_onion_done(self) -> None:
        self._onion_task = None

    def _on_onion(self, url) -> None:
        if not url or self._closing:
            return
        changed = url != self.settings.onion_base_url
        self.settings.onion_url = url
        self.settings.onion_checked = onion.now_iso()
        self._store(self.settings.save)
        if changed and self.settings.use_tor:
            log.info('onion: przelaczam na nowy adres uslugi %s', url)
            # Nowy klient: stary trzyma pule polaczen do POPRZEDNIEGO adresu.
            # Zamykamy go dopiero po chwili — moze jeszcze konczyc zapytanie
            # czynnosci uzytkownika.
            old_client, self.client = self.client, BeatTimeClient(self.settings)
            QTimer.singleShot(120_000, old_client.close)
            self._update_connection_label()

    def sync_clock_interactive(self) -> None:
        self._sync_clock(True)

    def _on_sync_failed(self, message: str, interactive: bool) -> None:
        self.statusBar().showMessage(
            _('The clock was not synchronised: %(reason)s') % {'reason': message}, 8000)
        if interactive:
            self.overlay.finish(_('The clock was not synchronised'), message, ok=False)

    def _on_synced(self, result, interactive: bool = False) -> None:
        self.clock.apply_sync(result.offset_seconds)
        warning = self.clock.drift_warning
        if warning:
            self.status_connection.setText('⚠ ' + _('clock out of step'))
            self.status_connection.setToolTip(warning)
        else:
            self._update_connection_label()
        summary = (_('difference %(offset)s s, round trip %(rtt)s ms')
                   % {'offset': f'{result.offset_seconds:+.2f}',
                      'rtt': f'{result.round_trip_seconds * 1000:.0f}'})
        self.statusBar().showMessage(
            _('Clock synchronised (difference %(offset)s s, round trip '
              '%(rtt)s ms).') % {'offset': f'{result.offset_seconds:+.2f}',
                                 'rtt': f'{result.round_trip_seconds * 1000:.0f}'},
            6000)
        if interactive:
            self.overlay.finish(
                _('The clock is out of step') if warning else _('Clock synchronised'),
                warning or summary, ok=not warning)

    def check_health(self) -> None:
        self.overlay.begin(_('Checking the service status…'),
                           _('Asking the Sigelith server about its database, cache '
                             'and clock'))
        if not self._start(workers.HealthTask(self.client), self._on_health,
                           label_text=_('Checking the service status…')):
            self.overlay.hide()
            return
        if self._active_task is not None:
            self._active_task.signals.failed.connect(lambda _m: self.overlay.hide())

    def _on_health(self, data: dict) -> None:
        self.overlay.hide()
        clock = data.get('clock') or {}
        offset = clock.get('offset')
        status = html.escape(str(data.get('status', '?')))
        source = html.escape(str(clock.get('server', '—')))
        working, broken = _('working'), _('unavailable')
        QMessageBox.information(
            self, _('Sigelith service status'),
            _('Overall state: <b>%(status)s</b><br>'
              'Database: %(database)s<br>'
              'Cache: %(cache)s<br>'
              'Server clock against NTP: %(offset)s (source: %(source)s)')
            % {'status': status,
               'database': working if data.get('database') else broken,
               'cache': working if data.get('cache') else broken,
               'offset': (f'{offset:+.4f} s' if isinstance(offset, (int, float))
                          else _('unknown')),
               'source': source})

    def open_settings(self) -> None:
        before = app_data_dir()
        dialog = SettingsDialog(self.settings, self)
        accepted = dialog.exec() == SettingsDialog.Accepted
        # Zakladka „Dane" dziala OD RAZU, a nie po przycisku „Zapisz".
        if app_data_dir() != before:
            self._adopt_data_dir()
        if not accepted:
            return
        new_settings = dialog.result_settings()
        theme_changed = new_settings.theme != self.settings.theme
        language_changed = new_settings.language != self.settings.language
        connection_changed = (
            new_settings.base_url != self.settings.base_url
            or new_settings.use_tor != self.settings.use_tor
            or new_settings.tor_proxy != self.settings.tor_proxy
            or new_settings.timeout_seconds != self.settings.timeout_seconds)
        mode_changed = new_settings.witness_mode != self.settings.witness_mode
        background_changed = (new_settings.background_checks
                              != self.settings.background_checks)

        override_changed = new_settings.key_override != self.settings.key_override
        exchange_changed = (new_settings.handover_exchange_dir
                            != self.settings.handover_exchange_dir)
        self.settings = new_settings
        self._store(self.settings.save)
        self.history.limit = new_settings.history_limit

        if connection_changed:
            # Nowa sesja HTTP: stara trzyma pule polaczen do POPRZEDNIEGO
            # adresu i poprzednie ustawienia proxy.
            old_client, self.client = self.client, BeatTimeClient(self.settings)
            old_client.close()
            self._update_connection_label()
            QTimer.singleShot(200, self._sync_clock)
            if self.settings.use_tor:
                # Wlaczony (albo przestawiony) tryb Tor: od razu sprawdz, czy
                # serwis nie oglasza nowszego adresu .onion.
                QTimer.singleShot(1500, lambda: self._refresh_onion(True))
        if theme_changed:
            theme.apply_theme(QApplication.instance(), self.settings.theme)
            icons.refresh()
            self.update()
        if language_changed:
            self._apply_language()
        if background_changed:
            if self.settings.background_checks and self._background_started:
                self._witness_timer.start()
                QTimer.singleShot(500, self._background_cycle)
            else:
                self._witness_timer.stop()
        if mode_changed and self.settings.witness_mode == witness.MODE_PRIVATE \
                and self._background_started:
            QTimer.singleShot(300, lambda: self.check_witnesses(False))
        self._render_witnesses()
        self.handover.refresh()
        if exchange_changed and self.settings.handover_exchange_dir:
            QTimer.singleShot(300, self.handover.background_check)
        if override_changed:
            self._update_connection_label()
            # Wpisy zweryfikowane usunietym (albo zmienionym) wlasnym kluczem
            # nie moga dalej pokazywac „Zakotwiczony".
            if self.history.demote_untrusted(new_settings.key_override):
                self._refresh_history_view()
            if new_settings.key_override:
                QMessageBox.warning(
                    self, _('Your own public key'),
                    _('Besides the built-in list of Sigelith keys, the '
                      'application will now also accept signatures made with '
                      '<b>the key you entered</b>.<br><br>Whoever gave you that '
                      'key can sign any "proof" with it. The status bar will '
                      'keep reminding you. To go back to the built-in list '
                      'alone, clear the field in Settings -> Trust.'))
        self.statusBar().showMessage(_('Settings saved.'), 4000)

    def _update_connection_label(self) -> None:
        """Pasek stanu ma mowic, jak jest NAPRAWDE — nie jak byc powinno.

        Dwa ustawienia potrafia po cichu uniewaznic gwarancje, ktore program
        obiecuje na tym samym pasku: proxy Tor pod adresem spoza tego
        komputera i wlasny klucz publiczny obok wbudowanej listy. Kazde z nich
        jest widoczne bez otwierania ustawien.
        """
        warnings = []
        if self.settings.key_override:
            warnings.append(_(
                'YOUR OWN public key is set — besides the built-in list of '
                'Sigelith keys the application also accepts signatures made '
                'with that key.'))

        if self.settings.use_tor:
            if self.settings.tor_proxy_is_local:
                text, tip = 'Tor (.onion)', _(
                    'Traffic goes through the Tor network to the Sigelith '
                    'hidden service.\nThe server does not learn your IP '
                    'address.')
            else:
                warnings.append(
                    _('The proxy "%(proxy)s" is not a local address. Traffic to '
                      'the .onion service goes over plain HTTP, so it reaches '
                      'that machine in clear text — this is NOT anonymisation.')
                    % {'proxy': self.settings.tor_proxy})
                text, tip = '⚠ ' + _('proxy outside this computer'), ''
        else:
            host = self.settings.base_url.replace('https://', '').rstrip('/')
            text = f'HTTPS · {host}'
            tip = _('HTTPS connection with full certificate verification '
                    '(certifi).')

        if warnings:
            self.status_connection.setText('⚠ ' + text.lstrip('⚠ '))
            self.status_connection.setToolTip('\n\n'.join(warnings))
        else:
            self.status_connection.setText(text)
            self.status_connection.setToolTip(tip)

    def _apply_language(self) -> None:
        """Przelacza jezyk i mowi wprost, ze pelna zmiana wymaga restartu."""
        applied = set_language(self.settings.language)
        log.info('jezyk interfejsu zmieniony na %s (ustawienie %r)',
                 applied, self.settings.language)
        QMessageBox.information(
            self, _('Interface language'),
            _('The new language applies to texts drawn from now on. The whole '
              'window switches after Sigelith Desktop is restarted.'))

    def show_about(self) -> None:
        AboutDialog(self).exec()

    def show_thanks(self) -> None:
        """Okno podziekowan. Nie pokazuje sie samo z siebie przy starcie."""
        ThanksDialog(self.client, self.pool, self).exec()

    def show_log(self) -> None:
        LogDialog(self).exec()

    # --- Zdarzenia okna -----------------------------------------------------

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if getattr(self, 'overlay', None) is not None and self.overlay.isVisible():
            self.overlay.setGeometry(self.centralWidget().rect())

    def dragEnterEvent(self, event) -> None:
        # Cale okno przyjmuje pliki — nie tylko strefa upuszczania.
        if not self._busy() and event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event) -> None:
        if not self._busy() and event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        if self._busy():
            return
        from .widgets import collect_paths
        paths = collect_paths(url.toLocalFile() for url in event.mimeData().urls())
        if not paths:
            return
        event.acceptProposedAction()
        # Pliki Handover (paczka, odpowiedz, karta) NIGDY nie ida do
        # stemplowania: skrot paczki nie ma czego szukac w publicznym dzienniku.
        if any(is_handover_file(p) for p in paths):
            self.handover.open_files([p for p in paths if is_handover_file(p)])
        elif self.tabs.currentIndex() == 1:
            self._verify_dropped(paths)
        elif self.tabs.currentWidget() is self.handover_scroll:
            self.handover.send(paths)
        else:
            self.stamp_files(paths)

    def closeEvent(self, event) -> None:
        if self._busy():
            if QMessageBox.question(
                    self, _('A task is running'),
                    _('A background task is still running. Close the program '
                      'and stop it?'),
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                event.ignore()
                return
            self._cancel_task()

        # Od tego miejsca okno jest w stanie zamykania: odlozone timery,
        # ktore zdaza jeszcze wystrzelic, nie uruchomia juz nowej pracy.
        self._closing = True
        self._witness_timer.stop()
        self._save_note_to_current()

        try:
            self.settings.window_geometry = bytes(
                self.saveGeometry().toBase64()).decode('ascii')
            self.settings.save()
        except Exception:          # noqa: BLE001 — zamkniecie ma sie udac zawsze
            log.warning('nie udało się zapisać ustawień przy zamknięciu', exc_info=True)

        # Czekamy na watki puli: bez tego proces potrafi zostac w pamieci albo
        # przewrocic sie na obiektach Qt niszczonych spod pracujacego watku.
        # Prace w tle PRZERYWAMY: do 2.2.0 przebieg swiadka nie dostawal
        # sygnalu i po zamknieciu okna proces zyl dalej niewidoczny (71 s
        # w pomiarze 2026-09-27), a otwarcie programu w tym czasie dawalo dwie
        # kopie na jednym katalogu danych.
        for task in self._background_tasks():
            task.cancel()
        self.pool.clear()
        if not self.pool.waitForDone(CLOSE_WAIT_MS):
            log.warning('wątki robocze nie zakończyły się w czasie %s s — proces '
                        'skończy się bez nich', CLOSE_WAIT_MS // 1000)
            self.abandoned_workers = True
        else:
            self.client.close()
        super().closeEvent(event)

    def activate_from_other_instance(self, files: list) -> None:
        """Druga kopia programu przekazala pliki (albo tylko prosi o pokazanie okna)."""
        if self._closing:
            return
        if self.isMinimized():
            self.showNormal()
        self.show()
        self.raise_()
        self.activateWindow()
        paths = [Path(f) for f in files if Path(f).is_file()]
        if paths:
            self.open_paths(paths)

    def handover_send(self, files: list) -> None:
        """Okno wysylki Sigelith Handover z plikami (`--handover`, np. z Sigelith Backup)."""
        if self._closing:
            return
        paths = [Path(f) for f in files if Path(f).is_file()]
        if not paths:
            return
        self.tabs.setCurrentWidget(self.handover_scroll)
        self.handover.send(paths)

    def open_paths(self, paths: list[Path]) -> None:
        """Pliki z wiersza polecen, z „Otworz za pomoca" i z drugiej kopii programu.

        Pliki Handover ida do zakladki Handover, reszta — jak zawsze — do
        stemplowania. Mieszanki nie stemplujemy: paczka obok zwyklego pliku to
        raczej pomylka niz prosba o publiczny stempel.
        """
        handover = [p for p in paths if is_handover_file(p)]
        proofs = [p for p in paths if fileproof.is_proof_file(p)]
        if handover:
            self.handover.open_files(handover)
        elif proofs:
            # Dowód (.beatproof, .sigelith-proof) idzie do SPRAWDZANIA — stempel
            # skrótu dowodu nic by nie znaczył, a wysłałby go do publicznego dziennika.
            self.check_bundle_path(proofs[0])
        elif paths:
            self.tabs.setCurrentIndex(0)
            self.stamp_files(paths)

    def restore_geometry(self) -> None:
        raw = self.settings.window_geometry
        if not raw:
            fit_to_screen(self, 1100, 780)
            return
        try:
            from PySide6.QtCore import QByteArray
            self.restoreGeometry(QByteArray.fromBase64(raw.encode('ascii')))
        except Exception:          # noqa: BLE001
            fit_to_screen(self, 1100, 780)
        # Zapisany rozmiar z wiekszego ekranu (albo sprzed zmiany skali) nie
        # moze wychodzic poza obecny.
        if not self.isMaximized():
            fit_to_screen(self, self.width(), self.height())
        # Okno zapisane na monitorze, ktorego juz nie ma, otworzyloby sie poza
        # widocznym obszarem — i wygladalo jak program, ktory sie nie uruchomil.
        screen = QGuiApplication.screenAt(self.geometry().center())
        if screen is None:
            self.resize(1100, 780)
            primary = QGuiApplication.primaryScreen()
            if primary is not None:
                self.move(primary.availableGeometry().center() - self.rect().center())
