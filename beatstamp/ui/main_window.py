"""
Glowne okno BeatStamp.

Uklad wyrasta z trzech czynnosci, które uzytkownik faktycznie wykonuje —
stad trzy zakladki zamiast jednej kolumny dziewieciu przyciskow, która była
wcześniej:

    Znakowanie   — nadaj plikowi znacznik czasu
    Weryfikacja  — sprawdź plik, skrót albo dowód .beatproof
    Historia     — co już ostemplowalem i na jakim etapie jest dowód

Zasady, ktorych trzyma się cały ten plik:

* nic dlugotrwalego nie dzieje się w watku GUI — liczenie skrótu i sieć ida
  przez `QThreadPool` (`workers.py`), zawsze z paskiem postepu i przyciskiem
  przerwania;
* kazdy komunikat idzie przez katalog tlumaczen i mowi, CO ZROBIC, a nie
  tylko co sie stalo;
* stan dowodu nie jest lukrowany: swiezy stempel jest opisany jako swiezy,
  a nie jako "zweryfikowany";
* każdy element sterujacy ma podpowiedz — program ma się tlumaczyc sam.
"""
from __future__ import annotations

import html
import logging
import sys
import webbrowser
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
    QSizePolicy,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import __version__, beatcore, bundle, certificate, keys, merkle, plural, proof
from ..api import ApiError, BeatTimeClient
from ..config import (
    IMPRESSUM_URL,
    MigrationReport,
    PRIVACY_POLICY_URL,
    Settings,
    WriteProblem,
    app_data_dir,
    describe_write_problem,
    history_path,
    probe_write,
    resource_path,
    write_atomic,
)
from ..history import SOURCE_TVS_LEGACY, History, entry_from_verification
from ..i18n import _, set_language
from ..proof import Level, VerificationResult
from .. import workers
from . import theme
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
from .widgets import BeatClock, CopyField, DropZone, StatusBadge, card, label

log = logging.getLogger(__name__)


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
        return '✔ ' + _('BeatTime key from the list built into the application')
    if signer_status == keys.SIGNER_OVERRIDE:
        return '⚠ ' + _('key accepted thanks to YOUR OWN key from the settings')
    if signer_status == keys.SIGNER_RETIRED:
        return '✘ ' + _('BeatTime key RETIRED — the proof needs refreshing')
    return '✘ ' + _('FOREIGN key — outside the BeatTime keys built into the '
                    'application')


def _retired_html(warnings: list[str]) -> str:
    """Opis stanu „podpis wycofanym kluczem" — tekst z escapowaniem."""
    return ('<b>' + _('The signature comes from a retired BeatTime key.')
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


def _time_html(beat: str, utc: str, note: str = '') -> str:
    """Wiersz „@beat · czas lokalny (UTC)" — z każdą wartością przepuszczoną
    przez `html.escape`.

    Etykiety Qt mają domyślnie `Qt::AutoText`: gdy tekst wygląda na HTML
    (a wygląda, bo sami wstawiamy `<b>`), CAŁOŚĆ trafia do parsera tekstu
    wzbogaconego — razem z wartościami wklejonymi ze środka. Qt rozumie w nim
    `<img src=...>` i ładuje wskazany zasób, także ze ścieżki sieciowej UNC.
    Wystarczyłby więc `"beat": "<img src='//host/x.png'>"` w pliku
    `.beatproof`, żeby samo WYŚWIETLENIE wyniku odpytało serwer atakującego —
    w programie, który obiecuje, że ten plik sprawdza wyłącznie lokalnie.

    `proof.py` odrzuca już takie wartości przy granicy zaufania; to jest
    druga warstwa, dla danych, które tamtędy nie przechodzą (pliki
    `.beatproof` czytane wprost).
    """
    dt = beatcore.parse_iso_utc(utc)
    text = (f'<b>{html.escape(beat or "—")}</b> · {html.escape(beatcore.local_str(dt))} '
            f'<span style="color:{theme.MUTED_INK}">'
            f'({html.escape(beatcore.utc_str(dt))})</span>')
    if note:
        text += (f'<br><span style="color:{theme.MUTED_INK}">'
                 f'{html.escape(note)}</span>')
    return text


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
        self.verify_result: VerificationResult | None = None
        self._active_task: workers.Task | None = None
        self._pending_files: list[Path] = []
        # Od chwili zamkniecia okna zadne odlozone wywolanie nie ma prawa
        # niczego uruchamiac. Timery z konstruktora (migracja, synchronizacja
        # zegara) sa zaplanowane na 0-300 ms; zamkniecie programu w tym oknie
        # czasu trafialoby w okno, ktorego pula watkow jest juz sprzatana.
        self._closing = False

        # Jeden watek roboczy: zadania i tak ida sekwencyjnie (limit serwera
        # to 20 stempli/min), a jeden watek znaczy, ze nie ma dwoch zapisow
        # historii naraz — bez potrzeby zakladania blokad.
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(1)

        # Tytul KONCZY SIE nazwa programu — tak samo jak kazde okno
        # dialogowe. To nie jest kwestia gustu: `setApplicationDisplayName`
        # kaze Qt dokleic „ - BeatStamp" do kazdego tytulu, ktory ta nazwa
        # sie nie konczy (`QPlatformWindow::formatWindowTitle`). Poprzednia
        # wersja zaczynala sie od nazwy, wiec system pokazywal
        # „BeatStamp 2.1.0 — znacznik czasu @beat - BeatStamp", z dwoma
        # roznymi myslnikami, na kazdym zrzucie ekranu.
        self.setWindowTitle(_('@beat timestamps %(version)s — BeatStamp')
                            % {'version': __version__})
        self.setMinimumSize(940, 660)
        self.setAcceptDrops(True)
        self._load_icon()

        self._build_ui()
        self._build_menu()
        self._refresh_history_view()

        # Wszystko, co moze wyswietlic okienko, odkladamy na PO starcie petli
        # zdarzen. Modalny komunikat wywolany jeszcze w konstruktorze
        # zatrzymuje program zanim glowne okno sie pokaze — uzytkownik widzi
        # wtedy sam dialog, bez kontekstu, jakby aplikacja sie nie uruchomila.
        QTimer.singleShot(0, self._check_data_dir)
        QTimer.singleShot(0, self._report_migration)
        QTimer.singleShot(0, self._report_history_problem)
        QTimer.singleShot(50, self._migrate_legacy_history)
        QTimer.singleShot(300, self._sync_clock)

    # --- Budowa interfejsu --------------------------------------------------

    def _load_icon(self) -> None:
        # Swiadomie BEZ awaryjnego siegania po `tvs_icon.ico`. Awaryjna ikona
        # starej marki na nowej aplikacji jest gorsza niz brak ikony: myli
        # uzytkownika co do tego, ktory program ma przed soba.
        path = resource_path('beatstamp.ico')
        if path.exists():
            self.setWindowIcon(QIcon(str(path)))

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(16, 12, 16, 10)
        layout.setSpacing(12)
        layout.addWidget(self._build_header())

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_stamp_tab(), _('Stamping'))
        self.tabs.addTab(self._build_verify_tab(), _('Verification'))
        self.tabs.addTab(self._build_history_tab(), _('History'))
        self.tabs.setTabToolTip(
            0, _('Give files a timestamp in the BeatTime register'))
        self.tabs.setTabToolTip(
            1, _('Check a file, a SHA-256 digest or a .beatproof proof'))
        self.tabs.setTabToolTip(
            2, _('Your stamps and the stage their proof has reached'))
        layout.addWidget(self.tabs, 1)

        layout.addWidget(self._build_progress())
        self.setCentralWidget(root)

        status = self.statusBar()
        self.status_connection = QLabel()
        self.status_connection.setObjectName('faint')
        status.addPermanentWidget(self.status_connection)
        self._update_connection_label()
        status.showMessage(_('Ready. Drag files in to give them a timestamp.'))

    def _build_header(self) -> QWidget:
        header = QWidget()
        row = QHBoxLayout(header)
        row.setContentsMargins(2, 0, 2, 0)

        left = QVBoxLayout()
        left.setSpacing(1)
        title = label('@ BeatStamp', role='h1')
        title.setStyleSheet(f'color: {theme.ACCENT};')
        left.addWidget(title)
        left.addWidget(label(
            _('Proof that a file existed in time — without sending the file'),
            role='hint',
            tooltip=_('Only the SHA-256 digest, computed on this computer, '
                      'reaches the BeatTime register.')))
        row.addLayout(left)
        row.addStretch(1)

        self.clock = BeatClock()
        row.addWidget(self.clock)
        return header

    def _build_progress(self) -> QWidget:
        wrapper = QWidget()
        row = QHBoxLayout(wrapper)
        row.setContentsMargins(0, 0, 0, 0)

        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        self.progress.setFormat('%p%')
        self.progress.hide()

        self.progress_label = QLabel()
        self.progress_label.setObjectName('hint')
        self.progress_label.hide()

        self.cancel_button = QPushButton(_('Stop'))
        self.cancel_button.setToolTip(_('Stops the current task (Esc)'))
        self.cancel_button.clicked.connect(self._cancel_task)
        self.cancel_button.hide()

        row.addWidget(self.progress_label)
        row.addWidget(self.progress, 1)
        row.addWidget(self.cancel_button)
        return wrapper

    # --- Zakladka: Znakowanie ----------------------------------------------

    def _build_stamp_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        self.drop_zone = DropZone(*_DROP_TEXTS())
        self.drop_zone.filesDropped.connect(self.stamp_files)
        self.drop_zone.browseRequested.connect(self.browse_files_to_stamp)
        layout.addWidget(self.drop_zone, 1)

        note_row = QHBoxLayout()
        note_label = label(_('Note:'),
                           tooltip=_('A description visible only to you'))
        self.note_input = QLineEdit()
        self.note_input.setPlaceholderText(
            _('e.g. "client contract, signed version" — optional'))
        self.note_input.setToolTip(_(
            'The note stays ONLY on this computer, in the local history.\n'
            'It is not sent to the register and does not reach the server '
            'certificate.\n'
            'It is saved together with the stamp and on every change of the '
            'text.'))
        self.note_input.editingFinished.connect(self._save_note_to_current)
        note_row.addWidget(note_label)
        note_row.addWidget(self.note_input, 1)
        layout.addLayout(note_row)

        self.stamp_result = self._build_result_card()
        layout.addWidget(self.stamp_result)
        return page

    def _build_result_card(self) -> QFrame:
        frame = card()
        grid = QGridLayout(frame)
        grid.setContentsMargins(16, 14, 16, 14)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(10)
        self.result_title = label(_('No result'), role='h2')
        self.result_badge = StatusBadge()
        top.addWidget(self.result_title)
        top.addWidget(self.result_badge)
        top.addStretch(1)
        grid.addLayout(top, 0, 0, 1, 2)

        self.result_description = label(
            _('Drag a file into the area above to give it a timestamp.'),
            role='hint', wrap=True)
        grid.addWidget(self.result_description, 1, 0, 1, 2)

        grid.addWidget(label(_('SHA-256 digest:'), role='hint'), 2, 0)
        self.result_digest = CopyField(
            _('not computed yet'),
            tooltip=_('The only information that reaches the BeatTime register'))
        grid.addWidget(self.result_digest, 2, 1)

        grid.addWidget(label(_('Timestamp:'), role='hint'), 3, 0)
        self.result_time = label('—', selectable=True)
        grid.addWidget(self.result_time, 3, 1)

        grid.addWidget(label(
            _('Local check:'), role='hint',
            tooltip=_('What the application computed ITSELF, without trusting '
                      'the server')), 4, 0)
        self.result_checks = label('—', role='hint', wrap=True)
        grid.addWidget(self.result_checks, 4, 1)

        actions = QHBoxLayout()
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
              'and without access to beattime.live: the digest, the inclusion '
              'path, the\nweek root and the Ed25519 signature in one JSON '
              'file.'))
        self.button_browser = self._action_button(
            _('Check in the browser'), self.open_in_browser,
            _('Opens the public verification page beattime.live/proof\n'
              'with the digest filled in — an independent confirmation.'))
        self.button_details = self._action_button(
            _('Details…'), self.show_details,
            _('The complete technical proof data in JSON'))
        for button in (self.button_pdf, self.button_bundle,
                       self.button_browser, self.button_details):
            button.setEnabled(False)
            actions.addWidget(button)
        self.button_pdf.setObjectName('primary')
        actions.addStretch(1)
        grid.addLayout(actions, 5, 0, 1, 2)
        grid.setColumnStretch(1, 1)
        return frame

    @staticmethod
    def _action_button(text: str, slot, tooltip: str) -> QPushButton:
        button = QPushButton(text)
        button.setToolTip(tooltip)
        button.clicked.connect(slot)
        return button

    # --- Zakladka: Weryfikacja ---------------------------------------------

    def _build_verify_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        intro = label(
            _('Check whether a document already has a timestamp — and whether '
              'the proof is consistent. Verification records nothing and '
              'changes nothing.'),
            role='hint', wrap=True)
        layout.addWidget(intro)

        self.verify_drop = DropZone(
            _('Drag a file here to check it'),
            _('the digest will be computed locally and looked up in the '
              'register'))
        self.verify_drop.setMinimumHeight(110)
        self.verify_drop.filesDropped.connect(self._verify_dropped)
        self.verify_drop.browseRequested.connect(self.browse_file_to_verify)
        layout.addWidget(self.verify_drop)

        hash_row = QHBoxLayout()
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
            'Asks the BeatTime register about this digest and checks the '
            'answer\nlocally: the inclusion path, the root signature and the '
            'identity of\nthe key. It records nothing and changes nothing.'))
        self.verify_button.setEnabled(False)
        self.verify_button.clicked.connect(self.verify_typed_hash)
        bundle_button = QPushButton(_('Load a .beatproof proof…'))
        bundle_button.setToolTip(_(
            'Checks a stand-alone proof file. The verification happens\n'
            'entirely locally — without connecting to anything.'))
        bundle_button.clicked.connect(self.check_bundle_file)
        hash_row.addWidget(self.verify_input, 1)
        hash_row.addWidget(self.verify_button)
        hash_row.addWidget(bundle_button)
        layout.addLayout(hash_row)

        result = card()
        grid = QGridLayout(result)
        grid.setContentsMargins(16, 14, 16, 14)
        grid.setVerticalSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(10)
        self.verify_title = label(_('No result'), role='h2')
        self.verify_badge = StatusBadge()
        top.addWidget(self.verify_title)
        top.addWidget(self.verify_badge)
        top.addStretch(1)
        grid.addLayout(top, 0, 0, 1, 2)

        self.verify_description = label(
            _('Drag a file in, paste a digest, or load a .beatproof file.'),
            role='hint', wrap=True)
        grid.addWidget(self.verify_description, 1, 0, 1, 2)

        grid.addWidget(label(_('Digest:'), role='hint'), 2, 0)
        self.verify_digest = CopyField('—')
        grid.addWidget(self.verify_digest, 2, 1)

        grid.addWidget(label(_('Timestamp:'), role='hint'), 3, 0)
        self.verify_time = label('—', selectable=True)
        grid.addWidget(self.verify_time, 3, 1)

        grid.addWidget(label(_('Local check:'), role='hint'), 4, 0)
        self.verify_checks = label('—', role='hint', wrap=True)
        grid.addWidget(self.verify_checks, 4, 1)

        actions = QHBoxLayout()
        self.verify_pdf_button = self._action_button(
            _('PDF certificate'), self.save_verify_certificate,
            _('Builds a certificate for the checked digest'))
        self.verify_bundle_button = self._action_button(
            _('Offline proof (.beatproof)'), self.save_verify_bundle,
            _('Saves a stand-alone proof for the checked digest'))
        self.verify_ots_button = self._action_button(
            _('Download the .ots proof'), self.download_ots,
            _('The OpenTimestamps proof of the week — to be checked with an\n'
              'OpenTimestamps client, entirely outside BeatTime and outside '
              'this application.'))
        self.verify_details_button = self._action_button(
            _('Details…'), self.show_verify_details,
            _('The complete proof data (JSON)'))
        for button in (self.verify_pdf_button, self.verify_bundle_button,
                       self.verify_ots_button, self.verify_details_button):
            button.setEnabled(False)
            actions.addWidget(button)
        actions.addStretch(1)
        grid.addLayout(actions, 5, 0, 1, 2)
        grid.setColumnStretch(1, 1)

        layout.addWidget(result)
        layout.addStretch(1)
        return page

    # --- Zakladka: Historia -------------------------------------------------

    def _build_history_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        controls = QHBoxLayout()
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
            'This operation asks the register about entries that are not yet\n'
            'anchored or are signed with a retired key. (F5)'))
        refresh.clicked.connect(self.refresh_history_statuses)
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
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents)
        self.history_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self._history_menu)
        self.history_table.doubleClicked.connect(lambda _: self.history_details())
        self.history_table.selectionModel().selectionChanged.connect(
            self._update_history_buttons)
        layout.addWidget(self.history_table, 1)

        buttons = QHBoxLayout()
        self.history_buttons = {
            'pdf': self._action_button(
                _('PDF certificate'), self.history_certificate,
                _('Issues a certificate for the selected entry')),
            'bundle': self._action_button(
                _('Offline proof'), self.history_bundle,
                _('Saves a stand-alone .beatproof proof')),
            'details': self._action_button(
                _('Details…'), self.history_details,
                _('The complete entry data (JSON)')),
            'copy': self._action_button(
                _('Copy digest'), self.history_copy_digest,
                _('Copies the full SHA-256 digest to the clipboard')),
            'delete': self._action_button(
                _('Remove from history'), self.history_delete,
                _('Removes the entry from this list ONLY.\n'
                  'The stamp in the public BeatTime register\n'
                  'stays — it cannot be undone.')),
        }
        for button in self.history_buttons.values():
            button.setEnabled(False)
            buttons.addWidget(button)
        buttons.addStretch(1)

        export = QPushButton(_('Export…'))
        export.setToolTip(_('Saves the history to a CSV (Excel) or JSON file'))
        export.clicked.connect(self.export_history)
        buttons.addWidget(export)
        layout.addLayout(buttons)

        self.history_summary = label('', role='faint')
        layout.addWidget(self.history_summary)
        return page

    # --- Menu ---------------------------------------------------------------

    def _build_menu(self) -> None:
        bar = self.menuBar()

        # Akcelerator (`&`) jest CZESCIA tlumaczenia: kazdy jezyk musi
        # postawic go przy innej literze i nie moze go zgubic. Pilnuje tego
        # `CatalogTests.test_menu_accelerators_are_unique_per_language`.
        file_menu = bar.addMenu(_('&File'))
        self._add_action(file_menu, _('Stamp files…'), self.browse_files_to_stamp,
                         QKeySequence.Open, _('Choose files to stamp'))
        self._add_action(file_menu, _('Verify a file…'), self.browse_file_to_verify,
                         QKeySequence('Ctrl+Shift+O'),
                         _('Check whether a file already has a stamp'))
        self._add_action(file_menu, _('Load a .beatproof proof…'),
                         self.check_bundle_file, QKeySequence('Ctrl+B'),
                         _('Check a stand-alone proof — without the network'))
        file_menu.addSeparator()
        self._add_action(file_menu, _('Export history…'), self.export_history,
                         QKeySequence('Ctrl+E'),
                         _('Save the history to CSV or JSON'))
        file_menu.addSeparator()
        self._add_action(file_menu, _('Quit'), self.close, QKeySequence.Quit, '')

        tools_menu = bar.addMenu(_('&Tools'))
        self._add_action(tools_menu, _('Refresh proof statuses'),
                         self.refresh_history_statuses, QKeySequence('F5'),
                         _('Check whether the proofs have matured'))
        self._add_action(tools_menu, _('Synchronise the clock'), self._sync_clock,
                         QKeySequence('F6'),
                         _('Measure the clock drift of this computer'))
        self._add_action(tools_menu, _('Check the service status'), self.check_health,
                         QKeySequence('F7'), _('State of the BeatTime server'))
        tools_menu.addSeparator()
        self._add_action(tools_menu, _('Settings…'), self.open_settings,
                         QKeySequence('Ctrl+,'),
                         _('Connection, trust, behaviour'))

        help_menu = bar.addMenu(_('Hel&p'))
        self._add_action(help_menu, _('About'), self.show_about,
                         QKeySequence('F1'), '')
        self._add_action(help_menu, _('How it works — beattime.live'),
                         lambda: QDesktopServices.openUrl(QUrl('https://beattime.live/proof/')),
                         None, _('The public verification page'))
        self._add_action(help_menu, _('Thank you to the supporters…'),
                         self.show_thanks, None,
                         _('People who support BeatTime — the list is loaded '
                           'from beattime.live'))
        help_menu.addSeparator()
        # Impressum i ochrona danych sa TUTAJ, a nie tylko w oknie
        # „O programie": § 5 DDG wymaga, zeby impressum bylo osiagalne
        # bezposrednio, w najwyzej dwoch klinieciach. Pomoc -> Impressum to
        # dokladnie dwa; przez „O programie" bylyby trzy. Adresy sa stale
        # (`config.IMPRESSUM_URL`), wiec wlasny serwer w Ustawieniach ich nie
        # podmienia.
        self._legal_action(help_menu, _('Legal notice (Impressum)'), IMPRESSUM_URL)
        self._legal_action(help_menu, _('Privacy policy'), PRIVACY_POLICY_URL)
        help_menu.addSeparator()
        self._add_action(help_menu, _('Show the event log'), self.show_log,
                         None, _('A record of errors — useful when reporting a '
                                 'problem'))
        self._add_action(help_menu, data_dir_button_text(), lambda: open_data_dir(),
                         None, data_dir_tooltip())

        escape = QAction(self)
        escape.setShortcut(QKeySequence('Esc'))
        escape.triggered.connect(self._cancel_task)
        self.addAction(escape)

    def _legal_action(self, menu: QMenu, text: str, url: str) -> QAction:
        """Pozycja menu otwierajaca dokument prawny w przegladarce.

        Adres siedzi takze w `QAction.data()` — dzieki temu da sie sprawdzic
        testem, DOKAD naprawde prowadzi pozycja menu, bez klikania w nia
        i bez otwierania przegladarki na maszynie budujacej.
        """
        action = self._add_action(
            menu, text, lambda: open_url(url), None,
            _('Opens in the browser: %(url)s') % {'url': url})
        action.setData(url)
        return action

    def _add_action(self, menu: QMenu, text: str, slot, shortcut, tip: str) -> QAction:
        action = QAction(text, self)
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
        """Uruchamia zadanie, o ile zadne inne nie trwa.

        Jedno zadanie naraz jest tu celowe: rownolegle stemplowanie i tak
        rozbiloby się o limit serwera, a przy okazji dwa wątki pisalyby
        jednoczesnie do tego samego pliku historii.
        """
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
        workers.launch(self.pool, task)
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
        # Do dziennika trafia KAZDE niepowodzenie. Wczesniej komunikat szedl
        # wylacznie do okienka, wiec po jego zamknieciu nie zostawal zaden
        # slad — a przy uruchomieniu bez konsoli (wersja .exe) nie bylo
        # zadnego sposobu, zeby dowiedziec sie, co poszlo nie tak.
        log.warning('zadanie nieudane: %s', message)
        self.statusBar().showMessage(_('The task ended with an error.'), 6000)
        QMessageBox.warning(self, _('It did not work'), message)

    def _on_task_done(self) -> None:
        self._active_task = None
        self._set_busy_ui(False)

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

        self.settings.last_directory = str(paths[0].parent)
        self.tabs.setCurrentIndex(0)
        self.drop_zone.set_texts(
            _('Working…'),
            _('%(files)s queued') % {'files': plural.files(len(paths))})
        task = workers.StampFilesTask(
            paths, self.client, note=self.note_input.text().strip(),
            key_override=self.settings.key_override)
        if not self._start(task, self._on_stamped, label_text=_('Preparing…')):
            self._reset_drop_texts()

    def _on_stamped(self, outcome: workers.BatchOutcome) -> None:
        self._reset_drop_texts()

        # `merge`, a nie petla `add`/`replace`: KOMPLET stempli ma wejsc do
        # pamieci, zanim cokolwiek dotknie dysku. Przy zablokowanym katalogu
        # `_store` powtarza sam zapis — a gdyby kazdy wpis zapisywal plik
        # osobno, pierwszy nieudany zapis przerwalby petle i stemple 2..N
        # przepadlyby mimo ze ich dowody sa juz w publicznym rejestrze.
        self._store(lambda: self.history.merge(
            [item.entry for item in outcome.successes]), self.history.save)
        self._refresh_history_view()

        if outcome.successes:
            last = outcome.successes[-1]
            self.current_result = last.result
            self.current_entry = last.entry
            self.note_input.setText(last.entry.note)
            self._show_result(last.result, last.entry, newly_created=last.newly_created,
                              count=len(outcome.successes))
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
            # NIE `_('Note:')`: ten sam msgid jest etykieta POLA notatki
            # (linia 309). Po angielsku oba znaczenia mieszcza sie w jednym
            # slowie, po niemiecku nie — „Notiz:" to pole uzytkownika,
            # a tu potrzebne jest „Hinweis:".
            extra = ('' if newly_created else
                     '<br><br><b>' + _('Please note:') + '</b> '
                     + _('the ORIGINAL timestamp was returned. The first stamp '
                         'wins — the date on an already registered document '
                         'cannot be refreshed.'))
            self.result_description.setText(result.level.description + extra)

        self.result_digest.set_value(result.digest)
        self.result_time.setText(_time_html(
            result.beat, result.utc, self._result_week_note(result)))
        self.result_checks.setText(self._checks_text(result))
        # Certyfikat i .beatproof tylko dla dowodu bez zastrzezen — dokument
        # wystawiony z odpowiedzi odrzuconej przez kontrole lokalna
        # wygladalby jak dowod, a nim nie jest.
        self._enable_result_buttons(True, exportable=not result.problems)

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
            parts.append('✔ ' + _('the inclusion path matches the week root')
                         if result.inclusion_ok else
                         '✘ ' + _('the inclusion path does NOT lead to the root'))
        else:
            parts.append('• ' + _('inclusion path — the week is still open'))
        if result.signature_checked:
            parts.append('✔ ' + _('the Ed25519 root signature is valid')
                         if result.signature_ok
                         else '✘ ' + _('the Ed25519 signature is invalid'))
            parts.append(_key_line(result.signer_status))
        else:
            parts.append('• ' + _('root signature — it arrives once the week '
                                  'closes'))
        # Nazwa banku przychodzi z sieci, a etykieta interpretuje HTML —
        # escapujemy KAZDA wartosc, takze nasze wlasne ostrzezenia.
        parts.append('• ' + _('anchor (according to the register): %(anchors)s')
                     % {'anchors': html.escape(result.anchor_summary)})
        for warning in result.warnings:
            parts.append(f'⚠ {html.escape(warning)}')
        return '<br>'.join(parts)

    def _enable_result_buttons(self, enabled: bool, *, exportable: bool = True) -> None:
        for button in (self.button_browser, self.button_details):
            button.setEnabled(enabled)
        for button in (self.button_pdf, self.button_bundle):
            button.setEnabled(enabled and exportable)

    def _save_note_to_current(self) -> None:
        """Notatka zapisuje się sama — bez osobnego przycisku "Zapisz".

        Poprzednik miał przycisk "Zapisz notatke", który dopisywal tekst do
        OSTATNIEGO wpisu historii, niezależnie od tego, czego dotyczyl. Przy
        dwoch plikach pod rzad notatka ladowala przy niewlasciwym.
        """
        if self.current_entry is None:
            return
        note = self.note_input.text().strip()
        if note == self.current_entry.note:
            return
        self.current_entry.note = note
        existing = self.history.find(self.current_entry.digest)
        if existing is not None:
            existing.note = note
            if not self._store(self.history.save):
                return
            self._refresh_history_view()
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
            digest, self.client, key_override=self.settings.key_override)
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
                _('This digest <b>does not appear</b> in the BeatTime '
                  'register.<br><br>')
                + (_('The file was never stamped, or it was changed after '
                     'stamping — even a single changed byte gives a completely '
                     'different digest.')
                   if source else
                   _('Check that the digest was pasted in full.')))
            self.verify_time.setText('—')
            self.verify_checks.setText('—')
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

        self.verify_time.setText(_time_html(
            result.beat, result.utc, self._result_week_note(result)))
        self.verify_checks.setText(self._checks_text(result))
        self._enable_verify_buttons(True, exportable=not result.problems)
        self.verify_ots_button.setEnabled(bool(result.week) and result.ots_status != 'none')

    def _enable_verify_buttons(self, enabled: bool, *, exportable: bool = True) -> None:
        self.verify_details_button.setEnabled(enabled)
        for button in (self.verify_pdf_button, self.verify_bundle_button):
            button.setEnabled(enabled and exportable)
        self.verify_ots_button.setEnabled(False)

    def check_bundle_file(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self, _('Choose a proof file'),
            self.settings.last_directory or str(Path.home()),
            _('BeatStamp proof (*.beatproof);;JSON files (*.json);;All files (*)'))
        if not path:
            return
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
            Path(path), document, key_override=self.settings.key_override)
        self._start(task, self._on_bundle_checked,
                    label_text=_('Checking the proof…'))

    def _on_bundle_checked(self, outcome: workers.BundleOutcome) -> None:
        check = outcome.check
        self.verify_result = None
        self._bundle_data = outcome.data
        self.verify_digest.set_value(check.digest)
        self.verify_input.setText(check.digest)

        lines = []
        if check.file_matches is True:
            lines.append('✔ ' + _('the document digest matches the proof'))
        elif check.file_matches is False:
            lines.append('✘ ' + _('the document digest does NOT match the proof'))
        else:
            lines.append('• ' + _('no document was pointed to — only the proof '
                                  'itself was checked'))
        lines.append('✔ ' + _('the inclusion path leads to the week root')
                     if check.inclusion_ok
                     else '✘ ' + _('the inclusion path does not match'))
        lines.append('✔ ' + _('the Ed25519 root signature is valid')
                     if check.signature_ok
                     else '✘ ' + _('no valid root signature'))
        if check.signer_status:
            lines.append(_key_line(check.signer_status))
        for warning in check.warnings:
            lines.append(f'⚠ {html.escape(warning)}')
        for note in check.notes:
            lines.append(f'• {html.escape(note)}')
        self.verify_checks.setText('<br>'.join(lines))

        data = outcome.data
        # Tresc pliku .beatproof pochodzi OD KOGOS INNEGO — to jedyne miejsce
        # w programie, gdzie dane wchodza wprost z pliku wskazanego przez
        # uzytkownika. Ida przez ten sam bezpieczny skladacz co reszta.
        # Podpis obejmuje tylko tydzien; bundle.check sprawdzil, ze czas w nim
        # lezy, wiec przy check.ok tydzien jest granica potwierdzona.
        self.verify_time.setText(_time_html(
            str(data.get('beat') or ''), str(data.get('utc') or ''),
            '' if check.problems else _week_note(check.week, check.ok)))

        if check.ok:
            self.verify_title.setText(_('Proof confirmed — %(name)s')
                                      % {'name': outcome.path.name})
            self.verify_badge.show_state('ok', _('Verified offline'))
            self.verify_description.setText(_(
                'The proof was checked <b>entirely locally</b> — without '
                'connecting to beattime.live and without trusting anyone. The '
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
        start = Path(self.settings.last_directory or str(Path.home())) / default_name
        path, _filter = QFileDialog.getSaveFileName(self, title, str(start), filters)
        if not path:
            return None
        target = Path(path)
        # QFileDialog pyta o nadpisanie samo, ale tylko gdy uzytkownik wpisze
        # nazwe recznie. Sprawdzamy jeszcze raz, bo poprzednik sklejal sciezke
        # z nazwy pliku zrodlowego i nadpisywal BEZ pytania.
        if self.settings.confirm_overwrite and target.exists():
            if QMessageBox.question(
                    self, _('The file already exists'),
                    _('The file <b>%(name)s</b> already exists in this '
                      'folder.<br><br>Overwrite it?') % {'name': target.name},
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No) != QMessageBox.Yes:
                return None
        self.settings.last_directory = str(target.parent)
        return target

    def _write_certificate(self, entry) -> None:
        if entry is None:
            return
        target = self._choose_save_path(
            _('Save the PDF certificate'),
            certificate.default_filename(entry) if self.settings.name_cert_after_source
            else _('certificate') + '_beattime.pdf',
            _('PDF document (*.pdf)'))
        if target is None:
            return
        try:
            write_atomic(target, certificate.build_certificate(
                entry, key_override=self.settings.key_override))
        except OSError as e:
            QMessageBox.warning(
                self, _('It could not be saved'),
                _('The certificate could not be saved:<br>%(reason)s')
                % {'reason': e.strerror or e})
            return
        self._offer_open(target, _('Certificate saved'))

    def _write_bundle(self, entry) -> None:
        if entry is None:
            return
        data = bundle.build(entry)
        target = self._choose_save_path(
            _('Save the offline proof'),
            bundle.default_name(str(getattr(entry, 'digest', '')),
                                str(getattr(entry, 'file_name', '') or '')),
            _('BeatStamp proof (*.beatproof)'))
        if target is None:
            return
        try:
            saved = bundle.save(data, target)
        except OSError as e:
            QMessageBox.warning(
                self, _('It could not be saved'),
                _('The proof could not be saved:<br>%(reason)s')
                % {'reason': e.strerror or e})
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
                  'BeatTime key.') % {'name': html.escape(saved.name)})
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

    def _offer_open(self, path: Path, title: str) -> None:
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setTextFormat(Qt.RichText)
        box.setText(_('<b>%(name)s</b> was saved.')
                    % {'name': html.escape(path.name)})
        box.setInformativeText(str(path.parent))
        open_button = box.addButton(_('Open the file'), QMessageBox.AcceptRole)
        folder_button = box.addButton(_('Show in folder'), QMessageBox.ActionRole)
        box.addButton(_('Close'), QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is open_button:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        elif box.clickedButton() is folder_button:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))

    def save_certificate(self) -> None:
        self._write_certificate(self.current_entry)

    def save_bundle(self) -> None:
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
            _('Save the OpenTimestamps proof'), f'beattime-{week}.ots',
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
              'outside BeatTime and outside this application.')
            % {'name': html.escape(target.name),
               'command': html.escape(target.name)})

    def open_in_browser(self) -> None:
        if self.current_result is None:
            return
        webbrowser.open(f'https://beattime.live/proof/?h={self.current_result.digest}')

    def show_details(self) -> None:
        if self.current_entry is None:
            return
        DetailsDialog(_('Proof details'),
                      bundle.build(self.current_entry), self).exec()

    def show_verify_details(self) -> None:
        data = (bundle.build(entry_from_verification(self.verify_result))
                if self.verify_result is not None
                else getattr(self, '_bundle_data', None))
        if data:
            DetailsDialog(_('Proof details'), data, self).exec()

    # --- Historia -----------------------------------------------------------

    def _refresh_history_view(self) -> None:
        self.history_model.set_entries(self.history.entries)
        total = len(self.history.entries)
        anchored = sum(1 for e in self.history.entries if e.level == Level.ANCHORED.value)
        legacy = sum(1 for e in self.history.entries if e.source == SOURCE_TVS_LEGACY)
        parts = [plural.entries(total),
                 _('%(count)s anchored') % {'count': anchored}]
        if legacy:
            parts.append(_('%(count)s from the TVS archive') % {'count': legacy})
        self.history_summary.setText(' · '.join(parts))
        self._update_history_buttons()

    # --- Katalog danych -----------------------------------------------------

    def _check_data_dir(self) -> None:
        """Sprawdza PRZY STARCIE, czy program ma gdzie zapisac dane.

        Plik probny kosztuje milisekundy i oszczedza sytuacji, w ktorej
        uzytkownik dowiaduje sie o blokadzie dopiero po policzeniu skrotu
        pliku o wielkosci kilku gigabajtow — a swiezy stempel, juz zapisany
        w publicznym rejestrze, przepada razem z nieudanym zapisem historii.
        """
        if self._closing:
            return
        problem = probe_write()
        if problem is not None:
            self._resolve_data_dir(problem)

    def _resolve_data_dir(self, problem: WriteProblem) -> bool:
        """Okno blokady + przyjecie nowego katalogu. `True` = da sie pisac.

        Rezygnacja NIE gasi programu: weryfikacja dowodow, podglad historii
        i eksport dzialaja dalej. Pasek stanu zostaje jednak z ostrzezeniem
        bez terminu waznosci — nowy stempel nie zostanie zapisany, dopoki
        katalog sie nie zmieni, i uzytkownik ma to widziec caly czas.
        """
        chosen = resolve_data_dir_problem(problem, self)
        if chosen is None:
            self.statusBar().showMessage(
                _('BeatStamp cannot save data in %(path)s — new stamps will '
                  'not be recorded in the history until the folder is changed '
                  '(Settings -> Data).') % {'path': problem.directory})
            return False
        self._adopt_data_dir()
        return True

    def _adopt_data_dir(self) -> None:
        """Po zmianie katalogu danych: historia musi pisac w NOWYM miejscu.

        `History` zapamietuje sciezke przy tworzeniu, wiec bez tego wiersza
        program pisalby dalej tam, gdzie zapis wlasnie sie nie udal.
        """
        self.history.path = history_path()
        self.statusBar().showMessage(
            _('Data folder: %(path)s') % {'path': app_data_dir()}, 20_000)

    def _store(self, action, save=None) -> bool:
        """Zapis danych programu z obsluga blokady. `True` = zapisane.

        Jedyne miejsce, przez ktore ida zapisy historii i ustawien. Bez niego
        blokada zapisu wychodzila ze slotu Qt jako nieprzechwycony wyjatek:
        uzytkownik dostawal slad `FileNotFoundError` mowiacy o pliku
        tymczasowym, ktorego nigdy nie widzial, a swiezy stempel przepadal.

        Po zmianie katalogu powtarzamy SAM ZAPIS, a nie cala czynnosc.
        `History.add` najpierw dopisuje wpis do listy w pamieci, a dopiero
        potem zapisuje plik — ponowienie calej czynnosci dolozyloby ten sam
        stempel po raz drugi.
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
            # Drugie niepowodzenie z rzedu: mowimy o nim i konczymy. Kolejne
            # okno z tym samym pytaniem bylaby petla, z ktorej uzytkownik nie
            # ma jak wyjsc.
            problem = describe_write_problem(app_data_dir(), e)
            QMessageBox.warning(self, problem.title, problem.message)
            return False
        return True

    def _report_migration(self) -> None:
        """Mowi o przeprowadzce danych — na pasku stanu, nie okienkiem.

        Przeniesienie plikow na nowe miejsce jest czynnoscia programu, nie
        problemem uzytkownika: nie ma tu decyzji do podjecia ani bledu do
        naprawienia. Modalne okienko przy starcie zatrzymywaloby program,
        zanim glowne okno zdazy sie pokazac (ten sam powod, dla ktorego caly
        ten blok jest odlozony na petle zdarzen). Kto chce szczegolow, ma je
        w dzienniku zdarzen — i w katalogu, ktory otwiera menu Pomoc.
        """
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
        """Szuka `history.json` starego klienta TVS.

        Sprawdzamy dwa miejsca, bo stary program zapisywal historie do
        KATALOGU ROBOCZEGO — czyli tam, skad go uruchomiono. Przy wersji
        skompilowanej bylo to zwykle miejsce, gdzie lezal `tvs_gui.exe`;
        przy uruchomieniu ze zrodel — katalog repozytorium. Szukanie tylko
        obok zrodel dzialaloby więc wyłącznie u programisty, a u uzytkownika
        wersji exe migracja po cichu nie robilaby nic.
        """
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
        # Liczymy z listy, a nie z wyniku funkcji: gdy pierwszy zapis padl na
        # blokadzie, wpisy sa juz w pamieci, a wartosc zwrocona przepadla
        # razem z wyjatkiem.
        added = len(self.history.entries) - before
        try:
            # Sciezke liczymy PONOWNIE: `_store` mogl w miedzyczasie przeniesc
            # katalog danych, a znacznik ma wyladowac tam, gdzie historia.
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
                  'independently, stamp those files again — BeatTime will write '
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
        usable = one and entries[0].source != SOURCE_TVS_LEGACY
        self.history_buttons['pdf'].setEnabled(one)
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
        if entries[0].source != SOURCE_TVS_LEGACY:
            menu.addAction(_('Offline proof (.beatproof)…'), self.history_bundle)
            menu.addAction(_('Check in the browser'), self.history_open_browser)
        menu.addSeparator()
        menu.addAction(_('Details…'), self.history_details)
        menu.addSeparator()
        menu.addAction(_('Remove from history'), self.history_delete)
        menu.exec(self.history_table.viewport().mapToGlobal(position))

    def history_certificate(self) -> None:
        entries = self._selected_entries()
        if entries:
            self._write_certificate(entries[0])

    def history_bundle(self) -> None:
        entries = self._selected_entries()
        if entries:
            self._write_bundle(entries[0])

    def history_details(self) -> None:
        entries = self._selected_entries()
        if entries:
            DetailsDialog(_('Entry details'), bundle.build(entries[0]), self).exec()

    def history_copy_digest(self) -> None:
        entries = self._selected_entries()
        if entries:
            QGuiApplication.clipboard().setText(entries[0].digest)
            self.statusBar().showMessage(_('Digest copied to the clipboard.'), 3000)

    def history_open_browser(self) -> None:
        entries = self._selected_entries()
        if entries:
            webbrowser.open(entries[0].verify_url)

    def history_delete(self) -> None:
        entries = self._selected_entries()
        if not entries:
            return
        if QMessageBox.question(
                self, _('Remove from history?'),
                _('Remove <b>%(entries)s</b> from the local history?<br><br>'
                  'The stamp <b>stays in the public BeatTime register</b> — the '
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
            key_override=self.settings.key_override)
        self._start(task, self._on_refreshed,
                    label_text=_('Refreshing statuses…'))

    def _on_refreshed(self, updated: list) -> None:
        # Ten sam powod co w `_on_stamped`: przerwana w polowie petla zapisow
        # utrwalilaby czesc odswiezonych statusow i zgubila reszte.
        self._store(lambda: self.history.merge(updated), self.history.save)
        self._refresh_history_view()
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
                / _('beatstamp-history.csv')),
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
                _('File write error:<br>%(reason)s') % {'reason': e.strerror or e})
            return
        self._offer_open(target, _('%(entries)s exported')
                         % {'entries': plural.entries(count)})

    # --- Narzedzia ----------------------------------------------------------

    def _sync_clock(self) -> None:
        if self._closing or self._busy():
            return
        task = workers.ClockSyncTask(self.client)
        task.signals.finished.connect(self._on_synced)
        # Synchronizacja jest czynnoscia tla — nie zajmuje paska postepu i nie
        # blokuje uzytkownika, wiec omija `_start`. Blad jest tylko logowany:
        # brak sieci przy starcie nie powinien witac uzytkownika okienkiem.
        task.signals.failed.connect(
            lambda message: self.statusBar().showMessage(
                _('The clock was not synchronised: %(reason)s')
                % {'reason': message}, 8000))
        workers.launch(self.pool, task)

    def _on_synced(self, result) -> None:
        self.clock.apply_sync(result.offset_seconds)
        warning = self.clock.drift_warning
        if warning:
            self.status_connection.setText('⚠ ' + _('clock out of step'))
            self.status_connection.setToolTip(warning)
        else:
            self._update_connection_label()
        self.statusBar().showMessage(
            _('Clock synchronised (difference %(offset)s s, round trip '
              '%(rtt)s ms).') % {'offset': f'{result.offset_seconds:+.2f}',
                                 'rtt': f'{result.round_trip_seconds * 1000:.0f}'},
            6000)

    def check_health(self) -> None:
        self._start(workers.HealthTask(self.client), self._on_health,
                    label_text=_('Checking the service status…'))

    def _on_health(self, data: dict) -> None:
        clock = data.get('clock') or {}
        offset = clock.get('offset')
        status = html.escape(str(data.get('status', '?')))
        source = html.escape(str(clock.get('server', '—')))
        working, broken = _('working'), _('unavailable')
        QMessageBox.information(
            self, _('BeatTime service status'),
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
        # Zakladka „Dane" dziala OD RAZU, a nie po przycisku „Zapisz" (katalog
        # danych nie jest polem `settings.json` — patrz `SettingsDialog._data_tab`).
        # Sprawdzamy wiec takze po rezygnacji: historia musi pisac tam, gdzie
        # dane naprawde sa.
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

        override_changed = new_settings.key_override != self.settings.key_override
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
        if theme_changed:
            theme.apply_theme(QApplication.instance(), self.settings.theme)
        if language_changed:
            self._apply_language()
        if override_changed:
            self._update_connection_label()
            # Wpisy zweryfikowane usunietym (albo zmienionym) wlasnym kluczem
            # nie moga dalej pokazywac „Zakotwiczony" — F5 dociagnie podpis
            # aktualnym kluczem.
            if self.history.demote_untrusted(new_settings.key_override):
                self._refresh_history_view()
            if new_settings.key_override:
                QMessageBox.warning(
                    self, _('Your own public key'),
                    _('Besides the built-in list of BeatTime keys, the '
                      'application will now also accept signatures made with '
                      '<b>the key you entered</b>.<br><br>Whoever gave you that '
                      'key can sign any "proof" with it. The status bar will '
                      'keep reminding you. To go back to the built-in list '
                      'alone, clear the field in Settings -> Trust.'))
        self.statusBar().showMessage(_('Settings saved.'), 4000)

    def _update_connection_label(self) -> None:
        """Pasek stanu ma mówić, jak jest NAPRAWDĘ — nie jak być powinno.

        Dwa ustawienia potrafią po cichu unieważnić gwarancje, które program
        obiecuje na tym samym pasku, i oba są zwykłym tekstem w pliku
        ustawień:

        * proxy Tor pod innym adresem niż lokalny — w trybie `.onion` ruch
          idzie zwykłym HTTP-em, bo szyfrowanie zapewnia Tor. Jeśli po drugiej
          stronie Tora nie ma, jest to ruch jawnym tekstem do cudzej maszyny,
          a nie anonimizacja;
        * własny klucz publiczny obok wbudowanej listy — kotwica zaufania
          przestaje być wyłącznie tą, którą dostarczono z programem.

        Wcześniej pasek w obu przypadkach pokazywał to samo zapewnienie co
        zawsze. Teraz każdy z nich jest widoczny bez otwierania ustawień.
        """
        warnings = []
        if self.settings.key_override:
            warnings.append(_(
                'YOUR OWN public key is set — besides the built-in list of '
                'BeatTime keys the application also accepts signatures made '
                'with that key.'))

        if self.settings.use_tor:
            if self.settings.tor_proxy_is_local:
                text, tip = '🧅 Tor (.onion)', _(
                    'Traffic goes through the Tor network to the BeatTime '
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
            text = f'🔒 {host}'
            tip = _('HTTPS connection with full certificate verification '
                    '(certifi).')

        if warnings:
            self.status_connection.setText('⚠ ' + text.lstrip('🔒🧅⚠ '))
            self.status_connection.setToolTip('\n\n'.join(warnings))
        else:
            self.status_connection.setText(text)
            self.status_connection.setToolTip(tip)

    def _apply_language(self) -> None:
        """Przelacza jezyk i mowi wprost, ze pelna zmiana wymaga restartu.

        Napisy sa wstrzykiwane w konstruktory widgetow, wiec te juz narysowane
        zostaja w poprzednim jezyku. Udawanie, ze zmiana jest natychmiastowa,
        byloby gorsze niz jedno zdanie prawdy: uzytkownik zobaczylby okno
        w dwoch jezykach naraz i uznal to za usterke.

        Komunikat powstaje PO przelaczeniu, wiec jest juz w nowym jezyku —
        czyli w tym, ktorego uzytkownik wlasnie zazadal.
        """
        applied = set_language(self.settings.language)
        log.info('jezyk interfejsu zmieniony na %s (ustawienie %r)',
                 applied, self.settings.language)
        QMessageBox.information(
            self, _('Interface language'),
            _('The new language applies to texts drawn from now on. The whole '
              'window switches after BeatStamp is restarted.'))

    def show_about(self) -> None:
        AboutDialog(self).exec()

    def show_thanks(self) -> None:
        """Okno podziekowan. Lista idzie przez te sama pule watkow co reszta.

        Okno NIE pokazuje sie samo z siebie przy starcie — podziekowanie jest
        do obejrzenia wtedy, gdy ktos chce je obejrzec.
        """
        ThanksDialog(self.client, self.pool, self).exec()

    def show_log(self) -> None:
        LogDialog(self).exec()

    # --- Zdarzenia okna -----------------------------------------------------

    def dragEnterEvent(self, event) -> None:
        # Cale okno przyjmuje pliki — nie tylko strefa upuszczania. Trafienie
        # w prostokat 150 px nie powinno byc warunkiem uzycia programu.
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
        if self.tabs.currentIndex() == 1:
            self._verify_dropped(paths)
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

        try:
            self.settings.window_geometry = bytes(
                self.saveGeometry().toBase64()).decode('ascii')
            self.settings.save()
        except Exception:          # noqa: BLE001 — zamkniecie ma sie udac zawsze
            log.warning('nie udało się zapisać ustawień przy zamknięciu', exc_info=True)

        # Czekamy na watki puli: bez tego proces potrafi zostac w pamieci albo
        # przewrocic sie na obiektach Qt niszczonych spod pracujacego watku.
        self.pool.clear()
        if not self.pool.waitForDone(4000):
            log.warning('wątki robocze nie zakończyły się w czasie 4 s')
        self.client.close()
        super().closeEvent(event)

    def restore_geometry(self) -> None:
        raw = self.settings.window_geometry
        if not raw:
            self.resize(1020, 720)
            return
        try:
            from PySide6.QtCore import QByteArray
            self.restoreGeometry(QByteArray.fromBase64(raw.encode('ascii')))
        except Exception:          # noqa: BLE001
            self.resize(1020, 720)
        # Okno zapisane na monitorze, ktorego juz nie ma, otworzyloby sie poza
        # widocznym obszarem — i wygladalo jak program, ktory sie nie uruchomil.
        screen = QGuiApplication.screenAt(self.geometry().center())
        if screen is None:
            self.resize(1020, 720)
            primary = QGuiApplication.primaryScreen()
            if primary is not None:
                self.move(primary.availableGeometry().center() - self.rect().center())
