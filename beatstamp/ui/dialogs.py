"""Okna pomocnicze: ustawienia, informacje o programie, szczegóły dowodu."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import __version__, keys, supporters, workers
from ..i18n import _, datetime_format, format_iso_date, language_choices
from ..config import (
    DATA_DIR_ENV,
    DEFAULT_BASE_URL,
    DEFAULT_TOR_PROXY,
    IMPRESSUM_URL,
    ONION_BASE_URL,
    PRIVACY_POLICY_URL,
    PYSIDE_SOURCE_URL,
    QT_SOURCE_URL,
    Settings,
    WriteProblem,
    app_data_dir,
    copy_data_to,
    data_dir_for_choice,
    is_inside_onedrive,
    is_packaged,
    log_path,
    probe_write,
    remember_data_dir,
    resource_path,
)
from .widgets import plain_tooltip

log = logging.getLogger(__name__)

def data_dir_button_text() -> str:
    """Napis przycisku „Otworz katalog danych".

    Funkcja, nie stala modulu: stala policzona w czasie importu zamrozilaby
    jezyk na tym, ktory obowiazywal przed wczytaniem ustawien.
    """
    return _('Open data folder')


def data_dir_tooltip() -> str:
    """Podpowiedz z PELNA, prawdziwa sciezka do danych.

    Liczona przy kazdym otwarciu okna, nie raz na import: w wersji przenosnej
    katalog wskazuje zmienna srodowiskowa, a w testach zmienia sie w trakcie.
    """
    return _('History, settings and the event log:\n%(path)s') % {
        'path': app_data_dir()}


def licenses_dir() -> Path:
    """Katalog z pelnymi tekstami licencji — DOSTARCZONY razem z programem.

    Nie odnosnik do sieci. LGPLv3 par. 4(c) mowi o dostarczeniu kopii GNU GPL
    i LGPL razem z kodem wynikowym, a nie o wskazaniu, gdzie ich szukac —
    i ma to sens praktyczny: uzytkownik, ktory chce sprawdzic, na czym stoi
    program sprzed trzech lat, nie zalezy wtedy od tego, czy cudzy serwer
    wciaz odpowiada. W wersji skompilowanej katalog lezy w `_internal/`,
    ze zrodel — obok pakietu.
    """
    return resource_path('licenses')


def open_licenses_dir() -> bool:
    """Otwiera katalog z tekstami licencji w menedzerze plikow."""
    path = licenses_dir()
    if not path.is_dir():
        log.error('katalog z tekstami licencji nie istnieje: %s (spakowany: %s)',
                  path, is_packaged())
        return False
    opened = QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
    if not opened:
        log.warning('nie udało się otworzyć katalogu licencji %s', path)
    return opened


def show_licenses(parent: QWidget | None = None) -> bool:
    """Pokazuje teksty licencji — droga, ktora dziala w OBU wydaniach.

    W wersji przenosnej najprostsza rzecza jest otwarcie katalogu
    w Eksploratorze: uzytkownik dostaje pliki, moze je skopiowac, wydrukowac,
    przeczytac czym chce.

    W wydaniu ze Sklepu ta droga jest zamknieta. Paczka MSIX instaluje sie
    do `C:\\Program Files\\WindowsApps\\<paczka>`, a ten katalog jest
    zastrzezony dla TrustedInstallera — Eksplorator, ktory dziala POZA
    kontenerem paczki (tak samo jak przy `open_data_dir`), pokaze odmowe
    dostepu zamiast tekstow. Sam PROCES aplikacji czyta wlasne pliki bez
    przeszkod, wiec w tym trybie pokazujemy je we wlasnym oknie.

    Teksty sa w paczce w obu wypadkach — tego wymaga LGPLv3 par. 4(c).
    Rzecz w tym, zeby dalo sie do nich dojsc, a nie tylko zeby lezaly.
    """
    if is_packaged():
        dialog = LicensesDialog(parent)
        dialog.exec()
        return True
    return open_licenses_dir()


def open_data_dir() -> bool:
    """Otwiera katalog danych w menedzerze plikow.

    Dwie rzeczy, ktorych brakowalo:

    1. **Katalog musi istnieć.** `QDesktopServices.openUrl` na nieistniejacej
       sciezce nie robi nic albo pokazuje blad systemu — a tak wyglada kazdy
       pierwszy start przed pierwszym zapisem.
    2. **Sciezka musi byc prawdziwa, nie zwirtualizowana.** W paczce MSIX
       Eksplorator dziala POZA kontenerem paczki, wiec adres w `%LOCALAPPDATA%`
       otwieral u niego prawdziwy, PUSTY katalog, podczas gdy aplikacja
       widziala swoja prywatna kopie w `…\\Packages\\<paczka>\\LocalCache`.
       Przycisk pokazywal wtedy pusty folder i wygladal na zepsuty. Odkad dane
       leza poza `AppData` (`config.app_data_dir`), obie strony widza ten sam
       katalog — i wlasnie dlatego ta funkcja nie ma zadnego wyjatku dla MSIX.
    """
    path = app_data_dir()
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass                    # brak katalogu zglosi juz system, przy otwieraniu
    opened = QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
    if not opened:
        log.warning('nie udało się otworzyć katalogu danych %s (spakowany: %s)',
                    path, is_packaged())
    return opened


# --- Zmiana katalogu danych -------------------------------------------------

#: Adresy strony „Ochrona przed ransomware" w Zabezpieczeniach Windows.
#: Dwa, bo pierwszy prowadzi wprost do wlasciwej strony, a drugi — pewny,
#: udokumentowany od Windows 10 — do „Ochrona przed wirusami i zagrozeniami",
#: z ktorej ta strona jest jedno klikniecie dalej. Jesli system nie zna
#: pierwszego adresu, uzytkownik i tak nie zostaje z niczym.
WINDOWS_PROTECTION_URLS = (
    'windowsdefender://RansomwareProtection',
    'windowsdefender://threat',
)


def data_dir_note() -> str:
    """Zdanie o kopii zapasowej — mowione wprost, bo jest kosztem wyboru.

    Katalog danych lezy w korzeniu profilu WLASNIE po to, zeby historia
    stempli nie wedrowala sama do chmury. Druga strona tej decyzji jest taka,
    ze nie obejmuje jej ani OneDrive, ani Kopia zapasowa Windows — i lepiej,
    zeby uzytkownik uslyszal to od programu niz po awarii dysku.
    """
    return _('This folder is outside OneDrive and outside Windows Backup, so '
             'the stamp history is not copied anywhere by itself. If it '
             'matters to you, make your own copy of the folder.')


def open_windows_protection_settings() -> bool:
    """Otwiera ustawienia ochrony przed ransomware. Zwraca, czy cokolwiek poszlo."""
    for url in WINDOWS_PROTECTION_URLS:
        if QDesktopServices.openUrl(QUrl(url)):
            return True
    log.warning('nie udało się otworzyć ustawień ochrony Windows')
    return False


def choose_data_dir(parent: QWidget | None = None,
                    start: Path | None = None) -> Path | None:
    """Okno wyboru folderu. Zwraca KATALOG DANYCH albo `None` (rezygnacja).

    Uzytkownik wskazuje miejsce, a `config.data_dir_for_choice` dokłada
    podkatalog `BeatStamp` — dzieki temu wskazanie `D:\\` nie wysypuje
    plikow programu do korzenia dysku.
    """
    base = start if start is not None else app_data_dir().parent
    directory = QFileDialog.getExistingDirectory(
        parent, _('Choose a folder for BeatStamp data'), str(base))
    if not directory:
        return None
    return data_dir_for_choice(Path(directory))


def switch_data_dir(target: Path, parent: QWidget | None = None) -> bool:
    """Przenosi dane do wskazanego katalogu i zapamietuje wybor.

    Kolejnosc kroków nie jest dowolna:

    1. **Najpierw proba zapisu.** Katalog, ktory nie przyjmuje zapisu, nie ma
       prawa zostac zapamietany — inaczej zamienilibysmy jedna blokade na
       druga, tyle ze trwala.
    2. **Potem kopia danych.** KOPIA: stary katalog zostaje nietkniety.
       Uzytkownik, ktory sie rozmysli, ma komplet w poprzednim miejscu.
    3. **Na koncu wskaznik.** Gdy zapisanie wskaznika sie nie uda, katalog
       dziala do konca sesji, a program mowi wprost, ze nastepny start wroci
       do poprzedniego miejsca — zamiast milczec i zgubic dane z oczu.
    """
    target = Path(target)
    problem = probe_write(target)
    if problem is not None:
        QMessageBox.warning(parent, problem.title, problem.message)
        return False

    if is_inside_onedrive(target):
        answer = QMessageBox.question(
            parent, _('This folder is inside OneDrive'),
            _('The stamp history is a list of your documents: their names and '
              'their digests. In this folder OneDrive will copy it to the '
              'cloud and to your other computers.\n\n'
              'Use this folder anyway?') + '\n\n' + str(target),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return False

    previous = app_data_dir()
    report = copy_data_to(target)
    remembered = remember_data_dir(target)

    lines = [_('The data folder is now:') + f'\n{target}']
    if report.copied or report.kept_aside:
        lines.append(_('The files were copied. The previous folder was left '
                       'untouched: %(path)s') % {'path': previous})
    if report.failed:
        lines.append(_('Some files could not be copied: %(names)s. The '
                       'originals stayed in the previous folder.')
                     % {'names': ', '.join(report.failed)})
    if not remembered:
        lines.append(_('The choice could not be written down, so the next '
                       'start will go back to the previous folder.'))
    lines.append(data_dir_note())
    QMessageBox.information(parent, _('Data folder'), '\n\n'.join(lines))
    log.info('katalog danych zmieniony na %s (skopiowano %s, nie udalo sie %s, '
             'wskaznik zapisany: %s)', target, report.copied, report.failed,
             remembered)
    return True


def switch_data_dir_interactively(parent: QWidget | None = None) -> bool:
    """Wybor folderu + przeprowadzka. Zwraca, czy katalog naprawde sie zmienil."""
    target = choose_data_dir(parent)
    if target is None:
        return False
    return switch_data_dir(target, parent)


class DataDirProblemDialog(QDialog):
    """Okno pokazywane zamiast sladu wyjatku, gdy zapis danych jest zablokowany.

    Dlaczego wlasne okno, a nie `QMessageBox`: przycisk „ustawienia Windows"
    NIE MOZE zamykac okna. Uzytkownik idzie do Zabezpieczen Windows, dodaje
    program do dozwolonych i wraca — a wtedy ma tu czekac przycisk „Sprawdz
    jeszcze raz". `QMessageBox` zamyka sie po kazdym klinieciu, wiec cala ta
    droga wymagalaby wywolywania okna od nowa.

    Po zamknieciu `chosen` trzyma katalog, ktory DZIALA (ten sam, jesli
    blokade zdjeto, albo nowo wybrany), albo `None`, jesli uzytkownik
    zrezygnowal.
    """

    def __init__(self, problem: WriteProblem, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(problem.title)
        self.setMinimumWidth(560)
        self._problem = problem
        self.chosen: Path | None = None

        self._text = QLabel(problem.message)
        # Tekst PROSTY: komunikat niesie sciezki (`C:\...`) i lamania wiersza,
        # a nie znaczniki. Przy autowykrywaniu Qt potrafi uznac go za tekst
        # wzbogacony i zjesc czesc tresci.
        self._text.setTextFormat(Qt.PlainText)
        self._text.setWordWrap(True)
        self._text.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self._hint = QLabel(_('In Windows Security open: Virus & threat '
                              'protection > Ransomware protection > Allow an '
                              'app through Controlled folder access.'))
        self._hint.setObjectName('hint')
        self._hint.setTextFormat(Qt.PlainText)
        self._hint.setWordWrap(True)

        self._choose_button = QPushButton(_('Pick another folder…'))
        self._choose_button.setToolTip(_('The data are copied to the new '
                                         'folder; nothing is deleted from the '
                                         'old one.'))
        self._choose_button.clicked.connect(self._pick_folder)

        self._settings_button = QPushButton(_('Windows protection settings…'))
        self._settings_button.setToolTip(_('Opens Windows Security, where '
                                           'BeatStamp can be allowed to write '
                                           'to protected folders.'))
        self._settings_button.clicked.connect(
            lambda: open_windows_protection_settings())

        self._retry_button = QPushButton(_('Check again'))
        self._retry_button.setToolTip(_('Tries to write a test file to the '
                                        'folder once more.'))
        self._retry_button.clicked.connect(self._retry)

        close = QPushButton(_('Close'))
        close.clicked.connect(self.reject)

        buttons = QHBoxLayout()
        buttons.addWidget(self._choose_button)
        buttons.addWidget(self._settings_button)
        buttons.addWidget(self._retry_button)
        buttons.addStretch(1)
        buttons.addWidget(close)

        layout = QVBoxLayout(self)
        layout.addWidget(self._text)
        layout.addWidget(self._hint)
        layout.addSpacing(6)
        layout.addLayout(buttons)
        self._apply(problem)

    def _apply(self, problem: WriteProblem) -> None:
        self._problem = problem
        self._text.setText(problem.message)
        self._hint.setVisible(problem.protected)

    def _pick_folder(self) -> None:
        target = choose_data_dir(self, self._problem.directory.parent)
        if target is None:
            return
        if not switch_data_dir(target, self):
            # Nowy katalog tez nie przyjmuje zapisu — komunikat pokazal juz
            # `switch_data_dir`. Okno zostaje otwarte, zeby dalo sie wskazac
            # nastepny, zamiast zaczynac cala droge od nowa.
            return
        self.chosen = target
        self.accept()

    def _retry(self) -> None:
        problem = probe_write(self._problem.directory)
        if problem is None:
            self.chosen = self._problem.directory
            QMessageBox.information(
                self, _('Data folder'),
                _('BeatStamp can write to this folder again:') +
                f'\n\n{self._problem.directory}')
            self.accept()
            return
        self._apply(problem)


def resolve_data_dir_problem(problem: WriteProblem,
                             parent: QWidget | None = None) -> Path | None:
    """Pokazuje okno blokady. Zwraca dzialajacy katalog albo `None`."""
    dialog = DataDirProblemDialog(problem, parent)
    dialog.exec()
    return dialog.chosen


class SettingsDialog(QDialog):
    """Ustawienia aplikacji. Kazde pole ma podpowiedz mowiaca, po co jest.

    Swiadomie NIE ma tu przelacznika "wyłącz weryfikacje TLS". Poprzednik nie
    miał go rowniez, ale nie miał tez zadnej kontroli — a pole, które jednym
    klikiem zdejmuje szyfrowanie z calego ruchu, predzej czy później zostaje
    kliknięte przy pierwszym bledzie sieci. Problemy z certyfikatem rozwiązuje
    się u źródła, nie wylaczeniem sprawdzania.
    """

    def __init__(self, settings: Settings, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(_('Settings — BeatStamp'))
        self.setMinimumWidth(560)
        self._settings = settings

        tabs = QTabWidget()
        tabs.addTab(self._connection_tab(), _('Connection'))
        tabs.addTab(self._trust_tab(), _('Trust'))
        tabs.addTab(self._behaviour_tab(), _('Behaviour'))
        tabs.addTab(self._data_tab(), _('Data'))

        buttons = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel | QDialogButtonBox.RestoreDefaults)
        buttons.button(QDialogButtonBox.Save).setText(_('Save'))
        buttons.button(QDialogButtonBox.Cancel).setText(_('Cancel'))
        buttons.button(QDialogButtonBox.RestoreDefaults).setText(_('Restore defaults'))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.RestoreDefaults).clicked.connect(self._restore_defaults)

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)

    # --- Zakladki ---

    def _connection_tab(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)
        form.setLabelAlignment(Qt.AlignRight)

        self.base_url = QLineEdit(self._settings.base_url)
        self.base_url.setToolTip(
            _('Address of the BeatTime server. It must start with https://\n'
              'Default value: %(default)s\n\n'
              'Change it only if you use your own instance.')
            % {'default': DEFAULT_BASE_URL})
        form.addRow(_('API address:'), self.base_url)

        self.use_tor = QCheckBox(_('Connect through the Tor network (.onion service)'))
        self.use_tor.setChecked(self._settings.use_tor)
        self.use_tor.setToolTip(_(
            'Routes traffic through a local Tor proxy to the BeatTime hidden '
            'service.\n\n'
            'What for: the server does not learn your IP address, so stamps\n'
            'cannot be tied to you through the connection. The digest itself\n'
            'says nothing about the content of the document anyway.\n\n'
            'Requires a running Tor Browser or tor service on this computer.'))
        form.addRow('', self.use_tor)

        onion = QLabel(ONION_BASE_URL)
        onion.setObjectName('mono')
        onion.setTextInteractionFlags(Qt.TextSelectableByMouse)
        onion.setWordWrap(True)
        form.addRow(_('.onion address:'), onion)

        self.tor_proxy = QLineEdit(self._settings.tor_proxy)
        self.tor_proxy.setToolTip(
            _('Address of the local SOCKS proxy. Default: %(default)s\n\n'
              'Tor Browser usually listens on port 9150, and the system tor\n'
              'service on 9050. The socks5h prefix means the .onion name is\n'
              'resolved by the Tor network, not by your computer (otherwise\n'
              'the address would leak to your internet provider).')
            % {'default': DEFAULT_TOR_PROXY})
        form.addRow(_('Tor proxy:'), self.tor_proxy)

        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(3.0, 120.0)
        self.timeout.setSingleStep(1.0)
        self.timeout.setSuffix(' s')
        self.timeout.setValue(self._settings.timeout_seconds)
        self.timeout.setToolTip(_(
            'How long to wait for the server answer. Over Tor it is worth\n'
            'raising to 30-60 s — the traffic goes through several relays.'))
        form.addRow(_('Time limit:'), self.timeout)

        self.use_tor.toggled.connect(self._sync_tor_fields)
        self._sync_tor_fields(self.use_tor.isChecked())
        return page

    def _trust_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        explain = QLabel(_(
            'BeatTime signs weekly Merkle roots with an Ed25519 key. The '
            'application checks that signature <b>locally</b> and compares the '
            'key with the <b>built-in list of BeatTime keys</b> — never with '
            'whatever the server sends.<br><br>'
            'Without that, the signature alone would prove nothing: a fake '
            'server would send its own key together with a matching signature '
            'and everything would add up. A signature from a <b>retired</b> key '
            'is not enough either — such a proof has to be refreshed online so '
            'that it gets a signature made with the current key.'))
        explain.setWordWrap(True)
        explain.setObjectName('hint')
        layout.addWidget(explain)

        builtin = QGroupBox(_('Built-in BeatTime keys'))
        builtin_layout = QVBoxLayout(builtin)
        lines = [_('<b>current</b> since %(date)s: '
                   '<span style="font-family:monospace">%(key)s</span>')
                 % {'date': format_iso_date(k['active_from']),
                    'key': k['public_key']}
                 for k in reversed(keys.CURRENT_KEYS)]
        lines += [_('retired %(date)s: '
                    '<span style="font-family:monospace">%(key)s</span>')
                  % {'date': format_iso_date(k['retired_on']),
                     'key': k['public_key']}
                  for k in reversed(keys.RETIRED_KEYS)]
        # Wartosci pochodza wylacznie z keys.py (stale w kodzie), wiec tekst
        # wzbogacony jest tu bezpieczny.
        key_list = QLabel('<br>'.join(lines))
        key_list.setTextFormat(Qt.RichText)
        key_list.setTextInteractionFlags(Qt.TextSelectableByMouse)
        key_list.setWordWrap(True)
        key_list.setToolTip(_(
            'The key history shipped with this version of the program.\n'
            'Public list: beattime.live/spec/#keys'))
        builtin_layout.addWidget(key_list)
        layout.addWidget(builtin)

        box = QGroupBox(_('Your own public key (advanced)'))
        box_layout = QVBoxLayout(box)
        self.pinned_key = QLineEdit(keys.normalize_override(
            self._settings.pinned_public_key))
        self.pinned_key.setObjectName('mono')
        self.pinned_key.setPlaceholderText(_('built-in list of keys'))
        self.pinned_key.setToolTip(_(
            'An additional Ed25519 public key in base64 (32 bytes).\n\n'
            'Leave it empty — the program knows the BeatTime keys itself.\n'
            'Fill it in only when BeatTime announces a new key before a new\n'
            'version of the program is released — and only with a value\n'
            'confirmed from an independent source. A retired key cannot be\n'
            'entered.'))
        box_layout.addWidget(self.pinned_key)

        row = QHBoxLayout()
        restore = QPushButton(_('Restore the built-in list'))
        restore.setToolTip(_(
            'Clears your own key — verification then uses only the keys shipped '
            'with this version of the program'))
        restore.clicked.connect(self.pinned_key.clear)
        row.addWidget(restore)
        row.addStretch(1)
        box_layout.addLayout(row)
        layout.addWidget(box)

        warning = QLabel('⚠ ' + _(
            'Your own key is accepted <b>alongside</b> the built-in list and is '
            'permanently visible in the status bar. Whoever slips you their key '
            'can sign any "proof" with it.'))
        warning.setWordWrap(True)
        warning.setObjectName('hint')
        layout.addWidget(warning)
        layout.addStretch(1)
        return page

    def _behaviour_tab(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)
        form.setLabelAlignment(Qt.AlignRight)

        self.language = QComboBox()
        for value, text in language_choices():
            self.language.addItem(text, value)
        index = self.language.findData(self._settings.language)
        self.language.setCurrentIndex(index if index >= 0 else 0)
        self.language.setToolTip(_(
            'Interface language. "Same as system" follows the language of the\n'
            'Windows interface (not the regional format).\n\n'
            'Texts already drawn on screen keep the previous language until\n'
            'the program is restarted.'))
        form.addRow(_('Language:'), self.language)

        self.theme = QComboBox()
        for value, text in (('auto', _('Same as system')),
                            ('light', _('Light')), ('dark', _('Dark'))):
            self.theme.addItem(text, value)
        index = self.theme.findData(self._settings.theme)
        self.theme.setCurrentIndex(index if index >= 0 else 0)
        self.theme.setToolTip(_('Colour theme. The change takes effect at once.'))
        form.addRow(_('Theme:'), self.theme)

        self.auto_verify = QCheckBox(_('Verify the proof right after stamping'))
        self.auto_verify.setChecked(self._settings.auto_verify_after_stamp)
        self.auto_verify.setToolTip(_(
            'After the digest is registered the application immediately checks\n'
            'the inclusion path and the signature — locally, without another '
            'request.'))
        form.addRow('', self.auto_verify)

        self.name_after_source = QCheckBox(
            _('Name certificates after the source file'))
        self.name_after_source.setChecked(self._settings.name_cert_after_source)
        self.name_after_source.setToolTip(_(
            'The certificate gets the name "document_beattime.pdf" instead of\n'
            'asking for it every time.'))
        form.addRow('', self.name_after_source)

        self.confirm_overwrite = QCheckBox(
            _('Ask before overwriting an existing file'))
        self.confirm_overwrite.setChecked(self._settings.confirm_overwrite)
        self.confirm_overwrite.setToolTip(_(
            'The previous version of the program overwrote certificates '
            'silently\nwhen a file of the same name was already in the '
            'folder.'))
        form.addRow('', self.confirm_overwrite)

        self.history_limit = QSpinBox()
        self.history_limit.setRange(0, 1_000_000)
        self.history_limit.setSingleStep(500)
        self.history_limit.setValue(self._settings.history_limit)
        self.history_limit.setSpecialValueText(_('no limit'))
        self.history_limit.setToolTip(_(
            'Upper ceiling on the number of entries in the local history. Above\n'
            'it the OLDEST entries are removed. 0 = no limit.\n\n'
            'The proof itself is in the public BeatTime register — removing an\n'
            'entry from the local history does not delete the stamp.'))
        form.addRow(_('History limit:'), self.history_limit)
        return page

    def _data_tab(self) -> QWidget:
        """Gdzie leza dane i jak to zmienic.

        Lokalizacja danych NIE JEST polem `Settings`, i nie moze nim byc:
        `settings.json` lezy w katalogu danych, wiec zapisany w nim adres tego
        katalogu bylby nie do odczytania, zanim sie go zna. Wybor idzie do
        osobnego wskaznika (`config.LOCATION_FILE`) i dlatego ta zakladka
        dziala OD RAZU — nie czeka na przycisk „Zapisz" i nie cofa jej
        „Przywroc domyslne".
        """
        page = QWidget()
        layout = QVBoxLayout(page)

        explain = QLabel(_(
            'BeatStamp keeps the stamp history, the settings and the event log '
            'in one folder. The proofs themselves live in the public BeatTime '
            'register, but the history is the only record of WHAT you stamped '
            'and when — it exists nowhere else.'))
        explain.setWordWrap(True)
        explain.setObjectName('hint')
        layout.addWidget(explain)

        row = QHBoxLayout()
        self.data_dir_field = QLineEdit(str(app_data_dir()))
        self.data_dir_field.setReadOnly(True)
        self.data_dir_field.setObjectName('mono')
        self.data_dir_field.setToolTip(_(
            'The current data folder. Changing it copies the files to the new '
            'place and checks straight away that writing works there — the old '
            'folder is left untouched.'))
        row.addWidget(self.data_dir_field, 1)

        self.data_dir_change = QPushButton(_('Change…'))
        self.data_dir_change.setToolTip(self.data_dir_field.toolTip())
        self.data_dir_change.clicked.connect(self._change_data_dir)
        row.addWidget(self.data_dir_change)

        open_button = QPushButton(data_dir_button_text())
        open_button.setToolTip(data_dir_tooltip())
        open_button.clicked.connect(lambda: open_data_dir())
        row.addWidget(open_button)
        layout.addLayout(row)

        note = QLabel(data_dir_note())
        note.setWordWrap(True)
        note.setObjectName('hint')
        layout.addWidget(note)

        # Zmienna srodowiskowa ma pierwszenstwo przed wyborem uzytkownika
        # (`config.resolved_data_dir`). Gdyby przycisk dzialal mimo niej,
        # uzytkownik zobaczylby komunikat „katalog zmieniony", a program
        # pisalby dalej w poprzednim miejscu.
        if (os.environ.get(DATA_DIR_ENV) or '').strip():
            self.data_dir_change.setEnabled(False)
            forced = QLabel(_('The folder is set for this run by the '
                              '%(name)s environment variable, so it cannot be '
                              'changed here.') % {'name': DATA_DIR_ENV})
            forced.setWordWrap(True)
            forced.setObjectName('hint')
            layout.addWidget(forced)

        layout.addStretch(1)
        return page

    def _change_data_dir(self) -> None:
        if switch_data_dir_interactively(self):
            self.data_dir_field.setText(str(app_data_dir()))

    def _sync_tor_fields(self, enabled: bool) -> None:
        self.tor_proxy.setEnabled(enabled)
        self.base_url.setEnabled(not enabled)

    def _restore_defaults(self) -> None:
        defaults = Settings()
        self.base_url.setText(defaults.base_url)
        self.use_tor.setChecked(defaults.use_tor)
        self.tor_proxy.setText(defaults.tor_proxy)
        self.timeout.setValue(defaults.timeout_seconds)
        self.pinned_key.setText(keys.normalize_override(defaults.pinned_public_key))
        self.language.setCurrentIndex(max(0, self.language.findData(defaults.language)))
        self.theme.setCurrentIndex(max(0, self.theme.findData(defaults.theme)))
        self.auto_verify.setChecked(defaults.auto_verify_after_stamp)
        self.name_after_source.setChecked(defaults.name_cert_after_source)
        self.confirm_overwrite.setChecked(defaults.confirm_overwrite)
        self.history_limit.setValue(defaults.history_limit)

    # --- Wynik ---

    def validate(self) -> tuple[str, str] | None:
        """Sprawdza wprowadzone wartości. Zwraca (tytul, tresc) bledu albo None.

        Czysta funkcja, bez rysowania czegokolwiek — dzieki temu regule
        "adres musi być po HTTPS" da się przetestowac bez uruchamiania okna
        dialogowego (i bez ryzyka, ze test zawisnie na modalnym okienku).
        """
        url = self.base_url.text().strip() or DEFAULT_BASE_URL
        if not self.use_tor.isChecked() and not url.lower().startswith('https://'):
            return (_('Invalid address'),
                    _('The API address must start with <b>https://</b>.<br><br>'
                      'An unencrypted connection exposes digests and answers to '
                      'being swapped on the way.'))
        key = self.pinned_key.text().strip()
        if key and not _looks_like_ed25519_key(key):
            return (_('Invalid key'),
                    _('An Ed25519 public key is 32 bytes written in canonical '
                      'base64 — 44 characters ending with "=".<br><br>'
                      'Leave the field empty to use the built-in list of '
                      'BeatTime keys (recommended).'))
        info = keys.retired_info(key)
        if info is not None:
            return (_('Retired key'),
                    _('This BeatTime key was retired on %(date)s and cannot be '
                      'accepted — a signature made with it is no longer a '
                      'proof.<br><br>'
                      'Leave the field empty to use the built-in list of keys.')
                    % {'date': format_iso_date(info['retired_on'])})
        return None

    def accept(self) -> None:
        problem = self.validate()
        if problem is not None:
            QMessageBox.warning(self, problem[0], problem[1])
            return
        super().accept()

    def result_settings(self) -> Settings:
        return replace(
            self._settings,
            base_url=self.base_url.text().strip() or DEFAULT_BASE_URL,
            use_tor=self.use_tor.isChecked(),
            tor_proxy=self.tor_proxy.text().strip() or DEFAULT_TOR_PROXY,
            timeout_seconds=float(self.timeout.value()),
            pinned_public_key=keys.normalize_override(self.pinned_key.text()),
            language=str(self.language.currentData()),
            theme=str(self.theme.currentData()),
            auto_verify_after_stamp=self.auto_verify.isChecked(),
            name_cert_after_source=self.name_after_source.isChecked(),
            confirm_overwrite=self.confirm_overwrite.isChecked(),
            history_limit=int(self.history_limit.value()),
        )


def _looks_like_ed25519_key(value: str) -> bool:
    """32 bajty w KANONICZNYM base64 (keys.canonical).

    Sam `b64decode(validate=True)` przyjmuje niezerowe bity dopelnienia, czyli
    alias tego samego klucza (`...yN0=` i `...yN1=`). Taki alias klucza
    wycofanego omijal sprawdzenie „klucz wycofany" ponizej.
    """
    return bool(keys.canonical(value))


def open_url(url: str) -> bool:
    """Otwiera adres w przegladarce systemowej. Zwraca, czy sie udalo.

    Jedno miejsce dla calego programu — takze dla menu Pomoc — zeby
    niepowodzenie (brak przegladarki domyslnej, zablokowane `ShellExecute`
    w srodowisku firmowym) zostawialo slad w dzienniku, a nie znikalo.
    """
    opened = QDesktopServices.openUrl(QUrl(url))
    if not opened:
        log.warning('nie udało się otworzyć adresu %s w przeglądarce', url)
    return opened


def link_button(text: str, url: str) -> QPushButton:
    """Przycisk wygladajacy jak odnosnik, otwierajacy `url` w przegladarce."""
    button = QPushButton(text)
    button.setObjectName('link')
    button.setToolTip(_('Opens in the browser: %(url)s') % {'url': url})
    button.setCursor(Qt.PointingHandCursor)
    button.setProperty('url', url)
    button.clicked.connect(lambda checked=False, target=url: open_url(target))
    return button


class AboutDialog(QDialog):
    """O programie — z uczciwym opisem tego, co dowód znaczy, a czego nie."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(_('About — BeatStamp'))
        self.setMinimumWidth(560)

        title = QLabel(f'<b style="font-size:14pt">BeatStamp {__version__}</b>')
        subtitle = QLabel(_('@beat timestamps for local files'))
        subtitle.setObjectName('hint')

        body = QLabel(_(
            '<p>Registers the SHA-256 digest of a document in the public, '
            'append-only <b>BeatTime</b> register, giving proof that the file '
            'existed at a given moment and has not been changed since.</p>'

            '<p><b>The document never leaves this computer.</b> Only the '
            '64-character digest goes to the network — the content, or even the '
            'file name, cannot be recovered from it.</p>'

            '<p><b>How the proof matures</b><br>'
            '1. <b>Recorded</b> — the digest reaches the register, the timestamp '
            'is already final.<br>'
            '2. <b>Signed</b> — after the week closes (Monday 00:00 UTC) the '
            'Merkle root is frozen and signed with an Ed25519 key.<br>'
            '3. <b>Anchored</b> — the root goes into the Bitcoin chain '
            '(OpenTimestamps) and is confirmed by an independent bank '
            'transfer.</p>'

            '<p><b>What the proof does NOT attest:</b> the authorship of the '
            'document or the truth of its content. It attests only existence in '
            'time and integrity.</p>'

            '<p>Verification is possible <b>without this application</b>: at '
            'beattime.live/proof, from a <code>.beatproof</code> file with any '
            'tool that computes SHA-256 and Ed25519, or from an <code>.ots</code> '
            'file with an OpenTimestamps client.</p>'))
        body.setWordWrap(True)
        body.setTextFormat(Qt.RichText)

        # Poprzednik tego programu. Jedno zdanie, bez ocen: TimeVaultSecure
        # jest wczesniejszym produktem TEGO SAMEGO autora, a BeatStamp
        # przejmuje jego historie — ktos, kto widzi w programie wpisy
        # oznaczone „archiwum TVS", ma prawo wiedziec, skad sie tam wziely.
        lineage = QLabel(_(
            'TimeVaultSecure (timevaultsecure.com) is an earlier product by '
            'the same author, and BeatStamp carries over the history it left '
            'behind.'))
        lineage.setObjectName('hint')
        lineage.setWordWrap(True)

        # Wymog LGPLv3 par. 4(a)(b)(c). Trzy rzeczy, ktore MUSZA byc widoczne,
        # a nie „gdzies w dokumentacji": ze program uzywa Qt i PySide6, czyje
        # to prawa autorskie i gdzie sa pelne teksty licencji — dostarczone
        # razem z programem, nie za odnosnikiem. Punkt (d), czyli zrodla samych
        # bibliotek, niosa dwa przyciski pod spodem i plik `NOTICE`.
        # Zdanie o relinkowaniu MUSI zalezec od wydania. W wersji przenosnej
        # biblioteki leza w `_internal/` i wolno je podmienic. W wydaniu ze
        # Sklepu paczka instaluje sie do `C:\Program Files\WindowsApps`:
        # katalog jest zastrzezony dla TrustedInstallera, a zawartosc
        # zwiazana podpisem paczki — obietnica podmiany pliku bylaby tam
        # po prostu nieprawdziwa.
        if is_packaged():
            relinking = _(
                'They are used unmodified and linked dynamically. This copy '
                'comes from the Microsoft Store, so its files cannot be '
                'exchanged in place — the package is installed read-only and '
                'bound to its signature. To run this program against your own '
                'build of Qt, use the portable release of the same version, '
                'where the libraries sit in the <code>_internal</code> folder '
                'next to the program; the notices below say how to obtain it.')
        else:
            relinking = _(
                'They are used unmodified and linked dynamically: the '
                'libraries sit in the <code>_internal</code> folder next to '
                'the program and may be replaced with your own build of the '
                'same version.')

        third_party = QLabel(_(
            '<p><b>Third-party software.</b> BeatStamp uses the <b>Qt</b> and '
            '<b>PySide6</b> libraries (copyright (C) The Qt Company Ltd. and '
            'other contributors) under the <b>GNU Lesser General Public '
            'License, version 3</b>. %(relinking)s</p>'

            '<p>Qt itself contains third-party code, among others FreeType: '
            'portions of this software are copyright (c) 2025 The FreeType '
            'Project (https://freetype.org), all rights reserved. The notices '
            'of the other components are delivered with the program.</p>'

            '<p>The full licence texts — including the GNU GPL and the GNU '
            'LGPL — and the list of every file in this package with its '
            'licence are delivered together with the program, and the button '
            'below opens them. The rest of BeatStamp is published under the '
            'Apache License 2.0.</p>') % {'relinking': relinking})
        third_party.setWordWrap(True)
        third_party.setTextFormat(Qt.RichText)

        sources = QHBoxLayout()
        for text, url in ((_('Qt sources'), QT_SOURCE_URL),
                          (_('PySide6 sources'), PYSIDE_SOURCE_URL)):
            sources.addWidget(link_button(text, url))
        sources.addStretch(1)

        notices = QPushButton(_('Licences and notices'))
        notices.setToolTip(_(
            'Shows the full licence texts delivered with the program:\n'
            '%(path)s') % {'path': licenses_dir()})
        notices.clicked.connect(lambda: show_licenses(self))

        links = QHBoxLayout()
        for text, url in (('beattime.live', 'https://beattime.live'),
                          (_('API documentation'), 'https://beattime.live/docs/'),
                          (_('Public register'), 'https://beattime.live/proof/')):
            links.addWidget(link_button(text, url))
        links.addStretch(1)

        # Impressum i ochrona danych sa TAKZE w menu Pomoc — tam sa dwa
        # klikniecia od okna glownego, czego wymaga § 5 DDG. Tutaj powtarzamy
        # je dlatego, ze „O programie" jest miejscem, w ktorym ludzie szukaja
        # informacji o wydawcy; brak ich w tym oknie wygladalby na przemilczenie.
        legal = QHBoxLayout()
        for text, url in ((_('Legal notice (Impressum)'), IMPRESSUM_URL),
                          (_('Privacy policy'), PRIVACY_POLICY_URL)):
            legal.addWidget(link_button(text, url))
        legal.addStretch(1)

        folder = QPushButton(data_dir_button_text())
        folder.setToolTip(data_dir_tooltip())
        folder.clicked.connect(lambda: open_data_dir())

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Close).setText(_('Close'))
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(8)
        layout.addWidget(body)
        layout.addWidget(lineage)
        layout.addLayout(links)
        layout.addSpacing(8)
        layout.addWidget(third_party)
        layout.addLayout(sources)
        layout.addLayout(legal)
        layout.addSpacing(6)
        layout.addWidget(notices)
        layout.addWidget(folder)
        layout.addWidget(buttons)


class ThanksDialog(QDialog):
    """Podziekowanie dla osob, ktore wsparly BeatTime i zgodzily sie na nazwe.

    Co to okno robi inaczej niz reszta programu:

    * **Nic nie dzieje sie w watku interfejsu.** Lista idzie przez ten sam
      `QThreadPool` i te sama klase zadan (`workers.SupportersTask`), co
      stemplowanie — z limitami czasu, trybem Tor i sufitem rozmiaru
      odpowiedzi z `api.BeatTimeClient`.
    * **Kopia listy ma termin waznosci.** Zgoda ze strony obiecuje, ze
      wycofanie dziala „w kazdej chwili", wiec kopia starsza niz doba nie
      jest pokazywana w ogole (`supporters.load_cache`), a po godzinie —
      tyle, ile `Cache-Control` endpointu — okno pyta serwer o nowa wersje.
    * **Kazdy stan jest nazwany.** Pusta lista (dzis tak wlasnie jest),
      brak sieci i zla odpowiedz maja wlasne zdanie; zadne z nich nie udaje
      wieczystego „wczytywanie…". Pilnuje tego takze `LOAD_TIMEOUT_MS`:
      pula ma jeden watek, wiec zapytanie moze czekac za dlugim zadaniem.
    * **Nazwy pochodza z sieci, wiec sa tekstem ZWYKLYM.** Ida do
      `QListWidget` (ktory nie zna tekstu wzbogaconego), pasek stanu ma
      wymuszony `Qt.PlainText`, a podpowiedzi przechodza przez
      `widgets.plain_tooltip`. Sama tresc jest wczesniej obcieta
      i oczyszczona w `supporters.parse`.
    """

    #: Po tym czasie okno przestaje mowic „wczytuje" i proponuje ponowienie.
    #: Wartosc z zapasem na komplet ponowien `api.BeatTimeClient` (do ~60 s)
    #: plus czekanie w kolejce puli.
    LOAD_TIMEOUT_MS = 90_000

    def __init__(self, client, pool, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(_('Thank you — BeatStamp'))
        self.setMinimumWidth(460)
        self._client = client
        self._pool = pool
        self._loading = False
        self._shown: supporters.ThanksList | None = None

        title = QLabel(f'<b style="font-size:14pt">{_("Thank you")}</b>')
        subtitle = QLabel(_('People who support BeatTime and agreed to be '
                            'named here'))
        subtitle.setObjectName('hint')
        subtitle.setWordWrap(True)

        note = QLabel(_('A thank-you at our discretion — not an entitlement '
                        'and not something a payment buys.'))
        note.setObjectName('faint')
        note.setWordWrap(True)

        source = QLabel(_(
            'The names come from a public list on beattime.live. Everyone on '
            'it asked to be named and can withdraw at any time, so BeatStamp '
            'reloads the list at least once a day and keeps no copy older '
            'than that.'))
        source.setObjectName('faint')
        source.setWordWrap(True)

        self.names = QListWidget()
        self.names.setSelectionMode(QListWidget.NoSelection)
        self.names.setFocusPolicy(Qt.NoFocus)
        self.names.setMinimumHeight(180)
        self.names.setToolTip(plain_tooltip(_(
            'The list is downloaded from beattime.live — it is not part of '
            'the installed program.')))

        self.status = QLabel()
        self.status.setObjectName('hint')
        self.status.setWordWrap(True)
        # Tresc paska stanu niesie komunikaty bledow i daty — nic z tego nie
        # ma prawa trafic do parsera tekstu wzbogaconego Qt.
        self.status.setTextFormat(Qt.PlainText)

        self.refresh = QPushButton(_('Refresh'))
        self.refresh.setToolTip(_('Downloads the list from beattime.live again'))
        self.refresh.clicked.connect(lambda: self._fetch(force=True))

        # Zegar pilnujacy, zeby okno nie zostalo na zawsze w stanie
        # „wczytywanie…". Nalezy do okna (a nie `QTimer.singleShot`), wiec
        # ginie razem z nim i da sie go zatrzymac, gdy odpowiedz przyjdzie
        # wczesniej — inaczej spozniony strzal z POPRZEDNIEGO zapytania
        # gasilby stan biezacego.
        self._watchdog = QTimer(self)
        self._watchdog.setSingleShot(True)
        self._watchdog.setInterval(self.LOAD_TIMEOUT_MS)
        self._watchdog.timeout.connect(self._on_timeout)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Close).setText(_('Close'))
        buttons.rejected.connect(self.reject)

        row = QHBoxLayout()
        row.addWidget(self.refresh)
        row.addStretch(1)
        row.addWidget(buttons)

        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(4)
        layout.addWidget(self.names, 1)
        layout.addWidget(self.status)
        layout.addSpacing(4)
        layout.addWidget(note)
        layout.addWidget(source)
        layout.addLayout(row)

        cached = supporters.load_cache()
        if cached is not None:
            self._show(cached)
        else:
            self.status.setText(_('Loading the list…'))
        # Zapytanie idzie PO zbudowaniu okna: kopia ma byc widoczna od razu,
        # a nie po powrocie z sieci.
        QTimer.singleShot(0, self._fetch)

    # --- Pobieranie ---------------------------------------------------------

    def _fetch(self, force: bool = False) -> None:
        """Odpytuje serwer, o ile jest po co: kopia stara, brak albo `force`."""
        if self._loading:
            return
        if not force and self._shown is not None and not self._shown.stale:
            return
        self._loading = True
        self.refresh.setEnabled(False)
        if self._shown is None:
            self.status.setText(_('Loading the list…'))
        task = workers.SupportersTask(self._client)
        task.signals.finished.connect(self._on_list)
        task.signals.failed.connect(self._on_failed)
        workers.launch(self._pool, task)
        self._watchdog.start()

    def _done_loading(self) -> None:
        self._loading = False
        self._watchdog.stop()
        self.refresh.setEnabled(True)

    def _on_list(self, data) -> None:
        self._done_loading()
        supporters.save_cache(data)
        self._show(data)

    def _on_failed(self, message: str) -> None:
        self._done_loading()
        # Kopia, ktora juz wisi w oknie, zostaje — ale okno mowi wprost, ze
        # to jest stan sprzed bledu, a nie swiezy odczyt.
        text = (_('The list could not be refreshed. %(reason)s')
                if self._shown is not None
                else _('The list could not be loaded. %(reason)s'))
        self.status.setText(text % {'reason': message})

    def _on_timeout(self) -> None:
        if not self._loading:
            return
        self._done_loading()
        self.status.setText(_('The list did not arrive in time. Please try '
                              'again in a moment.'))

    # --- Widok --------------------------------------------------------------

    def _show(self, data) -> None:
        self._shown = data
        self.names.clear()
        for name in data.names:
            # `addItem(str)` tworzy element tekstu ZWYKLEGO: znaczniki
            # w nazwie z sieci zostaja zwyklymi znakami na ekranie.
            self.names.addItem(name)
        self.status.setText(self._describe(data))

    @staticmethod
    def _describe(data) -> str:
        if not data.names:
            # Dzis to jest stan PRAWDZIWY: flaga po stronie serwera jest
            # wylaczona, wiec endpoint oddaje pusta liste.
            parts = [_('Nobody is named here right now.')]
        else:
            parts = [_('Downloaded: %(when)s')
                     % {'when': _local_moment(data.fetched_at)}]
            server = _server_moment(data.updated)
            if server:
                parts.append(_('last change on the server: %(when)s')
                             % {'when': server})
        if data.truncated:
            parts.append(_('The server sent more names than this window shows.'))
        return ' · '.join(parts)


def _local_moment(stamp: float) -> str:
    """Chwila z zegara lokalnego w formacie jezyka interfejsu."""
    try:
        return datetime.fromtimestamp(float(stamp)).strftime(datetime_format())
    except (OSError, OverflowError, TypeError, ValueError):
        return ''


def _server_moment(iso: str) -> str:
    """`updated` z serwera (ISO 8601, UTC) w czasie lokalnym albo ''."""
    if not iso:
        return ''
    try:
        moment = datetime.fromisoformat(iso.replace('Z', '+00:00'))
    except ValueError:
        return ''
    if moment.tzinfo is not None:
        moment = moment.astimezone()
    return moment.strftime(datetime_format())


class DetailsDialog(QDialog):
    """Pełne dane techniczne dowodu — dla kogos, kto chce sprawdzić recznie."""

    def __init__(self, title: str, data: dict, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(f'{title} — BeatStamp')
        self.resize(720, 560)

        hint = QLabel(_(
            'The complete proof data in JSON. The <b>.beatproof</b> export '
            'writes the same values — you can check them with your own tool.'))
        hint.setWordWrap(True)
        hint.setObjectName('hint')

        view = QPlainTextEdit()
        view.setObjectName('mono')
        view.setReadOnly(True)
        view.setPlainText(json.dumps(data, indent=2, ensure_ascii=False))
        view.setLineWrapMode(QPlainTextEdit.NoWrap)

        copy = QPushButton(_('Copy everything'))
        copy.setToolTip(_('Copies the whole JSON document to the clipboard'))
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(view.toPlainText()))

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Close).setText(_('Close'))
        buttons.rejected.connect(self.reject)

        row = QHBoxLayout()
        row.addWidget(copy)
        row.addStretch(1)
        row.addWidget(buttons)

        layout = QVBoxLayout(self)
        layout.addWidget(hint)
        layout.addWidget(view, 1)
        layout.addLayout(row)


class LicensesDialog(QDialog):
    """Teksty licencji czytane we wlasnym oknie.

    Potrzebne tylko w wydaniu ze Sklepu — patrz `show_licenses`. Okno nie
    ma wlasnej kopii niczego: czyta te same pliki, ktore leza w paczce obok
    programu, wiec nie da sie ich rozjechac.
    """

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(_('Licences and notices — BeatStamp'))
        self.resize(900, 620)

        directory = licenses_dir()
        # NOTICE i LICENSE na gorze: jeden mowi, na czym stoi program,
        # drugi — na jakiej licencji jest wydany. Reszta alfabetycznie.
        first = ['NOTICE', 'LICENSE']
        names = [name for name in first if (directory / name).is_file()]
        names += sorted(path.name for path in directory.glob('*.txt'))

        self._directory = directory
        self._files = QListWidget()
        self._files.addItems(names)
        self._files.setMaximumWidth(260)

        self._view = QPlainTextEdit()
        self._view.setObjectName('mono')
        self._view.setReadOnly(True)
        self._view.setLineWrapMode(QPlainTextEdit.NoWrap)

        self._files.currentTextChanged.connect(self._show)
        if names:
            self._files.setCurrentRow(0)
        else:
            self._view.setPlainText(
                _('The licence texts are missing from this installation: '
                  '%(path)s') % {'path': directory})

        location = QLabel(str(directory))
        location.setObjectName('faint')
        location.setTextInteractionFlags(Qt.TextSelectableByMouse)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Close).setText(_('Close'))
        buttons.rejected.connect(self.reject)

        columns = QHBoxLayout()
        columns.addWidget(self._files)
        columns.addWidget(self._view, 1)

        layout = QVBoxLayout(self)
        layout.addLayout(columns, 1)
        layout.addWidget(location)
        layout.addWidget(buttons)

    def _show(self, name: str) -> None:
        if not name:
            return
        try:
            text = (self._directory / name).read_text(encoding='utf-8',
                                                      errors='replace')
        except OSError as problem:
            log.error('nie udało się odczytać %s: %s', name, problem)
            text = _('This file could not be read: %(name)s') % {'name': name}
        self._view.setPlainText(text)
        self._view.moveCursor(self._view.textCursor().MoveOperation.Start)


class LogDialog(QDialog):
    """Dziennik zdarzeń — do zglaszania błędów bez zgadywania."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(_('Event log — BeatStamp'))
        self.resize(820, 520)

        path = log_path()
        try:
            # Czytamy ogon: przy dlugim dzienniku wczytanie calosci do widgetu
            # potrafi na chwile zablokowac okno, a interesuje nas koncowka.
            text = path.read_text(encoding='utf-8', errors='replace')[-200_000:]
        except OSError:
            text = _('The log is still empty.')

        location = QLabel(str(path))
        location.setObjectName('faint')
        location.setTextInteractionFlags(Qt.TextSelectableByMouse)

        view = QPlainTextEdit()
        view.setObjectName('mono')
        view.setReadOnly(True)
        view.setPlainText(text)
        view.moveCursor(view.textCursor().MoveOperation.End)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Close).setText(_('Close'))
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(location)
        layout.addWidget(view, 1)
        layout.addWidget(buttons)
