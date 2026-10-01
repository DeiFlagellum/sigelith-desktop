"""
Zakladka „Handover" — przekazanie plikow z dowodem doreczenia.

Ta zakladka niczego nie liczy i nie laczy sie z siecia: pokazuje stan z
`handover_app.store` (moja karta, kontakty, przesylki) i wysyla sygnaly
w gore, do okna glownego, ktore uruchamia zadania (handover_tasks.py).
Wzorzec jak `WitnessPanel`: sygnaly w gore, `set_*` w dol.

Kazdy tekst z zewnatrz (nazwy kontaktow, tytuly, nazwy plikow) idzie jako
zwykly tekst — nigdy jako HTML.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QGridLayout,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import beatcore
from ..handover import identity as I
from ..i18n import _, ltr, rtl_block
from . import icons
from .widgets import action_row, card, label, plain_tooltip, section_label

METHODS = ('qr-in-person', 'signed-document', 'handshake', 'voice', 'channel')


def method_text(method: str) -> str:
    """Jak nadawca powiazal karte z osoba (§3.3) — od najmocniejszego."""
    return {
        'qr-in-person': _('fingerprint QR code scanned in person'),
        'signed-document': _('fingerprint named in a document signed by the person'),
        'handshake': _('Sigelith handshake between the two devices'),
        'voice': _('fingerprint compared by voice (at least 4 groups)'),
        'channel': _('card received over a channel the person controls'),
    }.get(method, method)


def level_text(binding: dict) -> str:
    level = binding.get('level') if isinstance(binding, dict) else None
    method = binding.get('method') if isinstance(binding, dict) else ''
    if not isinstance(level, int):
        return _('not bound')
    # 1 = najmocniejsze powiazanie (§3.3); bez dopisku „1 z 5" czyta sie jak najslabsze.
    return _('level %(level)s of 5 (1 = strongest) — %(method)s') % {
        'level': level, 'method': method_text(method)}


def incoming_status(status: str) -> str:
    return {
        'new': _('Waiting for your decision'),
        'accepted': _('Accepted — waiting for the key part'),
        'refused': _('Refused'),
        'opened': _('Opened'),
        'expired': _('Expired'),
        'defective': _('Defective package'),
    }.get(status, status)


def outgoing_status(status: str) -> str:
    return {
        'sent': _('Waiting for the answer'),
        'delivered': _('Delivered'),
        'refused': _('Refused'),
        'expired': _('Not collected'),
        'failed': _('Not delivered'),
    }.get(status, status)


def fingerprint_text(card: dict) -> str:
    try:
        return I.read_card(card).fingerprint_text
    except Exception:                           # karta z magazynu jest sprawdzona; na wszelki wypadek
        return '—'


def when_text(iso: str | None) -> str:
    moment = beatcore.parse_iso_utc(iso or '')
    return beatcore.local_str(moment) if moment else '—'


def _table(headers: list[str]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.verticalHeader().setVisible(False)
    table.setMinimumHeight(150)
    header = table.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.ResizeToContents)
    header.setStretchLastSection(True)
    return table


def _cell(text: str, key: str = '') -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    item.setToolTip(plain_tooltip(text))
    if key:
        item.setData(Qt.UserRole, key)
    return item


class HandoverPanel(QWidget):
    """Tresc zakladki „Handover"."""

    createCardRequested = Signal()
    saveCardRequested = Signal()
    addContactRequested = Signal()
    removeContactRequested = Signal(str)
    sendRequested = Signal()
    openPackageRequested = Signal()
    loadAnswerRequested = Signal()
    incomingActivated = Signal(str)
    openFolderRequested = Signal(str)
    outgoingActivated = Signal(str)
    evidenceRequested = Signal(str)
    verifyEvidenceRequested = Signal()
    exchangeChooseRequested = Signal()
    checkNowRequested = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName('page')
        self._contacts: dict[str, str] = {}
        self._opened: set[str] = set()          # przesylki otwarte, z folderem na dysku
        self._has_identity = False
        self._exchange = ''
        self._running = False

        # --- Naglowek i glowne czynnosci ---------------------------------------
        hero = card()
        title = label(_('Hand over files with proof of delivery'), role='h2', wrap=True)
        # „Jak to dziala" w trzech krokach — test na sprzecie (2026-09-29) pokazal,
        # ze bez tego nie wiadomo, czy program wysyla plik, czy tylko potwierdzenie.
        steps = QGridLayout()
        steps.setHorizontalSpacing(10)
        steps.setVerticalSpacing(6)
        for row, text in enumerate((
                _('You choose a contact and files. The application encrypts them into a package '
                  'that only this person can open. The package travels by e-mail, a messenger, '
                  'a USB stick or a shared folder — never through the Sigelith server.'),
                _('The recipient sees the title and the list of files, but can open them only '
                  'after signing the receipt with their own key (Windows Hello).'),
                _('Your application then records the missing key part in the public Sigelith '
                  'log — that is the moment of delivery. The recipient\'s application finds it '
                  'and opens the files by itself; you keep the evidence package.'))):
            number = label(str(row + 1), role='h3')
            number.setAlignment(Qt.AlignTop)
            steps.addWidget(number, row, 0)
            steps.addWidget(label(text, wrap=True), row, 1)
        steps.setColumnStretch(1, 1)
        lead = label(_('The Sigelith server stores nothing — no files, no messages, no contacts; '
                       'only digests go to the public log.'), role='hint', wrap=True)
        self.send_button = QPushButton(_('Send files…'))
        self.send_button.setObjectName('primary')
        self.send_button.setToolTip(_('Choose a contact and files; the package is encrypted '
                                      'to the contact\'s card.'))
        self.send_button.clicked.connect(self.sendRequested)
        icons.apply(self.send_button, 'file-earmark-lock', icons.ON_ACCENT)
        self.open_button = QPushButton(_('Open a package…'))
        self.open_button.setToolTip(_('Open a .sigelith-handover file someone sent you.'))
        self.open_button.clicked.connect(self.openPackageRequested)
        icons.apply(self.open_button, 'download')
        self.answer_button = QPushButton(_('Load an answer…'))
        self.answer_button.setToolTip(_('Load the answer file, or paste the answer text, '
                                        'that the recipient sent back.'))
        self.answer_button.clicked.connect(self.loadAnswerRequested)
        icons.apply(self.answer_button, 'journal-check')
        self.verify_button = QPushButton(_('Verify evidence…'))
        self.verify_button.setToolTip(_('Check a Sigelith Handover evidence package or defect '
                                        'proof (.zip) — yours or someone else\'s.'))
        self.verify_button.clicked.connect(self.verifyEvidenceRequested)
        icons.apply(self.verify_button, 'shield-check')
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(18, 16, 18, 16)
        hero_layout.setSpacing(8)
        hero_layout.addWidget(title)
        hero_layout.addWidget(section_label(_('How it works')))
        hero_layout.addLayout(steps)
        hero_layout.addWidget(lead)
        hero_layout.addLayout(action_row([self.send_button, self.open_button,
                                          self.answer_button, self.verify_button]))

        # --- Moja karta ----------------------------------------------------------
        mine = card()
        self.card_title = label('', role='h3', wrap=True)
        self.card_fingerprint = label('', role='mono', selectable=True)
        self.card_fingerprint.setTextFormat(Qt.PlainText)
        self.card_detail = label('', role='hint', wrap=True)
        self.card_detail.setTextFormat(Qt.PlainText)
        self.create_button = QPushButton(_('Create my card'))
        self.create_button.setObjectName('primary')
        self.create_button.setToolTip(_('A new key in Windows Hello and a card with its public '
                                        'part. Windows Hello asks twice.'))
        self.create_button.clicked.connect(self.createCardRequested)
        self.save_card_button = QPushButton(_('Save my card file…'))
        self.save_card_button.setToolTip(_('Give this file to people who will send you '
                                           'packages. It holds only public keys.'))
        self.save_card_button.clicked.connect(self.saveCardRequested)
        icons.apply(self.save_card_button, 'person-check')
        mine_layout = QVBoxLayout(mine)
        mine_layout.setContentsMargins(18, 14, 18, 14)
        mine_layout.setSpacing(6)
        mine_layout.addWidget(section_label(_('My card')))
        mine_layout.addWidget(self.card_title)
        mine_layout.addWidget(self.card_fingerprint)
        mine_layout.addWidget(self.card_detail)
        mine_layout.addLayout(action_row([self.create_button, self.save_card_button]))

        # --- Kontakty --------------------------------------------------------------
        people = card()
        self.contacts_table = _table([_('Name'), _('Card fingerprint'), _('How it was bound')])
        self.add_contact_button = QPushButton(_('Add a contact from a card file…'))
        self.add_contact_button.setToolTip(_('Load someone\'s .sigelith-card file and record how '
                                             'you verified that it is theirs.'))
        self.add_contact_button.clicked.connect(self.addContactRequested)
        icons.apply(self.add_contact_button, 'people')
        self.remove_contact_button = QPushButton(_('Remove'))
        self.remove_contact_button.setToolTip(_('Remove the selected contact from this '
                                                'application. Sent packages stay.'))
        self.remove_contact_button.clicked.connect(self._remove_contact)
        people_layout = QVBoxLayout(people)
        people_layout.setContentsMargins(18, 14, 18, 14)
        people_layout.setSpacing(8)
        people_layout.addWidget(section_label(_('Contacts')))
        people_layout.addWidget(self.contacts_table)
        people_layout.addLayout(action_row([self.add_contact_button,
                                            self.remove_contact_button]))

        # --- Odebrane ----------------------------------------------------------------
        inbox = card()
        self.incoming_table = _table([_('Received'), _('From'), _('Title'), _('Status')])
        self.incoming_table.cellDoubleClicked.connect(
            lambda row, _col: self._activate(self.incoming_table, row, self.incomingActivated))
        self.incoming_button = QPushButton(_('Show…'))
        self.incoming_button.setToolTip(_('Show the selected package: decide, send the answer '
                                          'again, open the files.'))
        self.incoming_button.clicked.connect(
            lambda: self._activate(self.incoming_table, self.incoming_table.currentRow(),
                                   self.incomingActivated))
        self.incoming_folder_button = QPushButton(_('Open the folder with the files'))
        self.incoming_folder_button.setToolTip(_('Open the folder where the files of the '
                                                 'selected package were saved.'))
        self.incoming_folder_button.clicked.connect(
            lambda: self._activate(self.incoming_table, self.incoming_table.currentRow(),
                                   self.openFolderRequested))
        icons.apply(self.incoming_folder_button, 'folder2-open')
        self.incoming_table.itemSelectionChanged.connect(self._update_folder_button)
        inbox_layout = QVBoxLayout(inbox)
        inbox_layout.setContentsMargins(18, 14, 18, 14)
        inbox_layout.setSpacing(8)
        inbox_layout.addWidget(section_label(_('Received packages')))
        inbox_layout.addWidget(self.incoming_table)
        inbox_layout.addLayout(action_row([self.incoming_button, self.incoming_folder_button]))

        # --- Wyslane -------------------------------------------------------------------
        outbox = card()
        self.outgoing_table = _table([_('Sent'), _('To'), _('Title'), _('Status')])
        self.outgoing_table.cellDoubleClicked.connect(
            lambda row, _col: self._activate(self.outgoing_table, row, self.outgoingActivated))
        self.outgoing_button = QPushButton(_('Show…'))
        self.outgoing_button.setToolTip(_('Show the selected package and its status.'))
        self.outgoing_button.clicked.connect(
            lambda: self._activate(self.outgoing_table, self.outgoing_table.currentRow(),
                                   self.outgoingActivated))
        self.evidence_button = QPushButton(_('Save evidence…'))
        self.evidence_button.setToolTip(_('Save the evidence package of the selected handover. '
                                          'Sigelith keeps no copy — keep it safe.'))
        self.evidence_button.clicked.connect(
            lambda: self._activate(self.outgoing_table, self.outgoing_table.currentRow(),
                                   self.evidenceRequested))
        icons.apply(self.evidence_button, 'archive')
        outbox_layout = QVBoxLayout(outbox)
        outbox_layout.setContentsMargins(18, 14, 18, 14)
        outbox_layout.setSpacing(8)
        outbox_layout.addWidget(section_label(_('Sent packages')))
        outbox_layout.addWidget(self.outgoing_table)
        outbox_layout.addLayout(action_row([self.outgoing_button, self.evidence_button]))

        # --- Folder wymiany ------------------------------------------------------------
        exchange = card()
        self.exchange_label = label('', role='hint', wrap=True)
        self.exchange_label.setTextFormat(Qt.PlainText)
        self.exchange_button = QPushButton(_('Choose the exchange folder…'))
        self.exchange_button.setToolTip(_('A folder you share with the other person (OneDrive, '
                                          'Dropbox, Google Drive, Syncthing). Packages and '
                                          'answers in it are picked up automatically.'))
        self.exchange_button.clicked.connect(self.exchangeChooseRequested)
        icons.apply(self.exchange_button, 'folder2-open')
        self.check_button = QPushButton(_('Check now'))
        self.check_button.setToolTip(_('Look for new packages and answers in the exchange '
                                       'folder, and for key parts in the public log.'))
        self.check_button.clicked.connect(self.checkNowRequested)
        icons.apply(self.check_button, 'arrow-repeat')
        exchange_layout = QVBoxLayout(exchange)
        exchange_layout.setContentsMargins(18, 14, 18, 14)
        exchange_layout.setSpacing(8)
        exchange_layout.addWidget(section_label(_('Exchange folder')))
        exchange_layout.addWidget(self.exchange_label)
        exchange_layout.addLayout(action_row([self.exchange_button, self.check_button]))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(12)
        layout.addWidget(hero)
        layout.addWidget(mine)
        layout.addWidget(inbox)
        layout.addWidget(outbox)
        layout.addWidget(people)
        layout.addWidget(exchange)
        layout.addStretch(1)
        self.set_identity(None, hello=True)
        self.set_exchange('')

    # --- w dol ---------------------------------------------------------------------

    def set_identity(self, identity, *, hello: bool, attested: str | None = None) -> None:
        has = identity is not None
        self._has_identity = has
        self.save_card_button.setVisible(has)
        self.create_button.setText(_('Create a new card') if has else _('Create my card'))
        self.create_button.setObjectName('' if has else 'primary')
        self.create_button.style().unpolish(self.create_button)
        self.create_button.style().polish(self.create_button)
        self._update_buttons()
        if not has:
            self.card_title.setText(_('You have no card yet'))
            self.card_fingerprint.setText('')
            self.card_detail.setText(
                _('The card holds only public keys. The signing key is created in Windows '
                  'Hello and never leaves this computer.') if hello else
                _('Windows Hello is not available here: the signing key will be kept in '
                  'software, protected by your Windows account — the card says so.'))
            return
        self.card_title.setText(_('Your card fingerprint — compare it aloud, group by group:'))
        self.card_fingerprint.setText(ltr(fingerprint_text(identity.card)))
        storage = (_('Signing key in Windows Hello (TPM), used only after you unlock it.')
                   if identity.cred_id else
                   _('Signing key stored in software, protected by your Windows account.'))
        attestation = (_('Hardware attestation: %(what)s.') % {'what': attested} if attested
                       else _('No hardware attestation.'))
        self.card_detail.setText(rtl_block(f'{storage} {attestation}'))

    def set_contacts(self, contacts: list) -> None:
        self._contacts = {c.fingerprint: c.label for c in contacts}
        table = self.contacts_table
        table.setRowCount(0)
        for contact in contacts:
            row = table.rowCount()
            table.insertRow(row)
            table.setItem(row, 0, _cell(contact.label, contact.fingerprint))
            table.setItem(row, 1, _cell(fingerprint_text(contact.card)))
            table.setItem(row, 2, _cell(level_text(contact.binding)))
        self.remove_contact_button.setEnabled(bool(contacts))

    def _who(self, fingerprint: str, card: dict | None = None) -> str:
        if fingerprint in self._contacts:
            return self._contacts[fingerprint]
        text = fingerprint_text(card) if card else fingerprint[:16]
        return _('unknown card %(fingerprint)s') % {'fingerprint': text}

    def set_incoming(self, records: list) -> None:
        table = self.incoming_table
        selected = self._key_at(table, table.currentRow())
        table.setRowCount(0)
        for record in records:
            row = table.rowCount()
            table.insertRow(row)
            sender_card = record.offer.get('sender_card') if isinstance(record.offer, dict) else None
            table.setItem(row, 0, _cell(when_text(record.received), record.offer_digest))
            table.setItem(row, 1, _cell(self._who(record.sender, sender_card)))
            table.setItem(row, 2, _cell(str(record.preview.get('title') or '—')))
            table.setItem(row, 3, _cell(incoming_status(record.status)))
        self._opened = {r.offer_digest for r in records if r.status == 'opened' and r.folder}
        self.incoming_button.setEnabled(bool(records))
        if records:
            # Odswiezenie w tle nie gubi wyboru; bez wyboru — najnowsza przesylka,
            # zeby przyciski pod tabela dzialaly od razu.
            keys = [r.offer_digest for r in records]
            table.selectRow(keys.index(selected) if selected in keys else 0)
        self._update_folder_button()

    def set_outgoing(self, records: list) -> None:
        table = self.outgoing_table
        table.setRowCount(0)
        for record in records:
            row = table.rowCount()
            table.insertRow(row)
            status = outgoing_status(record.status)
            if record.status == 'delivered' and record.delivered_at:
                status = _('Delivered %(when)s') % {'when': when_text(record.delivered_at)}
            table.setItem(row, 0, _cell(when_text(record.created), record.offer_digest))
            table.setItem(row, 1, _cell(self._who(record.contact)))
            table.setItem(row, 2, _cell(record.title or '—'))
            table.setItem(row, 3, _cell(status))
        self.outgoing_button.setEnabled(bool(records))
        self.evidence_button.setEnabled(any(r.answers for r in records))

    def set_exchange(self, path: str) -> None:
        self.exchange_label.setText(
            _('Packages and answers are exchanged through: %(path)s') % {'path': path}
            if path else
            _('No exchange folder: you save and send the files yourself (e-mail, messenger, '
              'USB stick). A shared folder makes it automatic.'))
        self._exchange = path
        self._update_buttons()

    def set_running(self, running: bool) -> None:
        self._running = running
        self._update_buttons()

    def _update_buttons(self) -> None:
        idle = not self._running
        for button in (self.send_button, self.open_button, self.answer_button,
                       self.add_contact_button, self.save_card_button):
            button.setEnabled(idle and self._has_identity)
        self.create_button.setEnabled(idle)
        self.check_button.setEnabled(idle and self._has_identity)

    @staticmethod
    def _key_at(table: QTableWidget, row: int) -> str | None:
        item = table.item(row, 0) if row >= 0 else None
        key = item.data(Qt.UserRole) if item is not None else None
        return str(key) if key else None

    def _update_folder_button(self) -> None:
        key = self._key_at(self.incoming_table, self.incoming_table.currentRow())
        self.incoming_folder_button.setEnabled(key in self._opened)

    # --- w gore -----------------------------------------------------------------------

    @staticmethod
    def _activate(table: QTableWidget, row: int, signal) -> None:
        if row < 0:
            return
        item = table.item(row, 0)
        key = item.data(Qt.UserRole) if item else None
        if key:
            signal.emit(str(key))

    def _remove_contact(self) -> None:
        row = self.contacts_table.currentRow()
        if row < 0:
            return
        item = self.contacts_table.item(row, 0)
        if item is not None and item.data(Qt.UserRole):
            self.removeContactRequested.emit(str(item.data(Qt.UserRole)))

