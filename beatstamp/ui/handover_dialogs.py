"""
Okna Sigelith Handover: karta, kontakt, wysylka, decyzja, odpowiedz, dowod.

Okna nie lacza sie z siecia i niczego nie podpisuja — zbieraja decyzje
czlowieka, a prace wykonuje okno glowne zadaniami z handover_tasks.py.
Wszystko, co pochodzi z paczki albo pliku karty (tytuly, notatki, nazwy
plikow, nazwy nadawcow), idzie jako zwykly tekst.

Tresc oswiadczenia odbiorcy (`statement_accept`, `statement_refuse`) to
STALE odczytanie podpisywanego obiektu (HANDOVER_SPEC.md §6) — to samo
zdanie pokazuje strona weryfikatora (apps/web/views.py: statementAccept).
Zmiana brzmienia = ta sama zmiana tam i w specyfikacji.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from PySide6.QtCore import QDate, Qt
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from .. import beatcore, plural
from ..handover import identity as I, package as P
from ..handover.rules import is_risky
from ..i18n import _, format_iso_date, ltr
from .handover_panel import METHODS, incoming_status, level_text, method_text, outgoing_status, \
    when_text
from .widgets import action_row, fit_to_screen, label, plain_tooltip, section_label


def human_size(n: int) -> str:
    if n < 1024:
        return _('%(n)s B') % {'n': n}
    if n < 1024 * 1024:
        return _('%(n)s kB') % {'n': f'{n / 1024:.1f}'}
    if n < 1024 ** 3:
        return _('%(n)s MB') % {'n': f'{n / 1048576:.1f}'}
    return _('%(n)s GB') % {'n': f'{n / 1073741824:.2f}'}


def statement_accept(offer_digest: str, sender: str, deadline: str) -> str:
    return _('I confirm that I have received package %(offer)s from %(sender)s and that I hold '
             'its encrypted content. This confirmation takes effect at the moment the key part '
             'committed in the offer is recorded in the Sigelith log, provided that happens no '
             'later than %(deadline)s. Otherwise it has no effect.') % {
        'offer': offer_digest, 'sender': sender, 'deadline': deadline}


def statement_refuse(offer_digest: str, sender: str) -> str:
    return _('I refuse to accept package %(offer)s from %(sender)s.') % {
        'offer': offer_digest, 'sender': sender}


def _scrolled(widget: QWidget) -> QScrollArea:
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QScrollArea.NoFrame)
    widget.setObjectName('scrollBody')
    area.setWidget(widget)
    return area


def _plain(text: str, role: str = '') -> QLabel:
    lbl = label(text, role=role, wrap=True)
    lbl.setTextFormat(Qt.PlainText)
    return lbl


# --- nowa karta ------------------------------------------------------------------

class CreateCardDialog(QDialog):
    def __init__(self, *, hello: bool, replacing: bool, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(_('New card — Sigelith Desktop'))
        self.setMinimumWidth(560)
        column = QVBoxLayout(self)
        column.setSpacing(10)
        column.addWidget(label(_('Your Sigelith card'), role='h2'))
        column.addWidget(label(_(
            'The card holds two public keys: one for your signature and one that people use to '
            'encrypt packages to you. It contains no name — the people you exchange it with know '
            'whose it is.'), role='hint', wrap=True))
        if replacing:
            column.addWidget(label(_(
                'Your current card will be archived. Packages sent to it can still be opened '
                'here, but give people your new card file.'), role='warnText', wrap=True))
        self.name = QLineEdit(os.environ.get('USERNAME', ''))
        self.name.setMaxLength(64)
        self.name.setPlaceholderText(_('Name shown in the Windows Hello window'))
        self.name.setToolTip(_('Only for the Windows Hello window on this computer. It is not '
                               'part of the card.'))
        self.use_hello = QCheckBox(_('Keep the signing key in Windows Hello (recommended)'))
        self.use_hello.setChecked(hello)
        self.use_hello.setEnabled(hello)
        self.use_hello.setToolTip(_('The key is created in the TPM and each signature needs your '
                                    'PIN, face or fingerprint.') if hello else
                                  _('Windows Hello is not available on this computer.'))
        form = QFormLayout()
        form.addRow(_('Name in the Windows Hello window'), self.name)
        column.addLayout(form)
        column.addWidget(self.use_hello)
        column.addWidget(label(_('Windows Hello will ask twice: for the new key and for signing '
                                 'the card.') if hello else
                               _('Without Windows Hello the key is stored in software, protected '
                                 'by your Windows account. The card says so, and so does every '
                                 'evidence package.'), role='hint', wrap=True))
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText(_('Create the card'))
        buttons.button(QDialogButtonBox.Cancel).setText(_('Cancel'))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        column.addWidget(buttons)

    def values(self) -> tuple[str, bool]:
        return (self.name.text().strip() or 'Sigelith', self.use_hello.isChecked())


# --- nowy kontakt ------------------------------------------------------------------

class AddContactDialog(QDialog):
    def __init__(self, card_file, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(_('New contact — Sigelith Desktop'))
        self.setMinimumWidth(620)
        info = card_file.info
        column = QVBoxLayout(self)
        column.setSpacing(10)
        column.addWidget(label(_('Card fingerprint'), role='h3'))
        fp = label(ltr(info.fingerprint_text), role='mono', selectable=True)
        fp.setTextFormat(Qt.PlainText)
        column.addWidget(fp)
        column.addWidget(label(_(
            'Compare it with the person — in person, or at least the first four groups aloud on '
            'a call. A card from an e-mail alone proves only who controls that mailbox.'),
            role='hint', wrap=True))
        storage = (_('Signing key in hardware, used only after the person unlocks it.')
                   if info.storage == 'hardware-uv' else
                   _('Signing key stored in software.'))
        if card_file.attested:
            att = _('Hardware attestation: %(what)s.') % {'what': card_file.attested}
        elif card_file.attestation_problem:
            att = _('The hardware attestation does not verify (%(code)s); the card itself is '
                    'valid.') % {'code': card_file.attestation_problem}
        else:
            att = _('No hardware attestation.')
        column.addWidget(_plain(f'{storage} {att}', 'hint'))

        self.name = QLineEdit()
        self.name.setMaxLength(80)
        self.name.setPlaceholderText(_('For example: Anna Kowalska, ACME legal'))
        self.name.setToolTip(_('Your name for this contact. It stays on this computer.'))
        self.method = QComboBox()
        for m in METHODS:
            self.method.addItem(_('level %(level)s: %(method)s') % {
                'level': I.BINDING_METHODS[m], 'method': method_text(m)}, m)
        self.method.setToolTip(_('How you made sure that this card belongs to this person. The '
                                 'record is signed with your key and stamped.'))
        self.day = QDateEdit(QDate.currentDate())
        self.day.setCalendarPopup(True)
        self.day.setDisplayFormat('yyyy-MM-dd')
        self.day.setToolTip(_('When you verified the card.'))
        self.note = QLineEdit()
        self.note.setMaxLength(I.BINDING_NOTE_MAX)
        self.note.setPlaceholderText(_('Optional: where and how'))
        self.note.setToolTip(_('A short note inside the signed binding record.'))
        form = QFormLayout()
        form.addRow(_('Name'), self.name)
        form.addRow(_('Verified by'), self.method)
        form.addRow(_('On'), self.day)
        form.addRow(_('Note'), self.note)
        column.addLayout(form)
        self.error = label('', role='errorText', wrap=True)
        self.error.hide()
        column.addWidget(self.error)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText(_('Sign and add'))
        buttons.button(QDialogButtonBox.Cancel).setText(_('Cancel'))
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        column.addWidget(buttons)

    def _accept(self) -> None:
        if not self.name.text().strip():
            self.error.setText(_('Give the contact a name.'))
            self.error.show()
            return
        self.accept()

    def values(self) -> tuple[str, str, date, str]:
        q = self.day.date()
        return (self.name.text().strip(), self.method.currentData(),
                date(q.year(), q.month(), q.day()), self.note.text().strip())


# --- wysylka ---------------------------------------------------------------------------

class SendDialog(QDialog):
    def __init__(self, contacts: list, *, exchange: str, start_dir: str,
                 parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(_('Send files — Sigelith Desktop'))
        fit_to_screen(self, 720, 720)
        self._start_dir = start_dir
        self._exchange = exchange
        self._out_dir = ''
        body = QWidget()
        column = QVBoxLayout(body)
        column.setContentsMargins(18, 16, 18, 16)
        column.setSpacing(10)

        self.contact = QComboBox()
        for c in contacts:
            self.contact.addItem(f'{c.label} — {level_text(c.binding)}', c.fingerprint)
        self.contact.setToolTip(_('The package is encrypted to this card; only its owner can '
                                  'open it.'))
        column.addWidget(section_label(_('Recipient')))
        column.addWidget(self.contact)

        column.addWidget(section_label(_('Files')))
        self.files = QListWidget()
        self.files.setMinimumHeight(120)
        self.files.setToolTip(_('The files travel encrypted. Their names and contents are '
                                'visible only to the recipient.'))
        add = QPushButton(_('Add files…'))
        add.setToolTip(_('Choose the files to send.'))
        add.clicked.connect(self._add_files)
        remove = QPushButton(_('Remove'))
        remove.setToolTip(_('Remove the selected file from the package.'))
        remove.clicked.connect(lambda: [self.files.takeItem(self.files.row(item))
                                        for item in self.files.selectedItems()])
        column.addWidget(self.files)
        column.addLayout(action_row([add, remove]))

        column.addWidget(section_label(_('What the recipient sees before accepting')))
        self.title = QLineEdit()
        self.title.setMaxLength(P.TITLE_MAX)
        self.title.setPlaceholderText(_('Title, for example: Annex to the lease'))
        self.title.setToolTip(_('Shown to the recipient before they accept.'))
        self.note = QPlainTextEdit()
        self.note.setPlaceholderText(_('Note (optional)'))
        self.note.setToolTip(_('Shown to the recipient before they accept.'))
        self.note.setFixedHeight(80)
        self.sender_name = QLineEdit()
        self.sender_name.setMaxLength(P.SENDER_NAME_MAX)
        self.sender_name.setPlaceholderText(_('Your name as the recipient should see it'))
        self.sender_name.setToolTip(_('A courtesy only — the recipient identifies you by your '
                                      'card, not by this name.'))
        column.addWidget(self.title)
        column.addWidget(self.note)
        column.addWidget(self.sender_name)

        column.addWidget(section_label(_('Deadlines')))
        self.expires = QSpinBox()
        self.expires.setRange(1, 90)
        self.expires.setValue(30)
        self.expires.setToolTip(_('How long the recipient can answer.'))
        self.complete = QSpinBox()
        self.complete.setRange(1, 30)
        self.complete.setValue(14)
        self.complete.setToolTip(_('After an acceptance, how long this application has to '
                                   'publish the key part. Keep it open now and then.'))
        form = QFormLayout()
        form.addRow(_('Days to answer'), self.expires)
        form.addRow(_('Days to complete after an acceptance'), self.complete)
        column.addLayout(form)

        column.addWidget(section_label(_('Where the package goes')))
        self.to_exchange = QRadioButton(_('The exchange folder: %(path)s') % {'path': exchange}
                                        if exchange else _('The exchange folder (not set)'))
        self.to_exchange.setEnabled(bool(exchange))
        self.to_exchange.setToolTip(_('The recipient\'s application picks it up automatically.'))
        self.to_folder = QRadioButton(_('A folder I choose — I send the file myself'))
        self.to_folder.setToolTip(_('Send the file by e-mail, a messenger or a USB stick.'))
        group = QButtonGroup(self)
        group.addButton(self.to_exchange)
        group.addButton(self.to_folder)
        (self.to_exchange if exchange else self.to_folder).setChecked(True)
        column.addWidget(self.to_exchange)
        column.addWidget(self.to_folder)
        self.error = label('', role='errorText', wrap=True)
        self.error.hide()
        column.addWidget(self.error)
        column.addStretch(1)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText(_('Sign and send'))
        buttons.button(QDialogButtonBox.Cancel).setText(_('Cancel'))
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 12)
        outer.addWidget(_scrolled(body), 1)
        outer.addWidget(buttons)

    def add_paths(self, paths: list[Path]) -> None:
        known = {self.files.item(row).data(Qt.UserRole) for row in range(self.files.count())}
        for path in paths:
            if path.is_file() and str(path) not in known:
                item = QListWidgetItem(f'{path.name}  ({human_size(path.stat().st_size)})')
                item.setData(Qt.UserRole, str(path))
                item.setToolTip(plain_tooltip(str(path)))
                self.files.addItem(item)

    def _add_files(self) -> None:
        names, _filter = QFileDialog.getOpenFileNames(self, _('Choose files to send'),
                                                      self._start_dir)
        self.add_paths([Path(n) for n in names])

    def _accept(self) -> None:
        if self.contact.currentData() is None:
            return self._fail(_('Add a contact first.'))
        if self.files.count() == 0:
            return self._fail(_('Choose at least one file.'))
        if self.to_folder.isChecked():
            folder = QFileDialog.getExistingDirectory(self, _('Where to save the package'),
                                                      self._start_dir)
            if not folder:
                return None
            self._out_dir = folder
        self.accept()
        return None

    def _fail(self, text: str) -> None:
        self.error.setText(text)
        self.error.show()

    def request(self):
        from ..handover_tasks import SendRequest
        return SendRequest(
            contact=self.contact.currentData(),
            files=[Path(self.files.item(row).data(Qt.UserRole)) for row in range(self.files.count())],
            title=self.title.text().strip(), note=self.note.toPlainText().strip(),
            sender_name=self.sender_name.text().strip(), expires_days=self.expires.value(),
            complete_within_days=self.complete.value(),
            out_dir=Path(self._exchange if self.to_exchange.isChecked() else self._out_dir))


# --- odebrana paczka -----------------------------------------------------------------

class IncomingDialog(QDialog):
    """Decyzja o paczce (§7.2.6): Akceptuj, Odmow, Pozniej — albo stan po decyzji."""

    ACCEPT, REFUSE, SAVE_ANSWER, COPY_ANSWER, OPEN_FOLDER, EVIDENCE, DEFECT = range(1, 8)

    def __init__(self, record, *, contact, offer_time: str | None, defect: bool = False,
                 parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(_('Received package — Sigelith Desktop'))
        fit_to_screen(self, 760, 760)
        self.choice = 0
        offer = P.read_offer(record.offer)
        preview = record.preview
        body = QWidget()
        column = QVBoxLayout(body)
        column.setContentsMargins(18, 16, 18, 16)
        column.setSpacing(10)

        column.addWidget(_plain(str(preview.get('title') or _('(no title)')), 'h2'))
        column.addWidget(_plain(incoming_status(record.status), 'hint'))
        if record.status == 'expired':
            column.addWidget(label(
                _('The sender did not publish the key part before your acceptance expired, so '
                  'the acceptance has no effect. The encrypted content was deleted from this '
                  'computer.') if record.answer is not None else
                _('You did not answer before the deadline, so the offer lapsed. The encrypted '
                  'content was deleted from this computer.'), role='warnText', wrap=True))
        elif record.status == 'defective':
            column.addWidget(_plain(
                _('The package did not open the way the sender offered it (%(code)s). The offer '
                  'was defective, so your acceptance has no effect.')
                % {'code': record.error or '—'}, 'errorText'))

        sender_text = offer.sender.fingerprint_text
        column.addWidget(section_label(_('Sender')))
        if contact is not None:
            column.addWidget(_plain(f'{contact.label} — {level_text(contact.binding)}'))
        else:
            column.addWidget(label(_('Unknown card. Compare the fingerprint with the sender '
                                     'before you accept — anybody can send you a package.'),
                                   role='warnText', wrap=True))
        fp = label(ltr(sender_text), role='mono', selectable=True)
        fp.setTextFormat(Qt.PlainText)
        column.addWidget(fp)
        if preview.get('sender_name'):
            column.addWidget(_plain(_('The sender calls themselves: %(name)s')
                                    % {'name': preview['sender_name']}, 'hint'))
        column.addWidget(_plain(
            _('Offer recorded in the log: %(when)s') % {'when': when_text(offer_time)}
            if offer_time else _('The offer is not in the log.'), 'hint'))

        if preview.get('note'):
            column.addWidget(section_label(_('Note')))
            column.addWidget(_plain(str(preview['note'])))

        column.addWidget(section_label(_('Files')))
        files = QListWidget()
        files.setMinimumHeight(110)
        for entry in preview.get('files', []):
            text = f'{entry["name"]}  ({human_size(entry["size"])}, {entry["type"]})'
            if is_risky(entry['name']):
                text += '  — ' + _('a program or script: open it only if you trust the sender')
            item = QListWidgetItem(text)
            item.setToolTip(plain_tooltip(entry['name']))
            files.addItem(item)
        column.addWidget(files)
        count = preview.get('file_count', 0)
        if count > len(preview.get('files', [])):
            column.addWidget(_plain(_('…and %(files)s more.') % {
                'files': plural.files(count - len(preview.get('files', [])))}, 'hint'))
        column.addWidget(_plain(_('Together: %(size)s') % {
            'size': human_size(int(preview.get('total_size', 0)))}, 'hint'))

        buttons = []
        if record.status == 'new':
            deadline = (datetime.now(timezone.utc) + timedelta(seconds=offer.complete_within))
            column.addWidget(section_label(_('What you sign when you accept')))
            quote = _plain(statement_accept(record.offer_digest, sender_text,
                                            beatcore.local_str(deadline)))
            quote.setObjectName('value')
            column.addWidget(quote)
            column.addWidget(_plain(_('Answer by %(when)s. Nothing is sent anywhere until you '
                                      'decide.') % {'when': when_text(offer.raw['expires'])},
                                    'hint'))
            accept = QPushButton(_('Accept with Windows Hello'))
            accept.setObjectName('primary')
            accept.setToolTip(_('Signs the acceptance with your card and records it in the log '
                                'before it leaves this computer.'))
            accept.clicked.connect(lambda: self._done(self.ACCEPT))
            refuse = QPushButton(_('Refuse'))
            refuse.setToolTip(_('Signs a refusal. The package is deleted from this computer.'))
            refuse.clicked.connect(lambda: self._done(self.REFUSE))
            later = QPushButton(_('Later'))
            later.setToolTip(_('Decide later. Without an answer the offer simply expires.'))
            later.clicked.connect(self.reject)
            buttons = [accept, refuse, later]
        else:
            if record.answer_file:
                save = QPushButton(_('Save the answer file…'))
                save.setToolTip(_('Send this file back to the sender, the same way the package '
                                  'came.'))
                save.clicked.connect(lambda: self._done(self.SAVE_ANSWER))
                copy = QPushButton(_('Copy the answer text'))
                copy.setToolTip(_('The same answer as text, for pasting into a message.'))
                copy.clicked.connect(lambda: self._done(self.COPY_ANSWER))
                buttons += [save, copy]
            if record.status == 'opened':
                folder = QPushButton(_('Open the folder with the files'))
                folder.setToolTip(plain_tooltip(record.folder or ''))
                folder.clicked.connect(lambda: self._done(self.OPEN_FOLDER))
                evidence = QPushButton(_('Save my evidence copy…'))
                evidence.setToolTip(_('Proves when the package became readable for you.'))
                evidence.clicked.connect(lambda: self._done(self.EVIDENCE))
                buttons += [folder, evidence]
                if record.preview_differences:
                    column.addWidget(label(_('The opened files differ from what the preview '
                                             'showed — the offer was defective, so your '
                                             'acceptance has no effect.'),
                                           role='errorText', wrap=True))
            if defect:
                column.addWidget(label(_('The defect proof lets anyone check the defect, without '
                                         'you or the sender — at sigelith.org/handover/verify/ '
                                         'or in Sigelith Desktop.'), role='hint', wrap=True))
                proof = QPushButton(_('Save the defect proof…'))
                proof.setToolTip(_('The offer, both key parts and the encrypted package in one '
                                   'file.'))
                proof.clicked.connect(lambda: self._done(self.DEFECT))
                buttons.append(proof)
            close = QPushButton(_('Close'))
            close.setToolTip(_('Close this window.'))
            close.clicked.connect(self.reject)
            buttons.append(close)
        column.addStretch(1)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 12)
        outer.addWidget(_scrolled(body), 1)
        row = action_row(buttons)
        row.setContentsMargins(18, 0, 18, 0)
        outer.addLayout(row)

    def _done(self, choice: int) -> None:
        self.choice = choice
        self.accept()


# --- wyslana paczka ---------------------------------------------------------------------

class OutgoingDialog(QDialog):
    EVIDENCE, LOAD_ANSWER, SHOW_PACKAGE = range(1, 4)

    def __init__(self, record, *, contact, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(_('Sent package — Sigelith Desktop'))
        fit_to_screen(self, 700, 560)
        self.choice = 0
        column = QVBoxLayout(self)
        column.setContentsMargins(18, 16, 18, 12)
        column.setSpacing(10)
        column.addWidget(_plain(record.title or _('(no title)'), 'h2'))
        status = outgoing_status(record.status)
        if record.status == 'delivered' and record.delivered_at:
            status = _('Delivered %(when)s — the key part is in the public log.') % {
                'when': when_text(record.delivered_at)}
        elif record.status == 'refused':
            status = _('Refused %(when)s. The key part is never published.') % {
                'when': when_text(record.refused_at)}
        column.addWidget(_plain(status))
        if record.status == 'expired':
            column.addWidget(label(_('The recipient did not answer before %(when)s. This is a '
                                     'status, not evidence of anything.')
                                   % {'when': when_text(record.offer.get('expires'))},
                                   role='hint', wrap=True))
        elif record.status == 'failed':
            column.addWidget(label(
                _('The key part could not be published before the acceptance expired, so the '
                  'delivery did not happen. Send a new package.'), role='warnText', wrap=True))
            if record.error == 'publish-uncertain':
                column.addWidget(label(
                    _('The key part may have reached the log operator without being recorded. '
                      'The contents could therefore become readable without a proof of '
                      'delivery.'), role='warnText', wrap=True))
        elif record.error and record.status == 'sent':
            column.addWidget(label(_('The last answer could not be completed (%(code)s).')
                                   % {'code': record.error}, role='warnText', wrap=True))
        who = contact.label if contact is not None else record.contact[:16]
        column.addWidget(_plain(_('To: %(who)s') % {'who': who}, 'hint'))
        column.addWidget(_plain(_('Sent: %(when)s') % {'when': when_text(record.created)}, 'hint'))
        files = QListWidget()
        for name in record.files:
            files.addItem(name)
        column.addWidget(files)
        buttons = []
        if record.answers:
            evidence = QPushButton(_('Save evidence…'))
            evidence.setObjectName('primary')
            evidence.setToolTip(_('The evidence package: offer, answer and log proofs with '
                                  'their receipts. Sigelith keeps no copy — keep it safe.'))
            evidence.clicked.connect(lambda: self._done(self.EVIDENCE))
            buttons.append(evidence)
        if record.status in ('sent', 'expired') and record.part_b_blob:
            load = QPushButton(_('Load the answer…'))
            load.setToolTip(_('The answer file or text the recipient sent back.'))
            load.clicked.connect(lambda: self._done(self.LOAD_ANSWER))
            buttons.append(load)
        if record.package_path:
            show = QPushButton(_('Show the package file'))
            show.setToolTip(plain_tooltip(record.package_path))
            show.clicked.connect(lambda: self._done(self.SHOW_PACKAGE))
            buttons.append(show)
        close = QPushButton(_('Close'))
        close.setToolTip(_('Close this window.'))
        close.clicked.connect(self.reject)
        buttons.append(close)
        column.addLayout(action_row(buttons))

    def _done(self, choice: int) -> None:
        self.choice = choice
        self.accept()


# --- odpowiedz: wczytanie ------------------------------------------------------------------

class LoadAnswerDialog(QDialog):
    """Plik odpowiedzi albo tekst `sigelith:answer:` z wiadomosci."""

    def __init__(self, start_dir: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(_('Load an answer — Sigelith Desktop'))
        self.setMinimumWidth(620)
        self.data: bytes | str | None = None
        self._start_dir = start_dir
        column = QVBoxLayout(self)
        column.setSpacing(10)
        column.addWidget(label(_('Paste the answer text (it starts with sigelith:answer:) or '
                                 'open the answer file.'), wrap=True))
        self.text = QPlainTextEdit()
        self.text.setPlaceholderText('sigelith:answer:…')
        self.text.setToolTip(_('Line breaks and spaces from e-mail do not matter.'))
        column.addWidget(self.text)
        open_file = QPushButton(_('Open the answer file…'))
        open_file.setToolTip(_('A .sigelith-answer file.'))
        open_file.clicked.connect(self._open_file)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText(_('Load'))
        buttons.button(QDialogButtonBox.Cancel).setText(_('Cancel'))
        buttons.accepted.connect(self._accept_text)
        buttons.rejected.connect(self.reject)
        column.addLayout(action_row([open_file]))
        column.addWidget(buttons)

    def _open_file(self) -> None:
        name, _filter = QFileDialog.getOpenFileName(
            self, _('Open the answer file'), self._start_dir,
            _('Sigelith answers (*.sigelith-answer);;All files (*)'))
        if name:
            self.data = Path(name).read_bytes()
            self.accept()

    def _accept_text(self) -> None:
        text = self.text.toPlainText().strip()
        if text:
            self.data = text
            self.accept()


def copy_to_clipboard(text: str) -> None:
    QApplication.clipboard().setText(text)


# --- dowod: raport -------------------------------------------------------------------------

def _report_button(on_click) -> QPushButton:
    button = QPushButton(_('Save a PDF report…'))
    button.setToolTip(_('Every check in plain words, with instructions for an expert. The report '
                        'is not evidence — give it together with the checked file.'))
    button.clicked.connect(on_click)
    return button


def verdict_text(report, moment=None) -> tuple[str, str, str]:
    """(tytul, opis, rola koloru) werdyktu §12. `moment`: zapis czasu
    (domyslnie czas lokalny; raport PDF podaje UTC)."""
    moment = moment or beatcore.local_str
    if report.verdict == 'delivered':
        return (_('Delivered'),
                _('The recipient\'s signed acceptance took effect at %(when)s, when the key part '
                  'was recorded in the Sigelith log.') % {
                    'when': moment(report.delivered_at)}, 'okText')
    if report.verdict == 'refused':
        return (_('Refused'),
                _('The recipient refused the package (%(when)s).') % {
                    'when': moment(report.refused_at)} if report.refused_at else
                _('The recipient refused the package; the refusal is not in the log.'), 'value')
    if report.verdict == 'not-completed':
        return (_('Not completed'),
                _('No acceptance took effect: the key part was not recorded in the log after '
                  'the acceptance and before its deadline.'), 'warnText')
    return (_('Not valid evidence'),
            _('The package does not hold up: its format or a signature is wrong.'), 'errorText')


_TIME_CHECKS = ('offer-stamp', 'answer-stamp', 'part-b-stamp', 'binding-before-offer')


def check_label(code: str) -> str:
    """Nazwa kontroli dla czlowieka — te same etykiety co na stronie weryfikatora."""
    exact = {
        'offer-stamp': _('Offer recorded in the log'),
        'answer-stamp': _('Acceptance recorded in the log'),
        'part-b-stamp': _('Key part recorded in the log'),
        'binding-before-offer': _('Binding recorded before the offer'),
        'deadline': _('Recorded before the acceptance deadline'),
        'order': _('Recorded after the acceptance'),
        'disclosure': _('Disclosed content matches the package'),
        'cards': _('Cards of both parties'),
        'offer': _('Offer signed by the sender'),
        'binding': _('Binding of the recipient\'s card'),
        'answer': _('Answer signed by the recipient'),
    }
    if code in exact:
        return exact[code]
    defect = {
        'package': _('The package opens as offered'),
        'preview-mismatch': _('The preview matches the content'),
        'defect-claim': _('Key parts and encrypted package are the ones in the offer'),
    }
    if code in defect:
        return defect[code]
    for prefix, text in (('preview-', _('The preview matches the content')),
                         ('defect-', _('Defect proof')),
                         ('ciphertext-', _('The package opens as offered')),
                         ('content-', _('The package opens as offered')),
                         ('manifest-', _('The package opens as offered')),
                         ('container-', _('The package opens as offered')),
                         ('file-', _('The package opens as offered'))):
        if code.startswith(prefix):
            return text
    for prefix, text in (('evidence-', _('Evidence package')), ('card-', _('Cards of both parties')),
                         ('offer-', _('Offer signed by the sender')),
                         ('binding-', _('Binding of the recipient\'s card')),
                         ('attestation', _('Hardware attestation')),
                         ('answer-', _('Answer signed by the recipient')),
                         ('part-b', _('Key part matches the offer'))):
        if code.startswith(prefix):
            return text
    return _('Data format')


def _moment(value) -> str:
    return beatcore.local_str(value) if value is not None else _('not in the log')


def check_detail(check, moment=None) -> str:
    """Szczegol kontroli z jej danych (`Check.data`) — czas lokalny (albo zapis
    `moment`), bez kodow. Kontrola bez danych (blad formatu, podpisu) pokazuje
    opis techniczny."""
    if moment is not None:
        return _check_detail(check, lambda v: moment(v) if v is not None else _('not in the log'))
    return _check_detail(check, _moment)


def _check_detail(check, _moment) -> str:
    d = check.data
    code = check.code
    if not d:
        return ltr(f'{code}: {check.detail}' if check.detail else code)
    if code == 'cards':
        return _('sender %(sender)s, recipient %(recipient)s') % {
            'sender': ltr(d['sender']), 'recipient': ltr(d['recipient'])}
    if code == 'offer':
        return ltr(d['digest'])
    if code in _TIME_CHECKS:
        return _moment(d.get('at'))
    if code == 'binding':
        day = d['day'].isoformat() if isinstance(d['day'], date) else str(d['day'])
        return '%s, %s' % (level_text({'level': d['level'], 'method': d['method']}),
                           format_iso_date(day))
    if code == 'attestation':
        role = _('sender') if d['role'] == 'sender' else _('recipient')
        return f'{role}: {d["what"]}'
    if code == 'answer':
        return _('acceptance') if d['decision'] == 'accept' else _('refusal')
    if code == 'deadline':
        return _('recorded %(at)s, valid until %(until)s') % {
            'at': _moment(d['at']), 'until': _moment(d['until'])}
    if code == 'order':
        return _('acceptance: %(accepted)s, key part: %(recorded)s') % {
            'accepted': _moment(d['accepted']), 'recorded': _moment(d['recorded'])}
    if code == 'disclosure':
        names = ', '.join(f['name'] for f in d['files'][:5])
        if len(d['files']) > 5:
            names += ' …'
        return f'{plural.files(len(d["files"]))}: {names}'
    return ''


def log_roles(report) -> dict[str, str]:
    """Skrot z dziennika -> co to jest (oferta, przyjecie, czesc klucza...)."""
    roles: dict[str, str] = {}
    for c in report.checks:
        d = c.data
        if not d:
            continue                                # kontrola bez danych (blad formatu)
        if c.code == 'offer':
            roles[d['digest']] = _('Offer')
        elif c.code == 'answer':
            roles[d['digest']] = _('Acceptance') if d['decision'] == 'accept' else _('Refusal')
        elif c.code == 'part-b-commit':
            roles[d['digest']] = _('Key part — the moment of delivery')
        elif c.code == 'binding':
            roles[d['digest']] = _('Binding record')
        elif c.code == 'disclosure':
            for entry in d['files']:
                roles.setdefault(entry['sha256'], _('File %(name)s') % {'name': entry['name']})
    return roles


def confirmation_text(conf) -> str:
    if conf is None:
        return _('not checked')
    if conf.independent:
        return _('confirmed outside Sigelith: %(sources)s') % {
            'sources': ', '.join({'github': 'GitHub', 'wayback': 'Internet Archive',
                                  'zenodo': 'Zenodo'}.get(s, s) for s in conf.sources)}
    if conf.verified:
        return _('under a checkpoint this application verified; copies at third parties follow')
    return _('waiting for the next checkpoint (within a day)')


class EvidenceDialog(QDialog):
    SAVE_FILES, SAVE_REPORT = 1, 2

    def __init__(self, check, *, has_container: bool, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(_('Evidence check — Sigelith Desktop'))
        fit_to_screen(self, 780, 720)
        self.choice = 0
        report = check.report
        body = QWidget()
        column = QVBoxLayout(body)
        column.setContentsMargins(18, 16, 18, 16)
        column.setSpacing(10)
        title, text, role = verdict_text(report)
        column.addWidget(label(title, role='h1'))
        column.addWidget(_plain(text, role))
        if report.verdict in ('delivered', 'refused'):
            column.addWidget(_plain(_(
                'The times rest on the Sigelith log\'s signatures (receipts). Below: what this '
                'application confirmed outside Sigelith\'s control.'), 'hint'))
        roles = log_roles(report)
        column.addWidget(section_label(_('Log proofs')))
        order = {role: n for n, role in enumerate(roles.values())}
        for digest, conf in sorted(check.confirmations.items(),
                                   key=lambda kv: (order.get(roles.get(kv[0]), 99), kv[0])):
            row = _plain(f'{roles.get(digest, ltr(digest[:16] + "…"))} — {confirmation_text(conf)}',
                         'hint')
            row.setToolTip(plain_tooltip(digest))
            column.addWidget(row)
        for digest, code in sorted(check.log_errors.items()):
            column.addWidget(_plain(_('%(what)s: the log proof was not accepted (%(code)s)') % {
                'what': roles.get(digest, ltr(digest[:16] + '…')), 'code': code}, 'warnText'))
        binding = next((c for c in report.checks if c.code == 'binding' and c.ok and c.data), None)
        if binding is not None:
            column.addWidget(_plain(_('How the sender bound the recipient\'s card: %(level)s') % {
                'level': level_text(binding.data)}))
        for role_name, what in sorted(report.attested.items()):
            column.addWidget(_plain(_('Hardware attestation of the %(role)s: %(what)s') % {
                'role': _('sender') if role_name == 'sender' else _('recipient'), 'what': what}))
        column.addWidget(section_label(_('All checks')))
        for c in report.checks:
            head = _plain(f'{"✓" if c.ok else "✗"}  {check_label(c.code)}',
                          '' if c.ok else 'warnText')
            head.setToolTip(plain_tooltip(f'{c.code}: {c.detail}' if c.detail else c.code))
            column.addWidget(head)
            detail = check_detail(c)
            if detail:
                row = _plain(detail, 'hint')
                row.setIndent(22)                   # po stronie poczatku tekstu, takze w RTL
                column.addWidget(row)
        column.addStretch(1)
        buttons = [_report_button(lambda: self._done(self.SAVE_REPORT))]
        if has_container:
            files = QPushButton(_('Save the disclosed files…'))
            files.setToolTip(_('The exact files of the package, checked against the offer.'))
            files.clicked.connect(lambda: self._done(self.SAVE_FILES))
            buttons.append(files)
        close = QPushButton(_('Close'))
        close.setToolTip(_('Close this window.'))
        close.clicked.connect(self.reject)
        buttons.append(close)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 12)
        outer.addWidget(_scrolled(body), 1)
        row = action_row(buttons)
        row.setContentsMargins(18, 0, 18, 0)
        outer.addLayout(row)

    def _done(self, choice: int) -> None:
        self.choice = choice
        self.accept()


# --- dowod wady: raport (§11.3) ---------------------------------------------------------------

def defect_reason(code: str) -> str:
    """Na czym polega wada — kod pierwszej nieudanej kontroli, po ludzku."""
    if code == 'preview-mismatch':
        return _('the preview the recipient saw before accepting differs from the content')
    if code == 'ciphertext-tag':
        return _('the encrypted package does not decrypt with the key committed in the offer')
    if code == 'content-hash':
        return _('the decrypted content is not the content committed in the offer')
    if code.startswith('preview-'):
        return _('the preview cannot be read with the key part committed in the offer')
    return _('the content breaks the format rules (file list, names or sizes)')


def defect_verdict_text(report) -> tuple[str, str, str]:
    """(tytul, opis, rola koloru) werdyktu zarzutu wady."""
    code = report.checks[0].code if report.checks else ''
    if report.verdict == 'defective':
        return (_('Offer defective'),
                _('The package does not match what the sender signed in the offer: %(what)s. '
                  'The recipient\'s acceptance of this offer has no effect.') % {
                    'what': defect_reason(code)}, 'errorText')
    if report.verdict == 'not-defective':
        return (_('No defect'),
                _('The package opens with the key parts committed in the offer and matches its '
                  'preview. The claim of a defect is unfounded.'), 'okText')
    return (_('Not a valid defect proof'),
            _('The key parts or the encrypted package in this file are not the ones the offer '
              'commits to, or the file breaks the format. It proves nothing about the offer.'),
            'warnText')


def _file_names(files: list) -> str:
    names = ', '.join(str(f.get('name', '')) for f in files[:10])
    return names + (' …' if len(files) > 10 else '') if names else '—'


def defect_differences(data: dict) -> list[tuple[str, str, str]]:
    """(co, w podgladzie, w tresci) — tylko to, czym podglad rozni sie od tresci."""
    preview, manifest = data.get('preview'), data.get('manifest')
    if not preview or not manifest:
        return []
    content = P.build_preview(manifest, preview.get('sender_name', ''))
    rows = []
    for key in data.get('differences', []):
        if key == 'title':
            rows.append((_('Title'), preview['title'] or '—', content['title'] or '—'))
        elif key == 'note':
            rows.append((_('Note'), preview['note'] or '—', content['note'] or '—'))
        elif key == 'file_count':
            rows.append((_('Number of files'), str(preview['file_count']),
                         str(content['file_count'])))
        elif key == 'total_size':
            rows.append((_('Total size'), human_size(int(preview['total_size'])),
                         human_size(int(content['total_size']))))
        elif key == 'files':
            rows.append((_('Files'), _file_names(preview['files']), _file_names(content['files'])))
    return rows


class DefectDialog(QDialog):
    """Werdykt pliku `sigelith-handover-defect-v1`. Wszystko z pliku — zwykly tekst."""

    SAVE_REPORT = 1

    def __init__(self, check, *, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(_('Defect check — Sigelith Desktop'))
        fit_to_screen(self, 760, 640)
        self.choice = 0
        report, offer = check.report, check.offer
        body = QWidget()
        column = QVBoxLayout(body)
        column.setContentsMargins(18, 16, 18, 16)
        column.setSpacing(10)
        title, text, role = defect_verdict_text(report)
        column.addWidget(label(title, role='h1'))
        column.addWidget(_plain(text, role))
        column.addWidget(_plain(_('This check is arithmetic only: it needs neither the log nor '
                                  'the network, and anyone who repeats it gets the same '
                                  'result.'), 'hint'))
        if offer is not None:
            column.addWidget(section_label(_('Offer')))
            column.addWidget(_plain(_('sender %(sender)s, recipient %(recipient)s') % {
                'sender': ltr(offer.sender.fingerprint_text),
                'recipient': ltr(offer.recipient.fingerprint_text)}))
            digest = label(ltr(offer.digest.hex()), role='mono', selectable=True)
            digest.setTextFormat(Qt.PlainText)
            column.addWidget(digest)
            column.addWidget(_plain(_('Encrypted package: %(size)s') % {
                'size': human_size(offer.ciphertext_size)}, 'hint'))
        rows = defect_differences(report.checks[0].data) if report.checks else []
        if rows:
            column.addWidget(section_label(_('What the preview showed — and what the package '
                                             'holds')))
            for what, shown, held in rows:
                column.addWidget(_plain(what))
                for line in (_('Preview: %(value)s') % {'value': shown},
                             _('Content: %(value)s') % {'value': held}):
                    row = _plain(line, 'hint')
                    row.setIndent(22)
                    column.addWidget(row)
        column.addWidget(section_label(_('All checks')))
        for c in report.checks:
            head = _plain(f'{"✓" if c.ok else "✗"}  {check_label(c.code)}',
                          '' if c.ok else 'warnText')
            head.setToolTip(plain_tooltip(f'{c.code}: {c.detail}' if c.detail else c.code))
            column.addWidget(head)
        column.addStretch(1)
        close = QPushButton(_('Close'))
        close.setToolTip(_('Close this window.'))
        close.clicked.connect(self.reject)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 12)
        outer.addWidget(_scrolled(body), 1)
        row = action_row([_report_button(lambda: self._done(self.SAVE_REPORT)), close])
        row.setContentsMargins(18, 0, 18, 0)
        outer.addLayout(row)

    def _done(self, choice: int) -> None:
        self.choice = choice
        self.accept()
