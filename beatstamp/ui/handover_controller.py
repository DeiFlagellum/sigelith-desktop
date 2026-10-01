"""
Sigelith Handover w oknie glownym — laczy panel, okna i zadania.

Okno glowne daje trzy rzeczy: `_start` (jedno zadanie uzytkownika naraz,
pasek postepu, bledy w okienku), `_choose_save_path` i `_offer_open`. Reszta
Handover mieszka tutaj, zeby main_window.py dostal kilka linii podpiecia, a
nie kolejny tysiac.

Praca w tle (folder wymiany i szukanie czesci B w dzienniku, §7.5) idzie co
kilka minut, gdy okno jest otwarte i nic innego nie pracuje — tylko wtedy,
gdy jest na co czekac.
"""
from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QFileDialog, QMessageBox

from .. import handover_tasks as HT, workers
from ..config import default_handover_downloads, handover_dir
from ..handover import package as P
from ..handover.attestation import read_attestation
from ..handover.errors import HandoverError
from ..handover.identity import read_card
from ..handover_app import winhello
from ..handover_app.log import ClientLog
from ..handover_app.service import (ANSWER_SUFFIX, CARD_SUFFIX, DEFECT_SUFFIX, EVIDENCE_SUFFIX,
                                    PACKAGE_SUFFIX, HandoverService, ServiceError)
from ..handover_app.store import HandoverStore
from ..i18n import _
from . import handover_dialogs as D
from .handover_panel import HandoverPanel

log = logging.getLogger(__name__)

BACKGROUND_MS = 5 * 60 * 1000
HANDOVER_SUFFIXES = (PACKAGE_SUFFIX, ANSWER_SUFFIX, CARD_SUFFIX)


def is_handover_file(path: Path) -> bool:
    return path.name.lower().endswith(HANDOVER_SUFFIXES)


class HandoverController:
    def __init__(self, window) -> None:
        self.w = window
        self.store = HandoverStore(handover_dir())
        self.service = HandoverService(self.store, ClientLog(lambda: window.client),
                                       hwnd=lambda: int(window.winId()))
        self._hello = winhello.available()
        self._attested_cache: dict[str, str | None] = {}
        self._bg_task: workers.Task | None = None
        self.panel = HandoverPanel()
        p = self.panel
        p.createCardRequested.connect(self.create_card)
        p.saveCardRequested.connect(self.save_card)
        p.addContactRequested.connect(self.add_contact)
        p.removeContactRequested.connect(self.remove_contact)
        p.sendRequested.connect(lambda: self.send())
        p.openPackageRequested.connect(lambda: self.open_package())
        p.loadAnswerRequested.connect(self.load_answer)
        p.incomingActivated.connect(self.show_incoming)
        p.openFolderRequested.connect(self.open_incoming_folder)
        p.outgoingActivated.connect(self.show_outgoing)
        p.evidenceRequested.connect(self.save_evidence)
        p.verifyEvidenceRequested.connect(self.verify_evidence)
        p.exchangeChooseRequested.connect(self.choose_exchange)
        p.checkNowRequested.connect(self.check_now)
        self.timer = QTimer(window)
        self.timer.setInterval(BACKGROUND_MS)
        self.timer.timeout.connect(self.background_check)
        self.refresh()

    # --- stan ------------------------------------------------------------------------

    def adopt_data_dir(self) -> None:
        self.store.root = handover_dir()
        self.refresh()

    def _attested(self, ident) -> str | None:
        if ident is None or not ident.attestation:
            return None
        if ident.fingerprint not in self._attested_cache:
            try:
                self._attested_cache[ident.fingerprint] = read_attestation(
                    ident.attestation, read_card(ident.card)).description
            except HandoverError:
                self._attested_cache[ident.fingerprint] = None
        return self._attested_cache[ident.fingerprint]

    def refresh(self) -> None:
        try:
            ident = self.store.active_identity()
            contacts = self.store.contacts()
            incoming = self.store.incoming()
            outgoing = self.store.outgoing()
        except (OSError, ValueError) as e:
            log.warning('handover: stan nieczytelny: %s', e)
            ident, contacts, incoming, outgoing = None, [], [], []
        self.panel.set_identity(ident, hello=self._hello, attested=self._attested(ident))
        self.panel.set_contacts(contacts)
        self.panel.set_incoming(incoming)
        self.panel.set_outgoing(outgoing)
        self.panel.set_exchange(self.w.settings.handover_exchange_dir)

    def _exchange(self) -> Path | None:
        path = self.w.settings.handover_exchange_dir
        return Path(path) if path else None

    def _downloads(self) -> Path:
        chosen = self.w.settings.handover_downloads_dir
        return Path(chosen) if chosen else default_handover_downloads()

    def _start(self, task, on_result, text: str) -> bool:
        # `done` podpiete PRZED startem (sygnal z watku roboczego moglby
        # wyprzedzic podpiecie), a panel „zajety" dopiero, gdy zadanie ruszylo —
        # odmowa okna glownego (inne zadanie trwa) nie moze zamrozic przyciskow.
        task.signals.done.connect(lambda: self.panel.set_running(False))
        started = self.w._start(task, on_result, label_text=text)
        if started:
            self.panel.set_running(True)
        return started

    def _info(self, title: str, text: str) -> None:
        box = QMessageBox(QMessageBox.Information, title, text, QMessageBox.Ok, self.w)
        box.setTextFormat(Qt.PlainText)
        box.exec()

    def _later(self, fn) -> None:
        # Nastepny krok dopiero po `done` poprzedniego zadania (jedno naraz).
        QTimer.singleShot(80, fn)

    # --- pliki z zewnatrz (dwuklik, przeciagniecie, druga kopia programu) --------------

    def open_files(self, paths: list[Path]) -> None:
        """Pliki Handover NIE ida do stemplowania — skrot paczki nie ma czego szukac
        w publicznym dzienniku."""
        self.w.tabs.setCurrentWidget(self.w.handover_scroll)
        for path in paths:
            name = path.name.lower()
            if name.endswith(PACKAGE_SUFFIX):
                self.open_package(path)
            elif name.endswith(ANSWER_SUFFIX):
                self._take_answer(path.read_bytes())
            elif name.endswith(CARD_SUFFIX):
                self.add_contact(path)
            break                    # jedna czynnosc naraz; reszte uzytkownik otworzy po kolei

    # --- moja karta --------------------------------------------------------------------

    def create_card(self) -> None:
        replacing = self.store.active_identity() is not None
        if replacing and QMessageBox.question(
                self.w, _('A new card'),
                _('Create a new card? The current one will be archived; packages sent to it '
                  'can still be opened here.'),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        dialog = D.CreateCardDialog(hello=self._hello, replacing=replacing, parent=self.w)
        if dialog.exec() != D.QDialog.Accepted:
            return
        name, use_hello = dialog.values()
        self._start(HT.CreateCardTask(self.service, name, use_hello), self._card_created,
                    _('Creating your card…'))

    def _card_created(self, _ident) -> None:
        self.refresh()
        self._info(_('Your card is ready'),
                   _('Save your card file and give it to the people who will send you '
                     'packages. It holds only public keys.'))
        self._later(self.save_card)

    def save_card(self) -> None:
        ident = self.store.active_identity()
        if ident is None:
            return
        target = self.w._choose_save_path(_('Save my card'), f'sigelith-card{CARD_SUFFIX}',
                                          _('Sigelith cards (*%(suffix)s)') % {'suffix': CARD_SUFFIX})
        if target is None:
            return
        try:
            target.write_bytes(self.service.card_file(
                with_attestation=self.w.settings.handover_attestation))
        except OSError as e:
            self._info(_('It did not work'), str(e))
            return
        self.w._offer_open(target, _('Card saved'))

    # --- kontakty ----------------------------------------------------------------------------

    def add_contact(self, path: Path | None = None) -> None:
        if self.store.active_identity() is None:
            self._info(_('Create your card first'),
                       _('Contacts are bound with your own card — create it first.'))
            return
        if path is None:
            name, _filter = QFileDialog.getOpenFileName(
                self.w, _('Open a card file'), self.w.settings.last_directory,
                _('Sigelith cards (*%(suffix)s);;All files (*)') % {'suffix': CARD_SUFFIX})
            if not name:
                return
            path = Path(name)
        try:
            card_file = self.service.read_card_file(path.read_bytes())
        except (ServiceError, OSError) as e:
            self._info(_('It did not work'), HT.describe(e))
            return
        dialog = D.AddContactDialog(card_file, parent=self.w)
        if dialog.exec() != D.QDialog.Accepted:
            return
        label, method, day, note = dialog.values()
        self._start(HT.AddContactTask(self.service, card_file, label=label, method=method,
                                      day=day, note=note),
                    lambda _c: self.refresh(), _('Signing the binding record…'))

    def remove_contact(self, fingerprint: str) -> None:
        contact = self.store.contact(fingerprint)
        if contact is None:
            return
        if QMessageBox.question(
                self.w, _('Remove the contact'),
                _('Remove %(name)s from this application? Packages already sent stay.')
                % {'name': contact.label},
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self.store.remove_contact(fingerprint)
        self.refresh()

    # --- wysylka ------------------------------------------------------------------------------

    def send(self, paths: list[Path] | None = None) -> None:
        contacts = self.store.contacts()
        if not contacts:
            self._info(_('No contacts yet'),
                       _('Add the recipient first: load their card file and record how you '
                         'verified it.'))
            return
        dialog = D.SendDialog(contacts, exchange=self.w.settings.handover_exchange_dir,
                              start_dir=self.w.settings.last_directory, parent=self.w)
        if paths:
            dialog.add_paths(paths)
        if dialog.exec() != D.QDialog.Accepted:
            return
        request = dialog.request()
        self._start(HT.SendTask(self.service, request), self._sent, _('Preparing the package…'))

    def _sent(self, record) -> None:
        self.refresh()
        contact = self.store.contact(record.contact)
        who = contact.label if contact else ''
        exchange = self._exchange()
        path = Path(record.package_path)
        if exchange is not None and path.parent == exchange:
            self._info(_('Package sent'),
                       _('The package for %(who)s is in the exchange folder. Their application '
                         'will pick it up; the answer comes back the same way.') % {'who': who})
            return
        self.w._offer_open(path, _('Package ready'), note=_(
            'Send this file to %(who)s by e-mail, a messenger or a USB stick. It is encrypted '
            'to their card; nobody else can open it.') % {'who': who})

    # --- odbiorca ------------------------------------------------------------------------------

    def open_package(self, path: Path | None = None) -> None:
        if path is None:
            name, _filter = QFileDialog.getOpenFileName(
                self.w, _('Open a package'), self.w.settings.last_directory,
                _('Sigelith packages (*%(suffix)s);;All files (*)') % {'suffix': PACKAGE_SUFFIX})
            if not name:
                return
            path = Path(name)
        self._start(HT.ReceiveTask(self.service, path), self._received,
                    _('Checking the package…'))

    def _received(self, result) -> None:
        record, _t0 = result
        self.refresh()
        self._later(lambda: self.show_incoming(record.offer_digest))

    def show_incoming(self, digest: str) -> None:
        record = self.store.get_incoming(digest)
        if record is None:
            return
        dialog = D.IncomingDialog(record, contact=self.store.contact(record.sender),
                                  offer_time=record.offer_stamped_at,
                                  defect=self.service.has_defect(record), parent=self.w)
        if dialog.exec() != D.QDialog.Accepted:
            return
        choice = dialog.choice
        if choice == D.IncomingDialog.ACCEPT:
            self._start(HT.AnswerTask(self.service, digest, 'accept', self._exchange()),
                        self._answered, _('Signing the acceptance…'))
        elif choice == D.IncomingDialog.REFUSE:
            if QMessageBox.question(
                    self.w, _('Refuse the package'),
                    _('Refuse this package? The refusal is signed with your card, and the '
                      'package is deleted from this computer.'),
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
                self._start(HT.AnswerTask(self.service, digest, 'refuse', self._exchange()),
                            self._answered, _('Signing the refusal…'))
        elif choice == D.IncomingDialog.SAVE_ANSWER:
            self._save_answer(record)
        elif choice == D.IncomingDialog.COPY_ANSWER:
            D.copy_to_clipboard(self.service.answer_text(record))
            self.w.statusBar().showMessage(_('The answer text is in the clipboard.'), 6000)
        elif choice == D.IncomingDialog.OPEN_FOLDER:
            self.open_incoming_folder(digest)
        elif choice == D.IncomingDialog.EVIDENCE:
            self._evidence(digest, incoming=True)
        elif choice == D.IncomingDialog.DEFECT:
            self.save_defect(digest)

    def open_incoming_folder(self, digest: str) -> None:
        record = self.store.get_incoming(digest)
        folder = Path(record.folder) if record is not None and record.folder else None
        if folder is None or not folder.is_dir():
            self._info(_('Folder not found'),
                       _('The folder with the files of this package no longer exists: %(path)s')
                       % {'path': str(folder) if folder else '—'})
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def _opened_notice(self, record) -> None:
        """Po „Sprawdz teraz": przesylka otwarta — gdzie sa pliki. W tle tylko pasek
        stanu (bez wymuszonych powiadomien)."""
        text = (_('%(title)s — the files are saved in:')
                % {'title': record.preview.get('title') or _('(no title)')}
                + '\n' + (record.folder or ''))
        if record.preview_differences:
            text += '\n\n' + _('The opened files differ from what the preview showed — the offer '
                               'was defective, so your acceptance has no effect.')
        box = QMessageBox(QMessageBox.Information, _('Package opened'), text,
                          QMessageBox.NoButton, self.w)
        box.setTextFormat(Qt.PlainText)
        open_button = box.addButton(_('Open the folder'), QMessageBox.AcceptRole)
        box.addButton(_('Close'), QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is open_button:
            self.open_incoming_folder(record.offer_digest)

    def _answered(self, record) -> None:
        self.refresh()
        if self._exchange() is not None:
            self._info(_('Answer sent'),
                       _('Your answer is signed, recorded in the log and placed in the exchange '
                         'folder.') + ' ' +
                       (_('The files open as soon as the sender publishes the key part.')
                        if record.status == 'accepted' else ''))
            return
        self._later(lambda: self.show_incoming(record.offer_digest))

    def _save_answer(self, record) -> None:
        target = self.w._choose_save_path(
            _('Save the answer'), f'{record.offer_digest[:16]}{ANSWER_SUFFIX}',
            _('Sigelith answers (*%(suffix)s)') % {'suffix': ANSWER_SUFFIX})
        if target is None:
            return
        try:
            target.write_bytes(self.service.answer_file(record))
        except (OSError, ServiceError) as e:
            self._info(_('It did not work'), HT.describe(e))
            return
        self.w._offer_open(target, _('Answer saved'), note=_(
            'Send this file back to the sender, the same way the package came.'))

    # --- nadawca -------------------------------------------------------------------------------

    def load_answer(self) -> None:
        dialog = D.LoadAnswerDialog(self.w.settings.last_directory, parent=self.w)
        if dialog.exec() != D.QDialog.Accepted or dialog.data is None:
            return
        self._take_answer(dialog.data)

    def _take_answer(self, data) -> None:
        self._start(HT.TakeAnswerTask(self.service, data), self._answer_taken,
                    _('Checking the answer…'))

    def _answer_taken(self, record) -> None:
        self.refresh()
        if record.status == 'delivered':
            if QMessageBox.question(
                    self.w, _('Delivered'),
                    _('Delivered: the key part is in the public log (%(when)s). Save the '
                      'evidence package now? Sigelith keeps no copy.')
                    % {'when': D.when_text(record.delivered_at)},
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes) == QMessageBox.Yes:
                self._later(lambda: self.save_evidence(record.offer_digest))
        elif record.status == 'refused':
            self._info(_('Refused'), _('The recipient refused the package. The key part is '
                                       'never published.'))

    def show_outgoing(self, digest: str) -> None:
        record = self.store.get_outgoing(digest)
        if record is None:
            return
        dialog = D.OutgoingDialog(record, contact=self.store.contact(record.contact),
                                  parent=self.w)
        if dialog.exec() != D.QDialog.Accepted:
            return
        if dialog.choice == D.OutgoingDialog.EVIDENCE:
            self.save_evidence(digest)
        elif dialog.choice == D.OutgoingDialog.LOAD_ANSWER:
            self.load_answer()
        elif dialog.choice == D.OutgoingDialog.SHOW_PACKAGE and record.package_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(record.package_path).parent)))

    # --- dowody -------------------------------------------------------------------------------

    def save_evidence(self, digest: str) -> None:
        self._evidence(digest, incoming=False)

    def _evidence(self, digest: str, *, incoming: bool) -> None:
        box = QMessageBox(QMessageBox.Question, _('Evidence package'), _(
            'Include the delivered files in the evidence? Then it shows exactly what was '
            'delivered — and anyone who gets the evidence can read the files.'),
            QMessageBox.NoButton, self.w)
        with_files = box.addButton(_('With the files'), QMessageBox.AcceptRole)
        without = box.addButton(_('Without the files'), QMessageBox.ActionRole)
        box.addButton(_('Cancel'), QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() not in (with_files, without):
            return
        disclose = box.clickedButton() is with_files
        task = HT.EvidenceTask(self.service, digest, incoming=incoming, disclose=disclose,
                               attestation=self.w.settings.handover_attestation)
        self._start(task, lambda data: self._evidence_ready(digest, data),
                    _('Collecting the log proofs…'))

    def _evidence_ready(self, digest: str, data: bytes) -> None:
        target = self.w._choose_save_path(
            _('Save the evidence'), f'handover-{digest[:16]}{EVIDENCE_SUFFIX}',
            _('Evidence packages (*.zip)'))
        if target is None:
            return
        try:
            target.write_bytes(data)
        except OSError as e:
            self._info(_('It did not work'), str(e))
            return
        self.w._offer_open(target, _('Evidence saved'), note=_(
            'Keep this file safe — Sigelith keeps no copy. Anyone can check it at '
            'sigelith.org/handover/verify/ or in Sigelith Desktop.') + ' ' + _(
            'For a reader without a verifier — a lawyer, an expert, a court — open it with '
            'Verify evidence… and save a PDF report.'))

    def save_defect(self, digest: str) -> None:
        """Dowod wady (§11.3). Ujawnia obie czesci klucza — najpierw ostrzezenie."""
        box = QMessageBox(QMessageBox.Warning, _('Defect proof'), _(
            'The defect proof holds the offer, both key parts and the encrypted package. Anyone '
            'who gets it can open the package as far as it opens — give it only to those who '
            'must judge the defect: the sender, a lawyer, an expert or a court.'),
            QMessageBox.NoButton, self.w)
        box.setTextFormat(Qt.PlainText)
        save = box.addButton(_('Save the defect proof…'), QMessageBox.AcceptRole)
        box.addButton(_('Cancel'), QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is not save:
            return
        target = self.w._choose_save_path(
            _('Save the defect proof'), f'handover-{digest[:16]}{DEFECT_SUFFIX}',
            _('Defect proofs (*.zip)'))
        if target is None:
            return
        self._start(HT.DefectProofTask(self.service, digest, target),
                    lambda path: self.w._offer_open(path, _('Defect proof saved'), note=_(
                        'Anyone can check it at sigelith.org/handover/verify/ or in Sigelith '
                        'Desktop (Verify evidence…).')),
                    _('Saving the defect proof…'))

    def verify_evidence(self) -> None:
        name, _filter = QFileDialog.getOpenFileName(
            self.w, _('Open an evidence package'), self.w.settings.last_directory,
            _('Evidence packages and defect proofs (*.zip);;All files (*)'))
        if not name:
            return
        from ..handover import evidence as E
        try:
            with open(name, 'rb') as f:
                kind = E.archive_kind(f)
        except OSError as e:
            self._info(_('It did not work'), str(e))
            return
        if kind == 'defect':
            self._start(HT.CheckDefectTask(self.service, Path(name)),
                        lambda check: self._defect_checked(check, Path(name)),
                        _('Checking the defect proof…'))
            return
        other = None
        if QMessageBox.question(
                self.w, _('The other party\'s copy'),
                _('Do you also have the other party\'s copy of the same handover? It settles '
                  'the case where the recipient signed two different answers.'),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
            second, _filter = QFileDialog.getOpenFileName(
                self.w, _('Open the other party\'s copy'), str(Path(name).parent),
                _('Evidence packages (*.zip);;All files (*)'))
            if second:
                other = Path(second).read_bytes()
        data = Path(name).read_bytes()
        task = HT.CheckEvidenceTask(self.service, data, other, self.w.witness_state.copy(),
                                    self.w.settings.key_override)
        self._start(task, lambda check: self._evidence_checked(check, data, Path(name)),
                    _('Checking the evidence…'))

    def _defect_checked(self, check, path: Path) -> None:
        dialog = D.DefectDialog(check, parent=self.w)
        if dialog.exec() == D.QDialog.Accepted and dialog.choice == D.DefectDialog.SAVE_REPORT:
            from . import handover_report as R
            source = R.Source(path.name, check.size, check.sha256)
            self._save_report(path, R.defect_html(check, source),
                              _('Sigelith Handover — report on a defect proof'))

    def _save_report(self, checked: Path, page: str, title: str) -> None:
        """Raport PDF OBOK sprawdzonego pliku (§11.1) — nigdy w jego srodku."""
        from . import handover_report as R
        target = self.w._choose_save_path(_('Save the report'), checked.with_suffix('.pdf'),
                                          _('PDF documents (*.pdf)'))
        if target is None:
            return
        try:
            R.write_pdf(page, target, title=title)
        except OSError as e:
            self._info(_('It did not work'), str(e))
            return
        self.w._offer_open(target, _('Report saved'), note=_(
            'The report is a reading, not evidence — give it together with the checked file.'))

    def _evidence_checked(self, check, data: bytes, path: Path) -> None:
        from ..handover import evidence as E
        try:
            ev = E.Evidence(data)
            has_container = ev.has_container and any(
                c.code == 'disclosure' and c.ok for c in check.report.checks)
        except HandoverError:
            has_container = False
        dialog = D.EvidenceDialog(check, has_container=has_container, parent=self.w)
        if dialog.exec() != D.QDialog.Accepted:
            return
        if dialog.choice == D.EvidenceDialog.SAVE_REPORT:
            from . import handover_report as R
            source = R.Source(path.name, check.size, check.sha256)
            self._save_report(path, R.evidence_html(check, source, self.service.receipt_keys()),
                              _('Sigelith Handover — report on an evidence package'))
            return
        if dialog.choice == D.EvidenceDialog.SAVE_FILES:
            folder = QFileDialog.getExistingDirectory(self.w, _('Where to save the files'),
                                                      str(self._downloads()))
            if not folder:
                return
            try:
                ev = E.Evidence(data)
                offer = P.read_offer(ev.doc['offer'])
                with ev.open_container() as src:
                    P.extract_container(src, offer.content_size, Path(folder))
            except (HandoverError, OSError) as e:
                self._info(_('It did not work'), HT.describe(e))
                return
            QDesktopServices.openUrl(QUrl.fromLocalFile(folder))

    # --- folder wymiany i praca w tle -----------------------------------------------------------

    def choose_exchange(self) -> None:
        folder = QFileDialog.getExistingDirectory(
            self.w, _('Choose the exchange folder'),
            self.w.settings.handover_exchange_dir or str(Path.home()))
        if not folder:
            return
        self.w.settings.handover_exchange_dir = folder
        self.w._store(self.w.settings.save)
        self.refresh()
        self.check_now()

    def check_now(self) -> None:
        exchange = self._exchange()
        if exchange is None:
            if not self._maintain(interactive=True):
                self.w.statusBar().showMessage(
                    _('Nothing to check: no package is waiting for an answer or a key part.'),
                    8000)
            return
        self._start(HT.ExchangeTask(self.service, exchange), self._exchange_done,
                    _('Checking the exchange folder…'))

    def _exchange_done(self, result) -> None:
        self._report_exchange(result)
        self._later(lambda: self._maintain(interactive=True))

    def _report_exchange(self, result) -> None:
        self.refresh()
        new = [r for r in result.received if r.status == 'new']
        done = [r for r in result.answered if r.status in ('delivered', 'refused')]
        if new:
            self.w.statusBar().showMessage(
                _('New packages in the exchange folder: %(n)s') % {'n': len(new)}, 10_000)
        elif done:
            self.w.statusBar().showMessage(
                _('Answers processed from the exchange folder: %(n)s') % {'n': len(done)}, 10_000)
        for name, error in result.problems[:3]:
            log.warning('handover: folder wymiany %s: %s', name, error)

    def _maintain(self, *, interactive: bool) -> bool:
        """Przeglad (publikacje, B w dzienniku, terminy) — tylko gdy jest na co czekac."""
        try:
            pending = self.service.has_pending()
        except (OSError, ValueError) as e:
            log.warning('handover: stan nieczytelny: %s', e)
            return False
        if not pending:
            return False
        task = HT.MaintainTask(self.service, self._downloads())
        if interactive:
            return self._start(task, lambda result: self._maintained(result, interactive=True),
                               _('Looking for key parts in the log…'))
        self._launch_background(task, self._maintained)
        return True

    def _maintained(self, result, *, interactive: bool = False) -> None:
        self.refresh()
        for record in result.opened:
            self.w.statusBar().showMessage(
                _('A package is open: %(title)s') % {'title': record.preview.get('title') or ''},
                10_000)
        if interactive:
            # Okno dopiero po `done` zadania — pasek postepu juz schowany.
            for record in result.opened[:3]:
                self._later(lambda r=record: self._opened_notice(r))
        for record in result.delivered:
            self.w.statusBar().showMessage(
                _('Delivered: %(title)s') % {'title': record.title or '—'}, 10_000)
        for _digest, error in result.problems:
            if error.code == 'package-defective':
                self._info(_('A package is defective'), HT.describe(error))
                break
            log.info('handover: przeglad: %s', error)

    def _launch_background(self, task, on_result) -> None:
        if self._bg_task is not None or self.w._busy() or self.w._closing:
            return
        self._bg_task = task
        task.signals.finished.connect(on_result)
        task.signals.failed.connect(lambda text: log.info('handover w tle: %s', text))
        task.signals.done.connect(self._background_done)
        workers.launch(self.w.pool, task)

    def _background_done(self) -> None:
        self._bg_task = None

    def background_task(self) -> workers.Task | None:
        return self._bg_task

    def background_check(self) -> None:
        """Co kilka minut: folder wymiany, potem B w dzienniku (§7.5)."""
        if self.w._busy() or self._bg_task is not None or self.w._closing:
            return
        exchange = self._exchange()
        if exchange is not None:
            self._launch_background(HT.ExchangeTask(self.service, exchange), self._bg_exchange_done)
        else:
            self._maintain(interactive=False)

    def _bg_exchange_done(self, result) -> None:
        self._report_exchange(result)
        QTimer.singleShot(200, lambda: self._maintain(interactive=False))

    def start_background(self) -> None:
        self.timer.start()
        QTimer.singleShot(4000, self.background_check)

    def stop_background(self) -> None:
        self.timer.stop()
        if self._bg_task is not None:
            self._bg_task.cancel()
