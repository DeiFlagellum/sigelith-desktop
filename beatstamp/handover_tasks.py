"""
Zadania w tle dla Sigelith Handover (workers.Task + handover_app.service).

Kazde zadanie moze czekac na siec, a podpis — na czlowieka w oknie Windows
Hello (do dwoch minut). Dlatego wszystko idzie przez pule, nigdy w watku
interfejsu.

Bledy tlumaczymy TUTAJ, po kodzie. `HandoverError` dziedziczy po
`ValueError`, wiec bez tego `workers.Task` pokazalby czlowiekowi angielskie
„code: detail" — tekst dla programisty, nie dla kogos, kto wysyla umowe.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .handover.errors import HandoverError
from .handover_app import confirm, dpapi, winhello
from .handover_app.service import CardFile, HandoverService, ServiceError
from .i18n import _
from .workers import Task

log = logging.getLogger(__name__)


class HandoverFailure(ValueError):
    """Blad juz w jezyku uzytkownika — `workers.Task` pokazuje go wprost."""


def _package_reason(code: str) -> str:
    if code == 'offer-expired':
        return _('the offer has expired.')
    if code in ('ciphertext-hash', 'ciphertext-size', 'file-format'):
        return _('the file is damaged or incomplete.')
    if code in ('envelope-not-mine', 'offer-not-mine'):
        return _('it is addressed to someone else.')
    if code == 'offer-created-future':
        return _('its creation time lies in the future.')
    return _('it does not meet the rules of the format (%(code)s).') % {'code': code}


def describe(error: BaseException) -> str:
    """Zdanie dla czlowieka z bledu uslugi, Windows Hello albo DPAPI."""
    if isinstance(error, winhello.HelloError):
        if error.kind == 'cancelled':
            return _('Windows Hello was cancelled, so nothing was signed.')
        if error.kind == 'unavailable':
            return _('Windows Hello is not available on this computer.')
        if error.kind == 'not-found':
            return _('The Windows Hello key of this card is no longer on this computer. '
                     'Create a new card.')
        return _('Windows Hello reported an error: %(detail)s') % {'detail': error.detail}
    if isinstance(error, dpapi.DpapiError):
        return _('A protected key of Sigelith Handover cannot be read on this Windows account.')
    if isinstance(error, HandoverError):
        return _('The data does not meet the rules of the format (%(code)s).') % {'code': error.code}
    if not isinstance(error, ServiceError):
        return str(error)
    code, detail = error.code, error.detail
    if code == 'no-identity':
        return _('Create your Sigelith card first.')
    if code == 'secret-unreadable':
        return _('A protected key of Sigelith Handover cannot be read on this Windows account.')
    if code == 'card-invalid':
        return _('This is not a valid Sigelith card file.')
    if code == 'card-is-mine':
        return _('This is your own card.')
    if code == 'binding-invalid':
        return _('The binding record could not be made (%(code)s).') % {'code': detail}
    if code == 'no-contact':
        return _('Choose a contact first.')
    if code == 'no-files':
        return _('Choose at least one file.')
    if code == 'offer-invalid':
        if detail.startswith('file-name'):
            return _('A file name is not allowed — rename the file and try again.')
        if detail.startswith('text'):
            return _('The title or the note contains characters that are not allowed.')
        return _('The package could not be prepared (%(code)s).') % {'code': detail}
    if code == 'package-invalid':
        return _('This package cannot be opened: %(why)s') % {'why': _package_reason(detail)}
    if code == 'package-defective':
        return _('The package is defective, so the acceptance has no effect (%(code)s).') % {
            'code': detail}
    if code == 'not-defective':
        return _('This package opened as offered, so there is no defect to prove.')
    if code == 'already-answered':
        return _('This package has already been answered.')
    if code == 'offer-expired':
        return _('The time to answer this package has passed, so it can no longer be '
                 'accepted or refused.')
    if code == 'answer-invalid':
        return _('This answer cannot be read, or it does not belong to a package sent from '
                 'this application.')
    if code == 'no-package':
        return _('This package is not known to this application.')
    if code == 'not-answered':
        return _('There is no answer yet.')
    if code == 'publish-refused':
        if detail == 'answer-deadline-near':
            return _('Less than an hour is left before the acceptance expires, so the key '
                     'part was not published and the delivery did not happen. Send a new '
                     'package.')
        if detail in ('offer-refused', 'answer-refused'):
            return _('The recipient refused this package, so the key part is never published.')
        if detail == 'offer-closed':
            return _('The deadline of this package has passed, so the key part is never '
                     'published. Send a new package.')
        return _('The key part was not published (%(code)s).') % {'code': detail}
    if code == 'stamp-failed':
        return _('The Sigelith log answered for a different digest.')
    return _('Sigelith Handover could not finish this step (%(code)s).') % {'code': code}


class HandoverTask(Task):
    """Wspolna obsluga bledow: tekst dla czlowieka zamiast kodu."""

    def __init__(self, service: HandoverService) -> None:
        super().__init__()
        self.service = service

    def work(self):
        try:
            return self.step()
        except (ServiceError, winhello.HelloError, dpapi.DpapiError, HandoverError) as e:
            log.warning('handover: %s', e)
            raise HandoverFailure(describe(e)) from None
        except OSError as e:
            log.warning('handover: %s', e)
            raise HandoverFailure(_('The file could not be read or written: %(error)s')
                                  % {'error': e.strerror or e}) from None

    def step(self):                            # pragma: no cover — nadpisywane
        raise NotImplementedError


class CreateCardTask(HandoverTask):
    def __init__(self, service, display_name: str, use_windows_hello: bool = True) -> None:
        super().__init__(service)
        self.display_name = display_name
        self.use_windows_hello = use_windows_hello

    def step(self):
        self.signals.message.emit(_('Windows Hello asks twice: for the new key and for '
                                    'signing the card.'))
        return self.service.create_identity(display_name=self.display_name,
                                            use_windows_hello=self.use_windows_hello)


class AddContactTask(HandoverTask):
    def __init__(self, service, card_file: CardFile, *, label: str, method: str, day: date,
                 note: str = '') -> None:
        super().__init__(service)
        self.card_file, self.label, self.method, self.day, self.note = (
            card_file, label, method, day, note)

    def step(self):
        return self.service.add_contact(self.card_file, label=self.label, method=self.method,
                                        day=self.day, note=self.note)


@dataclass
class SendRequest:
    contact: str
    files: list[Path]
    title: str
    note: str
    sender_name: str
    expires_days: int
    complete_within_days: int
    out_dir: Path


class SendTask(HandoverTask):
    def __init__(self, service, request: SendRequest) -> None:
        super().__init__(service)
        self.request = request

    def step(self):
        r = self.request
        self.signals.message.emit(_('Encrypting the files and signing the offer…'))
        return self.service.send(r.contact, r.files, title=r.title, note=r.note,
                                 sender_name=r.sender_name, expires_days=r.expires_days,
                                 complete_within_days=r.complete_within_days, out_dir=r.out_dir)


class ReceiveTask(HandoverTask):
    def __init__(self, service, path: Path) -> None:
        super().__init__(service)
        self.path = path

    def step(self):
        record = self.service.receive(self.path)
        return record, self.service.offer_stamp_time(record)


class AnswerTask(HandoverTask):
    def __init__(self, service, digest: str, decision: str, exchange: Path | None) -> None:
        super().__init__(service)
        self.digest, self.decision, self.exchange = digest, decision, exchange

    def step(self):
        record = self.service.answer(self.digest, self.decision)
        if self.exchange is not None:
            self.service.write_answer_to(record, self.exchange)
        return record


class TakeAnswerTask(HandoverTask):
    def __init__(self, service, data: bytes | str) -> None:
        super().__init__(service)
        self.data = data

    def step(self):
        return self.service.take_answer(self.data)


class MaintainTask(HandoverTask):
    """Przeglad (service.maintain): publikacje do dokonczenia, B w dzienniku dla
    kazdej zaakceptowanej przesylki (§7.5), terminy (§7.6)."""

    def __init__(self, service, folder: Path) -> None:
        super().__init__(service)
        self.folder = folder

    def step(self):
        return self.service.maintain(self.folder)


class ExchangeTask(HandoverTask):
    def __init__(self, service, folder: Path) -> None:
        super().__init__(service)
        self.folder = folder

    def step(self):
        return self.service.scan_exchange(self.folder)


class EvidenceTask(HandoverTask):
    def __init__(self, service, digest: str, *, incoming: bool, disclose: bool,
                 attestation: bool) -> None:
        super().__init__(service)
        self.digest, self.incoming, self.disclose, self.attestation = (
            digest, incoming, disclose, attestation)

    def step(self):
        build = self.service.incoming_evidence if self.incoming else self.service.evidence
        return build(self.digest, disclose=self.disclose, with_attestations=self.attestation)


class DefectProofTask(HandoverTask):
    """Dowod wady (§11.3) do wskazanego pliku — szyfrogram moze miec gigabajty."""

    def __init__(self, service, digest: str, target: Path) -> None:
        super().__init__(service)
        self.digest, self.target = digest, target

    def step(self):
        return self.service.defect_proof(self.digest, self.target)


@dataclass
class DefectCheck:
    report: object
    offer: object | None                # handover.package.Offer, gdy oferta sie czyta
    sha256: str = ''                    # sprawdzony plik — do raportu PDF
    size: int = 0


def _file_sha256(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


class CheckDefectTask(HandoverTask):
    """Werdykt zarzutu wady (§11.3): sama arytmetyka — bez sieci i bez swiadka."""

    def __init__(self, service, path: Path) -> None:
        super().__init__(service)
        self.path = path

    def step(self):
        from .handover import evidence as E, package as P
        with open(self.path, 'rb') as f:
            defect = E.Defect(f)
            try:
                report = defect.verify()
            finally:
                defect.close()
        offer = None
        if isinstance(defect.doc, dict):
            try:
                offer = P.read_offer(defect.doc.get('offer'))
            except HandoverError:
                pass
        digest, size = _file_sha256(self.path)
        return DefectCheck(report=report, offer=offer, sha256=digest, size=size)


@dataclass
class EvidenceCheck:
    report: object
    confirmations: dict
    log_errors: dict
    proofs: dict = field(default_factory=dict)     # skrot hex -> LogProof (§12.1) albo None
    doc: dict | None = None                        # evidence.json sprawdzonego pliku
    sha256: str = ''
    size: int = 0


class CheckEvidenceTask(HandoverTask):
    """Werdykt (§12) + potwierdzenie czasow przez naszego swiadka (N16)."""

    def __init__(self, service, data: bytes, other: bytes | None, witness_state,
                 key_override: str = '') -> None:
        super().__init__(service)
        self.data, self.other = data, other
        self.state, self.key_override = witness_state, key_override

    def step(self):
        from .handover import evidence as E
        report = self.service.check_evidence(self.data, self.other)
        texts = {}
        errors = {}
        proofs = {}
        doc = None
        for blob in (self.data, self.other):
            if blob is None:
                continue
            ev = E.Evidence(blob)
            if doc is None and isinstance(ev.doc, dict):
                doc = ev.doc
            log_map = ev.doc.get('log') if isinstance(ev.doc, dict) else None
            if isinstance(log_map, dict):
                texts.update({k: v for k, v in log_map.items() if isinstance(v, str)})
                payload_log = ev.payload_log(self.service.receipt_keys())
                for digest in log_map:
                    try:
                        proof = payload_log.proof_of(bytes.fromhex(digest))
                    except ValueError:
                        continue
                    if proofs.get(digest) is None:
                        proofs[digest] = proof
                errors.update({k: e.code for k, e in payload_log.errors.items()})
        return EvidenceCheck(report=report,
                             confirmations=confirm.confirmations(texts, self.state,
                                                                 key_override=self.key_override),
                             log_errors=errors, proofs=proofs, doc=doc,
                             sha256=hashlib.sha256(self.data).hexdigest(), size=len(self.data))
