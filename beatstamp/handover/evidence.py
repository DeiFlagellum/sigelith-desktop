"""
Pakiet dowodowy i weryfikacja — HANDOVER_SPEC.md §11-12.

Weryfikacja NIE ufa nadawcy, ktory przynosi pakiet: przelicza kazdy podpis,
kazde zobowiazanie i kolejnosc czasow. Czasy bierze z „widoku dziennika"
(`LogView`) — w aplikacji i na stronie weryfikatora to `PayloadLog`: dowody
z /api/proof/verify zapisane w pakiecie, oceniane regula §12.1 (kwit
przypietego klucza + korzen tygodnia, logproof.py); w testach i wektorach
prosty slownik. Werdykt:

* `delivered`      — akceptacja weszla w zycie: B w dzienniku o czasie T,
                     po stemplu akceptacji T1 i nie pozniej niz `valid_until`;
* `refused`        — jest wazna odmowa, a zadna akceptacja nie weszla w zycie;
* `not-completed`  — akceptacja bez opublikowanego (albo spoznionego) B;
* `invalid`        — pakiet nie spelnia formatu albo podpisy sa zle.

Wade oferty rozstrzyga osobno `verify_defect` (§11.3); plik dowodu wady
(`sigelith-handover-defect-v1`) pisze `write_defect`, czyta `Defect`.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import BinaryIO, Iterable, Protocol

from . import jcs
from .answer import Answer, read_answer
from .attestation import read_attestation
from .errors import HandoverError
from .identity import read_binding
from .logproof import LogProof, read_log_proof
from .package import check_container, commit_b, examine_defect, read_offer
from .primitives import hex32, parse_log_utc
from .tpm_roots import TPM_ROOTS

EVIDENCE_V = 'sigelith-handover-evidence-v1'
EVIDENCE_FIELDS = frozenset({'v', 'offer', 'answer', 'part_b', 'binding', 'attestations', 'log',
                             'disclosure'})
MAX_ATTESTATIONS = 2
EVIDENCE_JSON = 'evidence.json'
CONTAINER_BIN = 'container.bin'
EVIDENCE_JSON_MAX = 8 << 20
EVIDENCE_DEPTH = 16
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)

DEFECT_V = 'sigelith-handover-defect-v1'
DEFECT_FIELDS = frozenset({'v', 'offer', 'part_a', 'part_b'})
DEFECT_JSON = 'defect.json'
CIPHERTEXT_BIN = 'ciphertext.bin'
DEFECT_JSON_MAX = 1 << 20


class LogView(Protocol):
    """Skad weryfikator wie, KIEDY dany skrot trafil do dziennika."""

    def time_of(self, digest: bytes) -> datetime | None: ...


class DictLog:
    """Dziennik z pamieci: {skrot hex: czas}. Testy i wektory."""

    def __init__(self, times: dict[str, datetime | str]) -> None:
        self._times = {k: parse_log_utc(v) if isinstance(v, str) else v
                       for k, v in times.items()}

    def time_of(self, digest: bytes) -> datetime | None:
        return self._times.get(digest.hex())


class PayloadLog:
    """Dziennik z dowodow zapisanych w pakiecie (`log`: skrot hex -> tekst JSON
    z /api/proof/verify), oceniany regula §12.1 (logproof.read_log_proof).

    `keys` to przypiete AKTUALNE klucze dziennika (aplikacja: keys.current_public_keys()).
    Dowod, ktory nie przechodzi reguly, nie daje czasu (None), a powod zostaje
    w `errors` (skrot hex -> HandoverError) — do raportu dla czlowieka.
    """

    def __init__(self, payloads: dict, keys: Iterable[str]) -> None:
        self._payloads = payloads if isinstance(payloads, dict) else {}
        self._keys = list(keys)
        self._proofs: dict[str, LogProof | None] = {}
        self.errors: dict[str, HandoverError] = {}

    def proof_of(self, digest: bytes) -> LogProof | None:
        key = digest.hex()
        if key not in self._proofs:
            proof = None
            if key in self._payloads:
                try:
                    proof = read_log_proof(self._payloads[key], digest, self._keys)
                except HandoverError as e:
                    self.errors[key] = e
            self._proofs[key] = proof
        return self._proofs[key]

    def time_of(self, digest: bytes) -> datetime | None:
        proof = self.proof_of(digest)
        return proof.utc if proof is not None else None


class MergedLog:
    """Dzienniki z dwoch pakietow tego samego przekazania (spor, §6).

    Czas skrotu bierze z ktoregokolwiek pakietu. Dwa POPRAWNE dowody z roznym
    czasem to dwa podpisane kwity, ktore sobie przecza — dowod niewlasciwego
    zachowania dziennika, nie rozstrzygniecie: czas sie wtedy nie liczy, a
    skrot trafia do `conflicts`.
    """

    def __init__(self, *logs: LogView) -> None:
        self._logs = logs
        self.conflicts: set[str] = set()

    def time_of(self, digest: bytes) -> datetime | None:
        times = {t for t in (log.time_of(digest) for log in self._logs) if t is not None}
        if len(times) > 1:
            self.conflicts.add(digest.hex())
            return None
        return times.pop() if times else None


@dataclass(frozen=True)
class Check:
    """Jedna kontrola. `detail` to opis techniczny (EN, jak w wektorach);
    `data` — te same fakty w postaci danych (czasy, rola, skroty) dla
    interfejsu, ktory mowi po ludzku i w jezyku uzytkownika. `data` nie
    wplywa ani na werdykt, ani na porownywanie kontroli."""

    code: str
    ok: bool
    detail: str = ''
    data: dict = field(default_factory=dict, compare=False, hash=False)


@dataclass
class Report:
    verdict: str
    checks: list[Check] = field(default_factory=list)
    delivered_at: datetime | None = None
    refused_at: datetime | None = None
    offer_stamped_at: datetime | None = None
    answer_stamped_at: datetime | None = None
    binding_level: int | None = None
    attested: dict = field(default_factory=dict)   # 'sender'/'recipient' -> opis TPM

    def get(self, code: str) -> list[Check]:
        return [c for c in self.checks if c.code == code]

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]


def _iso(moment: datetime | None) -> str:
    return moment.isoformat().replace('+00:00', 'Z') if moment else 'not in the log'


def verify_evidence(doc: object, log: LogView, *, container: BinaryIO | None = None,
                    extra_answers: Iterable[dict] = (),
                    attestation_roots: tuple = TPM_ROOTS) -> Report:
    """Algorytm §12. `extra_answers`: inne odpowiedzi odbiorcy (spor, §6).

    Atestacje (§3.6) sa DODATKIEM: potwierdzaja, ze klucz karty siedzi w TPM,
    ale ich brak albo blad nie zmienia werdyktu doreczenia — tylko raport.
    """
    report = Report('invalid')

    def add(code: str, ok: bool, detail: str = '', **data) -> bool:
        report.checks.append(Check(code, ok, detail, data))
        return ok

    if not isinstance(doc, dict) or set(doc) != EVIDENCE_FIELDS or doc.get('v') != EVIDENCE_V:
        add('evidence-structure', False, f'expected a {EVIDENCE_V} document')
        return report
    try:
        offer = read_offer(doc['offer'])
    except HandoverError as e:
        add(e.code, False, e.detail)
        return report
    add('cards', True, f'sender {offer.sender.fingerprint_text}, '
                       f'recipient {offer.recipient.fingerprint_text}',
        sender=offer.sender.fingerprint_text, recipient=offer.recipient.fingerprint_text)
    add('offer', True, offer.digest.hex(), digest=offer.digest.hex())
    report.offer_stamped_at = log.time_of(offer.digest)
    add('offer-stamp', report.offer_stamped_at is not None, _iso(report.offer_stamped_at),
        at=report.offer_stamped_at, digest=offer.digest.hex())

    if doc['binding'] is None:
        add('binding', False, 'no binding record: who holds the recipient card is not documented')
    else:
        try:
            binding = read_binding(doc['binding'], offer.sender, offer.recipient)
        except HandoverError as e:
            add(e.code, False, e.detail)
        else:
            report.binding_level = binding.level
            add('binding', True, f'level {binding.level} ({binding.method}, {binding.day})',
                level=binding.level, method=binding.method, day=binding.day,
                digest=binding.digest.hex())
            stamped = log.time_of(binding.digest)
            add('binding-before-offer', stamped is not None and (
                report.offer_stamped_at is None or stamped < report.offer_stamped_at),
                _iso(stamped), at=stamped, digest=binding.digest.hex())

    attestations = doc['attestations']
    if not isinstance(attestations, list) or len(attestations) > MAX_ATTESTATIONS:
        add('attestation-structure', False, f'attestations: a list of at most {MAX_ATTESTATIONS}')
        attestations = []
    for att in attestations:
        role = next((r for r, c in (('sender', offer.sender), ('recipient', offer.recipient))
                     if isinstance(att, dict) and att.get('card') == c.fingerprint_hex), None)
        if role is None or role in report.attested:
            add('attestation-card', False, 'the attestation is not for a new card of this handover')
            continue
        card = offer.sender if role == 'sender' else offer.recipient
        try:
            result = read_attestation(att, card, roots=attestation_roots)
        except HandoverError as e:
            add(e.code, False, f'{role}: {e.detail}')
        else:
            report.attested[role] = result.description
            add('attestation', True, f'{role}: {result.description} ({result.root})',
                role=role, what=result.description, root=result.root)

    answers: list[Answer] = []
    for raw in [doc['answer'], *extra_answers]:
        try:
            answers.append(read_answer(raw, offer))
        except HandoverError as e:
            add(e.code, False, e.detail)
    if not answers:
        return report
    for ans in answers:
        add('answer', True, f'{ans.decision}, signed with the recipient card',
            decision=ans.decision, digest=ans.digest.hex())

    part_b = None
    if doc['part_b'] is not None:
        try:
            part_b = hex32(doc['part_b'], 'part_b')
        except HandoverError as e:
            add('part-b', False, e.detail)

    delivered: tuple[Answer, datetime, datetime] | None = None
    for ans in (a for a in answers if a.accepted):
        t1 = log.time_of(ans.digest)
        add('answer-stamp', t1 is not None, _iso(t1), at=t1, digest=ans.digest.hex())
        if part_b is None:
            add('part-b', False, 'part B is not in the evidence')
            continue
        if not add('part-b-commit', commit_b(part_b) == offer.commit_b,
                   'part B matches the commitment in the offer', digest=part_b.hex()):
            continue
        t = log.time_of(part_b)
        if not add('part-b-stamp', t is not None, _iso(t), at=t, digest=part_b.hex()):
            continue
        assert ans.valid_until is not None
        in_time = add('deadline', t <= ans.valid_until,
                      f'recorded {_iso(t)}, valid until {_iso(ans.valid_until)}',
                      at=t, until=ans.valid_until)
        ordered = add('order', t1 is not None and t1 < t,
                      f'acceptance stamped {_iso(t1)}, part B recorded {_iso(t)}',
                      accepted=t1, recorded=t)
        if in_time and ordered and (delivered is None or t < delivered[1]):
            delivered = (ans, t, t1)

    if delivered is not None:
        report.verdict = 'delivered'
        report.delivered_at, report.answer_stamped_at = delivered[1], delivered[2]
    elif any(not a.accepted for a in answers):
        report.verdict = 'refused'
        times = [t for t in (log.time_of(a.digest) for a in answers if not a.accepted) if t]
        report.refused_at = min(times) if times else None
    else:
        report.verdict = 'not-completed'

    if container is not None:
        _check_disclosure(offer, container, add)
    return report


def _check_disclosure(offer, container: BinaryIO, add) -> None:
    held = io.BytesIO()
    h = hashlib.sha256()
    for chunk in iter(lambda: container.read(1 << 20), b''):
        h.update(chunk)
        held.write(chunk)
    if held.tell() != offer.content_size or h.digest() != offer.content_sha256:
        add('disclosure', False, 'the disclosed container is not the committed one')
        return
    held.seek(0)
    try:
        manifest = check_container(held, offer.content_size)
    except HandoverError as e:
        add('disclosure', False, f'{e.code}: {e.detail}')
        return
    names = ', '.join(e['name'] for e in manifest['files'][:5])
    more = f' (+{len(manifest["files"]) - 5})' if len(manifest['files']) > 5 else ''
    add('disclosure', True, f'{len(manifest["files"])} file(s): {names}{more}',
        files=[{'name': e['name'], 'size': e['size'], 'sha256': e['sha256']}
               for e in manifest['files']])


def verify_defect(offer_raw: dict, a: bytes, b: bytes, ciphertext: BinaryIO) -> Report:
    """Zarzut wady (§11.3) -> werdykt `defective`, `not-defective` albo `invalid-claim`.

    Jedyna kontrola to rozstrzygniecie: kod wady, `package` (paczka dobra) albo
    kod bledu samego zarzutu. W jej danych — podglad, manifest i roznice
    miedzy nimi, o ile daly sie odczytac.
    """
    try:
        found = examine_defect(offer_raw, a, b, ciphertext)
    except HandoverError as e:
        return Report('invalid-claim', [Check(e.code, False, e.detail)])
    data = {'preview': found.preview, 'manifest': found.manifest,
            'differences': list(found.differences)}
    if found.code is None:
        return Report('not-defective', [Check('package', True, 'the package opens correctly',
                                              data)])
    return Report('defective', [Check(found.code, False, 'the offer was defective: the '
                                      'acceptance has no effect', data)])


def verify_defect_doc(doc: object, ciphertext: BinaryIO) -> Report:
    """`defect.json` (§11.3) + szyfrogram -> werdykt jak `verify_defect`."""
    if not isinstance(doc, dict) or set(doc) != DEFECT_FIELDS or doc.get('v') != DEFECT_V:
        return Report('invalid-claim', [Check('defect-structure', False,
                                              f'expected a {DEFECT_V} document')])
    try:
        a, b = hex32(doc['part_a'], 'part_a'), hex32(doc['part_b'], 'part_b')
    except HandoverError as e:
        return Report('invalid-claim', [Check('defect-structure', False, e.detail)])
    return verify_defect(doc['offer'], a, b, ciphertext)


# --- plik ZIP pakietu --------------------------------------------------------

def build_evidence(*, offer: dict, answer: dict, part_b: bytes | None,
                   binding: dict | None, log: dict[str, str | dict],
                   container: BinaryIO | bytes | None = None,
                   attestations: Iterable[dict] = ()) -> bytes:
    """ZIP z `evidence.json` (i opcjonalnie `container.bin`). Deterministyczny."""
    doc = {'v': EVIDENCE_V, 'offer': offer, 'answer': answer,
           'part_b': part_b.hex() if part_b is not None else None, 'binding': binding,
           'attestations': list(attestations),
           'log': {k: v if isinstance(v, str) else json.dumps(v, separators=(',', ':'))
                   for k, v in log.items()},
           'disclosure': CONTAINER_BIN if container is not None else None}
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        info = zipfile.ZipInfo(EVIDENCE_JSON, date_time=_ZIP_TIME)
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, jcs.dumps(doc, max_depth=EVIDENCE_DEPTH))
        if container is not None:
            info = zipfile.ZipInfo(CONTAINER_BIN, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            data = container if isinstance(container, bytes) else container.read()
            z.writestr(info, data)
    return out.getvalue()


def _open_zip(source: bytes | BinaryIO, code: str) -> tuple[zipfile.ZipFile, list[str]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(source) if isinstance(source, bytes) else source)
        return archive, [i.filename for i in archive.infolist()]
    except (zipfile.BadZipFile, OSError, ValueError):
        raise HandoverError(code, 'not a ZIP file') from None


def _read_json(archive: zipfile.ZipFile, name: str, limit: int, prefix: str) -> object:
    """Kanoniczny JSON z archiwum; bledy: `<prefix>-archive` albo `<prefix>-structure`."""
    if archive.getinfo(name).file_size > limit:
        raise HandoverError(f'{prefix}-archive', f'{name} is too large')
    try:
        return jcs.loads(archive.read(name), max_bytes=limit, max_depth=EVIDENCE_DEPTH)
    except HandoverError as e:
        raise e.renamed(f'{prefix}-structure') from None
    except (zipfile.BadZipFile, OSError, ValueError):
        raise HandoverError(f'{prefix}-archive', 'damaged archive') from None


def archive_kind(source: bytes | BinaryIO) -> str | None:
    """'defect' albo 'evidence' po nazwach w ZIP-ie; None, gdy to nie ZIP Handover.
    Tylko rozpoznanie — o poprawnosci rozstrzygaja `Defect` i `Evidence`."""
    try:
        archive, names = _open_zip(source, 'evidence-archive')
    except HandoverError:
        return None
    archive.close()
    if DEFECT_JSON in names:
        return 'defect'
    return 'evidence' if EVIDENCE_JSON in names else None


def write_defect(dst: BinaryIO, *, offer: dict, part_a: bytes, part_b: bytes,
                 ciphertext: BinaryIO, size: int) -> None:
    """Dowod wady (§11.3) prosto do `dst`. Szyfrogram strumieniowo i bez
    kompresji — moze miec gigabajty (ZIP64 wtedy sam). Deterministyczny."""
    doc = {'v': DEFECT_V, 'offer': offer, 'part_a': part_a.hex(), 'part_b': part_b.hex()}
    with zipfile.ZipFile(dst, 'w') as z:
        info = zipfile.ZipInfo(DEFECT_JSON, date_time=_ZIP_TIME)
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, jcs.dumps(doc, max_depth=EVIDENCE_DEPTH))
        info = zipfile.ZipInfo(CIPHERTEXT_BIN, date_time=_ZIP_TIME)
        info.compress_type = zipfile.ZIP_STORED
        info.file_size = size
        with z.open(info, 'w') as out:
            for chunk in iter(lambda: ciphertext.read(1 << 20), b''):
                out.write(chunk)


class Defect:
    """Odczytany dowod wady: dokladnie `defect.json` i `ciphertext.bin`."""

    def __init__(self, source: bytes | BinaryIO) -> None:
        self._zip, names = _open_zip(source, 'defect-archive')
        if len(names) != len(set(names)) or set(names) != {DEFECT_JSON, CIPHERTEXT_BIN}:
            raise HandoverError('defect-archive', f'expected exactly {DEFECT_JSON} and '
                                f'{CIPHERTEXT_BIN}')
        self.doc = _read_json(self._zip, DEFECT_JSON, DEFECT_JSON_MAX, 'defect')

    def open_ciphertext(self) -> BinaryIO:
        return self._zip.open(CIPHERTEXT_BIN)

    def verify(self) -> Report:
        try:
            with self.open_ciphertext() as ciphertext:
                return verify_defect_doc(self.doc, ciphertext)
        except (zipfile.BadZipFile, OSError):
            raise HandoverError('defect-archive', 'damaged archive') from None

    def close(self) -> None:
        self._zip.close()


class Evidence:
    """Odczytany pakiet: tylko dwie znane nazwy, bez wypakowywania na dysk."""

    def __init__(self, source: bytes | BinaryIO) -> None:
        self._zip, names = _open_zip(source, 'evidence-archive')
        if (len(names) != len(set(names)) or EVIDENCE_JSON not in names
                or not set(names) <= {EVIDENCE_JSON, CONTAINER_BIN}):
            raise HandoverError('evidence-archive', f'expected only {EVIDENCE_JSON} '
                                f'and optionally {CONTAINER_BIN}')
        self.doc = _read_json(self._zip, EVIDENCE_JSON, EVIDENCE_JSON_MAX, 'evidence')
        self.has_container = CONTAINER_BIN in names
        if isinstance(self.doc, dict) and (self.doc.get('disclosure') is not None) != self.has_container:
            raise HandoverError('evidence-structure', 'disclosure does not match the archive')

    def open_container(self) -> BinaryIO | None:
        return self._zip.open(CONTAINER_BIN) if self.has_container else None

    def payload_log(self, keys: Iterable[str]) -> PayloadLog:
        log = self.doc.get('log') if isinstance(self.doc, dict) else None
        if not isinstance(log, dict) or not all(isinstance(v, str) for v in log.values()):
            raise HandoverError('evidence-structure', 'log: map of digest -> proof JSON')
        return PayloadLog(log, keys)

    def verify(self, log: LogView, *, extra_answers: Iterable[dict] = (),
               attestation_roots: tuple = TPM_ROOTS) -> Report:
        container = self.open_container()
        try:
            return verify_evidence(self.doc, log, container=container,
                                   extra_answers=extra_answers,
                                   attestation_roots=attestation_roots)
        finally:
            if container is not None:
                container.close()
