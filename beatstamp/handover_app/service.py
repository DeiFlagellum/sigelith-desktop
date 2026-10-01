"""
Sigelith Handover w aplikacji — przebieg HANDOVER_SPEC.md §7, bez Qt.

Warstwa laczy czysty protokol (beatstamp.handover) z tym, czego protokol nie
robi: kluczami na tym komputerze (Windows Hello, DPAPI), stanem na dysku
(store.py) i dziennikiem Sigelith (`LogClient` — stemple, dowody, wpisy).
Interfejs wola te metody w watkach roboczych: kazda moze czekac na siec, a
podpis — na decyzje czlowieka w oknie Windows Hello.

Kolejnosc krokow jest kolejnoscia ze specyfikacji i NIE WOLNO jej zmieniac:
odbiorca stempluje swoja odpowiedz ZANIM ja wyda (§7.3), nadawca publikuje B
dopiero po sprawdzeniu odpowiedzi z zapasem godziny (§7.4), a B nigdy nie
idzie do dziennika dla odmowionej oferty.

Sekrety przechodza przez pamiec tylko na czas operacji; na dysku wylacznie
jako DPAPI (store.py).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable, Protocol

from ..api import ApiError
from ..handover import answer as A_, evidence as E, identity as I, package as P, transport as T
from ..handover import primitives as X
from ..handover.attestation import read_attestation
from ..handover.errors import HandoverError
from ..handover.logproof import LogProof
from ..handover.logsearch import find_part_b
from ..handover.rules import WINDOWS_FORBIDDEN, check_mime
from . import dpapi, winhello
from .store import Contact, HandoverStore, Identity, Incoming, Outgoing

PACKAGE_SUFFIX = '.sigelith-handover'
ANSWER_SUFFIX = '.sigelith-answer'
CARD_SUFFIX = '.sigelith-card'
EVIDENCE_SUFFIX = '.sigelith-evidence.zip'
DEFECT_SUFFIX = '.sigelith-defect.zip'
ENTRIES_PAGE = 1000
# Bledy sieci, po ktorych krok „SHOULD" (stempel pliku, oferty, powiazania)
# zostaje do ponowienia, a przebieg idzie dalej.
NETWORK_ERRORS = (OSError, ApiError)
# Zapas po terminie, zanim przesylke uznamy za przepadla: stempel B zrobiony
# tuz przed `valid_until` moze byc jeszcze w drodze do listy wpisow.
EXPIRY_GRACE = timedelta(minutes=10)


class LogClient(Protocol):
    """Dziennik Sigelith widziany przez aplikacje (adapter: handover_app.log)."""

    def now(self) -> datetime: ...                          # czas dziennika, UTC
    def stamp(self, digest: bytes) -> dict: ...             # odpowiedz /api/proof/stamp
    def verify_text(self, digest: bytes) -> str | None: ...  # surowy tekst /api/proof/verify
    def entries(self, from_seq: int) -> list[dict]: ...     # /api/proof/entries?from=


class ServiceError(Exception):
    """Stan, ktory interfejs pokazuje czlowiekowi; `code` wybiera tekst."""

    def __init__(self, code: str, detail: str = '') -> None:
        super().__init__(f'{code}: {detail}' if detail else code)
        self.code = code
        self.detail = detail


def _b64(data: bytes) -> str:
    return X.b64encode(data)


def _unb64(text: str) -> bytes:
    return X.b64decode(text, 'blob')


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def _file_sha256(path: Path) -> bytes:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.digest()


@dataclass
class ExchangeResult:
    received: list[Incoming] = field(default_factory=list)
    answered: list[Outgoing] = field(default_factory=list)
    problems: list[tuple[str, 'ServiceError']] = field(default_factory=list)


@dataclass
class MaintenanceResult:
    """Przeglad w tle: co sie otworzylo, doreczylo, przepadlo — i co nie wyszlo."""

    opened: list[Incoming] = field(default_factory=list)
    delivered: list[Outgoing] = field(default_factory=list)
    expired: list[Incoming | Outgoing] = field(default_factory=list)
    problems: list[tuple[str, 'ServiceError']] = field(default_factory=list)


@dataclass(frozen=True)
class CardFile:
    """Karta z pliku, juz sprawdzona. `attested` = opis TPM albo None,
    `attestation_problem` = kod bledu atestacji (karta i tak jest wazna)."""

    card: dict
    info: I.Card
    attestation: dict | None
    attested: str | None
    attestation_problem: str | None


class HandoverService:
    def __init__(self, store: HandoverStore, log: LogClient, *,
                 hello=winhello, protect: Callable[[bytes, str], bytes] = dpapi.protect,
                 unprotect: Callable[[bytes, str], bytes] = dpapi.unprotect,
                 hwnd: Callable[[], int] | int = 0,
                 receipt_keys: Iterable[str] | None = None) -> None:
        self.store = store
        self.log = log
        self.hello = hello
        self._protect = protect
        self._unprotect = unprotect
        self.hwnd = hwnd
        # Przypiete AKTUALNE klucze dziennika (keys.py); testy podaja klucz testowy.
        self._receipt_keys = tuple(receipt_keys) if receipt_keys is not None else None

    # --- sekrety i klucze ------------------------------------------------------

    def _seal(self, data: bytes, purpose: str) -> str:
        return _b64(self._protect(data, purpose))

    def _open(self, blob: str, purpose: str) -> bytes:
        try:
            return self._unprotect(_unb64(blob), purpose)
        except (dpapi.DpapiError, HandoverError):
            raise ServiceError('secret-unreadable', purpose) from None

    def identity(self) -> Identity:
        ident = self.store.active_identity()
        if ident is None:
            raise ServiceError('no-identity')
        return ident

    def signer(self, ident: Identity) -> I.Signer:
        if ident.cred_id:
            public = X.b64decode(ident.card['sig_key'], 'sig_key', X.P256_PUBLIC_LEN)
            return self.hello.WindowsHelloSigner(_unb64(ident.cred_id), public, self.hwnd)
        return I.SoftwareSigner.from_bytes(self._open(ident.signing_blob, 'signing-key'),
                                           storage='software')

    def enc_keys(self) -> list[X.EncKey]:
        """Klucze wszystkich moich kart (aktywnej i archiwalnych) — koperta mowi, ktora."""
        keys = []
        for ident in self.store.identities():
            try:
                keys.append(X.EncKey.from_bytes(self._open(ident.enc_blob, 'enc-key')))
            except ServiceError:
                continue                     # karta z innego konta Windows — pomijamy
        return keys

    def _enc_key_for(self, fingerprint: str) -> tuple[Identity, X.EncKey]:
        for ident in self.store.identities():
            if ident.fingerprint == fingerprint:
                return ident, X.EncKey.from_bytes(self._open(ident.enc_blob, 'enc-key'))
        raise ServiceError('offer-not-mine')

    def _log_now(self) -> datetime:
        return self.log.now().astimezone(timezone.utc)

    def _stamp(self, digest: bytes) -> dict:
        payload = self.log.stamp(digest)
        if not isinstance(payload, dict) or payload.get('digest') != digest.hex():
            raise ServiceError('stamp-failed', 'the log answered for another digest')
        return payload

    # --- moja karta --------------------------------------------------------------

    def create_identity(self, *, display_name: str, use_windows_hello: bool = True) -> Identity:
        """Nowa karta. Windows Hello pyta dwa razy: przy kluczu i przy podpisie karty."""
        enc = X.EncKey.generate()
        created = self._log_now().replace(microsecond=0)
        attestation = attestation_raw = cred_id = signing_blob = None
        if use_windows_hello and self.hello.available():
            cred = self.hello.create_credential(self.hwnd() if callable(self.hwnd) else self.hwnd,
                                                'handover@sigelith.org', display_name)
            signer = self.hello.WindowsHelloSigner(cred.cred_id, cred.public, self.hwnd)
            cred_id = _b64(cred.cred_id)
        else:
            cred = None
            signer = I.SoftwareSigner(storage='software')
            signing_blob = self._seal(signer.to_bytes(), 'signing-key')
        card = I.make_card(signer, enc.public_bytes, created)
        info = I.read_card(card)
        if cred is not None:
            attestation = cred.companion(info.fingerprint_hex)
            if attestation is None and cred.attestation_object:
                attestation_raw = {'fmt': cred.fmt,
                                   'attestation_object': _b64(cred.attestation_object),
                                   'client_data_json': _b64(cred.client_data_json)}
        ident = Identity(fingerprint=info.fingerprint_hex, card=card,
                         enc_blob=self._seal(enc.to_bytes(), 'enc-key'), created=_iso(created),
                         attestation=attestation, attestation_raw=attestation_raw,
                         cred_id=cred_id, signing_blob=signing_blob)
        for old in self.store.identities():
            if not old.archived:
                old.archived = True
                self.store.save_identity(old)
        self.store.save_identity(ident)
        return ident

    def card_file(self, *, with_attestation: bool = True) -> bytes:
        ident = self.identity()
        return T.write_card_file(ident.card, ident.attestation if with_attestation else None)

    # --- kontakty ----------------------------------------------------------------

    def read_card_file(self, data: bytes) -> CardFile:
        try:
            card, attestation = T.read_card_file(data)
            info = I.read_card(card)
        except HandoverError as e:
            raise ServiceError('card-invalid', e.code) from None
        attested = problem = None
        if attestation is not None:
            try:
                attested = read_attestation(attestation, info).description
            except HandoverError as e:
                problem = e.code
        return CardFile(card=card, info=info, attestation=attestation, attested=attested,
                        attestation_problem=problem)

    def add_contact(self, card_file: CardFile, *, label: str, method: str, day: date,
                    note: str = '') -> Contact:
        """Zapis powiazania (§3.4) podpisany MOIM kluczem i ostemplowany (SHOULD)."""
        ident = self.identity()
        if card_file.info.fingerprint_hex == ident.fingerprint:
            raise ServiceError('card-is-mine')
        me = I.read_card(ident.card)
        try:
            record = I.make_binding(self.signer(ident), me, card_file.info, method, day, note)
        except HandoverError as e:
            raise ServiceError('binding-invalid', e.code) from None
        contact = Contact(fingerprint=card_file.info.fingerprint_hex, card=card_file.card,
                          label=label.strip(), binding=record, added=_iso(self._log_now()),
                          attestation=card_file.attestation if card_file.attested else None)
        self.store.save_contact(contact)
        self.stamp_binding(contact)
        return self.store.contact(contact.fingerprint)

    def binding_digest(self, contact: Contact) -> bytes:
        me = self.identity()
        return I.read_binding(contact.binding, I.read_card(me.card)).digest

    def stamp_binding(self, contact: Contact) -> bool:
        """Stempel zapisu powiazania — pokazuje, ze powstal przed sporem. Bez sieci:
        zostaje do ponowienia przy nastepnej wysylce."""
        try:
            self._stamp(self.binding_digest(contact))
        except (ServiceError, HandoverError, *NETWORK_ERRORS):
            return False
        contact.binding_stamped = True
        self.store.save_contact(contact)
        return True

    # --- nadawca: wysylka (§7.1) --------------------------------------------------

    def send(self, contact_fingerprint: str, files: list[Path], *, title: str = '',
             note: str = '', sender_name: str = '', expires_days: int = 30,
             complete_within_days: int = 14, out_dir: Path,
             stamp_files: bool = True) -> Outgoing:
        ident = self.identity()
        contact = self.store.contact(contact_fingerprint)
        if contact is None:
            raise ServiceError('no-contact')
        if not files:
            raise ServiceError('no-files')
        if not contact.binding_stamped:
            self.stamp_binding(contact)
        if stamp_files:
            # §7.1.2 (SHOULD): wlasny stempel kazdego pliku. Blad sieci nie
            # zatrzymuje wysylki — dowod doreczenia i tak powstanie.
            for path in files:
                try:
                    self._stamp(_file_sha256(path))
                except (ServiceError, *NETWORK_ERRORS):
                    break
        created = self._log_now().replace(microsecond=0)
        inputs = [P.InputFile(p.name, p, _mime(p)) for p in files]
        work = self.store.root / 'outgoing'
        work.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix='send-', suffix='.tmp', dir=work)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, 'w+b') as ciphertext:
                try:
                    out = P.create_offer(
                        signer=self.signer(ident), sender_card=ident.card,
                        recipient_card=contact.card, files=inputs, ciphertext_out=ciphertext,
                        created=created, title=title, note=note, sender_name=sender_name,
                        expires=created + _days(expires_days),
                        complete_within=complete_within_days * 86400)
                except HandoverError as e:
                    raise ServiceError('offer-invalid', f'{e.code}: {e.detail}') from None
                digest = out.info.digest.hex()
                ciphertext.flush()
                ciphertext.seek(0)
                out_dir.mkdir(parents=True, exist_ok=True)
                package = out_dir / f'{digest[:16]}{PACKAGE_SUFFIX}'
                with open(package, 'wb') as dst:
                    T.write_package_file(dst, out.info.recipient.enc_key, out.offer, ciphertext,
                                         out.info.ciphertext_size)
            os.replace(tmp, self.store.ciphertext_path('outgoing', digest))
        finally:
            if tmp.exists():
                tmp.unlink()
        record = Outgoing(offer_digest=digest, offer=out.offer, contact=contact.fingerprint,
                          title=title, files=[p.name for p in files],
                          total_size=sum(p.stat().st_size for p in files),
                          part_a_blob=self._seal(out.parts.a, 'part-a'),
                          part_b_blob=self._seal(out.parts.b, 'part-b'),
                          created=_iso(created), package_path=str(package), note=note)
        try:
            self._stamp(out.info.digest)                       # T0 (SHOULD)
            record.offer_stamped = True
        except (ServiceError, *NETWORK_ERRORS):
            pass
        self.store.save_outgoing(record)
        return record

    # --- odbiorca: przyjecie pliku paczki (§7.2) -----------------------------------

    def receive(self, package_path: Path) -> Incoming:
        keys = self.enc_keys()
        if not keys:
            raise ServiceError('no-identity')
        with open(package_path, 'rb') as src:
            try:
                offer_raw, _size = T.read_package_file(src, keys)
                offer = P.read_offer(offer_raw)
            except HandoverError as e:
                raise ServiceError('package-invalid', e.code) from None
            existing = self.store.get_incoming(offer.digest.hex())
            if existing is not None:
                return existing
            ident, enc = self._enc_key_for(offer.recipient.fingerprint_hex)
            try:
                P.check_offer_times(offer, self._log_now())
                a, preview = P.open_offer(offer, enc, I.read_card(ident.card))
            except HandoverError as e:
                raise ServiceError('package-invalid', e.code) from None
            target = self.store.ciphertext_path('incoming', offer.digest.hex())
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_suffix('.tmp')
            try:
                with open(tmp, 'wb') as dst:
                    P.copy_ciphertext(offer, src, dst)
                os.replace(tmp, target)
            except HandoverError as e:
                raise ServiceError('package-invalid', e.code) from None
            finally:
                if tmp.exists():
                    tmp.unlink()
        record = Incoming(offer_digest=offer.digest.hex(), offer=offer_raw,
                          sender=offer.sender.fingerprint_hex, my_card=ident.fingerprint,
                          preview=preview, part_a_blob=self._seal(a, 'part-a'),
                          received=_iso(self._log_now()))
        try:
            t0 = self.offer_stamp_time(record)                 # §7.2.4 — tylko informacja
            record.offer_stamped_at = _iso(t0) if t0 else None
        except NETWORK_ERRORS:
            pass
        self.store.save_incoming(record)
        return record

    def offer_stamp_time(self, record: Incoming | Outgoing) -> datetime | None:
        """T0, jesli oferta jest w dzienniku (§7.2.4) — tylko informacja."""
        proof = self.proof(bytes.fromhex(record.offer_digest))
        return proof.utc if proof else None

    # --- odbiorca: odpowiedz (§7.3) ------------------------------------------------

    def answer(self, digest: str, decision: str) -> Incoming:
        record = self.store.get_incoming(digest)
        if record is None:
            raise ServiceError('no-package')
        if record.answer is not None:
            raise ServiceError('already-answered')   # jedna odpowiedz na oferte (§6)
        offer = P.read_offer(record.offer)
        ident = next((i for i in self.store.identities() if i.fingerprint == record.my_card), None)
        if ident is None:
            raise ServiceError('offer-not-mine')
        if record.status != 'new':
            raise ServiceError('offer-expired')           # przepadla: nie ma juz czego podpisac
        now = self._log_now()
        if now >= offer.expires:
            # §7.3 „Pozniej / nic": po `expires` aplikacja porzuca oferte.
            self._expire_incoming(record)
            raise ServiceError('offer-expired')
        held = None
        if decision == 'accept':
            held = _file_sha256(self.store.ciphertext_path('incoming', digest))
        try:
            answer = A_.make_answer(self.signer(ident), offer, decision, log_now=now,
                                    ciphertext_sha256=held)
        except HandoverError as e:
            raise ServiceError('answer-invalid', e.code) from None
        parsed = A_.read_answer(answer, offer)
        # MUST: stempel odpowiedzi ZANIM ktokolwiek ja dostanie (T1). Bez stempla
        # odpowiedz nie wychodzi z aplikacji.
        payload = self._stamp(parsed.digest)
        record.answer = answer
        record.answer_seq = payload.get('seq') if isinstance(payload.get('seq'), int) else None
        record.answer_file = _b64(T.write_answer_file(offer.sender.enc_key, answer))
        record.status = 'accepted' if parsed.accepted else 'refused'
        if not parsed.accepted:
            # §7.3: po odmowie A i szyfrogram nie sa juz potrzebne.
            record.part_a_blob = ''
            self.store.ciphertext_path('incoming', digest).unlink(missing_ok=True)
        self.store.save_incoming(record)
        return record

    def answer_file(self, record: Incoming) -> bytes:
        if not record.answer_file:
            raise ServiceError('not-answered')
        return _unb64(record.answer_file)

    def answer_text(self, record: Incoming) -> str:
        return T.answer_text(self.answer_file(record))

    # --- nadawca: odpowiedz i publikacja B (§7.4) ------------------------------------

    def take_answer(self, data: bytes | str) -> Outgoing:
        if isinstance(data, str):
            try:
                data = T.parse_answer_text(''.join(data.split()))
            except HandoverError as e:
                raise ServiceError('answer-invalid', e.code) from None
        try:
            answer = T.read_answer_file(data, self.enc_keys())
        except HandoverError as e:
            raise ServiceError('answer-invalid', e.code) from None
        digest = answer.get('offer') if isinstance(answer, dict) else None
        record = self.store.get_outgoing(digest) if isinstance(digest, str) and len(digest) == 64 else None
        if record is None:
            raise ServiceError('no-package')
        offer = P.read_offer(record.offer)
        try:
            parsed = A_.read_answer(answer, offer)
        except HandoverError as e:
            raise ServiceError('answer-invalid', e.code) from None
        if not any(_same(a, answer) for a in record.answers):
            # Odpowiedz zostaje w rekordzie, ZANIM cokolwiek pojdzie przez siec:
            # po bledzie sieci publikacje ponowi `complete_pending`.
            record.answers.append(answer)
            self.store.save_outgoing(record)
        return self._complete(record, offer, parsed)

    def _complete(self, record: Outgoing, offer: P.Offer, parsed: A_.Answer) -> Outgoing:
        answer_payload = self._stamp(parsed.digest)              # T1 (idempotentne)
        if record.status == 'delivered':
            # Przyjecie, ktore weszlo w zycie, rozstrzyga (§6) — pozniejsza odmowa
            # zostaje w rekordzie jako dowod, ale niczego nie cofa.
            return record
        if not parsed.accepted:
            record.status = 'refused'
            record.refused_at = record.refused_at or answer_payload.get('utc')
            self._drop_outgoing_secrets(record)                  # B nigdy nie pojdzie (§7.4.2)
            self.store.save_outgoing(record)
            return record
        if record.status == 'refused' or any(not A_.read_answer(a, offer).accepted
                                             for a in record.answers):
            raise ServiceError('publish-refused', 'offer-refused')   # B nigdy po odmowie
        if not record.part_b_blob:
            raise ServiceError('publish-refused', 'offer-closed')    # po terminie B usuniete
        b = self._open(record.part_b_blob, 'part-b')
        if not hmac.compare_digest(P.commit_b(b), offer.commit_b):
            raise ServiceError('secret-unreadable', 'part-b')
        if record.publish_attempted:
            # B juz raz poszlo do dziennika i moglo zostac zapisane, choc odpowiedz
            # nie dotarla (§13 p. 4). Dopiero wtedy pytanie o B niczego nie zdradza.
            text = self.log.verify_text(b)
            if text is not None:
                return self._delivered(record, _payload_utc(text))
        try:
            A_.check_publish(parsed, self._log_now())
        except HandoverError as e:
            record.status = 'failed'                             # doreczenie sie nie odbylo
            record.error = 'publish-uncertain' if record.publish_attempted else e.code
            self.store.save_outgoing(record)
            raise ServiceError('publish-refused', e.code) from None
        record.publish_attempted = True
        self.store.save_outgoing(record)                         # ZANIM B wyjdzie z komputera
        payload = self._stamp(b)                                 # T: chwila doreczenia
        return self._delivered(record, payload.get('utc'))

    def _delivered(self, record: Outgoing, utc: object) -> Outgoing:
        record.status = 'delivered'
        record.delivered_at = utc if isinstance(utc, str) else None
        record.error = None
        self.store.save_outgoing(record)
        return record

    def complete_pending(self) -> tuple[list[Outgoing], list[tuple[str, ServiceError]]]:
        """Odpowiedzi, ktorych nie dalo sie dokonczyc (siec) — §7.4: ponawiac do
        godziny przed `valid_until`. Odmowa ma pierwszenstwo przed akceptacja,
        dopoki zadna akceptacja nie weszla w zycie (§6)."""
        done, problems = [], []
        for record in self.store.outgoing():
            if not record.answers or not record.part_b_blob:
                continue
            if not (record.status in ('sent', 'expired') or
                    (record.status == 'failed' and record.publish_attempted)):
                continue
            offer = P.read_offer(record.offer)
            parsed = [A_.read_answer(a, offer) for a in record.answers]
            chosen = next((p for p in parsed if not p.accepted), parsed[-1])
            try:
                done.append(self._complete(record, offer, chosen))
            except ServiceError as e:
                problems.append((record.offer_digest, e))
        return done, problems

    # --- odbiorca: B w dzienniku i otwarcie (§7.5) ------------------------------------

    def look_for_part_b(self, digest: str, *, folder: Path, max_pages: int = 50,
                        now: datetime | None = None) -> Incoming:
        """B w dzienniku (§7.5), od miejsca, w ktorym skonczyl poprzedni przeglad.

        Akceptacja przepada (§7.6), gdy przeglad doszedl do KONCA dziennika,
        a czas dziennika zmierzony PRZED nim jest juz po `valid_until` (z
        zapasem): kazdy stempel sprzed terminu ma wtedy numer, ktory przeglad
        widzial.
        """
        record = self.store.get_incoming(digest)
        if record is None or record.status != 'accepted':
            return record
        offer = P.read_offer(record.offer)
        now = now or self._log_now()
        start = record.search_seq or record.answer_seq or 1
        found = None
        complete = False
        for _ in range(max_pages):
            page = self.log.entries(start)
            hit = find_part_b(page, offer.commit_b)
            if hit is not None:
                found = hit[0]
                break
            seqs = [e.get('seq') for e in page if isinstance(e, dict) and isinstance(e.get('seq'), int)]
            if seqs:
                start = max(start, max(seqs) + 1)
            if len(page) < ENTRIES_PAGE or not seqs:
                complete = True
                break
        if found is not None:
            return self._open_package(record, offer, found, package_folder(folder, record))
        record.search_seq = start
        valid_until = A_.read_answer(record.answer, offer).valid_until
        if complete and valid_until is not None and now > valid_until + EXPIRY_GRACE:
            record.error = 'acceptance-lapsed'
            self._expire_incoming(record)
        self.store.save_incoming(record)
        return record

    def _open_package(self, record: Incoming, offer: P.Offer, b: bytes, folder: Path) -> Incoming:
        a = self._open(record.part_a_blob, 'part-a')
        folder.mkdir(parents=True, exist_ok=True)
        with open(self.store.ciphertext_path('incoming', record.offer_digest), 'rb') as ct:
            try:
                _manifest, saved, differences = P.open_package(offer, a, b, ct, record.preview, folder)
            except HandoverError as e:
                record.status = 'defective'
                record.error = e.code
                record.part_b = b.hex()
                self.store.save_incoming(record)
                raise ServiceError('package-defective', e.code) from None
        record.part_b = b.hex()
        record.status = 'opened'
        record.opened_at = _iso(self._log_now())
        record.folder = str(folder)
        record.saved = [str(p) for p in saved]
        record.preview_differences = differences
        if differences:
            record.error = 'preview-mismatch'
        self.store.save_incoming(record)
        return record

    # --- terminy (§7.3 „Pozniej", §7.6) i przeglad w tle --------------------------------

    def _expire_incoming(self, record: Incoming) -> None:
        """Przesylka, ktorej juz nie da sie otworzyc: A i szyfrogram na nic (§7.3)."""
        record.status = 'expired'
        record.part_a_blob = ''
        self.store.ciphertext_path('incoming', record.offer_digest).unlink(missing_ok=True)
        self.store.save_incoming(record)

    def _drop_outgoing_secrets(self, record: Outgoing) -> None:
        """B nie moze juz zostac opublikowane — B, A i kopia szyfrogramu znikaja.
        Oferta, odpowiedzi i dowody zostaja."""
        record.part_a_blob = ''
        record.part_b_blob = ''
        self.store.ciphertext_path('outgoing', record.offer_digest).unlink(missing_ok=True)

    def expire_overdue(self, now: datetime | None = None) -> list[Incoming | Outgoing]:
        """Statusy po terminach wedlug czasu DZIENNIKA. Rekordy zostaja — znikaja
        tylko sekrety, ktore nie moga sie juz przydac."""
        now = now or self._log_now()
        changed: list[Incoming | Outgoing] = []
        for record in self.store.incoming():
            if record.status == 'new' and now >= P.read_offer(record.offer).expires:
                self._expire_incoming(record)
                changed.append(record)
        for record in self.store.outgoing():
            if record.status not in ('sent', 'expired', 'failed'):
                continue
            offer = P.read_offer(record.offer)
            before = (record.status, record.part_b_blob)
            if record.status == 'sent' and not record.answers and now >= offer.expires:
                record.status = 'expired'            # „nieodebrana" — status, nie dowod (§7.6)
            if now >= offer.answer_bound + EXPIRY_GRACE:
                # Zadna odpowiedz nie moze juz wejsc w zycie (§6): koniec przesylki.
                if record.status == 'sent':
                    record.status = 'failed'
                self._drop_outgoing_secrets(record)
            if (record.status, record.part_b_blob) != before:
                self.store.save_outgoing(record)
                changed.append(record)
        return changed

    def has_pending(self) -> bool:
        """Czy przeglad w tle ma na co czekac."""
        return (any(r.status in ('new', 'accepted') for r in self.store.incoming()) or
                any(r.status in ('sent', 'expired', 'failed') and r.part_b_blob
                    for r in self.store.outgoing()))

    def maintain(self, folder: Path) -> MaintenanceResult:
        """Przeglad: dokonczenie publikacji (nadawca), B w dzienniku (odbiorca),
        potem terminy. Blad sieci przerywa przeglad — nastepny zacznie od nowa."""
        result = MaintenanceResult()
        now = self._log_now()
        result.delivered, result.problems = self.complete_pending()
        result.delivered = [r for r in result.delivered if r.status == 'delivered']
        for record in self.store.incoming():
            if record.status != 'accepted':
                continue
            try:
                after = self.look_for_part_b(record.offer_digest, folder=folder, now=now)
            except ServiceError as e:
                result.problems.append((record.offer_digest, e))
                continue
            if after.status == 'opened':
                result.opened.append(after)
            elif after.status == 'expired':
                result.expired.append(after)
        result.expired += self.expire_overdue(now)
        return result

    # --- folder wymiany (§10.3) ------------------------------------------------------

    def write_answer_to(self, record: Incoming, folder: Path) -> Path:
        """Plik odpowiedzi w folderze wymiany (albo innym) — zapieczetowany do nadawcy."""
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f'{record.offer_digest[:16]}{ANSWER_SUFFIX}'
        tmp = path.with_suffix('.tmp')
        tmp.write_bytes(self.answer_file(record))
        os.replace(tmp, path)
        return path

    def scan_exchange(self, folder: Path) -> 'ExchangeResult':
        """Nowe paczki i odpowiedzi w folderze wymiany.

        W folderze leza tez pliki DLA DRUGIEJ STRONY (moja paczka, jej odpowiedz
        do kogos innego) — koperta nie otwiera sie zadnym z moich kluczy i plik
        jest po cichu pomijany. Kazdy plik ogladamy raz (nazwa, rozmiar, czas
        zmiany); blad sieci zostawia go do nastepnego przegladu.
        """
        seen_path = self.store.root / 'exchange-seen.json'
        seen = set(self.store._read(seen_path, {'seen': []}).get('seen', []))
        result = ExchangeResult()
        candidates = (sorted(folder.glob('*' + PACKAGE_SUFFIX)) +
                      sorted(folder.glob('*' + ANSWER_SUFFIX))) if folder.is_dir() else []
        for path in candidates:
            try:
                st = path.stat()
            except OSError:
                continue
            key = f'{path.name}|{st.st_size}|{st.st_mtime_ns}'
            if key in seen:
                continue
            try:
                if path.name.endswith(PACKAGE_SUFFIX):
                    record = self.receive(path)
                    result.received.append(record)
                else:
                    result.answered.append(self.take_answer(path.read_bytes()))
            except ServiceError as e:
                if not (e.detail in ('envelope-not-mine', 'offer-not-mine') or e.code == 'no-package'):
                    result.problems.append((path.name, e))
            except NETWORK_ERRORS:
                break                                   # siec: sprobujemy przy nastepnym przegladzie
            seen.add(key)
        self.store._write(seen_path, {'seen': sorted(seen)[-5000:]})
        return result

    # --- dowody --------------------------------------------------------------------

    def proof(self, digest: bytes) -> LogProof | None:
        """Dowod z dziennika wedlug §12.1 (kwit + korzen tygodnia) albo None."""
        text = self.log.verify_text(digest)
        if text is None:
            return None
        log = E.PayloadLog({digest.hex(): text}, self.receipt_keys())
        return log.proof_of(digest)

    def receipt_keys(self) -> tuple[str, ...]:
        if self._receipt_keys is not None:
            return self._receipt_keys
        from .. import keys
        return keys.current_public_keys()

    def _log_texts(self, digests: Iterable[bytes]) -> dict[str, str]:
        texts = {}
        for d in digests:
            text = self.log.verify_text(d)
            if text is not None:
                texts[d.hex()] = text
        return texts

    def evidence(self, digest: str, *, disclose: bool = False,
                 with_attestations: bool = True) -> bytes:
        """Pakiet dowodowy nadawcy (§11.1) — odpowiedzi dziennika pobrane TERAZ,
        z kwitami. Odswiezenie po zamknieciu tygodnia = ponowne wywolanie."""
        record = self.store.get_outgoing(digest)
        if record is None:
            raise ServiceError('no-package')
        if not record.answers:
            raise ServiceError('not-answered')
        offer = P.read_offer(record.offer)
        contact = self.store.contact(record.contact)
        me = next((i for i in self.store.identities()
                   if i.fingerprint == offer.sender.fingerprint_hex), None)
        answer = next((a for a in record.answers if a.get('decision') == 'accept'),
                      record.answers[0])
        part_b = None
        if record.status == 'delivered':
            part_b = self._open(record.part_b_blob, 'part-b')
        binding = contact.binding if contact is not None else None
        digests = [offer.digest] + [A_.read_answer(a, offer).digest for a in record.answers]
        if part_b is not None:
            digests.append(part_b)
        if binding is not None and me is not None:
            digests.append(I.read_binding(binding, I.read_card(me.card)).digest)
        container = None
        if disclose and part_b is not None:
            container = self._container(record, offer, part_b)
            digests += [bytes.fromhex(f['sha256']) for f in _manifest_files(container)]
        attestations = []
        if with_attestations:
            if me is not None and me.attestation:
                attestations.append(me.attestation)
            if contact is not None and contact.attestation:
                attestations.append(contact.attestation)
        return E.build_evidence(offer=record.offer, answer=answer, part_b=part_b, binding=binding,
                                log=self._log_texts(digests), container=container,
                                attestations=attestations)

    def incoming_evidence(self, digest: str, *, disclose: bool = False,
                          with_attestations: bool = True) -> bytes:
        """Kopia dowodowa odbiorcy (§11.2): ta sama oferta, MOJA odpowiedz i B
        znalezione w dzienniku. Zapisu powiazania nie ma — ten robi nadawca."""
        record = self.store.get_incoming(digest)
        if record is None:
            raise ServiceError('no-package')
        if record.answer is None:
            raise ServiceError('not-answered')
        offer = P.read_offer(record.offer)
        part_b = bytes.fromhex(record.part_b) if record.part_b else None
        digests = [offer.digest, A_.read_answer(record.answer, offer).digest]
        if part_b is not None:
            digests.append(part_b)
        container = None
        if disclose and part_b is not None:
            a = self._open(record.part_a_blob, 'part-a')
            with open(self.store.ciphertext_path('incoming', digest), 'rb') as ct, \
                    tempfile.TemporaryFile() as out:
                P.decrypt_package(offer, a, part_b, ct, out)
                out.seek(0)
                container = out.read()
            digests += [bytes.fromhex(f['sha256']) for f in _manifest_files(container)]
        attestations = []
        if with_attestations:
            me = next((i for i in self.store.identities() if i.fingerprint == record.my_card), None)
            sender = self.store.contact(record.sender)
            if me is not None and me.attestation:
                attestations.append(me.attestation)
            if sender is not None and sender.attestation:
                attestations.append(sender.attestation)
        return E.build_evidence(offer=record.offer, answer=record.answer, part_b=part_b,
                                binding=None, log=self._log_texts(digests), container=container,
                                attestations=attestations)

    def has_defect(self, record: Incoming) -> bool:
        """Czy z tej paczki da sie zlozyc dowod wady (§11.3): nie otworzyla sie
        albo rozni sie od podgladu, a czesc A, B i szyfrogram sa na miejscu."""
        return ((record.status == 'defective' or bool(record.preview_differences))
                and bool(record.part_b) and bool(record.part_a_blob)
                and self.store.ciphertext_path('incoming', record.offer_digest).is_file())

    def defect_proof(self, digest: str, target: Path) -> Path:
        """Dowod wady (§11.3) do pliku `target`: oferta, obie czesci klucza
        i szyfrogram. Tylko dla wadliwej paczki — przy dobrej niczego by nie
        dowodzil, a ujawnilby tresc. Zapis przez plik `.part` i podmiane."""
        record = self.store.get_incoming(digest)
        if record is None:
            raise ServiceError('no-package')
        if not self.has_defect(record):
            raise ServiceError('not-defective')
        offer = P.read_offer(record.offer)
        a = self._open(record.part_a_blob, 'part-a')
        partial = target.with_name(target.name + '.part')
        try:
            with open(self.store.ciphertext_path('incoming', digest), 'rb') as ct, \
                    open(partial, 'wb') as out:
                E.write_defect(out, offer=record.offer, part_a=a,
                               part_b=bytes.fromhex(record.part_b), ciphertext=ct,
                               size=offer.ciphertext_size)
            os.replace(partial, target)
        except BaseException:
            partial.unlink(missing_ok=True)
            raise
        return target

    def _container(self, record: Outgoing, offer: P.Offer, b: bytes) -> bytes:
        a = self._open(record.part_a_blob, 'part-a')
        with open(self.store.ciphertext_path('outgoing', record.offer_digest), 'rb') as ct, \
                tempfile.TemporaryFile() as out:
            P.decrypt_package(offer, a, b, ct, out)
            out.seek(0)
            return out.read()

    def check_evidence(self, data: bytes, other: bytes | None = None) -> E.Report:
        """Weryfikacja pakietu (§12) z regula §12.1 i kluczami z keys.py."""
        ev = E.Evidence(data)
        log = ev.payload_log(self.receipt_keys())
        doc = dict(ev.doc)
        extra = ()
        if other is not None:
            second = E.Evidence(other)
            if second.doc.get('offer') == doc.get('offer'):
                log = E.MergedLog(log, second.payload_log(self.receipt_keys()))
                if second.doc.get('answer') != doc.get('answer'):
                    extra = (second.doc['answer'],)
                if doc.get('part_b') is None:
                    doc['part_b'] = second.doc.get('part_b')
        return E.verify_evidence(doc, log, container=ev.open_container(), extra_answers=extra)


def _same(a: dict, b: dict) -> bool:
    from ..handover import jcs
    return jcs.dumps(a, max_depth=16) == jcs.dumps(b, max_depth=16)


def package_folder(base: Path, record: Incoming) -> Path:
    """Osobny folder na kazda przesylke: tytul nadawcy bez znakow zakazanych
    w nazwach Windows i poczatek skrotu oferty — dwie paczki o tym samym
    tytule nie mieszaja plikow. Tytul przeszedl juz reguly §4.1 (bez znakow
    sterujacych i znakow kierunku tekstu)."""
    title = ''.join(ch for ch in str(record.preview.get('title') or '')
                    if ch not in WINDOWS_FORBIDDEN)
    title = ' '.join(title.split())[:60].rstrip('. ')
    return base / (f'{title} ({record.offer_digest[:8]})' if title else record.offer_digest[:16])


def _payload_utc(text: str) -> str | None:
    """Czas wpisu z odpowiedzi /api/proof/verify (jak `utc` odpowiedzi stempla)."""
    try:
        utc = json.loads(text).get('utc')
    except (ValueError, AttributeError):
        return None
    return utc if isinstance(utc, str) else None


def _days(n: int):
    from datetime import timedelta
    return timedelta(days=n)


def _mime(path: Path) -> str:
    import mimetypes
    guess = (mimetypes.guess_type(path.name)[0] or '').lower()
    try:
        return check_mime(guess)
    except HandoverError:
        return 'application/octet-stream'


def _manifest_files(container: bytes) -> list[dict]:
    manifest, _files = P.container_files(container)
    return manifest['files']
