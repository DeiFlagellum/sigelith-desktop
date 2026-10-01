"""
Samodzielny dowód offline (`.beatproof`) — nowa mozliwosc, której TVS nie miał.

Certyfikat PDF jest dokumentem dla czlowieka: można go wydrukowac, ale żeby
cokolwiek z niego Sprawdzić, trzeba isc do serwisu, który go wystawil. Jeśli
ten serwis kiedys zniknie, PDF zostaje kartka z ladnymi napisami.

`.beatproof` to ten sam dowód w formie, która weryfikuje się SAMA:

    {
      "format": "beatproof-v1",
      "digest":  "<SHA-256 dokumentu>",
      "week":    "2026-W25",
      "week_root": "<korzeń Merkle>",
      "inclusion_proof": [{"side": "R", "hash": "..."}, ...],
      "root_signature": "<Ed25519, base64>",
      "public_key":     "<Ed25519, base64>"
    }

Majac ten plik i sam dokument, każdy — także za dziesiec lat, bez dostępu do
sigelith.org — może przeliczyc SHA-256 dokumentu, zwinac ścieżkę inkluzji do
korzenia i sprawdzić podpis korzenia. Trzy operacje arytmetyczne, żadnego
zaufania do kogokolwiek. Czwarty krok to porównanie `public_key` z publiczną
historią kluczy Sigelith (keys.py, sigelith.org/spec/#keys): podpis kluczem
WYCOFANYM nie jest już dowodem — taki plik trzeba wyeksportować ponownie.

Podpis obejmuje TYDZIEŃ, nie dokładną chwilę: `utc` i `beat` to deklaracja
rejestru, więc muszą leżeć w podpisanym tygodniu (`proof.time_claim_problems`).
Potwierdzone jest „dokument istniał najpóźniej z końcem tygodnia `week`".

Warunek jest jeden i jest wpisany w format wprost: dowód ma sens dopiero, gdy
tydzień jest Zamknięty i korzeń podpisany. Dla swiezego stempla eksportujemy
go z ostrzezeniem zamiast udawac, ze jest kompletny.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import __app_name__, __version__, beatcore, keys, logtree, merkle, proof
from .config import write_atomic, json_loads
from .i18n import _

#: Format i rozszerzenie pliku sa CZESCIA FORMATU, nie marka: kazdy
#: `.beatproof` wystawiony od 2.0 ma sie dac otworzyc zawsze, a nowe pliki
#: maja dac sie otworzyc starszym wersjom programu. Nie zmieniac przy
#: zmianach nazwy (Sigelith, 2026-09-27).
FORMAT = 'beatproof-v1'
EXTENSION = '.beatproof'

#: Pole `authority`: adres uslugi, ktora wystawila dowod. Od 3.0.0
#: sigelith.org; pliki z 2.x maja `https://beattime.live` — to ta sama
#: instancja, ten sam dziennik i ten sam klucz. Pole jest OPISOWE:
#: o zaufaniu decyduja wylacznie podpis i lista kluczy w `keys.py`, wiec
#: `check` przyjmuje dowod z kazda z tych wartosci (i z kazda inna — jak
#: w 2.x; pilnuje tego `tests/test_core.py: BundleAuthorityTests`).
#: Struktura pliku v1 zostaje bez zmian: te same pola, zmienia sie tylko
#: wartosc tego jednego.
AUTHORITY = 'https://sigelith.org'


@dataclass
class BundleCheck:
    """Wynik sprawdzenia pliku `.beatproof` — w całości lokalnie."""

    ok: bool = False
    digest: str = ''
    week: str = ''
    file_matches: bool | None = None     # None = nie porownywano z plikiem
    inclusion_ok: bool = False
    signature_ok: bool = False
    key_pinned_ok: bool = False          # podpisal klucz ZAUFANY (keys.py / wlasny)
    signer_status: str = ''              # keys.SIGNER_*; '' = brak podpisu
    # Checkpoint dziennika globalnego (od 2.2): None = dowod go nie niesie.
    checkpoint_ok: bool | None = None
    checkpoint_n: int | None = None
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def needs_refresh(self) -> bool:
        """Poprawny podpis wycofanym kluczem: nie falszerstwo, ale nie dowód."""
        return self.signature_ok and self.signer_status == keys.SIGNER_RETIRED


def build(entry_or_result, *, file_name: str = '', note: str = '',
          checkpoint_file: bytes | None = None) -> dict:
    """Składa slownik dowodu z wpisu historii albo z wyniku weryfikacji.

    `checkpoint_file` to DOKLADNE bajty pliku checkpointu, ktory obejmuje
    wpis (z katalogu swiadka). Z nim dowod sprawdza sie offline az do
    podpisanego stanu calego dziennika — a hash tego pliku mozna porownac
    z kopia na GitHubie, w Internet Archive albo w Zenodo, bez Sigelith.
    """
    get = (lambda k, d=None: getattr(entry_or_result, k, d))
    level = get('level', '')
    level_value = level.value if hasattr(level, 'value') else str(level or '')
    cp = get('checkpoint', None) or {}
    checkpoint = None
    if cp.get('verified') and checkpoint_file:
        checkpoint = {
            'n': cp.get('n'), 'hash': cp.get('hash'), 'tree_size': cp.get('tree_size'),
            'root': cp.get('root'), 'leaf_index': cp.get('leaf_index'),
            'audit_path': list(cp.get('audit_path') or []),
            'file': bytes(checkpoint_file).decode('utf-8'),
        }
    data = {
        'format': FORMAT,
        'generator': f'{__app_name__} {__version__}',
        'authority': AUTHORITY,
        'digest': str(get('digest', '') or ''),
        'beat': str(get('beat', '') or ''),
        'utc': str(get('utc', '') or ''),
        'seq': get('seq'),
        'week': str(get('week', '') or ''),
        'week_closed': bool(get('week_closed', False)),
        'week_root': str(get('week_root', '') or ''),
        'inclusion_proof': list(get('inclusion_proof', []) or []),
        'root_signature': str(get('root_signature', '') or ''),
        'public_key': str(get('public_key', '') or ''),
        'chain_hash': str(get('chain_hash', '') or ''),
        'ots_status': str(get('ots_status', 'none') or 'none'),
        'ots_bitcoin_height': get('ots_height'),
        'anchors': list(get('anchors', []) or []),
        'level': level_value,
        'file_name': file_name or str(get('file_name', '') or ''),
        'note': note or str(get('note', '') or ''),
        'time': dict(get('time_bounds', None) or {}),
        'how_to_verify': _(
            '1) Compute the SHA-256 of the document and compare it with '
            '"digest". 2) Fold "inclusion_proof" from the leaf '
            'SHA-256(0x00||digest), computing SHA-256(0x01||left||right) at '
            'every step — the result must equal "week_root". 3) Check the '
            'Ed25519 signature "root_signature" over the text '
            '"beattime-proof-v1|<week>|<week_root>" with the key "public_key". '
            '4) Compare "public_key" with the current Sigelith key: %(key)s — '
            'the key history (including retired keys, whose signature is no '
            'longer binding): https://sigelith.org/spec/#keys. 5) The '
            'signature covers the week, not the exact moment: "utc" (and '
            '"beat") must lie within the ISO week "week". What is confirmed is '
            'that the document existed no later than the end of that week; the '
            'exact time is given by the Sigelith register.'
        ) % {'key': keys.primary_key()},
    }
    if checkpoint is not None:
        data['checkpoint'] = checkpoint
        data['how_to_verify_checkpoint'] = _(
            '6) "checkpoint.file" is the exact signed checkpoint of the whole '
            'Sigelith log (beattime-checkpoint-v1): check its Ed25519 signature '
            'over "beattime-checkpoint-v1|" + the file without "sig", and that '
            'SHA-256 of the file equals "checkpoint.hash". 7) The leaf of this '
            'entry is SHA-256(0x00 || "beattime-entry-v1|<seq>|<digest>|<utc with '
            'six fraction digits>Z"); fold "checkpoint.audit_path" with '
            '"leaf_index" and "tree_size" (RFC 9162) — the result must equal '
            '"root" in the file. 8) Compare the file with an independent copy: '
            'https://github.com/DeiFlagellum/sigelith-log/releases, the Internet '
            'Archive or Zenodo.')
    return data


def save(data: dict, target: Path) -> Path:
    """Zapisuje dowód. Rozszerzenie `.beatproof` dokładane automatycznie."""
    if target.suffix.lower() != EXTENSION:
        target = target.with_name(target.name + EXTENSION)
    write_atomic(target, json.dumps(data, indent=2, ensure_ascii=False).encode('utf-8'))
    return target


def default_name(digest: str, file_name: str = '') -> str:
    """Nazwa pliku dowodu: po dokumencie, a w ostatecznosci po skrócie."""
    stem = Path(file_name).stem if file_name else ''
    # Awaryjny rdzen nazwy jest TLUMACZONY, ale bez znakow diakrytycznych:
    # trafia do nazwy pliku, a te wedruja miedzy systemami plikow.
    stem = stem or (digest[:16] if digest else _('proof'))
    return f'{stem}{EXTENSION}'


def check(data: dict, *, document_digest: str = '',
          key_override: str = '') -> BundleCheck:
    """Sprawdza dowód w całości lokalnie. Zadnej sieci, żadnego zaufania.

    `document_digest` to skrót policzony TERAZ z pliku, którego dowód dotyczy.
    Bez niego sprawdzamy tylko spojnosc samego dowodu — a dowód spójny
    wewnetrznie, lecz opisujacy inny dokument, nic o naszym pliku nie mówi.

    O zaufaniu do klucza decyduje keys.py (plus opcjonalny `key_override`
    z ustawien) — nigdy klucz zapisany w samym pliku.
    """
    r = BundleCheck()
    if not isinstance(data, dict):
        r.problems.append(_('The file does not contain a valid JSON object.'))
        return r
    if str(data.get('format') or '') != FORMAT:
        r.problems.append(_('Unknown proof format (expected "%(format)s").')
                          % {'format': FORMAT})
        return r

    r.digest = str(data.get('digest') or '').strip().lower()
    week = str(data.get('week') or '').strip()
    week_root = str(data.get('week_root') or '').strip().lower()
    signature = str(data.get('root_signature') or '')
    public_key = str(data.get('public_key') or '')
    steps = data.get('inclusion_proof')
    steps = [s for s in steps if isinstance(s, dict)] if isinstance(steps, list) else []

    if not merkle.is_digest(r.digest):
        r.problems.append(_('The proof does not contain a valid SHA-256 digest.'))
        return r
    # Te same wzorce co dla odpowiedzi serwera (proof.verify_payload). Tydzien
    # trafia potem do komunikatow i podpowiedzi — wartosc spoza wzorca
    # odrzucamy, zamiast liczyc na escapowanie w kazdym miejscu.
    if week and not proof._WEEK_RE.match(week):
        r.problems.append(_('The proof gives the week in an invalid format.'))
        return r
    if week_root and not merkle.HEX64.match(week_root):
        r.problems.append(_(
            'The proof gives the week root in an invalid format.'))
        return r
    r.week = week

    # --- Czy dowod dotyczy TEGO pliku ---
    if document_digest:
        r.file_matches = (document_digest.strip().lower() == r.digest)
        if not r.file_matches:
            r.problems.append(_(
                'The digest of the selected file does NOT match the digest in '
                'the proof. The file was changed, or the proof is about a '
                'different document.'
            ))

    # --- Deklarowany czas a podpisany tydzien ---
    # Podpis obejmuje `tydzien|korzen`, lisc — sam skrot. `utc` i `beat` to
    # zwykle pola pliku: bez tej kontroli wystarczylo je przestawic na
    # dowolna wczesniejsza date, a dowod dalej byl „Zweryfikowany offline".
    r.problems.extend(proof.time_claim_problems(
        data.get('utc'), data.get('beat'), r.week))

    # --- Inkluzja w drzewie tygodnia ---
    if week_root:
        r.inclusion_ok = merkle.verify_inclusion(r.digest, steps, week_root)
        if not r.inclusion_ok:
            r.problems.append(_(
                'The inclusion path does not lead to the week root.'))
    else:
        r.notes.append(_(
            'The proof contains no week root — the week was still open when it '
            'was exported.'))

    # --- Podpis korzenia i tozsamosc klucza ---
    if signature and week_root and r.week:
        r.signature_ok = proof.verify_ed25519_root(
            r.week, week_root, signature, public_key or keys.primary_key())
        if not r.signature_ok:
            r.problems.append(_(
                'The Ed25519 signature of the week root is invalid.'))
        r.signer_status = keys.classify(public_key, key_override)
        r.key_pinned_ok = r.signer_status in keys.TRUSTED_STATUSES
        if r.signer_status == keys.SIGNER_RETIRED:
            if r.signature_ok:
                r.warnings.append(proof.retired_key_warning(
                    public_key, r.week,
                    hint=_('Check this digest in the register (Verification tab '
                           '-> Check digest) and export the proof again — it '
                           'will get a signature made with the current key.')))
        elif r.signer_status == keys.SIGNER_UNKNOWN:
            r.problems.append(
                _('The root was signed with a key other than the Sigelith keys '
                  'built into the application — the signature does not prove '
                  'its origin.')
                if public_key else
                _('The proof contains no public key for the signature.')
            )
    else:
        r.notes.append(_(
            'The proof contains no root signature. Export it again once the '
            'week has closed so that it is complete.'))

    _check_checkpoint(r, data, key_override)
    r.ok = (not r.problems) and r.inclusion_ok and r.signature_ok and r.key_pinned_ok
    return r


def _check_checkpoint(r: BundleCheck, data: dict, key_override: str) -> None:
    """Sekcja `checkpoint` (2.2): podpis pliku, hash i sciezka wpisu do korzenia.

    Brak sekcji niczego nie psuje — starsze dowody jej nie maja. Sekcja
    obecna, ale niezgodna, jest ZASTRZEZENIEM: ktos dopisal do dowodu
    checkpoint, ktory go nie obejmuje.
    """
    cp = data.get('checkpoint')
    if cp is None:
        return
    r.checkpoint_ok = False
    if not isinstance(cp, dict) or not isinstance(cp.get('file'), str):
        r.problems.append(_('The checkpoint section of the proof is damaged.'))
        return
    parsed = logtree.parse_checkpoint(cp['file'].encode('utf-8'), override=key_override)
    r.checkpoint_n = parsed.n or None
    if not parsed.ok:
        r.problems.append(_('The checkpoint in the proof is not signed with a '
                            'Sigelith key valid at that time.'))
        return
    if parsed.hash != str(cp.get('hash') or '') or parsed.root != str(cp.get('root') or '') \
            or parsed.tree_size != cp.get('tree_size'):
        r.problems.append(_('The checkpoint description does not match the '
                            'checkpoint file inside the proof.'))
        return
    seq = data.get('seq')
    dt = beatcore.parse_iso_utc(str(data.get('utc') or ''))
    index = cp.get('leaf_index')
    path = cp.get('audit_path')
    try:
        leaf = logtree.entry_leaf_hash(int(seq), r.digest, dt)  # seq: int sprawdzony wyzej
        steps = [bytes.fromhex(str(h)) for h in path]
        ok = (isinstance(index, int) and not isinstance(index, bool)
              and logtree.verify_inclusion(leaf, index, parsed.tree_size, steps,
                                           bytes.fromhex(parsed.root)))
    except (TypeError, ValueError, AttributeError):
        ok = False
    if not ok:
        r.problems.append(_('The path of this entry does not lead to the root of '
                            'the checkpoint inside the proof.'))
        return
    r.checkpoint_ok = True


def load(path: Path) -> dict:
    """Wczytuje plik dowodu. Podnosi ValueError z komunikatem dla czlowieka."""
    try:
        raw = path.read_text(encoding='utf-8')
    except OSError as e:
        raise ValueError(_('The proof file could not be opened: %(reason)s.')
                         % {'reason': e.strerror or e}) from e
    # Dowod to kilka kilobajtow; wiekszy plik to pomylka albo proba zapchania.
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError(_('The proof file is unnaturally large — rejected.'))
    try:
        data = json_loads(raw)
    except ValueError as e:
        raise ValueError(_('The file is not a valid JSON document.')) from e
    if not isinstance(data, dict):
        raise ValueError(_('The proof file has an unexpected structure.'))
    return data


def verified_view(data: dict, check: BundleCheck) -> dict:
    """Slownik dowodu do WYSWIETLENIA — pola zaufania z lokalnego sprawdzenia.

    Plik .beatproof moze przyslac kazdy. Pola, ktore mowia, jak mocny jest
    dowod — poziom, „podpis zweryfikowany", checkpoint sprawdzony, stan OTS,
    kotwice bankowe, granice czasu, kopie u osob trzecich — sa w pliku zwyklym
    tekstem, ktory kazdy moze wpisac. Do 2.2.0 okno „Szczegoly" pokazywalo je
    wprost: odrzucony, sfalszowany dowod wygladal tam na zakotwiczony
    (fuzzing przed Sklepem, 2026-09-27). Tu zostaje tylko to, co program
    sprawdzil sam; reszta, czego offline sprawdzic sie nie da, znika.
    """
    view = dict(data) if isinstance(data, dict) else {}
    view['level'] = proof.Level.SIGNED.value if check.ok else proof.Level.NONE.value
    view['verified_ok'] = bool(check.ok)
    view['trusted'] = bool(check.key_pinned_ok)
    view['week_closed'] = bool(check.signature_ok)
    view['problems'] = list(check.problems)
    # Twierdzenia pliku, ktorych offline nie da sie potwierdzic:
    view['ots_status'] = 'none'
    view.pop('ots_bitcoin_height', None)
    view['anchors'] = []
    view['time'] = {}
    view.pop('copies', None)
    section = view.get('checkpoint') if isinstance(view.get('checkpoint'), dict) else None
    if check.checkpoint_ok is True and section:
        view['checkpoint'] = {**section, 'n': check.checkpoint_n, 'verified': True}
    elif check.checkpoint_ok is False:
        view['checkpoint'] = {'n': check.checkpoint_n, 'verified': False}
    else:
        view.pop('checkpoint', None)
    return view
