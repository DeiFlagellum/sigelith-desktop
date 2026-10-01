"""
Sonda Windows Hello dla Sigelith Handover (HANDOVER_SPEC.md §2.1).

Narzedzie diagnostyczne — uruchamiane RECZNIE na komputerze z Windows Hello
(trzy razy prosi o PIN albo biometrie):

    .venv\\Scripts\\python.exe tools\\winhello_probe.py

Sprawdza na prawdziwym sprzecie, czy aplikacja desktopowa moze przez
webauthn.dll (uwierzytelniacz platformowy = Windows Hello):
  1. utworzyc klucz ES256 dla rpId `sigelith.org` z weryfikacja uzytkownika,
  2. podpisac nim KARTE i AKCEPTACJE z beatstamp.handover,
  3. przejsc weryfikator `es256-webauthn` bez zmian,
i jaka atestacje zwraca system. Klucz testowy usuwa na koncu.

Wynik z 2026-09-28 (Windows 11, API webauthn.dll 9, TPM Intel PTT): wszystko
przechodzi; atestacja `tpm` z lancuchem do „Microsoft TPM Root Certificate
Authority 2014". To NIE jest test automatyczny — wymaga czlowieka przed
ekranem, wiec nie wchodzi do `unittest discover`.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import io
import json
import os
import sys
import time
from ctypes import POINTER, c_long, c_ubyte, wintypes as W
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from beatstamp.handover import answer as A_, identity as I, package as P, primitives as X  # noqa: E402

RP_ID = 'sigelith.org'
dll = ctypes.WinDLL('webauthn.dll')


class RP(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('pwszId', W.LPCWSTR), ('pwszName', W.LPCWSTR),
                ('pwszIcon', W.LPCWSTR)]


class USER(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('cbId', W.DWORD), ('pbId', POINTER(c_ubyte)),
                ('pwszName', W.LPCWSTR), ('pwszIcon', W.LPCWSTR), ('pwszDisplayName', W.LPCWSTR)]


class COSE_PARAM(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('pwszCredentialType', W.LPCWSTR), ('lAlg', W.LONG)]


class COSE_PARAMS(ctypes.Structure):
    _fields_ = [('cCredentialParameters', W.DWORD), ('pCredentialParameters', POINTER(COSE_PARAM))]


class CLIENT_DATA(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('cbClientDataJSON', W.DWORD),
                ('pbClientDataJSON', POINTER(c_ubyte)), ('pwszHashAlgId', W.LPCWSTR)]


class CREDENTIAL(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('cbId', W.DWORD), ('pbId', POINTER(c_ubyte)),
                ('pwszCredentialType', W.LPCWSTR)]


class CREDENTIALS(ctypes.Structure):
    _fields_ = [('cCredentials', W.DWORD), ('pCredentials', POINTER(CREDENTIAL))]


class EXTENSION(ctypes.Structure):
    _fields_ = [('pwszExtensionIdentifier', W.LPCWSTR), ('cbExtension', W.DWORD),
                ('pvExtension', ctypes.c_void_p)]


class EXTENSIONS(ctypes.Structure):
    _fields_ = [('cExtensions', W.DWORD), ('pExtensions', POINTER(EXTENSION))]


class MC_OPTIONS(ctypes.Structure):                 # WEBAUTHN_..._MAKE_CREDENTIAL_OPTIONS v1
    _fields_ = [('dwVersion', W.DWORD), ('dwTimeoutMilliseconds', W.DWORD),
                ('CredentialList', CREDENTIALS), ('Extensions', EXTENSIONS),
                ('dwAuthenticatorAttachment', W.DWORD), ('bRequireResidentKey', W.BOOL),
                ('dwUserVerificationRequirement', W.DWORD),
                ('dwAttestationConveyancePreference', W.DWORD), ('dwFlags', W.DWORD)]


class ATTESTATION(ctypes.Structure):                # wspolny poczatek wszystkich wersji
    _fields_ = [('dwVersion', W.DWORD), ('pwszFormatType', W.LPCWSTR),
                ('cbAuthenticatorData', W.DWORD), ('pbAuthenticatorData', POINTER(c_ubyte)),
                ('cbAttestation', W.DWORD), ('pbAttestation', POINTER(c_ubyte)),
                ('dwAttestationDecodeType', W.DWORD), ('pvAttestationDecode', ctypes.c_void_p),
                ('cbAttestationObject', W.DWORD), ('pbAttestationObject', POINTER(c_ubyte)),
                ('cbCredentialId', W.DWORD), ('pbCredentialId', POINTER(c_ubyte))]


class GA_OPTIONS(ctypes.Structure):                 # WEBAUTHN_..._GET_ASSERTION_OPTIONS v1
    _fields_ = [('dwVersion', W.DWORD), ('dwTimeoutMilliseconds', W.DWORD),
                ('CredentialList', CREDENTIALS), ('Extensions', EXTENSIONS),
                ('dwAuthenticatorAttachment', W.DWORD), ('dwUserVerificationRequirement', W.DWORD),
                ('dwFlags', W.DWORD)]


class ASSERTION(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('cbAuthenticatorData', W.DWORD),
                ('pbAuthenticatorData', POINTER(c_ubyte)), ('cbSignature', W.DWORD),
                ('pbSignature', POINTER(c_ubyte)), ('Credential', CREDENTIAL),
                ('cbUserId', W.DWORD), ('pbUserId', POINTER(c_ubyte))]


dll.WebAuthNGetApiVersionNumber.restype = W.DWORD
dll.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.argtypes = [POINTER(W.BOOL)]
dll.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.restype = c_long
dll.WebAuthNAuthenticatorMakeCredential.argtypes = [
    W.HWND, POINTER(RP), POINTER(USER), POINTER(COSE_PARAMS), POINTER(CLIENT_DATA),
    POINTER(MC_OPTIONS), POINTER(POINTER(ATTESTATION))]
dll.WebAuthNAuthenticatorMakeCredential.restype = c_long
dll.WebAuthNFreeCredentialAttestation.argtypes = [POINTER(ATTESTATION)]
dll.WebAuthNFreeCredentialAttestation.restype = None
dll.WebAuthNAuthenticatorGetAssertion.argtypes = [
    W.HWND, W.LPCWSTR, POINTER(CLIENT_DATA), POINTER(GA_OPTIONS), POINTER(POINTER(ASSERTION))]
dll.WebAuthNAuthenticatorGetAssertion.restype = c_long
dll.WebAuthNFreeAssertion.argtypes = [POINTER(ASSERTION)]
dll.WebAuthNFreeAssertion.restype = None
dll.WebAuthNGetErrorName.argtypes = [c_long]
dll.WebAuthNGetErrorName.restype = W.LPCWSTR


def buf(data: bytes):
    arr = (c_ubyte * len(data)).from_buffer_copy(data)
    return arr, ctypes.cast(arr, POINTER(c_ubyte))


def take(ptr, size: int) -> bytes:
    return bytes(ctypes.cast(ptr, POINTER(c_ubyte * size)).contents) if size else b''


def check(hr: int, what: str) -> None:
    if hr != 0:
        name = dll.WebAuthNGetErrorName(hr)
        raise SystemExit(f'{what}: HRESULT 0x{hr & 0xFFFFFFFF:08X} ({name})')


def hwnd() -> int:
    return ctypes.windll.user32.GetForegroundWindow()


# --- minimalny CBOR (tylko to, co jest w danych WebAuthn) ---------------------

def cbor(data: bytes, i: int = 0):
    head = data[i]
    major, info = head >> 5, head & 31
    i += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        arg = int.from_bytes(data[i:i + n], 'big')
        i += n
    else:
        raise ValueError(f'CBOR: nieobslugiwana dlugosc {info}')
    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major == 2:
        return data[i:i + arg], i + arg
    if major == 3:
        return data[i:i + arg].decode('utf-8'), i + arg
    if major == 4:
        out = []
        for _ in range(arg):
            v, i = cbor(data, i)
            out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(arg):
            k, i = cbor(data, i)
            v, i = cbor(data, i)
            out[k] = v
        return out, i
    if major == 6:
        return cbor(data, i)
    if major == 7:
        return {20: False, 21: True, 22: None}.get(arg, arg), i
    raise ValueError('CBOR')


def parse_auth_data(auth: bytes) -> dict:
    out = {'rp_hash': auth[:32], 'flags': auth[32], 'count': int.from_bytes(auth[33:37], 'big')}
    if auth[32] & 0x40:
        n = int.from_bytes(auth[53:55], 'big')
        out['aaguid'] = auth[37:53]
        out['cred_id'] = auth[55:55 + n]
        out['cose'], _ = cbor(auth, 55 + n)
    return out


def flags_text(f: int) -> str:
    return ' '.join(n for bit, n in ((1, 'UP'), (4, 'UV'), (8, 'BE'), (16, 'BS'), (64, 'AT'), (128, 'ED')) if f & bit)


# --- operacje ----------------------------------------------------------------

def make_credential() -> tuple[bytes, bytes, str, dict, bytes, bytes]:
    rp = RP(1, RP_ID, 'Sigelith', None)
    uid = os.urandom(16)
    uid_arr, uid_ptr = buf(uid)
    user = USER(1, len(uid), uid_ptr, 'handover-probe@sigelith.org', None,
                'Sigelith Handover — test (do usuniecia)')
    param = COSE_PARAM(1, 'public-key', -7)
    params = COSE_PARAMS(1, ctypes.pointer(param))
    client = json.dumps({'type': 'webauthn.create', 'challenge': X.b64url(os.urandom(32)),
                         'origin': f'https://{RP_ID}', 'crossOrigin': False},
                        separators=(',', ':')).encode()
    c_arr, c_ptr = buf(client)
    cd = CLIENT_DATA(1, len(client), c_ptr, 'SHA-256')
    opts = MC_OPTIONS(1, 120_000, CREDENTIALS(0, None), EXTENSIONS(0, None),
                      1,       # WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM
                      False,
                      1,       # WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
                      3,       # WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT
                      0)
    out = POINTER(ATTESTATION)()
    check(dll.WebAuthNAuthenticatorMakeCredential(hwnd(), ctypes.byref(rp), ctypes.byref(user),
                                                  ctypes.byref(params), ctypes.byref(cd),
                                                  ctypes.byref(opts), ctypes.byref(out)),
          'MakeCredential')
    try:
        att = out.contents
        fmt = att.pwszFormatType
        auth = take(att.pbAuthenticatorData, att.cbAuthenticatorData)
        cred_id = take(att.pbCredentialId, att.cbCredentialId)
        att_obj = take(att.pbAttestationObject, att.cbAttestationObject)
    finally:
        dll.WebAuthNFreeCredentialAttestation(out)
    parsed = parse_auth_data(auth)
    cose = parsed['cose']
    if cose.get(1) != 2 or cose.get(3) != -7 or cose.get(-1) != 1:
        raise SystemExit(f'nieoczekiwany klucz COSE: { {k: v for k, v in cose.items() if not isinstance(v, bytes)} }')
    pub = b'\x04' + cose[-2] + cose[-3]
    obj, _ = cbor(att_obj)
    return cred_id, pub, fmt, {'auth': parsed, 'att_stmt': obj.get('attStmt', {})}, att_obj, client


def get_assertion(cred_id: bytes, client: bytes) -> tuple[bytes, bytes]:
    id_arr, id_ptr = buf(cred_id)
    cred = CREDENTIAL(1, len(cred_id), id_ptr, 'public-key')
    c_arr, c_ptr = buf(client)
    cd = CLIENT_DATA(1, len(client), c_ptr, 'SHA-256')
    opts = GA_OPTIONS(1, 120_000, CREDENTIALS(1, ctypes.pointer(cred)), EXTENSIONS(0, None),
                      1, 1, 0)
    out = POINTER(ASSERTION)()
    check(dll.WebAuthNAuthenticatorGetAssertion(hwnd(), RP_ID, ctypes.byref(cd), ctypes.byref(opts),
                                                ctypes.byref(out)), 'GetAssertion')
    try:
        a = out.contents
        return (take(a.pbAuthenticatorData, a.cbAuthenticatorData),
                take(a.pbSignature, a.cbSignature))
    finally:
        dll.WebAuthNFreeAssertion(out)


class WindowsHelloSigner:
    """Sygnatariusz `es256-webauthn` przez Windows Hello — ten sam protokol co w pakiecie."""

    alg = 'es256-webauthn'
    storage = 'hardware-uv'

    def __init__(self, cred_id: bytes, public: bytes) -> None:
        self.cred_id, self._public = cred_id, public
        self.last_auth = b''

    @property
    def public_bytes(self) -> bytes:
        return self._public

    def sign(self, message: bytes) -> dict:
        client = json.dumps({'type': 'webauthn.get', 'challenge': X.webauthn_challenge(message),
                             'origin': f'https://{RP_ID}', 'crossOrigin': False},
                            separators=(',', ':')).encode()
        auth, der = get_assertion(self.cred_id, client)
        self.last_auth = auth
        return {'authenticator_data': X.b64encode(auth), 'client_data_json': X.b64encode(client),
                'signature': X.b64encode(der)}


def delete_credential(cred_id: bytes) -> str:
    fn = getattr(dll, 'WebAuthNDeletePlatformCredential', None)
    if fn is None:
        return 'brak WebAuthNDeletePlatformCredential — usun recznie: Ustawienia > Konta > Klucze dostepu'
    fn.argtypes = [W.DWORD, POINTER(c_ubyte)]
    fn.restype = c_long
    arr, ptr = buf(cred_id)
    hr = fn(len(cred_id), ptr)
    return 'usuniety' if hr == 0 else f'nie usuniety: 0x{hr & 0xFFFFFFFF:08X} {dll.WebAuthNGetErrorName(hr)}'


def main() -> None:
    # --save PLIK: zapisuje karte i jej atestacje (spec §3.6) do pliku i konczy po
    # dwoch PIN-ach. Plik zawiera certyfikat TPM TEGO komputera — trzymac poza
    # repozytorium; sluzy tylko do sprawdzenia weryfikatora na prawdziwych danych.
    save = sys.argv[sys.argv.index('--save') + 1] if '--save' in sys.argv else None
    steps = 2 if save else 3
    print('API webauthn.dll:', dll.WebAuthNGetApiVersionNumber())
    ok = W.BOOL()
    check(dll.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(ctypes.byref(ok)), 'UVPA')
    print('Windows Hello (uwierzytelniacz platformowy z UV):', bool(ok.value))
    if not ok.value:
        raise SystemExit('Windows Hello niedostepne — sprawdzamy sciezke NCrypt/TPM')

    print(f'\n[1/{steps}] Tworze klucz testowy dla sigelith.org — Windows Hello zapyta o PIN...')
    t = time.perf_counter()
    cred_id, pub, fmt, info, att_obj, client = make_credential()
    auth = info['auth']
    print(f'      OK w {time.perf_counter() - t:.1f} s; format atestacji: {fmt}; '
          f'flagi: {flags_text(auth["flags"])}; licznik: {auth["count"]}')
    print(f'      rpIdHash == SHA-256("sigelith.org"): {auth["rp_hash"] == hashlib.sha256(RP_ID.encode()).digest()}')
    print(f'      AAGUID: {auth["aaguid"].hex()}  (dlugosc id klucza: {len(cred_id)} B)')
    stmt = info['att_stmt']
    if isinstance(stmt, dict) and stmt:
        print('      attStmt:', sorted(str(k) for k in stmt), '| alg:', stmt.get('alg'),
              '| ver:', stmt.get('ver'))
        if 'x5c' in stmt:
            from cryptography import x509
            for n, der in enumerate(stmt['x5c']):
                cert = x509.load_der_x509_certificate(der)
                print(f'      x5c[{n}] wystawca: {cert.issuer.rfc4514_string()[:110]}')
                print(f'             waznosc: {cert.not_valid_before_utc:%Y-%m-%d} .. '
                      f'{cert.not_valid_after_utc:%Y-%m-%d}')
                try:
                    aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
                    for d in aia.value:
                        print(f'             AIA: {d.access_location.value}')
                except x509.ExtensionNotFound:
                    pass
    X.p256_public(pub)

    signer = WindowsHelloSigner(cred_id, pub)
    enc = X.EncKey.generate()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    print(f'\n[2/{steps}] Podpisuje KARTE Sigelith ID kluczem Windows Hello — PIN...')
    t = time.perf_counter()
    card = I.make_card(signer, enc.public_bytes, now)
    card_info = I.read_card(card)
    a = parse_auth_data(signer.last_auth)
    print(f'      OK w {time.perf_counter() - t:.1f} s; weryfikator es256-webauthn: PRZESZLA; '
          f'flagi: {flags_text(a["flags"])}; licznik: {a["count"]}')
    print(f'      odcisk karty: {card_info.fingerprint_text}')
    if save:
        attestation = {'v': X.VERSION, 'type': 'attestation', 'card': card_info.fingerprint_hex,
                       'fmt': fmt, 'attestation_object': X.b64encode(att_obj),
                       'client_data_json': X.b64encode(client)}
        Path(save).write_text(json.dumps({'card': card, 'attestation': attestation}, indent=1),
                              encoding='utf-8')
        print(f'\nZapisano karte i atestacje: {save}')
        print('Sprzatanie:', delete_credential(cred_id))
        return

    sender = I.SoftwareSigner()
    s_enc = X.EncKey.generate()
    s_card = I.make_card(sender, s_enc.public_bytes, now)
    out = P.create_offer(signer=sender, sender_card=s_card, recipient_card=card,
                         files=[P.InputFile('test.txt', b'Sonda Windows Hello', 'text/plain')],
                         ciphertext_out=io.BytesIO(), created=now, title='Sonda')
    a_part, preview = P.open_offer(out.info, enc, card_info)
    print(f'\n[3/{steps}] Podpisuje AKCEPTACJE paczki kluczem Windows Hello — PIN...')
    t = time.perf_counter()
    ans = A_.make_answer(signer, out.info, 'accept', log_now=now,
                         ciphertext_sha256=out.info.ciphertext_sha256)
    A_.read_answer(ans, out.info)
    print(f'      OK w {time.perf_counter() - t:.1f} s; akceptacja przeszla read_answer; '
          f'podpis DER {len(base64.b64decode(ans["sig"]["signature"]))} B')

    print('\nSprzatanie:', delete_credential(cred_id))
    print('\nWYNIK: Windows Hello podpisuje obiekty Handover w formacie es256-webauthn; '
          'weryfikator przyjmuje je bez zmian.')


if __name__ == '__main__':
    main()
