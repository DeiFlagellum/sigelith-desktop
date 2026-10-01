"""
Windows Hello (webauthn.dll) — klucz podpisu karty Sigelith Handover.

HANDOVER_SPEC.md §2.1 i §3.6. Klucz ES256 tworzy uwierzytelniacz platformowy
(TPM) dla rpId `sigelith.org`; kazdy podpis wymaga weryfikacji uzytkownika
(PIN, twarz, palec). Klucz prywatny nigdy nie opuszcza TPM — aplikacja trzyma
tylko identyfikator poswiadczenia i klucz publiczny.

Sprawdzone na sprzecie 2026-09-28 (tools/winhello_probe.py: API 9, Intel PTT):
podpisy przechodza weryfikator `es256-webauthn` bez zmian, a atestacja `tpm`
lancuchem do Microsoft TPM Root CA 2014.

Wywolania webauthn.dll BLOKUJA do czasu decyzji czlowieka w oknie systemowym —
wolac z watku roboczego, nigdy z watku interfejsu. `hwnd` to okno aplikacji:
system pokazuje nad nim swoje okno (bez niego przejmowaloby je cokolwiek
akurat na wierzchu).
"""
from __future__ import annotations

import ctypes
import json
import os
import sys
from ctypes import POINTER, c_long, c_ubyte, wintypes as W
from dataclasses import dataclass
from typing import Callable

from ..handover import primitives as X
from ..handover.attestation import credential_key
from ..handover.errors import HandoverError

RP_ID = X.RP_ID
RP_NAME = 'Sigelith'
TIMEOUT_MS = 120_000

# HRESULT-y, ktore sa decyzja czlowieka, a nie awaria.
_CANCELLED = {0x800704C7, 0x80090036}      # ERROR_CANCELLED, NTE_USER_CANCELLED
_NOT_FOUND = {0x80090011, 0x80090029}      # NTE_NOT_FOUND, NTE_NOT_SUPPORTED (brak klucza)


class HelloError(Exception):
    """`kind`: unavailable | cancelled | not-found | failed."""

    def __init__(self, kind: str, detail: str = '') -> None:
        super().__init__(f'{kind}: {detail}' if detail else kind)
        self.kind = kind
        self.detail = detail


# --- struktury webauthn.h (wersje 1: dzialaja od API 1 do dzis) ---------------

class _RP(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('pwszId', W.LPCWSTR), ('pwszName', W.LPCWSTR),
                ('pwszIcon', W.LPCWSTR)]


class _User(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('cbId', W.DWORD), ('pbId', POINTER(c_ubyte)),
                ('pwszName', W.LPCWSTR), ('pwszIcon', W.LPCWSTR), ('pwszDisplayName', W.LPCWSTR)]


class _CoseParam(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('pwszCredentialType', W.LPCWSTR), ('lAlg', W.LONG)]


class _CoseParams(ctypes.Structure):
    _fields_ = [('cCredentialParameters', W.DWORD), ('pCredentialParameters', POINTER(_CoseParam))]


class _ClientData(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('cbClientDataJSON', W.DWORD),
                ('pbClientDataJSON', POINTER(c_ubyte)), ('pwszHashAlgId', W.LPCWSTR)]


class _Credential(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('cbId', W.DWORD), ('pbId', POINTER(c_ubyte)),
                ('pwszCredentialType', W.LPCWSTR)]


class _Credentials(ctypes.Structure):
    _fields_ = [('cCredentials', W.DWORD), ('pCredentials', POINTER(_Credential))]


class _Extensions(ctypes.Structure):
    _fields_ = [('cExtensions', W.DWORD), ('pExtensions', ctypes.c_void_p)]


class _MakeOptions(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('dwTimeoutMilliseconds', W.DWORD),
                ('CredentialList', _Credentials), ('Extensions', _Extensions),
                ('dwAuthenticatorAttachment', W.DWORD), ('bRequireResidentKey', W.BOOL),
                ('dwUserVerificationRequirement', W.DWORD),
                ('dwAttestationConveyancePreference', W.DWORD), ('dwFlags', W.DWORD)]


class _Attestation(ctypes.Structure):          # wspolny poczatek wszystkich wersji
    _fields_ = [('dwVersion', W.DWORD), ('pwszFormatType', W.LPCWSTR),
                ('cbAuthenticatorData', W.DWORD), ('pbAuthenticatorData', POINTER(c_ubyte)),
                ('cbAttestation', W.DWORD), ('pbAttestation', POINTER(c_ubyte)),
                ('dwAttestationDecodeType', W.DWORD), ('pvAttestationDecode', ctypes.c_void_p),
                ('cbAttestationObject', W.DWORD), ('pbAttestationObject', POINTER(c_ubyte)),
                ('cbCredentialId', W.DWORD), ('pbCredentialId', POINTER(c_ubyte))]


class _GetOptions(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('dwTimeoutMilliseconds', W.DWORD),
                ('CredentialList', _Credentials), ('Extensions', _Extensions),
                ('dwAuthenticatorAttachment', W.DWORD), ('dwUserVerificationRequirement', W.DWORD),
                ('dwFlags', W.DWORD)]


class _Assertion(ctypes.Structure):
    _fields_ = [('dwVersion', W.DWORD), ('cbAuthenticatorData', W.DWORD),
                ('pbAuthenticatorData', POINTER(c_ubyte)), ('cbSignature', W.DWORD),
                ('pbSignature', POINTER(c_ubyte)), ('Credential', _Credential),
                ('cbUserId', W.DWORD), ('pbUserId', POINTER(c_ubyte))]


_ATTACHMENT_PLATFORM = 1
_UV_REQUIRED = 1
_ATTESTATION_DIRECT = 3

_dll = None


def _load():
    global _dll
    if _dll is not None:
        return _dll
    if sys.platform != 'win32':
        raise HelloError('unavailable', 'Windows Hello exists only on Windows')
    try:
        dll = ctypes.WinDLL('webauthn.dll')
    except OSError:
        raise HelloError('unavailable', 'webauthn.dll is missing') from None
    dll.WebAuthNGetApiVersionNumber.restype = W.DWORD
    dll.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.argtypes = [POINTER(W.BOOL)]
    dll.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.restype = c_long
    dll.WebAuthNAuthenticatorMakeCredential.argtypes = [
        W.HWND, POINTER(_RP), POINTER(_User), POINTER(_CoseParams), POINTER(_ClientData),
        POINTER(_MakeOptions), POINTER(POINTER(_Attestation))]
    dll.WebAuthNAuthenticatorMakeCredential.restype = c_long
    dll.WebAuthNFreeCredentialAttestation.argtypes = [POINTER(_Attestation)]
    dll.WebAuthNFreeCredentialAttestation.restype = None
    dll.WebAuthNAuthenticatorGetAssertion.argtypes = [
        W.HWND, W.LPCWSTR, POINTER(_ClientData), POINTER(_GetOptions), POINTER(POINTER(_Assertion))]
    dll.WebAuthNAuthenticatorGetAssertion.restype = c_long
    dll.WebAuthNFreeAssertion.argtypes = [POINTER(_Assertion)]
    dll.WebAuthNFreeAssertion.restype = None
    dll.WebAuthNGetErrorName.argtypes = [c_long]
    dll.WebAuthNGetErrorName.restype = W.LPCWSTR
    _dll = dll
    return dll


def _buf(data: bytes):
    arr = (c_ubyte * max(1, len(data))).from_buffer_copy(data or b'\0')
    return arr, ctypes.cast(arr, POINTER(c_ubyte))


def _take(ptr, size: int) -> bytes:
    return bytes(ctypes.cast(ptr, POINTER(c_ubyte * size)).contents) if size else b''


def _check(dll, hr: int, what: str) -> None:
    if hr == 0:
        return
    code = hr & 0xFFFFFFFF
    name = dll.WebAuthNGetErrorName(hr) or ''
    if code in _CANCELLED or name == 'NotAllowedError':
        # NotAllowedError = anulowane okno albo uplyw czasu: dla czlowieka to samo.
        raise HelloError('cancelled', f'{what}: {name or hex(code)}')
    if code in _NOT_FOUND:
        raise HelloError('not-found', f'{what}: {name or hex(code)}')
    raise HelloError('failed', f'{what}: HRESULT 0x{code:08X} {name}')


def api_version() -> int:
    return int(_load().WebAuthNGetApiVersionNumber())


def available() -> bool:
    """Czy jest uwierzytelniacz platformowy z weryfikacja uzytkownika (Windows Hello)."""
    try:
        dll = _load()
    except HelloError:
        return False
    ok = W.BOOL()
    if dll.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(ctypes.byref(ok)) != 0:
        return False
    return bool(ok.value)


def _client_data(kind: str, challenge: str) -> bytes:
    return json.dumps({'type': kind, 'challenge': challenge, 'origin': f'https://{RP_ID}',
                       'crossOrigin': False}, separators=(',', ':')).encode('ascii')


@dataclass(frozen=True)
class Credential:
    """Nowy klucz Windows Hello. Atestacje system wydaje TYLKO teraz (§3.6)."""

    cred_id: bytes
    public: bytes              # P-256, 65 B SEC1
    fmt: str                   # format atestacji: 'tpm', 'packed', 'none'...
    attestation_object: bytes
    client_data_json: bytes

    def companion(self, card_fingerprint_hex: str) -> dict | None:
        """Obiekt `attestation` karty (§3.6) — tylko dla atestacji TPM, ktora
        umiemy zweryfikowac; inne formaty zostaja w danych aplikacji."""
        if self.fmt != 'tpm':
            return None
        return {'v': X.VERSION, 'type': 'attestation', 'card': card_fingerprint_hex,
                'fmt': self.fmt, 'attestation_object': X.b64encode(self.attestation_object),
                'client_data_json': X.b64encode(self.client_data_json)}


def create_credential(hwnd: int, user_name: str, display_name: str, *,
                      timeout_ms: int = TIMEOUT_MS) -> Credential:
    """Tworzy klucz ES256 w TPM (jedno pytanie o PIN/biometrie)."""
    dll = _load()
    rp = _RP(1, RP_ID, RP_NAME, None)
    uid = os.urandom(16)
    uid_arr, uid_ptr = _buf(uid)
    user = _User(1, len(uid), uid_ptr, user_name, None, display_name)
    param = _CoseParam(1, 'public-key', -7)
    params = _CoseParams(1, ctypes.pointer(param))
    client = _client_data('webauthn.create', X.b64url(os.urandom(32)))
    c_arr, c_ptr = _buf(client)
    cd = _ClientData(1, len(client), c_ptr, 'SHA-256')
    opts = _MakeOptions(1, timeout_ms, _Credentials(0, None), _Extensions(0, None),
                        _ATTACHMENT_PLATFORM, False, _UV_REQUIRED, _ATTESTATION_DIRECT, 0)
    out = POINTER(_Attestation)()
    _check(dll, dll.WebAuthNAuthenticatorMakeCredential(
        hwnd, ctypes.byref(rp), ctypes.byref(user), ctypes.byref(params), ctypes.byref(cd),
        ctypes.byref(opts), ctypes.byref(out)), 'MakeCredential')
    try:
        att = out.contents
        fmt = att.pwszFormatType or ''
        auth = _take(att.pbAuthenticatorData, att.cbAuthenticatorData)
        cred_id = _take(att.pbCredentialId, att.cbCredentialId)
        att_obj = _take(att.pbAttestationObject, att.cbAttestationObject)
    finally:
        dll.WebAuthNFreeCredentialAttestation(out)
    del uid_arr, c_arr
    try:
        public = credential_key(auth)
    except HandoverError as e:
        # Klucz, ktorego weryfikator by nie przyjal, nie trafi do karty.
        delete_credential(cred_id)
        raise HelloError('failed', f'unexpected key from the authenticator: {e.detail}') from None
    if not cred_id:
        raise HelloError('failed', 'no credential id')
    return Credential(cred_id=cred_id, public=public, fmt=fmt, attestation_object=att_obj,
                      client_data_json=client)


def _get_assertion(hwnd: int, cred_id: bytes, client: bytes, timeout_ms: int) -> tuple[bytes, bytes]:
    dll = _load()
    id_arr, id_ptr = _buf(cred_id)
    cred = _Credential(1, len(cred_id), id_ptr, 'public-key')
    c_arr, c_ptr = _buf(client)
    cd = _ClientData(1, len(client), c_ptr, 'SHA-256')
    opts = _GetOptions(1, timeout_ms, _Credentials(1, ctypes.pointer(cred)), _Extensions(0, None),
                       _ATTACHMENT_PLATFORM, _UV_REQUIRED, 0)
    out = POINTER(_Assertion)()
    _check(dll, dll.WebAuthNAuthenticatorGetAssertion(hwnd, RP_ID, ctypes.byref(cd),
                                                      ctypes.byref(opts), ctypes.byref(out)),
           'GetAssertion')
    try:
        a = out.contents
        result = (_take(a.pbAuthenticatorData, a.cbAuthenticatorData),
                  _take(a.pbSignature, a.cbSignature))
    finally:
        dll.WebAuthNFreeAssertion(out)
    del id_arr, c_arr
    return result


class WindowsHelloSigner:
    """Podpis `es256-webauthn` kluczem z TPM — interfejs `identity.Signer`.

    Kazde `sign` to jedno pytanie Windows Hello. Wynik jest od razu sprawdzany
    tym samym weryfikatorem co u odbiorcy: podpis, ktory by nie przeszedl
    (np. zly klucz), nie opuszcza aplikacji.
    """

    alg = 'es256-webauthn'
    storage = 'hardware-uv'

    def __init__(self, cred_id: bytes, public: bytes,
                 hwnd: Callable[[], int] | int = 0, *, timeout_ms: int = TIMEOUT_MS) -> None:
        X.p256_public(public)
        self.cred_id = cred_id
        self._public = public
        self._hwnd = hwnd
        self._timeout = timeout_ms

    @property
    def public_bytes(self) -> bytes:
        return self._public

    def sign(self, message: bytes) -> dict:
        hwnd = self._hwnd() if callable(self._hwnd) else self._hwnd
        client = _client_data('webauthn.get', X.webauthn_challenge(message))
        auth, der = _get_assertion(hwnd, self.cred_id, client, self._timeout)
        sig = {'authenticator_data': X.b64encode(auth), 'client_data_json': X.b64encode(client),
               'signature': X.b64encode(der)}
        try:
            X.verify_signature(self.alg, self._public, message, sig)
        except HandoverError as e:
            raise HelloError('failed', f'the authenticator signature does not verify: {e.detail}') from None
        return sig


def delete_credential(cred_id: bytes) -> bool:
    """Usuwa klucz z Windows Hello (API >= 4). False, gdy system nie umie albo klucza nie ma."""
    try:
        dll = _load()
    except HelloError:
        return False
    fn = getattr(dll, 'WebAuthNDeletePlatformCredential', None)
    if fn is None:
        return False
    fn.argtypes = [W.DWORD, POINTER(c_ubyte)]
    fn.restype = c_long
    arr, ptr = _buf(cred_id)
    ok = fn(len(cred_id), ptr) == 0
    del arr
    return ok
