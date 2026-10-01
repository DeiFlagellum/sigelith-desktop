"""
DPAPI (CryptProtectData) — sekrety Handover zapisane na dysku.

Klucz szyfrujacy karty (hybryda ML-KEM-768 + X25519, 96 B), czesc B wyslanych
paczek i czesc A odebranych trzymamy zaszyfrowane kluczem KONTA Windows:
odczyta je tylko ten sam uzytkownik na tym samym komputerze (albo w domenie —
jego profil wedrujacy). Skopiowany plik na innym koncie to smieci, a w kopii
zapasowej lezy tylko szyfrogram.

Kazdy sekret dostaje `purpose` jako entropie DPAPI. Blob klucza nie da sie
wiec podsunac jako blob czesci B (i odwrotnie): odszyfrowanie z innym celem
konczy sie bledem, a nie cichym uzyciem cudzych bajtow.

Podpis karty NIE jest tutaj — ten klucz nie opuszcza TPM (Windows Hello,
winhello.py). DPAPI chroni tylko to, co musi byc w pamieci programu.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes as W

PREFIX = b'sigelith-handover-v1|dpapi|'
_UI_FORBIDDEN = 0x1          # CRYPTPROTECT_UI_FORBIDDEN: nigdy okna z pytaniem


class DpapiError(Exception):
    """Sekretu nie da sie zabezpieczyc albo odczytac (inne konto, uszkodzony plik)."""


class _Blob(ctypes.Structure):
    _fields_ = [('cbData', W.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> tuple[_Blob, object]:
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def _functions():
    if sys.platform != 'win32':
        raise DpapiError('DPAPI is available only on Windows')
    crypt32 = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    protect = crypt32.CryptProtectData
    protect.argtypes = [ctypes.POINTER(_Blob), W.LPCWSTR, ctypes.POINTER(_Blob), ctypes.c_void_p,
                        ctypes.c_void_p, W.DWORD, ctypes.POINTER(_Blob)]
    protect.restype = W.BOOL
    unprotect = crypt32.CryptUnprotectData
    unprotect.argtypes = [ctypes.POINTER(_Blob), ctypes.POINTER(W.LPWSTR), ctypes.POINTER(_Blob),
                          ctypes.c_void_p, ctypes.c_void_p, W.DWORD, ctypes.POINTER(_Blob)]
    unprotect.restype = W.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    return protect, unprotect, local_free


def _entropy(purpose: str) -> bytes:
    if not purpose or not purpose.isascii():
        raise ValueError('purpose: ASCII text')
    return PREFIX + purpose.encode('ascii')


def _take(out: _Blob, local_free) -> bytes:
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        local_free(out.pbData)


def protect(data: bytes, purpose: str) -> bytes:
    """Szyfruje `data` kluczem biezacego konta Windows."""
    fn_protect, _unprotect, local_free = _functions()
    data_in, keep_in = _blob(data)
    entropy, keep_entropy = _blob(_entropy(purpose))
    out = _Blob()
    if not fn_protect(ctypes.byref(data_in), 'Sigelith Handover', ctypes.byref(entropy), None,
                      None, _UI_FORBIDDEN, ctypes.byref(out)):
        raise DpapiError(f'CryptProtectData failed (error {ctypes.get_last_error()})')
    del keep_in, keep_entropy
    return _take(out, local_free)


def unprotect(blob: bytes, purpose: str) -> bytes:
    """Odszyfrowuje blob z `protect` — tylko to samo konto i ten sam `purpose`."""
    _protect, fn_unprotect, local_free = _functions()
    data_in, keep_in = _blob(blob)
    entropy, keep_entropy = _blob(_entropy(purpose))
    out = _Blob()
    if not fn_unprotect(ctypes.byref(data_in), None, ctypes.byref(entropy), None, None,
                        _UI_FORBIDDEN, ctypes.byref(out)):
        raise DpapiError(f'CryptUnprotectData failed (error {ctypes.get_last_error()})')
    del keep_in, keep_entropy
    return _take(out, local_free)
