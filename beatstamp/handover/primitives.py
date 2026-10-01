"""
Prymitywy kryptograficzne `sigelith-handover-v1` — HANDOVER_SPEC.md §1-2.

Wszystko, co moze sie roznic miedzy implementacjami, jest nazwane i ustalone
tutaj: separatory domen, kodowanie kluczy, postac podpisu, dopuszczalne
base64 i format czasu. Reszta pakietu nie wola `cryptography` wprost do
podpisow i HPKE — tylko przez ten modul.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from datetime import date, datetime, timezone

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hpke, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import jcs
from .errors import HandoverError

VERSION = 'sigelith-handover-v1'


def domain(name: str) -> bytes:
    """`sigelith-handover-v1|<name>|` — zawsze z koncowym `|` (§1).

    Koncowy separator sprawia, ze zadna domena nie jest prefiksem innej
    (`preview|` vs `preview-key|`), wiec komunikatu z jednej domeny nie da sie
    przeczytac jako komunikatu z drugiej.
    """
    return f'{VERSION}|{name}|'.encode('ascii')


D_CARD = domain('card')
D_BINDING = domain('binding')
D_OFFER = domain('offer')
D_ANSWER = domain('answer')
D_PART_A = domain('part-a')
D_PART_B = domain('part-b')
D_SEAL_A = domain('seal-a')
D_CONTENT_KEY = domain('content-key')
D_CONTAINER = domain('container')
D_PREVIEW_KEY = domain('preview-key')
D_PREVIEW = domain('preview')
D_ENVELOPE = domain('envelope')


# --- skroty i wyprowadzanie kluczy -------------------------------------------

def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def signed_message(dom: bytes, obj: dict) -> bytes:
    """Bajty, ktore podpisuje podpis obiektu: `domena ‖ JCS(obiekt bez sig)`.

    Skrot obiektu (odcisk karty, skrot oferty, odpowiedzi...) to SHA-256 tych
    samych bajtow — nigdy nie obejmuje podpisu, wiec plastycznosc podpisu
    (np. s i n-s w ECDSA) nie zmienia skrotu.
    """
    body = {k: v for k, v in obj.items() if k != 'sig'}
    return dom + jcs.dumps(body)


def object_digest(dom: bytes, obj: dict) -> bytes:
    return sha256(signed_message(dom, obj))


# --- base64, hex, Base32 Crockforda ------------------------------------------

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def b64decode(text: object, field: str, size: int | None = None) -> bytes:
    """Scisle base64 (standard, z dopelnieniem) — tylko postac kanoniczna.

    Ostatni znak przed `=` niesie nieuzywane bity: `...yN0=` i `...yN1=`
    dekoduja sie do tych samych bajtow. Przepuszczenie obu postaci dawaloby
    dwa napisy dla jednego klucza (patrz keys.py).
    """
    if not isinstance(text, str) or not text.isascii():
        raise HandoverError('base64', f'{field}: not ASCII text')
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise HandoverError('base64', f'{field}: invalid base64') from None
    if b64encode(data) != text:
        raise HandoverError('base64', f'{field}: non-canonical base64')
    if size is not None and len(data) != size:
        raise HandoverError('base64', f'{field}: expected {size} bytes, got {len(data)}')
    return data


def b64url(data: bytes) -> str:
    """base64url bez dopelnienia (tekst odpowiedzi, wyzwanie WebAuthn)."""
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def b64url_decode(text: object, field: str) -> bytes:
    if not isinstance(text, str) or not text.isascii() or '=' in text:
        raise HandoverError('base64', f'{field}: not unpadded base64url')
    try:
        data = base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise HandoverError('base64', f'{field}: invalid base64url') from None
    if b64url(data) != text:
        raise HandoverError('base64', f'{field}: non-canonical base64url')
    return data


_HEX64 = re.compile(r'[0-9a-f]{64}')


def hex32(text: object, field: str) -> bytes:
    if not isinstance(text, str) or not _HEX64.fullmatch(text):
        raise HandoverError('hex', f'{field}: 64 lowercase hex characters')
    return bytes.fromhex(text)


_CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'


def crockford(data: bytes) -> str:
    """Base32 Crockforda (bez I, L, O, U — nie myla sie przy czytaniu na glos)."""
    bits = int.from_bytes(data, 'big')
    length = len(data) * 8
    pad = -length % 5
    bits <<= pad
    length += pad
    return ''.join(_CROCKFORD[(bits >> (length - 5 * (i + 1))) & 31]
                   for i in range(length // 5))


# --- czas --------------------------------------------------------------------

_TS = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
_DAY = re.compile(r'\d{4}-\d{2}-\d{2}')
_LOG_UTC = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z')


def format_ts(moment: datetime) -> str:
    """Czas w obiektach protokolu: UTC, co do sekundy, z `Z`."""
    if moment.tzinfo is None:
        raise ValueError('czas bez strefy — w protokole tylko UTC ze strefa')
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_ts(text: object, field: str) -> datetime:
    if not isinstance(text, str) or not _TS.fullmatch(text):
        raise HandoverError('time', f'{field}: expected YYYY-MM-DDTHH:MM:SSZ')
    try:
        return datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise HandoverError('time', f'{field}: not a real date') from None


def parse_day(text: object, field: str) -> date:
    if not isinstance(text, str) or not _DAY.fullmatch(text):
        raise HandoverError('time', f'{field}: expected YYYY-MM-DD')
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise HandoverError('time', f'{field}: not a real date') from None


def parse_log_utc(text: object) -> datetime:
    """Czas wpisu dziennika (`utc` z /api/proof/..., do mikrosekund)."""
    if not isinstance(text, str) or not _LOG_UTC.fullmatch(text):
        raise HandoverError('time', 'log utc: expected YYYY-MM-DDTHH:MM:SS[.ffffff]Z')
    try:
        return datetime.fromisoformat(text[:-1]).replace(tzinfo=timezone.utc)
    except ValueError:
        raise HandoverError('time', 'log utc: not a real date') from None


# --- ES256 (ECDSA P-256 + SHA-256) -------------------------------------------

P256_N = int('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16)
P256_PUBLIC_LEN = 65


def p256_public(data: bytes) -> ec.EllipticCurvePublicKey:
    """Klucz P-256 z 65 bajtow SEC1 (nieskompresowany) — z walidacja punktu."""
    if len(data) != P256_PUBLIC_LEN or data[0] != 0x04:
        raise HandoverError('key', 'P-256 key must be 65-byte uncompressed SEC1')
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)
    except ValueError:
        raise HandoverError('key', 'P-256 point is not on the curve') from None


def p256_public_bytes(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint)


def es256_sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Podpis 64 B `r‖s`: deterministyczny (RFC 6979), znormalizowany do low-S.

    Deterministyczne nonce, bo powtorzone nonce w ECDSA ujawnia klucz
    prywatny — przy kluczu programowym nie polegamy na generatorze losowym.
    """
    der = private_key.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    if s > P256_N // 2:
        s = P256_N - s
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def es256_verify(public: bytes, message: bytes, sig: bytes) -> None:
    if len(sig) != 64:
        raise HandoverError('signature', 'ES256 signature must be 64 bytes')
    r = int.from_bytes(sig[:32], 'big')
    s = int.from_bytes(sig[32:], 'big')
    if not (1 <= r < P256_N and 1 <= s <= P256_N // 2):
        raise HandoverError('signature', 'ES256 signature out of range or not low-S')
    try:
        p256_public(public).verify(encode_dss_signature(r, s), message,
                                   ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise HandoverError('signature', 'ES256 signature does not verify') from None


# --- ES256 w postaci WebAuthn (Windows Hello, passkeys) ----------------------

RP_ID = 'sigelith.org'
FLAG_UP = 0x01   # user present
FLAG_UV = 0x04   # user verified (PIN, biometria)
WEBAUTHN_FIELDS = frozenset({'authenticator_data', 'client_data_json', 'signature'})


def webauthn_challenge(message: bytes) -> str:
    return b64url(sha256(message))


def webauthn_verify(public: bytes, message: bytes, sig: object, rp_id: str = RP_ID) -> None:
    """Asercja WebAuthn nad `message` (§2.1).

    Uwierzytelniacz podpisuje `authenticatorData ‖ SHA-256(clientDataJSON)`,
    a nasz komunikat siedzi w `challenge`. Wymagamy flag UP i UV: podpis bez
    weryfikacji uzytkownika znaczylby „proces podpisal", nie „czlowiek
    zatwierdzil". `origin` nie sprawdzamy — poza przegladarka wpisuje go
    wolajaca aplikacja, wiec niczego nie dowodzi.
    """
    if not isinstance(sig, dict) or set(sig) != WEBAUTHN_FIELDS:
        raise HandoverError('signature', 'WebAuthn signature needs authenticator_data, '
                            'client_data_json and signature')
    auth = b64decode(sig['authenticator_data'], 'authenticator_data')
    client = b64decode(sig['client_data_json'], 'client_data_json')
    der = b64decode(sig['signature'], 'signature')
    if len(auth) < 37:
        raise HandoverError('signature', 'WebAuthn authenticator data too short')
    if not hmac.compare_digest(auth[:32], sha256(rp_id.encode('ascii'))):
        raise HandoverError('signature', f'WebAuthn credential is not bound to {rp_id}')
    flags = auth[32]
    if not flags & FLAG_UP or not flags & FLAG_UV:
        raise HandoverError('signature', 'WebAuthn assertion without user presence '
                            'and user verification')
    try:
        data = jcs.parse_strict(client.decode('utf-8'))
    except (UnicodeDecodeError, HandoverError):
        raise HandoverError('signature', 'WebAuthn client data is not valid JSON') from None
    if not isinstance(data, dict) or data.get('type') != 'webauthn.get':
        raise HandoverError('signature', 'WebAuthn client data type is not webauthn.get')
    if data.get('challenge') != webauthn_challenge(message):
        raise HandoverError('signature', 'WebAuthn challenge is not the signed object')
    try:
        p256_public(public).verify(der, auth + sha256(client), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise HandoverError('signature', 'WebAuthn signature does not verify') from None


def webauthn_sign(private_key: ec.EllipticCurvePrivateKey, message: bytes, *,
                  rp_id: str = RP_ID, sign_count: int = 1, user_verified: bool = True) -> dict:
    """Programowy odpowiednik uwierzytelniacza — TYLKO testy i wektory.

    Prawdziwy podpis Windows Hello powstaje w module platformy; tu skladamy
    te same bajty kluczem programowym, zeby weryfikator mial na czym pracowac.
    """
    flags = FLAG_UP | (FLAG_UV if user_verified else 0)
    auth = sha256(rp_id.encode('ascii')) + bytes([flags]) + sign_count.to_bytes(4, 'big')
    client = json.dumps({'type': 'webauthn.get', 'challenge': webauthn_challenge(message),
                         'origin': f'https://{rp_id}', 'crossOrigin': False},
                        separators=(',', ':')).encode('utf-8')
    der = private_key.sign(auth + sha256(client),
                           ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    return {'authenticator_data': b64encode(auth), 'client_data_json': b64encode(client),
            'signature': b64encode(der)}


SIG_ALGS = ('es256', 'es256-webauthn')


def verify_signature(alg: str, public: bytes, message: bytes, sig: object) -> None:
    if alg == 'es256':
        es256_verify(public, message, b64decode(sig, 'sig', 64))
    elif alg == 'es256-webauthn':
        webauthn_verify(public, message, sig)
    else:
        raise HandoverError('signature', f'unknown signature algorithm {alg!r}')


# --- HPKE: hybryda ML-KEM-768 + X25519 ---------------------------------------

ENC_ALG = 'hpke-mlkem768x25519-hkdfsha256-aes256gcm'
MLKEM768_PUBLIC_LEN = 1184
X25519_LEN = 32
ENC_PUBLIC_LEN = MLKEM768_PUBLIC_LEN + X25519_LEN      # 1216 B
ENC_PRIVATE_LEN = 64 + X25519_LEN                      # ziarno ML-KEM + X25519
_SUITE = hpke.Suite(hpke.KEM.MLKEM768_X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)
HPKE_ENC_LEN = hpke.KEM.MLKEM768_X25519.enc_length()   # 1120 B
HPKE_OVERHEAD = HPKE_ENC_LEN + 16                      # enc + tag AES-GCM


class EncKey:
    """Prywatny klucz szyfrujacy (hybryda ML-KEM-768 + X25519).

    Programowy z wyboru (§2.2): TPM nie robi ML-KEM. Aplikacja trzyma
    `to_bytes()` zaszyfrowane przez profil uzytkownika (DPAPI).
    """

    def __init__(self, mlkem_seed: bytes, x25519_private: bytes) -> None:
        if len(mlkem_seed) != 64 or len(x25519_private) != X25519_LEN:
            raise ValueError('klucz hybrydowy: 64 B ziarna ML-KEM i 32 B X25519')
        self._mlkem = mlkem.MLKEM768PrivateKey.from_seed_bytes(mlkem_seed)
        self._x25519 = x25519.X25519PrivateKey.from_private_bytes(x25519_private)
        self._key = hpke.MLKEM768X25519PrivateKey(self._mlkem, self._x25519)
        self._raw = mlkem_seed + x25519_private

    @classmethod
    def generate(cls) -> 'EncKey':
        return cls(mlkem.MLKEM768PrivateKey.generate().private_bytes_raw(),
                   x25519.X25519PrivateKey.generate().private_bytes_raw())

    @classmethod
    def from_bytes(cls, raw: bytes) -> 'EncKey':
        if len(raw) != ENC_PRIVATE_LEN:
            raise ValueError(f'klucz hybrydowy ma {ENC_PRIVATE_LEN} bajtow')
        return cls(raw[:64], raw[64:])

    def to_bytes(self) -> bytes:
        return self._raw

    @property
    def public_bytes(self) -> bytes:
        return (self._mlkem.public_key().public_bytes_raw()
                + self._x25519.public_key().public_bytes_raw())

    def open(self, ciphertext: bytes, info: bytes) -> bytes:
        try:
            return _SUITE.decrypt(ciphertext, self._key, info=info)
        except (InvalidTag, ValueError):
            raise HandoverError('hpke', 'cannot open: another key, another context '
                                'or damaged data') from None


def enc_public(data: bytes) -> hpke.MLKEM768X25519PublicKey:
    if len(data) != ENC_PUBLIC_LEN:
        raise HandoverError('key', f'hybrid public key must be {ENC_PUBLIC_LEN} bytes')
    try:
        return hpke.MLKEM768X25519PublicKey(
            mlkem.MLKEM768PublicKey.from_public_bytes(data[:MLKEM768_PUBLIC_LEN]),
            x25519.X25519PublicKey.from_public_bytes(data[MLKEM768_PUBLIC_LEN:]))
    except ValueError:
        raise HandoverError('key', 'invalid hybrid public key') from None


def hpke_seal(public: bytes, plaintext: bytes, info: bytes) -> bytes:
    """Jednorazowe HPKE do klucza hybrydowego; kontekst wiazemy przez `info` (§2)."""
    return _SUITE.encrypt(plaintext, enc_public(public), info=info)


# --- AES-256-GCM podgladu ----------------------------------------------------

def preview_seal(key: bytes, plaintext: bytes) -> bytes:
    """Zerowe nonce jest tu poprawne: klucz podgladu wyprowadzamy raz na oferte."""
    return AESGCM(key).encrypt(bytes(12), plaintext, D_PREVIEW)


def preview_open(key: bytes, ciphertext: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(bytes(12), ciphertext, D_PREVIEW)
    except (InvalidTag, ValueError):
        raise HandoverError('preview-open', 'the preview does not decrypt') from None
