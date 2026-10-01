"""
Atestacja sprzetowa karty (TPM przez Windows Hello) — HANDOVER_SPEC.md §3.6.

Karta mowi `sig_storage: hardware-uv`, ale to tylko deklaracja jej wlasciciela.
Atestacja zamienia ja w dowod: TPM komputera podpisuje (kluczem AIK, ktory
Microsoft poswiadczyl certyfikatem) strukture opisujaca klucz karty. Jesli
wszystko sie zgadza, klucz podpisu naprawde siedzi w TPM tego producenta
i nie da sie go z niego wyjac.

Weryfikacja wedlug W3C WebAuthn §8.3 (format `tpm`) plus reguly Sigelith:

1. obiekt towarzyszacy: pola, odcisk karty, `clientDataJSON` typu
   `webauthn.create`, obiekt atestacji w SCISLYM CBOR;
2. authenticatorData: rpIdHash sigelith.org, flagi UP+UV+AT, klucz COSE
   ES256 rowny `sig_key` karty;
3. pubArea (TPMT_PUBLIC): klucz ECC P-256 identyczny z kluczem karty;
4. certInfo (TPMS_ATTEST): TPM_GENERATED, ATTEST_CERTIFY, extraData = skrot
   (authenticatorData ‖ SHA-256(clientDataJSON)), Name = nameAlg ‖ H(pubArea);
5. podpis certInfo kluczem AIK (RS1, RS256 albo ES256);
6. certyfikat AIK: v3, pusty podmiot, SAN (krytyczne) z producentem, modelem
   i wersja TPM, EKU tcg-kp-AIKCertificate, CA=false, AAGUID zgodny jesli jest,
   zadnych nieznanych rozszerzen krytycznych;
7. lancuch do PRZYPIETEGO korzenia (tpm_roots.py), wszystkie certyfikaty
   wazne w chwili utworzenia karty.

Bez sieci i bez list odwolan: status certyfikatow TPM zglaszaja uslugi
metadanych, a dowod ma sie sprawdzac takze za 20 lat, offline.

LUSTRO: apps/web/static/web/handover/attestation.js — te same reguly, te same
kody bledow (wektory: `attestation` w tests/vectors/handover-v1.json).
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID

from . import jcs
from .errors import HandoverError
from .identity import Card
from .primitives import RP_ID, VERSION, b64decode, hex32, sha256
from .tpm_roots import TPM_ROOTS

ATTESTATION_FIELDS = frozenset({'v', 'type', 'card', 'fmt', 'attestation_object',
                                'client_data_json'})
FMT_TPM = 'tpm'
STATEMENT_FIELDS = frozenset({'ver', 'alg', 'x5c', 'sig', 'certInfo', 'pubArea'})
MAX_OBJECT = 32 * 1024
MAX_CERTS = 5

# COSE: -65535 RS1 (tak podpisuje wiekszosc TPM pod Windows), -257 RS256, -7 ES256.
ALGS = {-65535: ('RS1', hashes.SHA1), -257: ('RS256', hashes.SHA256), -7: ('ES256', hashes.SHA256)}

FLAG_UP, FLAG_UV, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x40, 0x80

TPM_GENERATED = 0xFF544347
TPM_ST_ATTEST_CERTIFY = 0x8017
TPM_ALG_ECC = 0x0023
TPM_ALG_NULL = 0x0010
TPM_ECC_NIST_P256 = 0x0003
NAME_ALGS = {0x0004: hashlib.sha1, 0x000B: hashlib.sha256, 0x000C: hashlib.sha384,
             0x000D: hashlib.sha512}

TCG_KP_AIK = '2.23.133.8.3'
TPM_MANUFACTURER, TPM_MODEL, TPM_VERSION = '2.23.133.2.1', '2.23.133.2.2', '2.23.133.2.3'
FIDO_AAGUID = '1.3.6.1.4.1.45724.1.1.4'
# Rozszerzenia, ktore rozumiemy. Krytyczne spoza tej listy = odrzucenie (RFC 5280).
KNOWN_EXTENSIONS = frozenset({
    '2.5.29.15', '2.5.29.19', '2.5.29.32', '2.5.29.37', '2.5.29.17', '2.5.29.35',
    '2.5.29.14', '2.5.29.31', '1.3.6.1.5.5.7.1.1', FIDO_AAGUID})
# Podpisy certyfikatow: RSA PKCS#1 v1.5 z SHA-2 albo ECDSA. SHA-1 tylko w RS1
# samej atestacji (tak robi TPM), nigdy w certyfikatach.
CERT_SIG_ALGS = {
    '1.2.840.113549.1.1.11': ('rsa', hashes.SHA256), '1.2.840.113549.1.1.12': ('rsa', hashes.SHA384),
    '1.2.840.113549.1.1.13': ('rsa', hashes.SHA512), '1.2.840.10045.4.3.2': ('ec', hashes.SHA256),
    '1.2.840.10045.4.3.3': ('ec', hashes.SHA384)}
# Krzywe kluczy wystawcow — te, ktore zna Web Crypto (inaczej JS i Python
# ocenilyby egzotyczny certyfikat roznie).
CERT_CURVES = (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)

# Rejestr producentow TPM (TCG Vendor ID Registry) — tylko do opisu w raporcie.
TPM_VENDORS = {
    'AMD': 'AMD', 'ATML': 'Atmel', 'BRCM': 'Broadcom', 'CSCO': 'Cisco', 'FLYS': 'Flyslice',
    'GOOG': 'Google', 'HPE': 'HPE', 'HISI': 'Huawei', 'IBM': 'IBM', 'IFX': 'Infineon',
    'INTC': 'Intel', 'LEN': 'Lenovo', 'MSFT': 'Microsoft', 'NSM': 'National Semiconductor',
    'NTZ': 'Nationz', 'NTC': 'Nuvoton', 'QCOM': 'Qualcomm', 'ROCC': 'Fuzhou Rockchip',
    'SECE': 'SecEdge', 'SMSC': 'SMSC', 'SMSN': 'Samsung', 'SNS': 'Sinosun', 'STM': 'STMicroelectronics',
    'TXN': 'Texas Instruments', 'WEC': 'Winbond'}


@dataclass(frozen=True)
class Attestation:
    """Wynik: klucz karty jest w TPM tego producenta, poswiadczony lancuchem do `root`."""

    card: bytes
    alg: str
    vendor_id: str
    vendor: str
    model: str
    firmware: str
    aaguid: bytes
    root: str

    @property
    def description(self) -> str:
        return f'TPM {self.vendor} {self.model}'.strip()


def _err(code: str, detail: str) -> HandoverError:
    return HandoverError(code, detail)


# --- scisly CBOR (tylko to, co wystepuje w atestacji WebAuthn) ---------------

class _Cbor:
    """Dekoder CBOR bez furtek: dlugosci okreslone i minimalne, bez duplikatow
    kluczy mapy, bez znacznikow i liczb zmiennoprzecinkowych, bez nadmiaru."""

    def __init__(self, data: bytes) -> None:
        self.d = data
        self.i = 0

    def _take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise _err('attestation-structure', 'CBOR ends too early')
        out = self.d[self.i:self.i + n]
        self.i += n
        return out

    def _arg(self, info: int) -> int:
        if info < 24:
            return info
        if info in (24, 25, 26, 27):
            size = 1 << (info - 24)
            value = int.from_bytes(self._take(size), 'big')
            if value < (24 if size == 1 else 1 << (4 * size)):
                raise _err('attestation-structure', 'CBOR length is not minimal')
            return value
        raise _err('attestation-structure', 'CBOR indefinite or reserved length')

    def item(self, depth: int = 0):
        if depth > 16:
            raise _err('attestation-structure', 'CBOR nested too deeply')
        head = self._take(1)[0]
        major, arg = head >> 5, self._arg(head & 31)
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            return self._take(arg)
        if major == 3:
            try:
                return self._take(arg).decode('utf-8')
            except UnicodeDecodeError:
                raise _err('attestation-structure', 'CBOR text is not UTF-8') from None
        if major == 4:
            return [self.item(depth + 1) for _ in range(arg)]
        if major == 5:
            out: dict = {}
            for _ in range(arg):
                key = self.item(depth + 1)
                if not isinstance(key, (int, str)) or isinstance(key, bool):
                    raise _err('attestation-structure', 'CBOR map key must be an integer or text')
                if key in out:
                    raise _err('attestation-structure', 'CBOR map has a duplicate key')
                out[key] = self.item(depth + 1)
            return out
        if major == 7 and arg in (20, 21, 22):
            return {20: False, 21: True, 22: None}[arg]
        raise _err('attestation-structure', 'CBOR tags and floats are not allowed')


def cbor_decode(data: bytes, *, allow_rest: bool = False) -> tuple[object, int]:
    reader = _Cbor(data)
    value = reader.item()
    if not allow_rest and reader.i != len(data):
        raise _err('attestation-structure', 'bytes after the CBOR item')
    return value, reader.i


# --- struktury TPM (big-endian) ------------------------------------------------

class _Tpm:
    def __init__(self, data: bytes, what: str) -> None:
        self.d, self.i, self.what = data, 0, what

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise _err('attestation-statement', f'{self.what} ends too early')
        out = self.d[self.i:self.i + n]
        self.i += n
        return out

    def u16(self) -> int:
        return int.from_bytes(self.take(2), 'big')

    def u32(self) -> int:
        return int.from_bytes(self.take(4), 'big')

    def tpm2b(self) -> bytes:
        return self.take(self.u16())

    def done(self) -> None:
        if self.i != len(self.d):
            raise _err('attestation-statement', f'bytes after {self.what}')


def _pub_area(data: bytes) -> tuple[int, bytes, bytes]:
    """TPMT_PUBLIC klucza ECC P-256 -> (nameAlg, x, y)."""
    r = _Tpm(data, 'pubArea')
    if r.u16() != TPM_ALG_ECC:
        raise _err('attestation-statement', 'pubArea is not an ECC key')
    name_alg = r.u16()
    if name_alg not in NAME_ALGS:
        raise _err('attestation-statement', 'pubArea nameAlg is not supported')
    r.u32()                                       # objectAttributes
    r.tpm2b()                                     # authPolicy
    if r.u16() != TPM_ALG_NULL:                   # symmetric: algorithm (+ keyBits, mode)
        r.u16()
        r.u16()
    if r.u16() != TPM_ALG_NULL:                   # scheme (+ hashAlg)
        r.u16()
    if r.u16() != TPM_ECC_NIST_P256:
        raise _err('attestation-statement', 'pubArea curve is not NIST P-256')
    if r.u16() != TPM_ALG_NULL:                   # kdf (+ hashAlg)
        r.u16()
    px, py = r.tpm2b(), r.tpm2b()
    r.done()
    if len(px) > 32 or len(py) > 32:
        raise _err('attestation-statement', 'pubArea point is not a P-256 point')
    return name_alg, px.rjust(32, b'\x00'), py.rjust(32, b'\x00')


def _cert_info(data: bytes) -> tuple[bytes, bytes]:
    """TPMS_ATTEST typu CERTIFY -> (extraData, name)."""
    r = _Tpm(data, 'certInfo')
    if r.u32() != TPM_GENERATED:
        raise _err('attestation-statement', 'certInfo was not generated by a TPM')
    if r.u16() != TPM_ST_ATTEST_CERTIFY:
        raise _err('attestation-statement', 'certInfo is not a CERTIFY attestation')
    r.tpm2b()                                     # qualifiedSigner
    extra = r.tpm2b()
    r.take(17)                                    # clockInfo
    r.take(8)                                     # firmwareVersion
    name = r.tpm2b()
    r.tpm2b()                                     # qualifiedName
    r.done()
    return extra, name


# --- authenticatorData --------------------------------------------------------

def _auth_data(auth: bytes) -> tuple[bytes, bytes]:
    """-> (aaguid, klucz P-256 SEC1). Kod `attestation-structure`, gdy cos nie gra."""
    if len(auth) < 55:
        raise _err('attestation-structure', 'authenticator data too short')
    if not hmac.compare_digest(auth[:32], sha256(RP_ID.encode('ascii'))):
        raise _err('attestation-structure', f'the credential is not bound to {RP_ID}')
    flags = auth[32]
    if not flags & FLAG_UP or not flags & FLAG_UV or not flags & FLAG_AT:
        raise _err('attestation-structure', 'key creation without user presence, user '
                   'verification or attested data')
    aaguid = auth[37:53]
    n = int.from_bytes(auth[53:55], 'big')
    if 55 + n > len(auth):
        raise _err('attestation-structure', 'authenticator data ends inside the credential id')
    cose, end = cbor_decode(auth[55 + n:], allow_rest=True)
    rest = auth[55 + n + end:]
    if flags & FLAG_ED:
        _ext, used = cbor_decode(rest, allow_rest=True)
        rest = rest[used:]
    if rest:
        raise _err('attestation-structure', 'bytes after the authenticator data')
    if (not isinstance(cose, dict) or set(cose) != {1, 3, -1, -2, -3} or cose[1] != 2
            or cose[3] != -7 or cose[-1] != 1 or not isinstance(cose[-2], bytes)
            or not isinstance(cose[-3], bytes) or len(cose[-2]) != 32 or len(cose[-3]) != 32):
        raise _err('attestation-structure', 'the credential is not an ES256 P-256 key')
    return aaguid, b'\x04' + cose[-2] + cose[-3]


def credential_key(auth: bytes) -> bytes:
    """Klucz P-256 (SEC1) z authenticatorData tworzenia klucza — te same reguly
    co przy weryfikacji atestacji, wiec aplikacja nie wlozy do karty klucza,
    ktorego weryfikator potem nie przyjmie."""
    return _auth_data(auth)[1]


# --- certyfikaty ---------------------------------------------------------------

def _load(der: object, code: str) -> x509.Certificate:
    if not isinstance(der, bytes):
        raise _err(code, 'x5c entry is not a byte string')
    try:
        cert = x509.load_der_x509_certificate(der)
        list(cert.extensions)                     # parsowanie (i duplikaty) teraz
        cert.subject, cert.issuer, cert.not_valid_before_utc, cert.not_valid_after_utc
    except (ValueError, TypeError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType) as e:
        raise _err(code, f'cannot parse a certificate: {e}') from None
    return cert


def _check_critical(cert: x509.Certificate, code: str) -> None:
    for ext in cert.extensions:
        if ext.critical and ext.oid.dotted_string not in KNOWN_EXTENSIONS:
            raise _err(code, f'unknown critical extension {ext.oid.dotted_string}')


def _verify_cert_signature(child: x509.Certificate, parent_key, code: str) -> None:
    kind_hash = CERT_SIG_ALGS.get(child.signature_algorithm_oid.dotted_string)
    if kind_hash is None:
        raise _err(code, 'unsupported certificate signature algorithm')
    kind, hash_cls = kind_hash
    try:
        if kind == 'rsa' and isinstance(parent_key, rsa.RSAPublicKey):
            parent_key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(),
                              hash_cls())
        elif kind == 'ec' and isinstance(parent_key, ec.EllipticCurvePublicKey) \
                and isinstance(parent_key.curve, CERT_CURVES):
            parent_key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(hash_cls()))
        else:
            raise _err(code, 'the issuer key does not match the signature algorithm')
    except InvalidSignature:
        raise _err(code, 'a certificate signature does not verify') from None


def _name_bytes(name: x509.Name) -> bytes:
    return name.public_bytes()


def _san_values(cert: x509.Certificate) -> dict[str, str]:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        raise _err('attestation-certificate', 'the AIK certificate has no subject alternative name') from None
    if not san.critical:
        raise _err('attestation-certificate', 'the AIK subject alternative name must be critical')
    values: dict[str, str] = {}
    for name in san.value.get_values_for_type(x509.DirectoryName):
        for attr in name:
            if isinstance(attr.value, str):
                values.setdefault(attr.oid.dotted_string, attr.value)
    for oid in (TPM_MANUFACTURER, TPM_MODEL, TPM_VERSION):
        if oid not in values:
            raise _err('attestation-certificate', 'the AIK certificate does not name the TPM '
                       'manufacturer, model and version')
    return values


def _vendor(manufacturer: str) -> tuple[str, str]:
    """`id:494E5443` -> ('INTC', 'Intel')."""
    vendor_id = manufacturer
    if manufacturer.startswith('id:'):
        try:
            vendor_id = bytes.fromhex(manufacturer[3:]).decode('ascii').rstrip('\x00 ')
        except ValueError:
            vendor_id = manufacturer
    return vendor_id, TPM_VENDORS.get(vendor_id, vendor_id)


def _check_aik(cert: x509.Certificate, aaguid: bytes) -> dict[str, str]:
    code = 'attestation-certificate'
    if cert.version != x509.Version.v3:
        raise _err(code, 'the AIK certificate is not X.509 v3')
    if len(cert.subject) != 0:
        raise _err(code, 'the AIK certificate subject must be empty')
    _check_critical(cert, code)
    values = _san_values(cert)
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        raise _err(code, 'the AIK certificate has no extended key usage') from None
    if TCG_KP_AIK not in {oid.dotted_string for oid in eku}:
        raise _err(code, 'the AIK certificate is not for tcg-kp-AIKCertificate')
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        raise _err(code, 'the AIK certificate has no basic constraints') from None
    if bc.ca:
        raise _err(code, 'the AIK certificate must not be a CA')
    for ext in cert.extensions:
        if ext.oid.dotted_string == FIDO_AAGUID:
            raw = ext.value.value
            if raw[:2] != b'\x04\x10' or len(raw) != 18 or not hmac.compare_digest(raw[2:], aaguid):
                raise _err(code, 'the AIK certificate AAGUID does not match the authenticator')
    return values


def _chain(certs: list[x509.Certificate], roots, when: datetime) -> str:
    """Lancuch x5c do przypietego korzenia; kazdy certyfikat wazny w chwili `when`."""
    code = 'attestation-chain'
    for cert in certs:
        if not cert.not_valid_before_utc <= when <= cert.not_valid_after_utc:
            raise _err(code, 'a certificate was not valid when the card was created')
    for child, parent in zip(certs, certs[1:]):
        _check_critical(parent, code)
        try:
            bc = parent.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        except x509.ExtensionNotFound:
            raise _err(code, 'an intermediate certificate is not a CA') from None
        if not bc.ca:
            raise _err(code, 'an intermediate certificate is not a CA')
        if _name_bytes(child.issuer) != _name_bytes(parent.subject):
            raise _err(code, 'the certificates do not form a chain')
        _verify_cert_signature(child, parent.public_key(), code)
    last = certs[-1]
    for name, der in roots:
        root = x509.load_der_x509_certificate(der)
        if last.public_bytes(serialization.Encoding.DER) == der:
            return name
        if _name_bytes(last.issuer) == _name_bytes(root.subject):
            if not root.not_valid_before_utc <= when <= root.not_valid_after_utc:
                raise _err(code, 'the root was not valid when the card was created')
            _verify_cert_signature(last, root.public_key(), code)
            return name
    raise _err(code, 'the chain does not end in a trusted TPM root')


# --- weryfikacja ---------------------------------------------------------------

def read_attestation(obj: object, card: Card, *,
                     roots: tuple[tuple[str, bytes], ...] = TPM_ROOTS) -> Attestation:
    """Sprawdza atestacje karty. `roots` zmieniaja tylko testy (korzen testowy)."""
    if not isinstance(obj, dict) or set(obj) != ATTESTATION_FIELDS:
        raise _err('attestation-structure', f'expected fields {sorted(ATTESTATION_FIELDS)}')
    try:
        if obj['v'] != VERSION or obj['type'] != 'attestation':
            raise _err('attestation-structure', 'not a sigelith-handover-v1 attestation')
        card_fp = hex32(obj['card'], 'card')
        raw = b64decode(obj['attestation_object'], 'attestation_object')
        client = b64decode(obj['client_data_json'], 'client_data_json')
    except HandoverError as e:
        raise (e if e.code == 'attestation-structure' else e.renamed('attestation-structure')) from None
    if obj['fmt'] != FMT_TPM:
        raise _err('attestation-unsupported', f'attestation format {obj["fmt"]!r} is not supported')
    if not hmac.compare_digest(card_fp, card.fingerprint):
        raise _err('attestation-card', 'the attestation belongs to another card')
    if len(raw) > MAX_OBJECT:
        raise _err('attestation-structure', 'attestation object too large')
    try:
        data = jcs.parse_strict(client.decode('utf-8'))
    except (UnicodeDecodeError, HandoverError):
        raise _err('attestation-structure', 'client data is not valid JSON') from None
    if not isinstance(data, dict) or data.get('type') != 'webauthn.create':
        raise _err('attestation-structure', 'client data type is not webauthn.create')

    att, _ = cbor_decode(raw)
    if not isinstance(att, dict) or set(att) != {'fmt', 'attStmt', 'authData'}:
        raise _err('attestation-structure', 'attestation object needs fmt, attStmt and authData')
    if att['fmt'] != obj['fmt'] or not isinstance(att['authData'], bytes):
        raise _err('attestation-structure', 'attestation object does not match its companion')
    auth = att['authData']
    aaguid, credential = _auth_data(auth)
    if not hmac.compare_digest(credential, card.sig_key):
        raise _err('attestation-card', 'the attested key is not the card signing key')

    stmt = att['attStmt']
    if not isinstance(stmt, dict) or set(stmt) != STATEMENT_FIELDS:
        raise _err('attestation-structure', f'tpm statement needs {sorted(STATEMENT_FIELDS)}')
    if stmt['ver'] != '2.0':
        raise _err('attestation-structure', 'tpm statement version is not 2.0')
    x5c = stmt['x5c']
    if (not isinstance(x5c, list) or not 1 <= len(x5c) <= MAX_CERTS
            or not all(isinstance(c, bytes) for c in (stmt['sig'], stmt['certInfo'], stmt['pubArea']))):
        raise _err('attestation-structure', 'tpm statement fields have wrong types')
    alg = stmt['alg']
    if type(alg) is not int or alg not in ALGS:
        raise _err('attestation-unsupported', f'attestation algorithm {alg!r} is not supported')
    alg_name, hash_cls = ALGS[alg]

    name_alg, x, y = _pub_area(stmt['pubArea'])
    if not hmac.compare_digest(b'\x04' + x + y, credential):
        raise _err('attestation-statement', 'the TPM key is not the attested credential')
    extra, name = _cert_info(stmt['certInfo'])
    digest = hashes.Hash(hash_cls())
    digest.update(auth + sha256(client))
    if not hmac.compare_digest(extra, digest.finalize()):
        raise _err('attestation-statement', 'certInfo does not cover this key creation')
    expected_name = name_alg.to_bytes(2, 'big') + NAME_ALGS[name_alg](stmt['pubArea']).digest()
    if not hmac.compare_digest(name, expected_name):
        raise _err('attestation-statement', 'certInfo names another TPM key')

    certs = [_load(der, 'attestation-certificate') for der in x5c[:1]]
    certs += [_load(der, 'attestation-chain') for der in x5c[1:]]
    aik = certs[0]
    key = aik.public_key()
    try:
        if alg in (-65535, -257) and isinstance(key, rsa.RSAPublicKey):
            key.verify(stmt['sig'], stmt['certInfo'], padding.PKCS1v15(), hash_cls())
        elif alg == -7 and isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
            key.verify(stmt['sig'], stmt['certInfo'], ec.ECDSA(hash_cls()))
        else:
            raise _err('attestation-statement', 'the AIK key does not match the algorithm')
    except InvalidSignature:
        raise _err('attestation-statement', 'the TPM signature over certInfo does not verify') from None

    values = _check_aik(aik, aaguid)
    root = _chain(certs, roots, card.created)
    vendor_id, vendor = _vendor(values[TPM_MANUFACTURER])
    return Attestation(card=card.fingerprint, alg=alg_name, vendor_id=vendor_id, vendor=vendor,
                       model=values[TPM_MODEL], firmware=values[TPM_VERSION], aaguid=aaguid,
                       root=root)
