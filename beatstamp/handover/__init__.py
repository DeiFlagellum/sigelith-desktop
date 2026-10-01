"""
Sigelith Handover — implementacja referencyjna `sigelith-handover-v1`.

Specyfikacja: apps/tsa/HANDOVER_SPEC.md (DRAFT 0.3), decyzje: apps/tsa/HANDOVER.md
sekcje 8-9. Pakiet jest czystym Pythonem (tylko `cryptography` >= 50): bez Qt,
bez sieci, bez importow z reszty programu. Siec (stemple, odczyt dziennika)
i interfejs dochodza w warstwie aplikacji; tutaj sa formaty, kryptografia
i reguly weryfikacji — to, co musi byc identyczne w kazdej implementacji
(drugi, niezalezny weryfikator w JS przechodzi te same wektory testowe).

Przebieg (§0.1): nadawca `package.create_offer` -> plik `transport.write_package_file`
-> odbiorca `transport.read_package_file`, `package.read_offer`,
`package.open_offer`, `package.copy_ciphertext` -> `answer.make_answer` (stempel
skrotu PRZED wydaniem) -> `transport.write_answer_file` -> nadawca
`answer.read_answer`, `answer.check_publish`, stempel B -> odbiorca
`logsearch.find_part_b`, `package.open_package` -> `evidence.build_evidence`
i `evidence.verify_evidence`.

Moduly:
  errors      HandoverError ze stalym kodem
  jcs         kanoniczny JSON (zapis i scisly odczyt)
  primitives  skroty, HKDF, ES256 (surowe i WebAuthn), HPKE hybrydowe, base64
  stream      AES-256-GCM-STREAM (lustro apps/seal/stream.py)
  rules       reguly tekstu i nazw plikow
  identity    karta Sigelith ID, odcisk, zapis powiazania
  package     manifest i kontener, czesci A/B, podglad, oferta, otwarcie, wada
  answer      akceptacja / odmowa i reguly nadawcy przed publikacja B
  transport   koperty, plik paczki, plik i tekst odpowiedzi
  logsearch   znalezienie B w publicznym dzienniku
  receipt     podpisany kwit stempla (§9.2)
  logproof    kiedy czas z dowodu dziennika sie liczy (§12.1)
  attestation atestacja TPM karty (§3.6), tpm_roots: przypiety korzen
  evidence    pakiet dowodowy i weryfikacja
"""
from .errors import HandoverError
from .primitives import VERSION

__all__ = ['HandoverError', 'VERSION']
