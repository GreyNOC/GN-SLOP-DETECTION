"""Post-quantum (PQ) readiness rules.

The PQ-era problem is concrete: Shor's algorithm breaks RSA, finite-
field Diffie-Hellman, and every elliptic-curve scheme once a
cryptographically relevant quantum computer (CRQC) exists — and
ciphertext recorded today can be decrypted then ("harvest now,
decrypt later"). NIST finalized the replacements in August 2024
(FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA), and NIST IR 8547
schedules 112-bit-security classical asymmetric crypto for deprecation
by 2030 and disallowance by 2035.

These rules build a *crypto inventory* rather than shout "broken".
Severity is calibrated to migration urgency:

- Key establishment (RSA transport, ECDH/DH agreement) is MEDIUM —
  recorded ciphertext is retroactively exposed, so it migrates first.
- Config that pins classical-only TLS/SSH groups is MEDIUM — it
  actively opts out of the hybrid PQ key exchange modern stacks
  (OpenSSL 3.5+, Go 1.24+, browsers, OpenSSH 9+) negotiate by default.
- Signatures are LOW — forgery needs a live CRQC; there is no
  retroactive break.
- Asymmetric keys <= 1024 bits are HIGH and category "crypto", not
  "pqc" — they are weak classically, today, and count fully in the
  composite score. Everything in category "pqc" is inventory and is
  dampened by the composite scorer (see model.compute_score) so a
  codebase full of today-standard RSA/ECDH does not read as a
  backdoor-grade risk.
- AES-128/192 selection and PQC adoption are INFO-grade inventory.

The companion ``pq_readiness`` module aggregates the hits into a
single migration-status summary on the scan result.
"""

from __future__ import annotations

import re

from app.core.code_scanner.model import Confidence, Severity
from app.core.code_scanner.rules.base import RegexRule

# When a hybrid / PQC mechanism is named near the classical primitive
# (same line or the following window — multi-line group lists are the
# dominant Go/C style), the classical name is one half of a hybrid
# exchange, not an unmitigated exposure — suppress the classical rules.
_HYBRID_MARKERS = (
    "mlkem",
    "MLKEM",
    "ML-KEM",
    "ml_kem",
    "kyber",
    "Kyber",
    "KYBER",
    "sntrup",
    "SNTRUP",
    "hybrid",
    "Hybrid",
)

RULES = (
    RegexRule(
        rule_id="pqc.rsa-in-use",
        title="RSA cryptography in use (quantum-vulnerable)",
        description=(
            "RSA key generation or key handling detected. RSA is broken by Shor's "
            "algorithm on a quantum computer; RSA key transport is harvest-now-"
            "decrypt-later exposed, and NIST IR 8547 deprecates RSA-2048 by 2030."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category="pqc",
        remediation=(
            "Migrate key establishment to ML-KEM (FIPS 203), preferably hybrid "
            "(e.g. X25519MLKEM768), and signatures to ML-DSA (FIPS 204). Track the "
            "NIST IR 8547 transition timeline."
        ),
        pattern=(
            r"rsa\.generate_private_key\s*\("  # Python cryptography
            r"|(?:^|[^A-Za-z0-9_])RSA\.generate\s*\("  # PyCryptodome
            r"|rsa\.GenerateKey\s*\("  # Go
            r"|KeyPairGenerator\.getInstance\s*\(\s*[\"']RSA"  # Java
            r"|generateKeyPair(?:Sync)?\s*\(\s*[\"']rsa[\"']"  # Node
            r"|RSACryptoServiceProvider|(?:^|[^A-Za-z0-9_])RSA\.Create\s*\("  # .NET
            r"|openssl\s+genrsa|genpkey\s+-algorithm\s+RSA"  # OpenSSL CLI
        ),
        flags=re.MULTILINE,
        unique=True,
    ),
    RegexRule(
        rule_id="pqc.classical-key-exchange",
        title="Classical key exchange (harvest-now-decrypt-later exposure)",
        description=(
            "ECDH / X25519 / finite-field Diffie-Hellman key agreement detected "
            "with no hybrid PQC mechanism nearby. Traffic recorded today becomes "
            "readable once a quantum computer exists."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category="pqc",
        remediation=(
            "Use a hybrid key exchange combining a classical curve with a "
            "post-quantum KEM (TLS 1.3: X25519MLKEM768; SSH: "
            "mlkem768x25519-sha256 or sntrup761x25519-sha512@openssh.com) so "
            "both problems must be broken."
        ),
        pattern=(
            r"KeyAgreement\.getInstance\s*\(\s*[\"'](?:ECDH|XDH|X25519|X448|DH|DiffieHellman)[\"']"  # Java
            r"|create(?:ECDH|DiffieHellman(?:Group)?)\s*\("  # Node
            r"|ECDiffieHellman(?:Cng|OpenSsl)?\.Create\s*\("  # .NET
            r"|ec\.ECDH\s*\(|X25519PrivateKey|X448PrivateKey"  # Python cryptography
            r"|dh\.generate_parameters\s*\("
            r"|ecdh\.(?:P256|P384|P521|X25519)\s*\(\s*\)"  # Go crypto/ecdh
            r"|curve25519\.X25519\s*\("  # Go x/crypto
            r"|crypto_kx_|crypto_scalarmult"  # libsodium
            r"|openssl\s+dhparam"
        ),
        flags=re.MULTILINE,
        unique=True,
        nearby_must_not_contain=_HYBRID_MARKERS,
    ),
    RegexRule(
        rule_id="pqc.classical-kex-pinned-config",
        title="TLS/SSH configuration pins classical-only key exchange",
        description=(
            "An explicit curve/group/KEX list contains no hybrid PQC mechanism. "
            "Modern stacks negotiate hybrid post-quantum key exchange by default; "
            "pinning a classical-only list silently opts out of it."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category="pqc",
        remediation=(
            "Add a hybrid group first in the list (TLS: X25519MLKEM768; SSH: "
            "sntrup761x25519-sha512@openssh.com / mlkem768x25519-sha256), or drop "
            "the pin and accept the stack's defaults."
        ),
        # "auto" values (nginx ssl_ecdh_curve auto, Node ecdhCurve: 'auto')
        # delegate group selection to the library, whose modern defaults
        # already include hybrid PQ — excluded in the pattern itself, not
        # via a substring filter, so a "# autogenerated" comment on a real
        # pin does not suppress the finding.
        pattern=(
            r"(?:^|[^A-Za-z0-9_])ssl_ecdh_curve\s+(?!auto\b)\S"  # nginx
            r"|SSL_CTX_set1_(?:groups|curves)_list\s*\("  # OpenSSL C API
            r"|CurvePreferences\s*[:=]"  # Go tls.Config
            r"|ecdhCurve\s*[:=](?![^\n,}]*\bauto\b)"  # Node tls
            r"|(?:^|\s|-o)KexAlgorithms\s*[=\s]\s*\S"  # OpenSSH (space or = form)
            r"|SSLOpenSSLConfCmd\s+(?:Groups|Curves)\s+\S"  # Apache
            r"|(?:^|\s)(?:Groups|Curves)\s*=\s*[^\n]*(?:X25519|x25519|P-(?:256|384|521)|prime256v1|secp(?:256|384|521)r1|brainpool)"  # openssl.cnf
        ),
        flags=re.MULTILINE,
        unique=True,
        nearby_must_not_contain=_HYBRID_MARKERS,
    ),
    RegexRule(
        rule_id="pqc.classical-signature",
        title="Quantum-vulnerable signature scheme in use",
        description=(
            "ECDSA / EdDSA / DSA / RSA signing detected. Signature forgery needs a "
            "live quantum computer (no retroactive break), but long-lived trust "
            "anchors — firmware, code signing, certificates, blockchain keys — "
            "outlive the transition timeline."
        ),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        category="pqc",
        remediation=(
            "Plan migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); prioritize "
            "signatures that must stay valid past 2035 (firmware, roots of trust)."
        ),
        pattern=(
            r"Signature\.getInstance\s*\(\s*[\"'][A-Za-z0-9/-]*(?i:with(?:ecdsa|dsa|rsa))"  # Java (JCA names are case-insensitive)
            r"|Signature\.getInstance\s*\(\s*[\"'](?:RSASSA-PSS|Ed25519|Ed448|EdDSA)[\"']"  # Java modern names
            r"|ec\.generate_private_key\s*\(|dsa\.generate_private_key\s*\("  # Python
            r"|Ed25519PrivateKey|Ed448PrivateKey"  # Python cryptography
            r"|ecdsa\.GenerateKey\s*\(|ed25519\.GenerateKey\s*\("  # Go
            r"|generateKeyPair(?:Sync)?\s*\(\s*[\"'](?:ec|ed25519|ed448|dsa)[\"']"  # Node
            r"|ECDsa\.Create\s*\(|DSACryptoServiceProvider"  # .NET
            r"|openssl\s+ecparam[^\n]{0,40}-genkey"
            # ssh-keygen keys (including RSA) authenticate; they are not
            # key-transport, so they belong here and not in the HNDL rules.
            r"|ssh-keygen\s[^\n]{0,40}-t\s+(?:rsa|ecdsa|ed25519|dsa)\b"
            r"|secp256k1"
        ),
        flags=re.MULTILINE,
        unique=True,
        nearby_must_not_contain=_HYBRID_MARKERS,
    ),
    RegexRule(
        rule_id="pqc.jwt-classical-alg",
        title="JWT/JOSE pinned to a quantum-vulnerable algorithm",
        description=(
            "A token algorithm is pinned to RSA or ECDSA (RS*/ES*/PS*/EdDSA). "
            "Tokens are short-lived so the practical risk is low, but the pin is "
            "part of the crypto inventory a PQ migration has to touch."
        ),
        severity=Severity.INFO,
        confidence=Confidence.MEDIUM,
        category="pqc",
        remediation=(
            "Inventory the issuer and verifier; JOSE PQC algorithm identifiers "
            "(ML-DSA) are being standardized in draft-ietf-cose-dilithium."
        ),
        # Quotes around the alg key are optional (jose npm uses `{ alg: 'ES256' }`),
        # and array allow-lists get a bounded skip so RS256 is found in any
        # position of `algorithms=["HS256", "RS256"]`.
        pattern=(
            r"[\"']?alg[\"']?\s*[:=]\s*[\"'](?:RS|ES|PS)(?:256|384|512)[\"']"
            r"|algorithms?\s*[:=]\s*(?:\[[^\]\n]{0,120}?)?[\"'](?:RS|ES|PS)(?:256|384|512)[\"']"
            r"|[\"']EdDSA[\"']"
        ),
        flags=re.MULTILINE,
        unique=True,
    ),
    RegexRule(
        rule_id="pqc.weak-asymmetric-keysize",
        title="Asymmetric key size <= 1024 bits",
        description=(
            "RSA/DSA/DH keys of 1024 bits or less are considered breakable with "
            "classical resources today — this is a present-day weakness, not just "
            "a post-quantum one."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        # Category "crypto", not "pqc": a 1024-bit key is weak today, so it
        # must count fully in the composite score (the scorer dampens "pqc"
        # inventory findings). The pq_readiness roll-up maps it by rule_id.
        category="crypto",
        remediation=(
            "Use at least 2048-bit RSA (3072+ preferred) while planning the move "
            "to ML-KEM / ML-DSA; regenerate and rotate any 1024-bit keys now."
        ),
        # Every alternative is self-anchored to a crypto API or tool so no
        # line-level keyword filter is needed (a bare `key_size` filter would
        # either self-satisfy or miss the two-line Java KeyPairGenerator
        # idiom, whose algorithm name sits on the getInstance() line).
        pattern=(
            r"genrsa[^\n]{0,40}\s(?:512|768|1024)\b"
            r"|(?:dhparam|dsaparam)[^\n]{0,40}\s(?:512|768|1024)\b"
            r"|rsa\.generate_private_key\s*\([^)]{0,80}key_size\s*=\s*(?:512|768|1024)\b"
            r"|RSA\.generate\s*\(\s*(?:512|768|1024)\b"
            r"|rsa\.GenerateKey\s*\([^,\n]{0,40},\s*(?:512|768|1024)\s*\)"
            r"|KeyPairGenerator[\s\S]{0,200}?\.initialize\s*\(\s*(?:512|768|1024)\s*[,)]"  # Java, spans the two-line idiom
            r"|ssh-keygen[^\n]{0,60}-b\s*(?:512|768|1024)\b"
            r"|(?:^|[^A-Za-z0-9_])(?i:rsa|dsa|dh)[a-z_]{0,20}[^\n]{0,40}key_?size\s*[:=]\s*(?:512|768|1024)\b"
        ),
        flags=re.MULTILINE,
    ),
    RegexRule(
        rule_id="pqc.small-symmetric-key",
        title="AES-128/192 selected (below CNSA 2.0 margin)",
        description=(
            "AES-128/192 remains safe classically, but Grover's algorithm halves "
            "the effective security margin and CNSA 2.0 mandates AES-256 for "
            "national-security systems."
        ),
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        category="pqc",
        remediation="Prefer AES-256-GCM (or ChaCha20-Poly1305) for data that must stay confidential long-term.",
        pattern=(
            r"(?:^|[^A-Za-z0-9_])(?i:aes)[-_]?1(?:28|92)(?![0-9])"
            r"|KeyGenerator[\s\S]{0,120}?\binit\s*\(\s*1(?:28|92)\s*\)"  # Java, spans the two-line idiom
        ),
        flags=re.MULTILINE,
        unique=True,
    ),
    RegexRule(
        rule_id="pqc.pqc-in-use",
        title="Post-quantum cryptography in use (inventory)",
        description=(
            "A NIST post-quantum algorithm or PQC library was referenced. This is "
            "a positive migration signal — verify it runs in hybrid mode with an "
            "approved parameter set."
        ),
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        category="pqc",
        remediation=(
            "Confirm hybrid deployment (classical + PQC) and parameter sets of "
            "NIST security category 3 or higher (ML-KEM-768+, ML-DSA-65+)."
        ),
        # Left-boundary guarded so camelCase identifiers like xmlDsaValidator
        # or htmlKemNode cannot match mid-word. The bare mineral names are
        # deliberately absent: "kyber"/"dilithium" alone match DeFi
        # protocols (@kyber/contracts, KyberNetworkProxy) and sci-fi prose,
        # while real PQC code writes a parameter suffix (Kyber768) or the
        # official CRYSTALS- prefix. A stray match here flips the headline
        # pq_readiness status, so precision matters more than recall.
        pattern=(
            r"(?:^|[^A-Za-z0-9_])(?i:"
            r"ml[-_]?kem|ml[-_]?dsa|slh[-_]?dsa"
            r"|kyber[-_]?(?:512|768|1024)[a-z0-9]*"
            r"|x25519kyber768[a-z0-9]*"
            r"|crystals[-_]?(?:kyber|dilithium)"
            r"|dilithium[-_]?[2-5][a-z0-9]*"
            r"|sphincs(?:\+|plus)?(?![a-z])"
            r"|falcon[-_]?(?:512|1024)"
            r"|fn[-_]?dsa|sntrup761|frodokem|liboqs"
            r"|x25519mlkem768|secp(?:256|384)r1mlkem(?:768|1024)|x448mlkem1024"
            r")"
            r"|import\s+oqs|from\s+oqs\s+import"
            r"|(?:^|[^A-Za-z0-9])HQC(?:[^A-Za-z0-9]|$)"
        ),
        flags=re.MULTILINE,
        unique=True,
    ),
    RegexRule(
        rule_id="pqc.weak-pqc-parameter-set",
        title="PQC parameter set below recommended strength",
        description=(
            "A NIST security category 1/2 parameter set (ML-KEM-512, ML-DSA-44, "
            "Falcon-512, SLH-DSA-*-128*) is in use. CNSA 2.0 requires ML-KEM-1024 "
            "and ML-DSA-87; general guidance prefers category 3 or higher."
        ),
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        category="pqc",
        remediation="Move to ML-KEM-768/1024, ML-DSA-65/87, or SLH-DSA-192/256 variants.",
        pattern=(
            r"(?:^|[^A-Za-z0-9_])(?i:ml[-_]?kem[-_]?512|kyber[-_]?512|ml[-_]?dsa[-_]?44"
            r"|dilithium[-_]?2(?![0-9])|falcon[-_]?512"
            r"|slh[-_]?dsa[-_]?(?:sha2|shake)?[-_]?128[sf]?)"
        ),
        flags=re.MULTILINE,
        unique=True,
    ),
)
