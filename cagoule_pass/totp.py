"""
totp.py — TOTP / 2FA compatible RFC 6238.

Implémentation native stdlib (hmac + hashlib + base64).
Compatible : Google Authenticator, Authy, Bitwarden, 1Password, etc.

Format stocké dans le coffre (champ `totp_secret` de Entry) :
    {
        "issuer":    "GitHub",
        "account":   "user@example.com",
        "secret":    "JBSWY3DPEHPK3PXP",   ← Base32, jamais en clair hors coffre
        "digits":    6,
        "period":    30,
        "algorithm": "SHA1"
    }
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import struct
import time
from dataclasses import asdict, dataclass, field
from typing import Optional


# ─── Dataclass ────────────────────────────────────────────────────────────────

@dataclass
class TOTPEntry:
    """
    Entrée TOTP liée à un service cagoule-pass.

    Attributes:
        issuer:    Nom du service (ex: "GitHub")
        account:   Identifiant de compte (ex: "user@example.com")
        secret:    Clé secrète encodée Base32 (RFC 4648)
        digits:    Nombre de chiffres du code (6 ou 8)
        period:    Durée d'un intervalle en secondes (30 ou 60)
        algorithm: Algorithme HMAC ("SHA1", "SHA256", "SHA512")
    """
    issuer:    str = ""
    account:   str = ""
    secret:    str = ""
    digits:    int = 6
    period:    int = 30
    algorithm: str = "SHA1"

    def __post_init__(self) -> None:
        self.secret = self.secret.upper().replace(" ", "").replace("-", "")
        if self.digits not in (6, 8):
            raise ValueError(f"digits doit être 6 ou 8 (reçu {self.digits})")
        if self.period not in (30, 60):
            raise ValueError(f"period doit être 30 ou 60 (reçu {self.period})")
        if self.algorithm not in ("SHA1", "SHA256", "SHA512"):
            raise ValueError(f"algorithm inconnu : {self.algorithm}")
        _validate_base32(self.secret)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "TOTPEntry":
        return cls(
            issuer=d.get("issuer", ""),
            account=d.get("account", ""),
            secret=d.get("secret", ""),
            digits=int(d.get("digits", 6)),
            period=int(d.get("period", 30)),
            algorithm=d.get("algorithm", "SHA1"),
        )

    def to_uri(self) -> str:
        """
        Génère l'URI otpauth:// pour import QR code.
        Format : otpauth://totp/{issuer}:{account}?secret=...&issuer=...
        """
        from urllib.parse import quote
        label = quote(f"{self.issuer}:{self.account}" if self.issuer else self.account)
        params = f"secret={self.secret}&issuer={quote(self.issuer)}"
        if self.digits != 6:
            params += f"&digits={self.digits}"
        if self.period != 30:
            params += f"&period={self.period}"
        if self.algorithm != "SHA1":
            params += f"&algorithm={self.algorithm}"
        return f"otpauth://totp/{label}?{params}"


# ─── Moteur TOTP (RFC 6238 + RFC 4226) ───────────────────────────────────────

def _validate_base32(secret: str) -> None:
    """Vérifie que le secret est un Base32 valide."""
    if not secret:
        raise ValueError("Le secret TOTP ne peut pas être vide.")
    try:
        _decode_base32(secret)
    except Exception:
        raise ValueError(
            "Secret TOTP invalide : doit être encodé en Base32 "
            "(caractères A-Z et 2-7 uniquement)."
        )


def _decode_base32(secret: str) -> bytes:
    """Décode Base32 avec padding automatique."""
    padding = (8 - len(secret) % 8) % 8
    return base64.b32decode(secret + "=" * padding, casefold=True)


def _hotp(secret_bytes: bytes, counter: int, digits: int, algorithm: str) -> str:
    """
    HMAC-Based One-Time Password (RFC 4226).

    Args:
        secret_bytes: Clé secrète décodée
        counter:      Valeur compteur (8 octets big-endian)
        digits:       Nombre de chiffres
        algorithm:    "SHA1", "SHA256" ou "SHA512"

    Returns:
        Code OTP zéro-paddé
    """
    alg_map = {
        "SHA1":   hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
    }
    digest_func = alg_map[algorithm]

    # Counter → 8 octets big-endian
    msg = struct.pack(">Q", counter)
    h   = hmac.new(secret_bytes, msg, digest_func).digest()

    # Dynamic truncation
    offset  = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF

    return str(code_int % (10 ** digits)).zfill(digits)


def generate_code(entry: TOTPEntry, at: Optional[float] = None) -> str:
    """
    Génère le code TOTP courant.

    Args:
        entry: Entrée TOTP
        at:    Timestamp Unix (défaut : maintenant)

    Returns:
        Code TOTP (6 ou 8 chiffres)
    """
    t    = at if at is not None else time.time()
    counter = int(t) // entry.period
    secret_bytes = _decode_base32(entry.secret)
    return _hotp(secret_bytes, counter, entry.digits, entry.algorithm)


def time_remaining(entry: TOTPEntry, at: Optional[float] = None) -> int:
    """
    Secondes restantes avant expiration du code courant.

    Returns:
        Entier entre 1 et period (inclus)
    """
    t = at if at is not None else time.time()
    return entry.period - (int(t) % entry.period)


def progress_ratio(entry: TOTPEntry, at: Optional[float] = None) -> float:
    """
    Ratio d'avancement du code courant [0.0, 1.0].
    1.0 = vient d'être généré, 0.0 = sur le point d'expirer.
    """
    remaining = time_remaining(entry, at)
    return remaining / entry.period


def verify_code(entry: TOTPEntry, code: str, window: int = 1) -> bool:
    """
    Vérifie un code TOTP avec fenêtre de tolérance.

    Args:
        entry:  Entrée TOTP
        code:   Code saisi par l'utilisateur
        window: Nombre d'intervalles de tolérance (±window)

    Returns:
        True si le code est valide
    """
    if not code or len(code) not in (6, 8):
        return False

    t       = time.time()
    counter = int(t) // entry.period
    secret_bytes = _decode_base32(entry.secret)

    for delta in range(-window, window + 1):
        expected = _hotp(secret_bytes, counter + delta, entry.digits, entry.algorithm)
        if hmac.compare_digest(expected, code.zfill(entry.digits)):
            return True
    return False


def generate_secret(length: int = 20) -> str:
    """
    Génère un secret TOTP aléatoire (Base32, cryptographiquement sûr).

    Args:
        length: Longueur en octets (défaut 20 = 160 bits, recommandé RFC 4226)

    Returns:
        Secret encodé Base32 sans padding
    """
    import os
    raw = os.urandom(length)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def parse_otpauth_uri(uri: str) -> TOTPEntry:
    """
    Parse un URI otpauth:// (QR code ou import manuel).

    Args:
        uri: URI otpauth://totp/... ou otpauth://hotp/...

    Returns:
        TOTPEntry peuplé

    Raises:
        ValueError: URI invalide ou type non supporté
    """
    from urllib.parse import parse_qs, unquote, urlparse

    parsed = urlparse(uri)
    if parsed.scheme != "otpauth":
        raise ValueError(f"Schéma invalide : {parsed.scheme!r} (attendu 'otpauth')")
    if parsed.netloc != "totp":
        raise ValueError(
            f"Type non supporté : {parsed.netloc!r} (seul 'totp' est supporté)"
        )

    # Label : {issuer}:{account} ou juste {account}
    label  = unquote(parsed.path.lstrip("/"))
    issuer = ""
    account = label
    if ":" in label:
        issuer, account = label.split(":", 1)

    params = parse_qs(parsed.query)

    secret = params.get("secret", [""])[0].upper()
    if not secret:
        raise ValueError("URI invalide : champ 'secret' manquant.")

    issuer    = params.get("issuer",    [issuer])[0]
    digits    = int(params.get("digits",    ["6"])[0])
    period    = int(params.get("period",    ["30"])[0])
    algorithm = params.get("algorithm", ["SHA1"])[0].upper()

    return TOTPEntry(
        issuer=issuer,
        account=account,
        secret=secret,
        digits=digits,
        period=period,
        algorithm=algorithm,
    )