"""
entry.py — Modèle d'une entrée v1.5 dans le coffre cagoule-pass.

Nouveautés v1.5 :
    - Champ `totp`    : dict sérialisé TOTPEntry (None si absent)
    - Champ `ssh_key` : dict sérialisé SSHKeyPair (None si absent)

Les deux champs optionnels sont chiffrés dans le coffre CGL1 comme le reste.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Entry:
    """
    Représente une entrée dans le coffre.

    Attributs obligatoires :
        service  : nom du service (ex: "github", "gmail")

    Attributs optionnels (mots de passe) :
        username : identifiant de connexion
        password : mot de passe (en clair en mémoire, chiffré sur disque)
        url      : URL associée
        notes    : notes libres
        tags     : liste de tags pour organiser

    Attributs v1.5 (optionnels) :
        totp    : dict sérialisé TOTPEntry — None si pas de 2FA configuré
        ssh_key : dict sérialisé SSHKeyPair — None si pas de clé SSH

    Timestamps :
        created  : date de création (ISO 8601 UTC)
        updated  : date de dernière modification (ISO 8601 UTC)
    """
    # ── Champs de base ────────────────────────────────────────────────────────
    service:  str
    username: str           = ""
    password: str           = ""
    url:      str           = ""
    notes:    str           = ""
    tags:     list[str]     = field(default_factory=list)

    # ── Champs v1.5 ───────────────────────────────────────────────────────────
    totp:    Optional[dict] = field(default=None)   # TOTPEntry.to_dict()
    ssh_key: Optional[dict] = field(default=None)   # SSHKeyPair.to_dict()

    # ── Timestamps ────────────────────────────────────────────────────────────
    created: str = field(default_factory=_now)
    updated: str = field(default_factory=_now)

    def __post_init__(self) -> None:
        if not self.service or not self.service.strip():
            raise ValueError("Le nom du service ne peut pas être vide.")
        self.service = self.service.strip().lower()

    # ── Propriétés de commodité ───────────────────────────────────────────────

    @property
    def has_totp(self) -> bool:
        return self.totp is not None and bool(self.totp.get("secret"))

    @property
    def has_ssh_key(self) -> bool:
        return self.ssh_key is not None and bool(self.ssh_key.get("private_key_pem"))

    @property
    def totp_entry(self):
        """Retourne un objet TOTPEntry ou None."""
        if not self.has_totp:
            return None
        from .totp import TOTPEntry
        return TOTPEntry.from_dict(self.totp)

    @property
    def ssh_key_pair(self):
        """Retourne un objet SSHKeyPair ou None."""
        if not self.has_ssh_key:
            return None
        from .ssh import SSHKeyPair
        return SSHKeyPair.from_dict(self.ssh_key)

    # ── Sérialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "service":  self.service,
            "username": self.username,
            "password": self.password,
            "url":      self.url,
            "notes":    self.notes,
            "tags":     self.tags,
            "totp":     self.totp,
            "ssh_key":  self.ssh_key,
            "created":  self.created,
            "updated":  self.updated,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        return cls(
            service  = d.get("service",  ""),
            username = d.get("username", ""),
            password = d.get("password", ""),
            url      = d.get("url",      ""),
            notes    = d.get("notes",    ""),
            tags     = d.get("tags",     []),
            totp     = d.get("totp",     None),
            ssh_key  = d.get("ssh_key",  None),
            created  = d.get("created",  _now()),
            updated  = d.get("updated",  _now()),
        )

    # ── Modification ──────────────────────────────────────────────────────────

    def update(self, **kwargs) -> None:
        allowed = {"username", "password", "url", "notes", "tags", "totp", "ssh_key"}
        for key, val in kwargs.items():
            if key not in allowed:
                raise ValueError(f"Champ inconnu : {key!r}")
            setattr(self, key, val)
        self.updated = _now()

    def touch(self) -> None:
        self.updated = _now()

    # ── Affichage ─────────────────────────────────────────────────────────────

    def display(self, show_password: bool = False) -> str:
        pwd = self.password if show_password else ("*" * min(len(self.password), 8) or "—")
        lines = [
            f"  Service  : {self.service}",
            f"  Username : {self.username or '—'}",
            f"  Password : {pwd}",
        ]
        if self.url:
            lines.append(f"  URL      : {self.url}")
        if self.notes:
            lines.append(f"  Notes    : {self.notes}")
        if self.tags:
            lines.append(f"  Tags     : {', '.join(self.tags)}")

        # v1.5 — TOTP
        if self.has_totp:
            t = self.totp_entry
            lines.append(f"  2FA      : ✓ TOTP ({t.issuer or self.service}, {t.digits} chiffres)")

        # v1.5 — SSH
        if self.has_ssh_key:
            k = self.ssh_key_pair
            lines.append(f"  SSH      : ✓ {k.algorithm}  {k.fingerprint[:30]}...")

        lines += [
            f"  Créé     : {self.created}",
            f"  Modifié  : {self.updated}",
        ]
        return "\n".join(lines)

    def summary(self) -> str:
        user  = self.username or "—"
        url   = f"  {self.url}" if self.url else ""
        tags  = f"  [{', '.join(self.tags)}]" if self.tags else ""
        icons = ""
        if self.has_totp:    icons += " [2FA]"
        if self.has_ssh_key: icons += " [SSH]"
        return f"  {self.service:<20} {user:<30}{url}{tags}{icons}"

    def __repr__(self) -> str:
        return f"Entry(service={self.service!r}, username={self.username!r})"