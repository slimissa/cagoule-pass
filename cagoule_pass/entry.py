"""
entry.py — Modèle d'une entrée dans le coffre cagoule-pass.

Une entrée stocke : service, username, password, url, notes, timestamps.
La sérialisation est en JSON (chiffré par le coffre).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


def _now() -> str:
    """Retourne la date/heure UTC actuelle au format ISO 8601."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Entry:
    """
    Représente une entrée dans le coffre.

    Attributs obligatoires :
        service  : nom du service (ex: "github", "gmail")

    Attributs optionnels :
        username : identifiant de connexion
        password : mot de passe (en clair dans la mémoire, chiffré sur disque)
        url      : URL associée
        notes    : notes libres
        tags     : liste de tags pour organiser
        created  : date de création (ISO 8601 UTC)
        updated  : date de dernière modification (ISO 8601 UTC)
    """
    service:  str
    username: str           = ""
    password: str           = ""
    url:      str           = ""
    notes:    str           = ""
    tags:     list[str]     = field(default_factory=list)
    created:  str           = field(default_factory=_now)
    updated:  str           = field(default_factory=_now)

    def __post_init__(self) -> None:
        if not self.service or not self.service.strip():
            raise ValueError("Le nom du service ne peut pas être vide.")
        self.service = self.service.strip().lower()

    # ── Sérialisation ─────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Entry:
        return cls(
            service  = d.get("service",  ""),
            username = d.get("username", ""),
            password = d.get("password", ""),
            url      = d.get("url",      ""),
            notes    = d.get("notes",    ""),
            tags     = d.get("tags",     []),
            created  = d.get("created",  _now()),
            updated  = d.get("updated",  _now()),
        )

    # ── Modification ──────────────────────────────────────────────────

    def update(self, **kwargs) -> None:
        """Met à jour les champs spécifiés et rafraîchit updated."""
        allowed = {"username", "password", "url", "notes", "tags"}
        for key, val in kwargs.items():
            if key not in allowed:
                raise ValueError(f"Champ inconnu : {key!r}")
            setattr(self, key, val)
        self.updated = _now()

    def touch(self) -> None:
        """Met à jour le timestamp sans changer le contenu."""
        self.updated = _now()

    # ── Affichage ─────────────────────────────────────────────────────

    def display(self, show_password: bool = False) -> str:
        """Retourne une représentation lisible de l'entrée."""
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
        lines += [
            f"  Créé     : {self.created}",
            f"  Modifié  : {self.updated}",
        ]
        return "\n".join(lines)

    def summary(self) -> str:
        """Résumé court pour la commande list."""
        user = self.username or "—"
        url  = f"  {self.url}" if self.url else ""
        tags = f"  [{', '.join(self.tags)}]" if self.tags else ""
        return f"  {self.service:<20} {user:<30}{url}{tags}"

    def __repr__(self) -> str:
        return f"Entry(service={self.service!r}, username={self.username!r})"
