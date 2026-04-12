"""
vault.py — Coffre chiffré cagoule-pass.

Format sur disque :
    ~/.cagoule-pass/
    ├── vault.cgl1      ← coffre chiffré (format CGL1 CAGOULE)
    └── config.json     ← métadonnées non-sensibles (version, créé le)

Le coffre est un JSON chiffré contenant la liste des entrées.
Chaque ouverture déchiffre tout en mémoire, chaque sauvegarde rechiffre tout.

Schéma interne du JSON déchiffré :
{
  "version": "1.0",
  "created": "2026-04-09T...",
  "entries": [ {entry dict}, ... ]
}
"""

from __future__ import annotations

import getpass
import json
import os
import sys
from pathlib import Path
from typing import Optional

from .entry import Entry, _now


# ─── Constantes ───────────────────────────────────────────────────────────────

DEFAULT_VAULT_DIR  = Path.home() / ".cagoule-pass"
VAULT_FILE         = "vault.cgl1"
CONFIG_FILE        = "config.json"
VAULT_SCHEMA_VER   = "1.0"


# ─── Erreurs ──────────────────────────────────────────────────────────────────

class VaultError(Exception):
    """Erreur de base du coffre."""

class VaultNotFoundError(VaultError):
    """Le coffre n'existe pas encore."""

class VaultAuthError(VaultError):
    """Mot de passe maître incorrect."""

class VaultCorruptError(VaultError):
    """Le coffre est corrompu ou illisible."""

class EntryNotFoundError(VaultError):
    """Service introuvable dans le coffre."""

class EntryExistsError(VaultError):
    """Le service existe déjà dans le coffre."""


# ─── Vault ────────────────────────────────────────────────────────────────────

class Vault:
    """
    Coffre chiffré cagoule-pass.

    Usage typique :
        vault = Vault.open(password)
        vault.add(Entry("github", username="user", password="secret"))
        vault.save(password)
    """

    def __init__(self, entries: list[Entry], created: str, vault_dir: Path) -> None:
        self._entries:  list[Entry] = entries
        self._created:  str        = created
        self._vault_dir: Path      = vault_dir

    # ── Propriétés ────────────────────────────────────────────────────

    @property
    def vault_path(self) -> Path:
        return self._vault_dir / VAULT_FILE

    @property
    def config_path(self) -> Path:
        return self._vault_dir / CONFIG_FILE

    @property
    def entries(self) -> list[Entry]:
        return list(self._entries)

    @property
    def count(self) -> int:
        return len(self._entries)

    # ── Initialisation ────────────────────────────────────────────────

    @classmethod
    def init(cls, password: bytes, vault_dir: Path = DEFAULT_VAULT_DIR) -> "Vault":
        """
        Crée un nouveau coffre vide.

        Raises:
            VaultError : si le coffre existe déjà
        """
        vault_dir.mkdir(parents=True, exist_ok=True)
        vault_path = vault_dir / VAULT_FILE

        if vault_path.exists():
            raise VaultError(
                f"Un coffre existe déjà dans {vault_dir}. "
                "Utilisez 'cagoule-pass open' pour l'ouvrir."
            )

        vault = cls(entries=[], created=_now(), vault_dir=vault_dir)
        vault.save(password)

        # Écrire la config non-sensible
        config = {
            "version": VAULT_SCHEMA_VER,
            "created": vault._created,
            "vault_format": "CGL1",
        }
        (vault_dir / CONFIG_FILE).write_text(json.dumps(config, indent=2))

        return vault

    @classmethod
    def open(cls, password: bytes, vault_dir: Path = DEFAULT_VAULT_DIR) -> "Vault":
        """
        Ouvre et déchiffre un coffre existant.

        Raises:
            VaultNotFoundError : si le coffre n'existe pas
            VaultAuthError     : si le mot de passe est incorrect
            VaultCorruptError  : si le fichier est corrompu
        """
        vault_path = vault_dir / VAULT_FILE
        if not vault_path.exists():
            raise VaultNotFoundError(
                f"Aucun coffre trouvé dans {vault_dir}. "
                "Initialisez-en un avec : cagoule-pass init"
            )

        raw = vault_path.read_bytes()

        try:
            from cagoule import decrypt, CagouleAuthError
            plaintext = decrypt(raw, password)
        except Exception as e:
            if "auth" in str(e).lower() or "InvalidTag" in str(type(e)):
                raise VaultAuthError("Mot de passe maître incorrect.") from e
            # Essayer de distinguer les erreurs d'auth des erreurs de format
            err_name = type(e).__name__
            if "Auth" in err_name:
                raise VaultAuthError("Mot de passe maître incorrect.") from e
            raise VaultCorruptError(f"Coffre illisible : {e}") from e

        try:
            data = json.loads(plaintext.decode("utf-8"))
            entries = [Entry.from_dict(e) for e in data.get("entries", [])]
            created = data.get("created", _now())
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            raise VaultCorruptError(f"Structure du coffre invalide : {e}") from e

        return cls(entries=entries, created=created, vault_dir=vault_dir)

    def save(self, password: bytes) -> None:
        """
        Chiffre et sauvegarde le coffre sur disque.

        Le fichier est écrit atomiquement (fichier temporaire + rename).
        """
        data = {
            "version": VAULT_SCHEMA_VER,
            "created": self._created,
            "entries": [e.to_dict() for e in self._entries],
        }
        plaintext = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")

        from cagoule import encrypt
        ciphertext = encrypt(plaintext, password)

        # Écriture atomique
        tmp_path = self.vault_path.with_suffix(".tmp")
        tmp_path.write_bytes(ciphertext)
        tmp_path.replace(self.vault_path)

    # ── Gestion des entrées ───────────────────────────────────────────

    def add(self, entry: Entry) -> None:
        """
        Ajoute une entrée dans le coffre.

        Raises:
            EntryExistsError : si le service existe déjà
        """
        if self._find(entry.service) is not None:
            raise EntryExistsError(
                f"Le service '{entry.service}' existe déjà. "
                "Utilisez 'edit' pour le modifier."
            )
        self._entries.append(entry)

    def get(self, service: str) -> Entry:
        """
        Récupère une entrée par nom de service.

        Raises:
            EntryNotFoundError : si le service n'existe pas
        """
        entry = self._find(service)
        if entry is None:
            raise EntryNotFoundError(
                f"Service '{service}' introuvable. "
                "Utilisez 'list' pour voir les services disponibles."
            )
        return entry

    def update(self, service: str, **kwargs) -> Entry:
        """
        Met à jour une entrée existante.

        Raises:
            EntryNotFoundError : si le service n'existe pas
        """
        entry = self.get(service)
        entry.update(**kwargs)
        return entry

    def remove(self, service: str) -> Entry:
        """
        Supprime une entrée du coffre.

        Raises:
            EntryNotFoundError : si le service n'existe pas
        """
        entry = self.get(service)
        self._entries.remove(entry)
        return entry

    def search(self, query: str) -> list[Entry]:
        """
        Recherche des entrées par service, username, url ou tags.
        Recherche insensible à la casse.
        """
        q = query.lower()
        return [
            e for e in self._entries
            if (q in e.service.lower()
                or q in e.username.lower()
                or q in e.url.lower()
                or any(q in tag.lower() for tag in e.tags))
        ]

    def list_all(self, tag: Optional[str] = None) -> list[Entry]:
        """
        Liste toutes les entrées, optionnellement filtrées par tag.
        Triées alphabétiquement par service.
        """
        entries = self._entries
        if tag:
            entries = [e for e in entries if tag.lower() in [t.lower() for t in e.tags]]
        return sorted(entries, key=lambda e: e.service)

    # ── Changement de mot de passe maître ─────────────────────────────

    def change_password(self, old_password: bytes, new_password: bytes) -> None:
        """
        Change le mot de passe maître du coffre.
        Vérifie l'ancien mot de passe avant de rechiffrer.

        Raises:
            VaultAuthError : si l'ancien mot de passe est incorrect
        """
        # Vérifier l'ancien mot de passe en lisant le coffre
        try:
            Vault.open(old_password, self._vault_dir)
        except VaultAuthError:
            raise VaultAuthError("Ancien mot de passe incorrect.")

        self.save(new_password)

    # ── Export / Import ───────────────────────────────────────────────

    def export_json(self, path: Path, include_passwords: bool = True) -> None:
        """
        Exporte le coffre en JSON clair (non chiffré).
        ATTENTION : contient les mots de passe en clair.
        """
        data = {
            "export_version": VAULT_SCHEMA_VER,
            "exported_at": _now(),
            "warning": "Ce fichier contient des mots de passe en clair.",
            "entries": [
                {k: v for k, v in e.to_dict().items()
                 if include_passwords or k != "password"}
                for e in self._entries
            ],
        }
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2))

    def import_json(self, path: Path, overwrite: bool = False) -> tuple[int, int]:
        """
        Importe des entrées depuis un JSON exporté.

        Returns:
            (importées, ignorées) : tuple de compteurs
        """
        data = json.loads(path.read_text())
        imported = skipped = 0

        for e_dict in data.get("entries", []):
            entry = Entry.from_dict(e_dict)
            existing = self._find(entry.service)
            if existing is not None:
                if overwrite:
                    self._entries.remove(existing)
                    self._entries.append(entry)
                    imported += 1
                else:
                    skipped += 1
            else:
                self._entries.append(entry)
                imported += 1

        return imported, skipped

    # ── Helpers privés ────────────────────────────────────────────────

    def _find(self, service: str) -> Optional[Entry]:
        """Recherche une entrée par service (exact, insensible à la casse)."""
        service = service.strip().lower()
        for e in self._entries:
            if e.service == service:
                return e
        return None

    def __repr__(self) -> str:
        return f"Vault({self.count} entrées, dir={self._vault_dir})"
