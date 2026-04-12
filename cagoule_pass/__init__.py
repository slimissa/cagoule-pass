"""
cagoule-pass — Gestionnaire de mots de passe chiffré avec CAGOULE.

Dépend du package cagoule (core) pour le chiffrement CGL1.
"""

from .__version__ import __version__, __version_info__
from .entry      import Entry
from .vault      import (
    Vault, DEFAULT_VAULT_DIR,
    VaultError, VaultNotFoundError, VaultAuthError,
    VaultCorruptError, EntryNotFoundError, EntryExistsError,
)
from .generator  import generate, entropy_bits, strength

__all__ = [
    "__version__",
    "Entry",
    "Vault",
    "DEFAULT_VAULT_DIR",
    "VaultError",
    "VaultNotFoundError",
    "VaultAuthError",
    "VaultCorruptError",
    "EntryNotFoundError",
    "EntryExistsError",
    "generate",
    "entropy_bits",
    "strength",
]
