"""
config.py — Configuration persistante cagoule-pass (TOML).

Emplacement : ~/.cagoule-pass/config.toml
Créé automatiquement avec les valeurs par défaut si absent.

Priorité de résolution :
    1. Flags CLI (priorité maximale)
    2. Fichier config.toml
    3. Valeurs par défaut du code

Structure du fichier :
    [vault]
    dir = "~/.cagoule-pass"

    [clipboard]
    clear_after_seconds = 30   # 0 = désactivé
    no_clear = false

    [generator]
    default_length = 16
    use_symbols = false
    no_ambiguous = false
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ─── Compatibilité Python 3.9 / 3.10 / 3.11+ ────────────────────────────────

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # pip install tomli pour 3.9/3.10
    except ImportError:
        tomllib = None  # type: ignore[assignment]


# ─── Contenu par défaut ───────────────────────────────────────────────────────

DEFAULT_TOML = """\
# cagoule-pass — Configuration
# Généré automatiquement. Modifiez selon vos besoins.

[vault]
# Dossier du coffre (supporte ~)
dir = "~/.cagoule-pass"

[clipboard]
# Délai d'auto-effacement du presse-papier en secondes (0 = désactivé)
clear_after_seconds = 30
# Désactiver l'auto-effacement globalement
no_clear = false

[generator]
# Longueur par défaut des mots de passe générés
default_length = 16
# Inclure les symboles par défaut
use_symbols = false
# Exclure les caractères ambigus (0, O, l, I, 1) par défaut
no_ambiguous = false
"""


# ─── Dataclasses de configuration ────────────────────────────────────────────

@dataclass
class VaultConfig:
    dir: str = "~/.cagoule-pass"

    @property
    def vault_dir(self) -> Path:
        return Path(self.dir).expanduser()


@dataclass
class ClipboardConfig:
    clear_after_seconds: int = 30
    no_clear: bool = False

    @property
    def should_clear(self) -> bool:
        """Retourne True si l'auto-effacement est actif."""
        return not self.no_clear and self.clear_after_seconds > 0


@dataclass
class GeneratorConfig:
    default_length: int = 16
    use_symbols: bool = False
    no_ambiguous: bool = False


@dataclass
class CagouleConfig:
    vault:     VaultConfig     = field(default_factory=VaultConfig)
    clipboard: ClipboardConfig = field(default_factory=ClipboardConfig)
    generator: GeneratorConfig = field(default_factory=GeneratorConfig)

    # Chemin du fichier chargé (pour diagnostic)
    _source: Optional[Path] = field(default=None, repr=False, compare=False)

    # ── Chargement ────────────────────────────────────────────────────────────

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "CagouleConfig":
        """
        Charge la configuration depuis un fichier TOML.

        Si le fichier n'existe pas, le crée avec les valeurs par défaut.
        Si tomllib n'est pas disponible, retourne les valeurs par défaut
        sans erreur (dégradation silencieuse).

        Args:
            config_path: Chemin explicite. Si None, utilise le chemin par défaut.

        Returns:
            CagouleConfig avec les valeurs du fichier.
        """
        path = config_path or cls._default_path()

        # Créer le fichier par défaut si absent
        if not path.exists():
            cls._create_default(path)
            return cls(_source=path)

        # Dégradation silencieuse si tomllib absent
        if tomllib is None:
            return cls(_source=path)

        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            import warnings
            warnings.warn(
                f"cagoule-pass: Impossible de lire {path} : {e}. "
                "Utilisation des valeurs par défaut.",
                stacklevel=2,
            )
            return cls(_source=path)

        return cls._from_dict(data, source=path)

    @classmethod
    def _from_dict(cls, data: dict, source: Optional[Path] = None) -> "CagouleConfig":
        """Construit une CagouleConfig depuis un dict TOML parsé."""
        vault_data = data.get("vault", {})
        clip_data  = data.get("clipboard", {})
        gen_data   = data.get("generator", {})

        vault = VaultConfig(
            dir=vault_data.get("dir", "~/.cagoule-pass"),
        )
        clipboard = ClipboardConfig(
            clear_after_seconds=int(clip_data.get("clear_after_seconds", 30)),
            no_clear=bool(clip_data.get("no_clear", False)),
        )
        generator = GeneratorConfig(
            default_length=int(gen_data.get("default_length", 16)),
            use_symbols=bool(gen_data.get("use_symbols", False)),
            no_ambiguous=bool(gen_data.get("no_ambiguous", False)),
        )
        return cls(vault=vault, clipboard=clipboard, generator=generator, _source=source)

    @staticmethod
    def _default_path() -> Path:
        return Path.home() / ".cagoule-pass" / "config.toml"

    @staticmethod
    def _create_default(path: Path) -> None:
        """Crée le fichier de configuration avec les valeurs par défaut."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(DEFAULT_TOML, encoding="utf-8")