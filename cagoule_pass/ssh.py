"""
ssh.py — Gestion de paires de clés SSH dans le coffre cagoule-pass.

Supporte :
    - Ed25519  (recommandé — moderne, rapide, compact)
    - RSA 4096 (interopérabilité legacy)

Les clés privées sont stockées chiffrées dans le coffre CGL1.
Les clés publiques sont stockées en clair (format OpenSSH).

Usage typique :
    pair = SSHKeyPair.generate("Ed25519", comment="user@host")
    # stocker pair.to_dict() dans Entry.ssh_key
    pub = pair.public_key_openssh   # → copier dans ~/.ssh/authorized_keys
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ─── Algorithmes supportés ────────────────────────────────────────────────────

SUPPORTED_ALGORITHMS = ("Ed25519", "RSA-4096", "RSA-2048")


# ─── Dataclass principale ─────────────────────────────────────────────────────

@dataclass
class SSHKeyPair:
    """
    Paire de clés SSH stockée dans le coffre.

    Attributes:
        algorithm:          "Ed25519", "RSA-4096" ou "RSA-2048"
        comment:            Commentaire de la clé (ex: "user@laptop")
        public_key_openssh: Clé publique au format OpenSSH (ligne complète)
        private_key_pem:    Clé privée au format PEM (non chiffrée en mémoire)
        fingerprint:        Empreinte SHA256 de la clé publique
        created:            Date de génération (ISO 8601 UTC)
    """
    algorithm:          str = "Ed25519"
    comment:            str = ""
    public_key_openssh: str = ""
    private_key_pem:    str = ""
    fingerprint:        str = ""
    created:            str = field(default_factory=lambda: _now())

    # ── Génération ────────────────────────────────────────────────────────────

    @classmethod
    def generate(
        cls,
        algorithm: str = "Ed25519",
        comment: str = "",
    ) -> "SSHKeyPair":
        """
        Génère une nouvelle paire de clés SSH.

        Args:
            algorithm: "Ed25519" (défaut), "RSA-4096" ou "RSA-2048"
            comment:   Commentaire de la clé publique

        Returns:
            SSHKeyPair avec private_key_pem et public_key_openssh peuplés

        Raises:
            ValueError:  Algorithme non supporté
            ImportError: cryptography non installé
        """
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Algorithme {algorithm!r} non supporté. "
                f"Choix : {', '.join(SUPPORTED_ALGORITHMS)}"
            )
        _require_cryptography()

        if algorithm == "Ed25519":
            return cls._generate_ed25519(comment)
        else:
            bits = 4096 if algorithm == "RSA-4096" else 2048
            return cls._generate_rsa(bits, comment)

    @classmethod
    def _generate_ed25519(cls, comment: str) -> "SSHKeyPair":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat
        )

        private_key = Ed25519PrivateKey.generate()
        public_key  = private_key.public_key()

        private_pem = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
        ).decode("utf-8")

        pub_openssh = public_key.public_bytes(
            Encoding.OpenSSH, PublicFormat.OpenSSH
        ).decode("utf-8")

        if comment:
            pub_openssh = pub_openssh.rstrip() + f" {comment}"

        fingerprint = _compute_fingerprint(public_key)

        return cls(
            algorithm="Ed25519",
            comment=comment,
            public_key_openssh=pub_openssh,
            private_key_pem=private_pem,
            fingerprint=fingerprint,
        )

    @classmethod
    def _generate_rsa(cls, bits: int, comment: str) -> "SSHKeyPair":
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat
        )

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
        ).decode("utf-8")

        pub_openssh = public_key.public_bytes(
            Encoding.OpenSSH, PublicFormat.OpenSSH
        ).decode("utf-8")

        if comment:
            pub_openssh = pub_openssh.rstrip() + f" {comment}"

        fingerprint = _compute_fingerprint(public_key)

        return cls(
            algorithm=f"RSA-{bits}",
            comment=comment,
            public_key_openssh=pub_openssh,
            private_key_pem=private_pem,
            fingerprint=fingerprint,
        )

    # ── Import depuis fichier existant ────────────────────────────────────────

    @classmethod
    def from_file(
        cls,
        private_key_path: str,
        comment: str = "",
    ) -> "SSHKeyPair":
        """
        Importe une paire de clés SSH depuis des fichiers existants.

        Args:
            private_key_path: Chemin vers la clé privée (ex: ~/.ssh/id_ed25519)
            comment:          Commentaire optionnel (écrase celui du fichier)

        Returns:
            SSHKeyPair peuplé

        Raises:
            FileNotFoundError: Fichier clé privée absent
            ValueError:        Format de clé non reconnu
        """
        import os
        from pathlib import Path

        _require_cryptography()
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat
        )

        priv_path = Path(private_key_path).expanduser()
        if not priv_path.exists():
            raise FileNotFoundError(f"Clé privée introuvable : {priv_path}")

        raw = priv_path.read_bytes()

        try:
            private_key = load_pem_private_key(raw, password=None)
        except Exception as e:
            raise ValueError(
                f"Impossible de charger la clé privée : {e}\n"
                "Si elle est protégée par passphrase, utilisez ssh-keygen -p d'abord."
            ) from e

        public_key = private_key.public_key()

        # Détecter le type
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

        if isinstance(private_key, Ed25519PrivateKey):
            algorithm = "Ed25519"
        elif isinstance(private_key, RSAPrivateKey):
            bits = private_key.key_size
            algorithm = f"RSA-{bits}"
        else:
            algorithm = type(private_key).__name__

        private_pem = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
        ).decode("utf-8")

        pub_openssh = public_key.public_bytes(
            Encoding.OpenSSH, PublicFormat.OpenSSH
        ).decode("utf-8")

        # Essayer de lire le commentaire depuis le fichier .pub existant
        pub_path = priv_path.with_suffix(".pub")
        if not comment and pub_path.exists():
            parts = pub_path.read_text().strip().split()
            if len(parts) >= 3:
                comment = " ".join(parts[2:])

        if comment:
            pub_openssh = pub_openssh.rstrip() + f" {comment}"

        fingerprint = _compute_fingerprint(public_key)

        return cls(
            algorithm=algorithm,
            comment=comment,
            public_key_openssh=pub_openssh,
            private_key_pem=private_pem,
            fingerprint=fingerprint,
        )

    # ── Export vers fichiers ──────────────────────────────────────────────────

    def export_to_files(
        self,
        output_dir: str = "~/.ssh",
        filename: Optional[str] = None,
        overwrite: bool = False,
    ) -> tuple[str, str]:
        """
        Exporte la paire de clés vers des fichiers SSH standards.

        Args:
            output_dir: Dossier de destination
            filename:   Nom de base (sans extension). Auto-détecté si None.
            overwrite:  Écraser si les fichiers existent

        Returns:
            (chemin_privée, chemin_publique)

        Raises:
            FileExistsError: Si les fichiers existent et overwrite=False
        """
        from pathlib import Path

        out = Path(output_dir).expanduser()
        out.mkdir(parents=True, exist_ok=True)

        if filename is None:
            algo_slug = self.algorithm.lower().replace("-", "")
            filename = f"id_{algo_slug}"

        priv_path = out / filename
        pub_path  = out / f"{filename}.pub"

        if priv_path.exists() and not overwrite:
            raise FileExistsError(
                f"Le fichier {priv_path} existe déjà. "
                "Utilisez --force pour écraser."
            )

        priv_path.write_text(self.private_key_pem, encoding="utf-8")
        priv_path.chmod(0o600)

        pub_path.write_text(self.public_key_openssh + "\n", encoding="utf-8")
        pub_path.chmod(0o644)

        return str(priv_path), str(pub_path)

    # ── Sérialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "algorithm":          self.algorithm,
            "comment":            self.comment,
            "public_key_openssh": self.public_key_openssh,
            "private_key_pem":    self.private_key_pem,
            "fingerprint":        self.fingerprint,
            "created":            self.created,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SSHKeyPair":
        return cls(
            algorithm=d.get("algorithm", "Ed25519"),
            comment=d.get("comment", ""),
            public_key_openssh=d.get("public_key_openssh", ""),
            private_key_pem=d.get("private_key_pem", ""),
            fingerprint=d.get("fingerprint", ""),
            created=d.get("created", _now()),
        )

    # ── Affichage ─────────────────────────────────────────────────────────────

    def display(self, show_private: bool = False) -> str:
        lines = [
            f"  Algorithme  : {self.algorithm}",
            f"  Empreinte   : {self.fingerprint}",
            f"  Commentaire : {self.comment or '—'}",
            f"  Créée le    : {self.created}",
            f"  Clé publique: {self.public_key_openssh[:60]}...",
        ]
        if show_private:
            lines.append(f"  Clé privée  :\n{self.private_key_pem}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"SSHKeyPair({self.algorithm}, fp={self.fingerprint[:20]}...)"


# ─── Helpers privés ───────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_cryptography() -> None:
    try:
        import cryptography
    except ImportError:
        raise ImportError(
            "Le module 'cryptography' est requis pour la gestion SSH.\n"
            "Installez-le : pip install cryptography"
        )


def _compute_fingerprint(public_key) -> str:
    """
    Calcule l'empreinte SHA-256 de la clé publique (format OpenSSH standard).
    Format : SHA256:Base64NoPadding
    """
    import hashlib
    import base64

    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat
    )

    raw_bytes = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    digest    = hashlib.sha256(raw_bytes).digest()
    b64       = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{b64}"