"""tests/test_ssh.py — Tests unitaires pour le module SSH (v1.5)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from cagoule_pass.ssh import (
    SSHKeyPair,
    SUPPORTED_ALGORITHMS,
    _now,
    _compute_fingerprint,
    _require_cryptography,
)


# ─── Helper pour vérifier si cryptography est installé ────────────────────────
def _has_cryptography() -> bool:
    """Vérifie si la bibliothèque cryptography est installée."""
    try:
        import cryptography
        return True
    except ImportError:
        return False


class TestSSHKeyPair:
    """Tests de la structure SSHKeyPair."""

    def test_creation_minimale(self):
        pair = SSHKeyPair(algorithm="Ed25519")
        assert pair.algorithm == "Ed25519"
        assert pair.comment == ""
        assert pair.public_key_openssh == ""
        assert pair.private_key_pem == ""

    def test_creation_avec_commentaire(self):
        pair = SSHKeyPair(algorithm="RSA-4096", comment="user@host")
        assert pair.comment == "user@host"

    def test_timestamp_auto(self):
        pair = SSHKeyPair()
        assert pair.created
        assert "T" in pair.created

    def test_to_dict(self):
        pair = SSHKeyPair(
            algorithm="Ed25519",
            comment="test",
            public_key_openssh="ssh-ed25519 AAA...",
            private_key_pem="-----BEGIN OPENSSH PRIVATE KEY-----",
            fingerprint="SHA256:abc123",
        )
        d = pair.to_dict()
        assert d["algorithm"] == "Ed25519"
        assert d["comment"] == "test"
        assert d["public_key_openssh"] == "ssh-ed25519 AAA..."
        assert d["fingerprint"] == "SHA256:abc123"

    def test_from_dict(self):
        d = {
            "algorithm": "Ed25519",
            "comment": "test",
            "public_key_openssh": "ssh-ed25519 AAA...",
            "private_key_pem": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "fingerprint": "SHA256:abc123",
            "created": "2026-01-01T00:00:00Z",
        }
        pair = SSHKeyPair.from_dict(d)
        assert pair.algorithm == "Ed25519"
        assert pair.comment == "test"
        assert pair.fingerprint == "SHA256:abc123"


class TestSSHGeneration:
    """Tests de génération de clés SSH."""

    @pytest.mark.skipif(
        not _has_cryptography(),
        reason="cryptographie non installé"
    )
    def test_generate_ed25519(self):
        pair = SSHKeyPair.generate("Ed25519", comment="test@example.com")
        assert pair.algorithm == "Ed25519"
        assert pair.comment == "test@example.com"
        assert pair.public_key_openssh.startswith("ssh-ed25519")
        assert "BEGIN OPENSSH PRIVATE KEY" in pair.private_key_pem
        assert pair.fingerprint.startswith("SHA256:")

    @pytest.mark.skipif(
        not _has_cryptography(),
        reason="cryptographie non installé"
    )
    def test_generate_rsa_4096(self):
        pair = SSHKeyPair.generate("RSA-4096", comment="test")
        assert pair.algorithm == "RSA-4096"
        assert "ssh-rsa" in pair.public_key_openssh

    @pytest.mark.skipif(
        not _has_cryptography(),
        reason="cryptographie non installé"
    )
    def test_generate_rsa_2048(self):
        pair = SSHKeyPair.generate("RSA-2048")
        assert pair.algorithm == "RSA-2048"

    def test_generate_algorithme_invalide(self):
        with pytest.raises(ValueError, match="Algorithme 'INVALID' non supporté"):
            SSHKeyPair.generate("INVALID")


class TestSSHImport:
    """Tests d'import de clés SSH existantes."""

    @pytest.fixture
    def temp_key_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            priv_path = Path(tmpdir) / "id_test"
            pub_path = Path(tmpdir) / "id_test.pub"

            priv_content = "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n"
            pub_content = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... test@host\n"

            priv_path.write_text(priv_content)
            pub_path.write_text(pub_content)

            yield priv_path

    @pytest.mark.skipif(
        not _has_cryptography(),
        reason="cryptographie non installé"
    )
    def test_from_file(self, temp_key_files):
        # Test avec une clé invalide
        with pytest.raises((ValueError, FileNotFoundError)):
            SSHKeyPair.from_file(str(temp_key_files))

    def test_from_file_inexistant(self):
        with pytest.raises(FileNotFoundError):
            SSHKeyPair.from_file("/nonexistent/key/path")


class TestSSHExport:
    """Tests d'export de clés SSH."""

    @pytest.fixture
    def sample_keypair(self):
        return SSHKeyPair(
            algorithm="Ed25519",
            comment="test",
            public_key_openssh="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... test",
            private_key_pem="-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n",
            fingerprint="SHA256:abc123",
        )

    def test_export_to_files(self, sample_keypair, tmp_path):
        priv, pub = sample_keypair.export_to_files(
            output_dir=str(tmp_path),
            filename="test_key",
            overwrite=True,
        )
        assert Path(priv).exists()
        assert Path(pub).exists()

    def test_export_sans_ecrasement(self, sample_keypair, tmp_path):
        existing = tmp_path / "id_ed25519"
        existing.write_text("existing")
        with pytest.raises(FileExistsError):
            sample_keypair.export_to_files(
                output_dir=str(tmp_path),
                overwrite=False,
            )

    def test_export_force_ecrasement(self, sample_keypair, tmp_path):
        existing = tmp_path / "id_ed25519"
        existing.write_text("existing")
        priv, pub = sample_keypair.export_to_files(
            output_dir=str(tmp_path),
            overwrite=True,
        )
        assert Path(priv).read_text() != "existing"


class TestSSHFingerprint:
    """Tests de calcul d'empreinte."""

    def test_fingerprint_format(self):
        class MockPublicKey:
            def public_bytes(self, encoding, format):
                return b"mock_key_bytes"

        fingerprint = _compute_fingerprint(MockPublicKey())
        assert fingerprint.startswith("SHA256:")


class TestSSHDisplay:
    """Tests d'affichage des clés SSH."""

    def test_display_sans_privée(self):
        pair = SSHKeyPair(
            algorithm="Ed25519",
            comment="test",
            fingerprint="SHA256:abc123",
        )
        display = pair.display(show_private=False)
        assert "Algorithme  : Ed25519" in display
        assert "Empreinte   : SHA256:abc123" in display
        assert "Clé privée" not in display

    def test_display_avec_privée(self):
        pair = SSHKeyPair(
            algorithm="Ed25519",
            comment="test",
            fingerprint="SHA256:abc123",
            private_key_pem="-----BEGIN PRIVATE KEY-----\n",
        )
        display = pair.display(show_private=True)
        assert "Clé privée" in display

    def test_repr(self):
        pair = SSHKeyPair(algorithm="Ed25519", fingerprint="SHA256:abc1234567890")
        repr_str = repr(pair)
        assert "SSHKeyPair" in repr_str
        assert "Ed25519" in repr_str


class TestSSHConstants:
    """Tests des constantes SSH."""

    def test_supported_algorithms(self):
        assert "Ed25519" in SUPPORTED_ALGORITHMS
        assert "RSA-4096" in SUPPORTED_ALGORITHMS
        assert "RSA-2048" in SUPPORTED_ALGORITHMS