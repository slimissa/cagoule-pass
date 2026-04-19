"""tests/test_config.py — Tests du module de configuration TOML (v1.2)."""
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from pathlib import Path
from cagoule_pass.config import CagouleConfig, VaultConfig, ClipboardConfig, GeneratorConfig, DEFAULT_TOML


class TestConfigDefaults:

    def test_defaults_vault(self):
        cfg = CagouleConfig()
        assert "cagoule-pass" in cfg.vault.dir
        assert cfg.vault.vault_dir == Path.home() / ".cagoule-pass"

    def test_defaults_clipboard(self):
        cfg = CagouleConfig()
        assert cfg.clipboard.clear_after_seconds == 30
        assert cfg.clipboard.no_clear is False
        assert cfg.clipboard.should_clear is True

    def test_defaults_generator(self):
        cfg = CagouleConfig()
        assert cfg.generator.default_length == 16
        assert cfg.generator.use_symbols is False
        assert cfg.generator.no_ambiguous is False

    def test_no_clear_disables_auto_clear(self):
        cfg = CagouleConfig(clipboard=ClipboardConfig(no_clear=True))
        assert cfg.clipboard.should_clear is False

    def test_zero_delay_disables_auto_clear(self):
        cfg = CagouleConfig(clipboard=ClipboardConfig(clear_after_seconds=0))
        assert cfg.clipboard.should_clear is False


class TestConfigLoad:

    def test_load_cree_fichier_par_defaut(self, tmp_path):
        config_file = tmp_path / "config.toml"
        assert not config_file.exists()
        cfg = CagouleConfig.load(config_file)
        assert config_file.exists()
        # Valeurs par défaut
        assert cfg.clipboard.clear_after_seconds == 30

    def test_load_contenu_defaut_valide(self, tmp_path):
        config_file = tmp_path / "config.toml"
        cfg = CagouleConfig.load(config_file)
        content = config_file.read_text()
        assert "[vault]" in content
        assert "[clipboard]" in content
        assert "[generator]" in content

    def test_load_fichier_personnalise(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            "[vault]\n"
            'dir = "/tmp/my-vault"\n\n'
            "[clipboard]\n"
            "clear_after_seconds = 60\n"
            "no_clear = false\n\n"
            "[generator]\n"
            "default_length = 24\n"
            "use_symbols = true\n"
            "no_ambiguous = true\n",
            encoding="utf-8"
        )
        cfg = CagouleConfig.load(config_file)
        assert cfg.vault.dir == "/tmp/my-vault"
        assert cfg.clipboard.clear_after_seconds == 60
        assert cfg.generator.default_length == 24
        assert cfg.generator.use_symbols is True
        assert cfg.generator.no_ambiguous is True

    def test_load_section_manquante(self, tmp_path):
        """Un fichier TOML partiel ne doit pas planter."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[clipboard]\nclear_after_seconds = 45\n", encoding="utf-8")
        cfg = CagouleConfig.load(config_file)
        assert cfg.clipboard.clear_after_seconds == 45
        # Les sections absentes prennent les valeurs par défaut
        assert cfg.generator.default_length == 16

    def test_load_fichier_corrompu_ne_plante_pas(self, tmp_path):
        """Un TOML invalide déclenche un warning mais ne lève pas d'exception."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("ceci n'est pas du TOML valide = = :", encoding="utf-8")
        import warnings
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            cfg = CagouleConfig.load(config_file)
        # Doit retourner les valeurs par défaut
        assert cfg.clipboard.clear_after_seconds == 30

    def test_source_enregistre(self, tmp_path):
        config_file = tmp_path / "config.toml"
        cfg = CagouleConfig.load(config_file)
        assert cfg._source == config_file


class TestClipboardConfig:

    def test_should_clear_true_par_defaut(self):
        c = ClipboardConfig()
        assert c.should_clear is True

    def test_should_clear_false_si_no_clear(self):
        c = ClipboardConfig(no_clear=True)
        assert c.should_clear is False

    def test_should_clear_false_si_delay_zero(self):
        c = ClipboardConfig(clear_after_seconds=0)
        assert c.should_clear is False

    def test_should_clear_false_les_deux(self):
        c = ClipboardConfig(no_clear=True, clear_after_seconds=0)
        assert c.should_clear is False


class TestVaultConfig:

    def test_vault_dir_expanduser(self):
        v = VaultConfig(dir="~/.cagoule-pass")
        assert "~" not in str(v.vault_dir)
        assert v.vault_dir == Path.home() / ".cagoule-pass"

    def test_vault_dir_absolu(self):
        v = VaultConfig(dir="/tmp/vault")
        assert v.vault_dir == Path("/tmp/vault")


class TestDefaultToml:

    def test_default_toml_contient_sections(self):
        assert "[vault]" in DEFAULT_TOML
        assert "[clipboard]" in DEFAULT_TOML
        assert "[generator]" in DEFAULT_TOML

    def test_default_toml_parseable(self, tmp_path):
        """Le TOML par défaut doit être parseable sans erreur."""
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                pytest.skip("tomllib/tomli non disponible")

        data = tomllib.loads(DEFAULT_TOML)
        assert "vault" in data
        assert "clipboard" in data
        assert "generator" in data