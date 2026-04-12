"""tests/test_vault.py — Tests complets du coffre chiffré."""
import sys, os, json, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from pathlib import Path
from cagoule_pass.entry import Entry
from cagoule_pass.vault import (
    Vault, VaultNotFoundError, VaultAuthError,
    VaultCorruptError, EntryNotFoundError, EntryExistsError,
)

_PWD = b"test_master_password_cagoule_pass"


@pytest.fixture
def vault_dir(tmp_path):
    """Dossier temporaire pour chaque test."""
    return tmp_path / "test_vault"


@pytest.fixture
def vault(vault_dir):
    """Coffre initialisé et vide."""
    return Vault.init(_PWD, vault_dir)


@pytest.fixture
def vault_with_entries(vault, vault_dir):
    """Coffre avec 3 entrées pré-chargées."""
    vault.add(Entry("github",  username="user1", password="pass1", tags=["dev"]))
    vault.add(Entry("gmail",   username="user@gmail.com", password="pass2", tags=["perso"]))
    vault.add(Entry("twitter", username="user2", password="pass3", tags=["perso", "social"]))
    vault.save(_PWD)
    return vault


# ── Init & Open ──────────────────────────────────────────────────────────────

class TestVaultInit:

    def test_init_cree_fichier(self, vault_dir):
        v = Vault.init(_PWD, vault_dir)
        assert (vault_dir / "vault.cgl1").exists()

    def test_init_deux_fois_exc(self, vault_dir):
        Vault.init(_PWD, vault_dir)
        with pytest.raises(Exception):
            Vault.init(_PWD, vault_dir)

    def test_open_vault_inexistant_exc(self, vault_dir):
        with pytest.raises(VaultNotFoundError):
            Vault.open(_PWD, vault_dir)

    def test_open_bon_password(self, vault_dir):
        Vault.init(_PWD, vault_dir)
        v = Vault.open(_PWD, vault_dir)
        assert v is not None
        assert v.count == 0

    def test_open_mauvais_password(self, vault_dir):
        Vault.init(_PWD, vault_dir)
        with pytest.raises(VaultAuthError):
            Vault.open(b"mauvais_password", vault_dir)

    def test_open_fichier_corrompu(self, vault_dir):
        vault_dir.mkdir(parents=True)
        (vault_dir / "vault.cgl1").write_bytes(b"not a valid cgl1 file at all")
        with pytest.raises((VaultCorruptError, VaultAuthError, Exception)):
            Vault.open(_PWD, vault_dir)


# ── CRUD ─────────────────────────────────────────────────────────────────────

class TestVaultCRUD:

    def test_add_et_get(self, vault, vault_dir):
        vault.add(Entry("github", username="user", password="pass"))
        vault.save(_PWD)
        v2 = Vault.open(_PWD, vault_dir)
        e = v2.get("github")
        assert e.username == "user"
        assert e.password == "pass"

    def test_add_doublon_exc(self, vault):
        vault.add(Entry("github"))
        with pytest.raises(EntryExistsError):
            vault.add(Entry("github"))

    def test_get_inexistant_exc(self, vault):
        with pytest.raises(EntryNotFoundError):
            vault.get("inexistant")

    def test_service_insensible_casse(self, vault):
        vault.add(Entry("GitHub", username="user"))
        e = vault.get("github")
        assert e.service == "github"

    def test_remove(self, vault, vault_dir):
        vault.add(Entry("github", password="pass"))
        vault.remove("github")
        vault.save(_PWD)
        v2 = Vault.open(_PWD, vault_dir)
        assert v2.count == 0

    def test_remove_inexistant_exc(self, vault):
        with pytest.raises(EntryNotFoundError):
            vault.remove("inexistant")

    def test_update(self, vault, vault_dir):
        vault.add(Entry("github", username="old", password="old"))
        vault.update("github", username="new", password="new")
        vault.save(_PWD)
        v2 = Vault.open(_PWD, vault_dir)
        e = v2.get("github")
        assert e.username == "new"
        assert e.password == "new"

    def test_count(self, vault_with_entries):
        assert vault_with_entries.count == 3


# ── Persistance ───────────────────────────────────────────────────────────────

class TestVaultPersistence:

    def test_roundtrip_complet(self, vault_dir):
        """Init → add → save → open → get : les données survivent."""
        v = Vault.init(_PWD, vault_dir)
        v.add(Entry("github", username="user", password="s3cr3t",
                    url="https://github.com", tags=["dev"]))
        v.save(_PWD)

        v2 = Vault.open(_PWD, vault_dir)
        e = v2.get("github")
        assert e.username == "user"
        assert e.password == "s3cr3t"
        assert e.url == "https://github.com"
        assert "dev" in e.tags

    def test_multiple_sauvegardes(self, vault_dir):
        v = Vault.init(_PWD, vault_dir)
        for i in range(5):
            v.add(Entry(f"service{i}", password=f"pass{i}"))
            v.save(_PWD)

        v2 = Vault.open(_PWD, vault_dir)
        assert v2.count == 5
        for i in range(5):
            assert v2.get(f"service{i}").password == f"pass{i}"


# ── Recherche & Liste ─────────────────────────────────────────────────────────

class TestVaultSearch:

    def test_list_all_triee(self, vault_with_entries):
        entries = vault_with_entries.list_all()
        services = [e.service for e in entries]
        assert services == sorted(services)

    def test_list_par_tag(self, vault_with_entries):
        entries = vault_with_entries.list_all(tag="dev")
        assert len(entries) == 1
        assert entries[0].service == "github"

    def test_list_tag_perso(self, vault_with_entries):
        entries = vault_with_entries.list_all(tag="perso")
        assert len(entries) == 2

    def test_search_par_service(self, vault_with_entries):
        r = vault_with_entries.search("git")
        assert len(r) == 1
        assert r[0].service == "github"

    def test_search_par_username(self, vault_with_entries):
        r = vault_with_entries.search("user@gmail")
        assert len(r) == 1
        assert r[0].service == "gmail"

    def test_search_insensible_casse(self, vault_with_entries):
        r = vault_with_entries.search("GITHUB")
        assert len(r) == 1

    def test_search_aucun_resultat(self, vault_with_entries):
        r = vault_with_entries.search("xxxxxx")
        assert r == []


# ── Changement de mot de passe ────────────────────────────────────────────────

class TestVaultPasswd:

    def test_change_password(self, vault, vault_dir):
        vault.add(Entry("test", password="secret"))
        vault.save(_PWD)

        new_pwd = b"nouveau_mot_de_passe_cagoule"
        vault.change_password(_PWD, new_pwd)

        # L'ancien mot de passe ne fonctionne plus
        with pytest.raises(VaultAuthError):
            Vault.open(_PWD, vault_dir)

        # Le nouveau fonctionne
        v2 = Vault.open(new_pwd, vault_dir)
        assert v2.get("test").password == "secret"

    def test_change_password_ancien_incorrect(self, vault, vault_dir):
        vault.save(_PWD)
        with pytest.raises(VaultAuthError):
            vault.change_password(b"mauvais", b"nouveau")


# ── Export / Import ───────────────────────────────────────────────────────────

class TestVaultExportImport:

    def test_export_import_roundtrip(self, vault_with_entries, tmp_path):
        export_file = tmp_path / "export.json"
        vault_with_entries.export_json(export_file)

        # Nouveau coffre vide
        new_dir = tmp_path / "new_vault"
        v2 = Vault.init(b"pwd2", new_dir)
        imported, skipped = v2.import_json(export_file)

        assert imported == 3
        assert skipped == 0
        assert v2.count == 3

    def test_import_sans_ecrasement(self, vault_with_entries, tmp_path):
        export_file = tmp_path / "export.json"
        vault_with_entries.export_json(export_file)

        # Importer dans le même coffre (doublons)
        imported, skipped = vault_with_entries.import_json(export_file, overwrite=False)
        assert skipped == 3
        assert imported == 0

    def test_import_avec_ecrasement(self, vault_with_entries, tmp_path):
        # Modifier une entrée et réexporter
        vault_with_entries.update("github", password="newpass")
        export_file = tmp_path / "export.json"
        vault_with_entries.export_json(export_file)

        # Réimporter avec overwrite
        imported, skipped = vault_with_entries.import_json(export_file, overwrite=True)
        assert imported == 3

    def test_export_json_valide(self, vault_with_entries, tmp_path):
        export_file = tmp_path / "export.json"
        vault_with_entries.export_json(export_file)
        data = json.loads(export_file.read_text())
        assert "entries" in data
        assert len(data["entries"]) == 3
        assert "warning" in data  # avertissement mots de passe en clair


# ── Context manager ───────────────────────────────────────────────────────────

class TestVaultContextManager:

    def test_repr(self, vault):
        r = repr(vault)
        assert "Vault" in r
        assert "0 entrées" in r
