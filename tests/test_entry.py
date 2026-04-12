"""tests/test_entry.py — Tests du modèle Entry."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from cagoule_pass.entry import Entry


class TestEntry:

    def test_creation_minimal(self):
        e = Entry("github")
        assert e.service == "github"
        assert e.username == ""
        assert e.password == ""

    def test_service_normalise(self):
        e = Entry("  GitHub  ")
        assert e.service == "github"

    def test_service_vide_exc(self):
        with pytest.raises(ValueError):
            Entry("")
        with pytest.raises(ValueError):
            Entry("   ")

    def test_to_dict_from_dict(self):
        e = Entry("github", username="user", password="s3cr3t",
                  url="https://github.com", tags=["dev", "pro"])
        d = e.to_dict()
        e2 = Entry.from_dict(d)
        assert e2.service  == e.service
        assert e2.username == e.username
        assert e2.password == e.password
        assert e2.tags     == e.tags

    def test_update_champs(self):
        e = Entry("github", username="old", password="old")
        e.update(username="new", password="newpass")
        assert e.username == "new"
        assert e.password == "newpass"

    def test_update_champ_inconnu(self):
        e = Entry("github")
        with pytest.raises(ValueError):
            e.update(inconnu="valeur")

    def test_display_cache_password(self):
        e = Entry("github", password="secret123")
        display = e.display(show_password=False)
        assert "secret123" not in display
        assert "****" in display or "*" in display

    def test_display_montre_password(self):
        e = Entry("github", password="secret123")
        display = e.display(show_password=True)
        assert "secret123" in display

    def test_summary(self):
        e = Entry("github", username="user@example.com")
        s = e.summary()
        assert "github" in s
        assert "user@example.com" in s

    def test_timestamps_automatiques(self):
        e = Entry("test")
        assert e.created
        assert e.updated
        assert "T" in e.created  # format ISO 8601

    def test_update_rafraichit_timestamp(self):
        import time
        e = Entry("test")
        old = e.updated
        time.sleep(0.01)
        e.update(username="new")
        assert e.updated >= old
