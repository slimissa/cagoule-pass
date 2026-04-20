# tui/screens/edit_screen.py
from textual import on
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.app import ComposeResult
from textual.widgets import Button, Input, Label

from ...entry import Entry


class EditScreen(ModalScreen):
    """Écran d'édition d'une entrée existante."""

    CSS = """
    EditScreen {
        align: center middle;
    }
    #edit-box {
        width: 70;
        height: auto;
        border: round $primary;
        padding: 2 3;
        background: $surface;
    }
    #edit-title {
        text-style: bold;
        color: $primary;
        text-align: center;
        margin-bottom: 2;
    }
    .field-row {
        margin-bottom: 1;
    }
    .field-label {
        color: $text-muted;
        width: 12;
    }
    .field-input {
        width: 1fr;
    }
    #actions {
        margin-top: 2;
        height: auto;
    }
    """

    def __init__(self, entry, vault, master_password: bytes) -> None:
        super().__init__()
        self.entry = entry
        self.vault = vault
        self.master_password = master_password

    def compose(self) -> ComposeResult:
        e = self.entry
        with Container(id="edit-box"):
            yield Label(f"✏️  Modifier {e.service}", id="edit-title")

            # Username
            with Horizontal(classes="field-row"):
                yield Label("Username", classes="field-label")
                yield Input(e.username, id="input-username", classes="field-input")

            # Password
            with Horizontal(classes="field-row"):
                yield Label("Password", classes="field-label")
                yield Input(e.password, password=True, id="input-password", classes="field-input")

            # URL
            with Horizontal(classes="field-row"):
                yield Label("URL", classes="field-label")
                yield Input(e.url, id="input-url", classes="field-input")

            # Tags
            with Horizontal(classes="field-row"):
                yield Label("Tags", classes="field-label")
                yield Input(", ".join(e.tags), id="input-tags", classes="field-input")

            # Notes
            with Horizontal(classes="field-row"):
                yield Label("Notes", classes="field-label")
                yield Input(e.notes, id="input-notes", classes="field-input")

            # Actions
            with Horizontal(id="actions"):
                yield Button("💾 Enregistrer", variant="primary", id="btn-save")
                yield Button("✕ Annuler", variant="error", id="btn-cancel")

    @on(Button.Pressed, "#btn-save")
    def save(self) -> None:
        """Enregistre les modifications."""
        changes = {
            "username": self.query_one("#input-username", Input).value,
            "password": self.query_one("#input-password", Input).value,
            "url": self.query_one("#input-url", Input).value,
            "tags": [t.strip() for t in self.query_one("#input-tags", Input).value.split(",") if t.strip()],
            "notes": self.query_one("#input-notes", Input).value,
        }
        try:
            self.vault.update(self.entry.service, **changes)
            self.vault.save(self.master_password)
            self.notify(f"Entrée '{self.entry.service}' modifiée", title="Succès")
            self.dismiss(True)
        except Exception as e:
            self.notify(str(e), severity="error")

    @on(Button.Pressed, "#btn-cancel")
    def cancel(self) -> None:
        self.dismiss(False)