# tui/screens/delete_screen.py
from textual import on
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.app import ComposeResult
from textual.widgets import Button, Label


class DeleteScreen(ModalScreen):
    """Écran de confirmation de suppression."""

    CSS = """
    DeleteScreen {
        align: center middle;
    }
    #delete-box {
        width: 40;
        height: auto;
        border: round $error;
        padding: 2 3;
        background: $surface;
    }
    #delete-title {
        text-align: center;
        color: $error;
        margin-bottom: 1;
    }
    #delete-message {
        text-align: center;
        margin-bottom: 2;
    }
    #delete-actions {
        height: auto;
    }
    """

    def __init__(self, entry) -> None:
        super().__init__()
        self.entry = entry

    def compose(self) -> ComposeResult:
        with Container(id="delete-box"):
            yield Label("⚠️  Supprimer l'entrée", id="delete-title")
            yield Label(f"'{self.entry.service}' sera supprimé définitivement.", id="delete-message")
            with Horizontal(id="delete-actions"):
                yield Button("🗑️ Supprimer", variant="error", id="btn-confirm")
                yield Button("Annuler", variant="default", id="btn-cancel")

    @on(Button.Pressed, "#btn-confirm")
    def confirm(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#btn-cancel")
    def cancel(self) -> None:
        self.dismiss(False)