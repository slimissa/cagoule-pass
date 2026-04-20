"""totp_widget.py — Widget TOTP live pour l'interface TUI."""

from textual.reactive import reactive
from textual.widgets import Static, Label, ProgressBar
from textual.app import ComposeResult


class TOTPWidget(Static):
    """
    Widget live pour l'affichage du code TOTP avec barre de progression.
    Se met à jour chaque seconde.
    """

    CSS = """
    TOTPWidget {
        border: round $accent;
        padding: 1 2;
        margin-top: 1;
        height: auto;
    }
    #totp-label {
        color: $text-muted;
    }
    #totp-code {
        text-style: bold;
        font-size: 5;
        color: $primary;
        text-align: center;
    }
    #totp-code.danger {
        color: $error;
    }
    #totp-progress {
        margin-top: 1;
    }
    """

    code = reactive("------")
    seconds = reactive(30)
    progress = reactive(1.0)

    def __init__(self, totp_entry) -> None:
        super().__init__()
        self.totp_entry = totp_entry

    def compose(self) -> ComposeResult:
        yield Label("Code TOTP (2FA)", id="totp-label")
        yield Label(self.code, id="totp-code")
        yield ProgressBar(
            total=self.totp_entry.period,
            show_eta=False,
            id="totp-progress"
        )

    def on_mount(self) -> None:
        self._refresh_code()
        self.set_interval(1.0, self._refresh_code)

    def _refresh_code(self) -> None:
        from ....totp import generate_code, time_remaining

        self.code = generate_code(self.totp_entry)
        remaining = time_remaining(self.totp_entry)
        self.seconds = remaining

        pb = self.query_one("#totp-progress", ProgressBar)
        pb.update(progress=remaining)

        code_lbl = self.query_one("#totp-code", Label)
        code_lbl.update(f"{self.code[:3]} {self.code[3:]}")

        if remaining <= 5:
            code_lbl.add_class("danger")
        else:
            code_lbl.remove_class("danger")
