# tui/screens/qrcode_screen.py
from textual import on
from textual.containers import Center, Container
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static


class QRCodeScreen(ModalScreen):
    """Affichage d'un QR code pour TOTP."""

    CSS = """
    QRCodeScreen {
        align: center middle;
    }
    #qrcode-box {
        width: 40;
        height: auto;
        border: round $primary;
        padding: 2 3;
        background: $surface;
    }
    #qrcode-title {
        text-align: center;
        text-style: bold;
        margin-bottom: 2;
    }
    #qrcode-display {
        height: auto;
        text-align: center;
        margin-bottom: 2;
    }
    #qrcode-secret {
        color: $text-muted;
        text-align: center;
        margin-bottom: 2;
    }
    """

    def __init__(self, totp_entry) -> None:
        super().__init__()
        self.totp_entry = totp_entry

    def compose(self) -> ComposeResult:
        uri = self.totp_entry.to_uri()
        # Simulation d'un QR code en ASCII (avec segno on aurait une image)
        qr_ascii = self._generate_ascii_qr(uri)

        with Container(id="qrcode-box"):
            yield Label("📱  Scannez ce QR code", id="qrcode-title")
            yield Static(qr_ascii, id="qrcode-display")
            yield Label(f"Secret : {self.totp_entry.secret}", id="qrcode-secret")
            yield Button("Fermer", variant="primary", id="btn-close")

    def _generate_ascii_qr(self, uri: str) -> str:
        """Génère une représentation ASCII du QR code."""
        try:
            import segno
            qr = segno.make(uri)
            return qr.to_str()  # ASCII art
        except ImportError:
            return "[Installez 'segno' pour afficher le QR code]"

    @on(Button.Pressed, "#btn-close")
    def close(self) -> None:
        self.dismiss()