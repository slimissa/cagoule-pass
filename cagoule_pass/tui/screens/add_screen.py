# tui/screens/add_screen.py
from textual import on
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Switch, TabbedContent, TabPane

from ...entry import Entry
from ...generator import generate, entropy_bits, strength
from ...totp import TOTPEntry, generate_secret
from ...ssh import SSHKeyPair


class AddScreen(ModalScreen):
    """Écran d'ajout d'une nouvelle entrée."""

    BINDINGS = [
        Binding("escape", "dismiss", "Annuler"),
        Binding("ctrl+s", "submit", "Enregistrer"),
    ]

    CSS = """
    AddScreen {
        align: center middle;
    }
    #add-box {
        width: 70;
        height: auto;
        max-height: 90vh;
        border: round $primary;
        padding: 2 3;
        background: $surface;
        overflow-y: auto;
    }
    #add-title {
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
        width: 14;
    }
    .field-input {
        width: 1fr;
    }
    .field-hint {
        color: $text-muted;
        text-style: italic;
        margin-left: 14;
        height: 1;
    }
    #actions {
        margin-top: 2;
        height: auto;
    }
    """

    def __init__(self, vault, master_password: bytes, vault_dir) -> None:
        super().__init__()
        self.vault = vault
        self.master_password = master_password
        self.vault_dir = vault_dir

    def compose(self) -> ComposeResult:
        with Container(id="add-box"):
            yield Label("➕  Nouvelle entrée", id="add-title")

            # Service (obligatoire)
            with Horizontal(classes="field-row"):
                yield Label("Service *", classes="field-label")
                yield Input(placeholder="github, gmail, aws...", id="input-service", classes="field-input")
            yield Label("Nom du service (obligatoire)", classes="field-hint")

            # Username
            with Horizontal(classes="field-row"):
                yield Label("Username", classes="field-label")
                yield Input(placeholder="Identifiant de connexion", id="input-username", classes="field-input")

            # Password
            with Horizontal(classes="field-row"):
                yield Label("Password", classes="field-label")
                yield Input(placeholder="Mot de passe", password=True, id="input-password", classes="field-input")
            with Horizontal(id="password-actions"):
                yield Button("🔑 Générer", id="btn-generate-pwd", variant="default")
                yield Button("👁️ Afficher", id="btn-toggle-pwd", variant="default")

            # URL
            with Horizontal(classes="field-row"):
                yield Label("URL", classes="field-label")
                yield Input(placeholder="https://...", id="input-url", classes="field-input")

            # Tags
            with Horizontal(classes="field-row"):
                yield Label("Tags", classes="field-label")
                yield Input(placeholder="dev, pro, personal", id="input-tags", classes="field-input")

            # Notes
            with Horizontal(classes="field-row"):
                yield Label("Notes", classes="field-label")
                yield Input(placeholder="Informations complémentaires", id="input-notes", classes="field-input")

            # Section TOTP
            with TabbedContent(initial="totp-no"):
                with TabPane("🔐 2FA (optionnel)", id="totp-tab"):
                    with Horizontal():
                        yield Button("🎲 Générer secret", id="btn-gen-totp", variant="default")
                        yield Button("📋 Importer QR", id="btn-import-qr", variant="default")
                    yield Input(placeholder="Secret Base32 (JBSWY3DPEHP...)", id="input-totp-secret")
                    yield Label("Laissez vide pour désactiver le 2FA", classes="field-hint")

            # Section SSH
            with TabbedContent(initial="ssh-no"):
                with TabPane("🔑 Clé SSH (optionnel)", id="ssh-tab"):
                    with Horizontal():
                        yield Select(
                            [("Ed25519 (recommandé)", "Ed25519"), ("RSA-4096", "RSA-4096")],
                            prompt="Algorithme",
                            id="select-ssh-algo",
                        )
                        yield Button("🎲 Générer", id="btn-gen-ssh", variant="default")
                        yield Button("📂 Importer", id="btn-import-ssh", variant="default")

            # Actions
            with Horizontal(id="actions"):
                yield Button("💾 Enregistrer", variant="primary", id="btn-save")
                yield Button("✕ Annuler", variant="error", id="btn-cancel")

    @on(Button.Pressed, "#btn-generate-pwd")
    def generate_password(self) -> None:
        """Génère un mot de passe sécurisé."""
        pwd = generate(length=20, use_symbols=True)
        self.query_one("#input-password", Input).value = pwd
        self.notify(f"Mot de passe généré : {pwd[:4]}...{pwd[-4:]}", title="Généré")

    @on(Button.Pressed, "#btn-toggle-pwd")
    def toggle_password_visibility(self) -> None:
        """Affiche/masque le mot de passe."""
        pwd_input = self.query_one("#input-password", Input)
        pwd_input.password = not pwd_input.password

    @on(Button.Pressed, "#btn-gen-totp")
    def generate_totp_secret(self) -> None:
        """Génère un secret TOTP aléatoire."""
        secret = generate_secret()
        self.query_one("#input-totp-secret", Input).value = secret
        self.notify(f"Secret TOTP généré : {secret[:8]}...", title="TOTP")

    @on(Button.Pressed, "#btn-import-qr")
    def import_qr(self) -> None:
        """Importe un secret depuis QR code (simulé)."""
        self.notify("Scannez le QR code avec votre terminal", title="QR Code")
        # Implémentation réelle : afficher un champ pour coller l'URI otpauth://

    @on(Button.Pressed, "#btn-gen-ssh")
    def generate_ssh(self) -> None:
        """Génère une paire de clés SSH."""
        algo = self.query_one("#select-ssh-algo", Select).value
        if not algo:
            algo = "Ed25519"
        pair = SSHKeyPair.generate(algo, comment="cagoule-pass")
        self._temp_ssh_pair = pair
        self.notify(f"Clé SSH {algo} générée", title="SSH")

    @on(Button.Pressed, "#btn-import-ssh")
    def import_ssh(self) -> None:
        """Importe une clé SSH depuis un fichier."""
        self.notify("Placez le chemin de la clé privée", title="Import SSH")
        # Implémentation réelle : modal avec champ de chemin

    @on(Button.Pressed, "#btn-save")
    def save_entry(self) -> None:
        """Enregistre la nouvelle entrée."""
        service = self.query_one("#input-service", Input).value.strip().lower()
        if not service:
            self.notify("Le service est obligatoire", severity="error")
            return

        # Construction de l'entrée
        entry = Entry(
            service=service,
            username=self.query_one("#input-username", Input).value,
            password=self.query_one("#input-password", Input).value,
            url=self.query_one("#input-url", Input).value,
            tags=[t.strip() for t in self.query_one("#input-tags", Input).value.split(",") if t.strip()],
            notes=self.query_one("#input-notes", Input).value,
        )

        # Ajout TOTP si présent
        totp_secret = self.query_one("#input-totp-secret", Input).value.strip()
        if totp_secret:
            totp = TOTPEntry(secret=totp_secret, issuer=service)
            entry.totp = totp.to_dict()

        # Ajout SSH si généré/importé
        if hasattr(self, "_temp_ssh_pair"):
            entry.ssh_key = self._temp_ssh_pair.to_dict()

        try:
            self.vault.add(entry)
            self.vault.save(self.master_password)
            self.notify(f"Entrée '{service}' ajoutée", title="Succès")
            self.dismiss()
        except Exception as e:
            self.notify(str(e), severity="error")

    @on(Button.Pressed, "#btn-cancel")
    def cancel(self) -> None:
        self.dismiss()