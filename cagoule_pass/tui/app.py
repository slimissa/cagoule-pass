"""
tui/app.py — Interface TUI cagoule-pass v1.5 (Textual).

Screens :
    UnlockScreen  — saisie du mot de passe maître
    MainScreen    — liste des entrées + recherche + navigation
    EntryScreen   — détail d'une entrée (TOTP live, SSH keys, copy)

Lancement :
    cagoule-pass tui
    cagoule-pass tui --dir /chemin/vault
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label,
    ProgressBar, Static,
)
from textual.reactive import reactive

# Imports des nouveaux écrans
from .screens import AddScreen, DeleteScreen, EditScreen, QRCodeScreen
from .widgets import TOTPWidget


# ─── UnlockScreen ─────────────────────────────────────────────────────────────

class UnlockScreen(Screen):
    """Écran de déverrouillage — saisie du mot de passe maître."""

    CSS = """
    UnlockScreen {
        align: center middle;
    }
    #unlock-box {
        width: 50;
        height: auto;
        border: round $primary;
        padding: 2 3;
        background: $surface;
    }
    #unlock-title {
        text-align: center;
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
    }
    #unlock-subtitle {
        text-align: center;
        color: $text-muted;
        margin-bottom: 2;
    }
    #unlock-input {
        margin-bottom: 1;
    }
    #unlock-error {
        color: $error;
        text-align: center;
        height: 1;
    }
    #unlock-btn {
        width: 100%;
        margin-top: 1;
    }
    """

    def __init__(self, vault_dir: Path) -> None:
        super().__init__()
        self.vault_dir = vault_dir

    def compose(self) -> ComposeResult:
        with Container(id="unlock-box"):
            yield Label("🔐  cagoule-pass", id="unlock-title")
            yield Label(str(self.vault_dir), id="unlock-subtitle")
            yield Input(
                placeholder="Mot de passe maître",
                password=True,
                id="unlock-input",
            )
            yield Label("", id="unlock-error")
            yield Button("Déverrouiller", variant="primary", id="unlock-btn")

    def on_mount(self) -> None:
        self.query_one("#unlock-input", Input).focus()

    @on(Button.Pressed, "#unlock-btn")
    def on_unlock(self) -> None:
        self._try_unlock()

    @on(Input.Submitted, "#unlock-input")
    def on_enter(self) -> None:
        self._try_unlock()

    def _try_unlock(self) -> None:
        pwd_input = self.query_one("#unlock-input", Input)
        error_lbl = self.query_one("#unlock-error", Label)

        password = pwd_input.value.strip()
        if not password:
            error_lbl.update("Le mot de passe ne peut pas être vide.")
            return

        try:
            from ..vault import Vault
            vault = Vault.open(password.encode("utf-8"), self.vault_dir)
            self.app.dismiss_unlock(vault, password.encode("utf-8"))
        except Exception as exc:
            err_name = type(exc).__name__
            if "Auth" in err_name or "auth" in str(exc).lower():
                error_lbl.update("Mot de passe incorrect.")
            elif "NotFound" in err_name:
                error_lbl.update(f"Aucun coffre dans {self.vault_dir}")
            else:
                error_lbl.update(f"Erreur : {exc}")
            pwd_input.value = ""
            pwd_input.focus()


# ─── EntryScreen ──────────────────────────────────────────────────────────────

class EntryScreen(ModalScreen):
    """Écran de détail d'une entrée."""

    BINDINGS = [
        Binding("escape", "dismiss", "Fermer"),
        Binding("c", "copy_password", "Copier mdp"),
        Binding("t", "copy_totp", "Copier TOTP"),
    ]

    CSS = """
    EntryScreen {
        align: center middle;
    }
    #entry-box {
        width: 70;
        height: auto;
        max-height: 90vh;
        border: round $primary;
        padding: 2 3;
        background: $surface;
        overflow-y: auto;
    }
    #entry-title {
        text-style: bold;
        color: $primary;
        text-align: center;
        margin-bottom: 1;
    }
    .entry-row {
        height: 1;
        margin-bottom: 1;
    }
    .row-label {
        color: $text-muted;
        width: 12;
    }
    .row-value {
        color: $text;
    }
    #entry-actions {
        margin-top: 2;
        height: auto;
    }
    """

    def __init__(self, entry, master_password: bytes) -> None:
        super().__init__()
        self.entry = entry
        self.master_password = master_password

    def compose(self) -> ComposeResult:
        e = self.entry
        with Container(id="entry-box"):
            yield Label(f"🔑  {e.service.upper()}", id="entry-title")

            if e.username:
                with Horizontal(classes="entry-row"):
                    yield Label("Username", classes="row-label")
                    yield Label(e.username, classes="row-value")

            if e.password:
                with Horizontal(classes="entry-row"):
                    yield Label("Password", classes="row-label")
                    yield Label("••••••••", classes="row-value", id="pwd-display")

            if e.url:
                with Horizontal(classes="entry-row"):
                    yield Label("URL", classes="row-label")
                    yield Label(e.url, classes="row-value")

            if e.notes:
                with Horizontal(classes="entry-row"):
                    yield Label("Notes", classes="row-label")
                    yield Label(e.notes, classes="row-value")

            if e.tags:
                with Horizontal(classes="entry-row"):
                    yield Label("Tags", classes="row-label")
                    yield Label(", ".join(e.tags), classes="row-value")

            # TOTP live widget
            if e.has_totp:
                yield TOTPWidget(e.totp_entry)

            # SSH key info
            if e.has_ssh_key:
                k = e.ssh_key_pair
                with Container():
                    yield Label(f"🔐 SSH  {k.algorithm}  |  {k.fingerprint[:40]}...")
                    yield Label(f"   {k.public_key_openssh[:60]}...", classes="row-value")

            # Actions
            with Horizontal(id="entry-actions"):
                if e.password:
                    yield Button("📋 Copier mdp", id="btn-copy-pwd", variant="primary")
                if e.has_totp:
                    yield Button("📋 Copier TOTP", id="btn-copy-totp", variant="default")
                if e.has_ssh_key:
                    yield Button("💾 Exporter SSH", id="btn-export-ssh", variant="default")
                yield Button("✕ Fermer", id="btn-close", variant="error")

    @on(Button.Pressed, "#btn-copy-pwd")
    def copy_password(self) -> None:
        self._copy_to_clipboard(self.entry.password, "Mot de passe copié !")

    @on(Button.Pressed, "#btn-copy-totp")
    def copy_totp(self) -> None:
        from ..totp import generate_code
        code = generate_code(self.entry.totp_entry)
        self._copy_to_clipboard(code, f"Code TOTP copié : {code}")

    @on(Button.Pressed, "#btn-export-ssh")
    def export_ssh(self) -> None:
        try:
            priv, pub = self.entry.ssh_key_pair.export_to_files()
            self.notify(f"Clé exportée : {priv}", title="SSH exportée")
        except Exception as e:
            self.notify(str(e), title="Erreur SSH", severity="error")

    @on(Button.Pressed, "#btn-close")
    def close(self) -> None:
        self.dismiss()

    def action_dismiss(self) -> None:
        self.dismiss()

    def _copy_to_clipboard(self, text: str, msg: str) -> None:
        import subprocess
        for cmd in [["xclip", "-selection", "clipboard"],
                    ["xsel", "--clipboard", "--input"],
                    ["wl-copy"], ["pbcopy"]]:
            try:
                p = subprocess.Popen(
                    cmd, stdin=subprocess.PIPE, stderr=subprocess.DEVNULL
                )
                p.communicate(text.encode("utf-8"))
                if p.returncode == 0:
                    self.notify(msg, title="Copié")
                    return
            except FileNotFoundError:
                continue
        self.notify("Presse-papier non disponible", title="Erreur", severity="warning")


# ─── MainScreen ───────────────────────────────────────────────────────────────

class MainScreen(Screen):
    """Écran principal — liste + recherche des entrées."""

    BINDINGS = [
        Binding("q", "quit", "Quitter", priority=True),
        Binding("n", "new_entry", "Nouvelle entrée"),
        Binding("e", "edit_entry", "Modifier"),
        Binding("d", "delete_entry", "Supprimer"),
        Binding("r", "refresh", "Rafraîchir"),
        Binding("/", "focus_search", "Rechercher"),
        Binding("escape", "clear_search", "Effacer recherche"),
        Binding("enter", "open_entry", "Ouvrir"),
        Binding("t", "show_totp_qr", "QR TOTP"),
        Binding("?", "help", "Aide"),
    ]

    CSS = """
    MainScreen {
        layout: vertical;
    }
    #toolbar {
        height: 3;
        padding: 0 2;
        background: $surface;
        border-bottom: solid $border;
    }
    #search-input {
        width: 40;
    }
    #vault-stats {
        color: $text-muted;
        margin-left: 2;
        content-align: left middle;
    }
    #entries-table {
        height: 1fr;
    }
    """

    def __init__(self, vault, master_password: bytes, vault_dir: Path) -> None:
        super().__init__()
        self.vault = vault
        self.master_password = master_password
        self.vault_dir = vault_dir
        self._all_entries: list = []
        self._filtered_entries: list = []
        self._current_delete_entry = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="toolbar"):
            yield Input(
                placeholder="/ Rechercher...",
                id="search-input",
            )
            yield Label("", id="vault-stats")
        yield DataTable(id="entries-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self._setup_table()
        self._load_entries()

    def _setup_table(self) -> None:
        table = self.query_one("#entries-table", DataTable)
        table.add_columns("Service", "Username", "URL", "2FA", "SSH", "Tags")

    def _load_entries(self, query: str = "") -> None:
        table = self.query_one("#entries-table", DataTable)
        table.clear()

        if query:
            entries = self.vault.search(query)
        else:
            entries = self.vault.list_all()

        self._filtered_entries = entries

        for e in entries:
            table.add_row(
                e.service,
                e.username or "—",
                (e.url[:30] + "...") if len(e.url) > 30 else (e.url or "—"),
                "✓" if e.has_totp else "—",
                "✓" if e.has_ssh_key else "—",
                ", ".join(e.tags) if e.tags else "—",
                key=e.service,
            )

        count = len(entries)
        total = self.vault.count
        self.query_one("#vault-stats", Label).update(
            f"  {count} / {total} entrée(s)"
            + (f"  •  Recherche : '{query}'" if query else "")
        )

    @on(Input.Changed, "#search-input")
    def on_search(self, event: Input.Changed) -> None:
        self._load_entries(event.value.strip())

    @on(DataTable.RowSelected, "#entries-table")
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key and self._filtered_entries:
            service = str(event.row_key.value)
            entry = next((e for e in self._filtered_entries if e.service == service), None)
            if entry:
                self.app.push_screen(EntryScreen(entry, self.master_password))

    def action_focus_search(self) -> None:
        self.query_one("#search-input", Input).focus()

    def action_clear_search(self) -> None:
        inp = self.query_one("#search-input", Input)
        inp.value = ""
        self._load_entries()
        self.query_one("#entries-table", DataTable).focus()

    def action_open_entry(self) -> None:
        table = self.query_one("#entries-table", DataTable)
        if table.cursor_row is not None and self._filtered_entries:
            entry = self._filtered_entries[table.cursor_row]
            self.app.push_screen(EntryScreen(entry, self.master_password))

    def action_refresh(self) -> None:
        from ..vault import Vault
        self.vault = Vault.open(self.master_password, self.vault_dir)
        self._load_entries()
        self.notify("Coffre rechargé", title="Rafraîchi")

    def action_new_entry(self) -> None:
        """Ouvre l'écran d'ajout."""
        self.app.push_screen(AddScreen(self.vault, self.master_password, self.vault_dir))

    def action_edit_entry(self) -> None:
        """Ouvre l'écran d'édition."""
        table = self.query_one("#entries-table", DataTable)
        if table.cursor_row is not None and self._filtered_entries:
            entry = self._filtered_entries[table.cursor_row]
            self.app.push_screen(EditScreen(entry, self.vault, self.master_password), self._refresh_after_edit)

    def _refresh_after_edit(self, saved: bool) -> None:
        """Callback après édition."""
        if saved:
            self._load_entries()

    def action_delete_entry(self) -> None:
        """Supprime l'entrée sélectionnée après confirmation."""
        table = self.query_one("#entries-table", DataTable)
        if table.cursor_row is not None and self._filtered_entries:
            self._current_delete_entry = self._filtered_entries[table.cursor_row]
            self.app.push_screen(DeleteScreen(self._current_delete_entry), self._confirm_delete)

    def _confirm_delete(self, confirmed: bool) -> None:
        """Callback après confirmation de suppression."""
        if confirmed and self._current_delete_entry is not None:
            entry = self._current_delete_entry
            try:
                self.vault.remove(entry.service)
                self.vault.save(self.master_password)
                self._load_entries()
                self.notify(f"Entrée '{entry.service}' supprimée", title="Succès")
            except Exception as e:
                self.notify(str(e), severity="error")
            self._current_delete_entry = None

    def action_show_totp_qr(self) -> None:
        """Affiche le QR code TOTP pour l'entrée sélectionnée."""
        table = self.query_one("#entries-table", DataTable)
        if table.cursor_row is not None and self._filtered_entries:
            entry = self._filtered_entries[table.cursor_row]
            if entry.has_totp:
                self.app.push_screen(QRCodeScreen(entry.totp_entry))
            else:
                self.notify("Cette entrée n'a pas de 2FA configuré", severity="warning")

    def action_help(self) -> None:
        self.notify(
            "/ : rechercher  •  Enter : ouvrir  •  n : nouvelle  •  e : éditer  •  d : supprimer  •  t : QR TOTP  •  q : quitter",
            title="Raccourcis",
            timeout=5,
        )

    def action_quit(self) -> None:
        self.app.exit()


# ─── Application principale ───────────────────────────────────────────────────

class CagoulePassApp(App):
    """Application TUI cagoule-pass."""

    TITLE = "cagoule-pass"
    SUB_TITLE = "Gestionnaire de mots de passe"

    CSS = """
    App {
        background: $background;
    }
    """

    def __init__(self, vault_dir: Path) -> None:
        super().__init__()
        self.vault_dir = vault_dir
        self._vault = None
        self._master_password: Optional[bytes] = None

    def on_mount(self) -> None:
        self.push_screen(UnlockScreen(self.vault_dir))

    def dismiss_unlock(self, vault, master_password: bytes) -> None:
        """Callback appelé par UnlockScreen après authentification réussie."""
        self._vault = vault
        self._master_password = master_password
        self.pop_screen()
        self.push_screen(
            MainScreen(vault, master_password, self.vault_dir)
        )


def launch_tui(vault_dir: Path) -> None:
    """Point d'entrée pour lancer la TUI."""
    app = CagoulePassApp(vault_dir=vault_dir)
    app.run()