"""
cli.py — Interface ligne de commande cagoule-pass v1.2.

Nouveautés v1.2 :
    - Option --version / -V
    - Auto-effacement presse-papier (configurable via TOML)
    - Chargement config.toml (~/.cagoule-pass/config.toml)

Commandes :
    cagoule-pass init                          Créer un nouveau coffre
    cagoule-pass add <service>                 Ajouter une entrée
    cagoule-pass get <service>                 Afficher une entrée
    cagoule-pass copy <service>                Copier le mot de passe
    cagoule-pass list [--tag <tag>]            Lister les entrées
    cagoule-pass search <query>                Rechercher
    cagoule-pass edit <service>                Modifier une entrée
    cagoule-pass remove <service>              Supprimer une entrée
    cagoule-pass generate                      Générer un mot de passe
    cagoule-pass passwd                        Changer le mot de passe maître
    cagoule-pass export <fichier>              Exporter en JSON
    cagoule-pass import <fichier>              Importer depuis JSON
    cagoule-pass info                          Infos sur le coffre
    cagoule-pass config                        Afficher la configuration active
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from .__version__ import __version__
from .config import CagouleConfig
from .entry import Entry
from .generator import generate, entropy_bits, strength
from .vault import (
    Vault, DEFAULT_VAULT_DIR,
    VaultError, VaultNotFoundError, VaultAuthError,
    VaultCorruptError, EntryNotFoundError, EntryExistsError,
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _err(msg: str) -> None:
    print(f"  ✗  {msg}", file=sys.stderr)

def _ok(msg: str) -> None:
    print(f"  ✓  {msg}")

def _info(msg: str) -> None:
    print(f"  •  {msg}")

def _sep(char: str = "─", n: int = 55) -> None:
    print(char * n)

def _get_password(prompt: str = "Mot de passe maître : ") -> bytes:
    try:
        pwd = getpass.getpass(prompt)
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(130)
    if not pwd:
        _err("Le mot de passe ne peut pas être vide.")
        sys.exit(1)
    return pwd.encode("utf-8")

def _get_password_confirmed(prompt: str = "Mot de passe maître : ") -> bytes:
    pwd1 = _get_password(prompt)
    pwd2 = _get_password("Confirmer : ")
    if pwd1 != pwd2:
        _err("Les mots de passe ne correspondent pas.")
        sys.exit(1)
    return pwd1

def _open_vault(vault_dir: Path) -> tuple[Vault, bytes]:
    password = _get_password()
    try:
        vault = Vault.open(password, vault_dir)
        return vault, password
    except VaultNotFoundError as e:
        _err(str(e))
        sys.exit(1)
    except VaultAuthError as e:
        _err(str(e))
        sys.exit(1)
    except VaultCorruptError as e:
        _err(str(e))
        sys.exit(1)


# ─── Presse-papier ────────────────────────────────────────────────────────────

def _clipboard_copy(text: str) -> bool:
    """Copie dans le presse-papier (cross-platform, best-effort)."""
    import subprocess
    try:
        # Linux (xclip ou xsel ou wl-copy)
        for cmd in [["xclip", "-selection", "clipboard"],
                    ["xsel", "--clipboard", "--input"],
                    ["wl-copy"]]:
            try:
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
                p.communicate(text.encode("utf-8"))
                if p.returncode == 0:
                    return True
            except FileNotFoundError:
                continue
        # macOS
        try:
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(text.encode("utf-8"))
            return p.returncode == 0
        except FileNotFoundError:
            pass
        # Windows
        try:
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE, shell=True)
            p.communicate(text.encode("utf-8"))
            return p.returncode == 0
        except Exception:
            pass
    except Exception:
        pass
    return False


def _schedule_clipboard_clear(delay_seconds: int) -> None:
    """
    Lance l'effacement du presse-papier après `delay_seconds` secondes.

    Utilise un thread daemon : le timer ne bloque pas la sortie du process
    et est annulé automatiquement si le process se termine avant l'expiration.
    """
    def _clear() -> None:
        time.sleep(delay_seconds)
        _clipboard_copy("")

    t = threading.Thread(target=_clear, daemon=True)
    t.start()
    # Attendre pour que le timer s'exécute même si main() se termine rapidement
    # On garde le process vivant via t.join() côté appelant si nécessaire
    return t


def _copy_with_autoclear(text: str, cfg: CagouleConfig, no_clear_flag: bool = False) -> bool:
    """
    Copie `text` dans le presse-papier, puis planifie l'auto-effacement.

    La priorité CLI (--no-clear) surpasse la config TOML.

    Returns:
        True si la copie a réussi.
    """
    if not _clipboard_copy(text):
        return False

    # Résolution des flags : CLI > config TOML
    skip_clear = no_clear_flag or cfg.clipboard.no_clear
    delay = cfg.clipboard.clear_after_seconds

    if not skip_clear and delay > 0:
        _info(f"Auto-effacement du presse-papier dans {delay}s.")
        t = _schedule_clipboard_clear(delay)
        t.join()  # Bloquer jusqu'à effacement pour que le process reste actif
    else:
        _info("Presse-papier non effacé automatiquement (--no-clear ou config).")

    return True


# ─── Commandes ────────────────────────────────────────────────────────────────

def cmd_init(args, cfg: CagouleConfig) -> int:
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir

    if (vault_dir / "vault.cgl1").exists():
        _err(f"Un coffre existe déjà dans {vault_dir}.")
        _info("Utilisez 'cagoule-pass info' pour voir son état.")
        return 1

    print(f"\n  Initialisation du coffre dans {vault_dir}")
    _sep()
    password = _get_password_confirmed("Choisissez un mot de passe maître : ")

    try:
        vault = Vault.init(password, vault_dir)
        _ok(f"Coffre créé : {vault.vault_path}")
        _info("Gardez votre mot de passe maître en lieu sûr — il est irrécupérable.")
    except VaultError as e:
        _err(str(e))
        return 1
    return 0


def cmd_add(args, cfg: CagouleConfig) -> int:
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, password = _open_vault(vault_dir)

    service = args.service.strip().lower()

    username = args.username or input("  Username (optionnel) : ").strip()
    url      = args.url      or input("  URL (optionnel) : ").strip()
    notes    = args.notes    or input("  Notes (optionnel) : ").strip()
    tags     = [t.strip() for t in (args.tags or "").split(",") if t.strip()]

    if args.password:
        pwd = args.password
    elif args.generate:
        # Appliquer les défauts de la config si non spécifiés en CLI
        length  = args.length   if args.length != 16 else cfg.generator.default_length
        symbols = args.symbols  or cfg.generator.use_symbols
        no_amb  = args.no_ambiguous or cfg.generator.no_ambiguous
        pwd = generate(
            length=length,
            use_upper=not args.no_upper,
            use_digits=not args.no_digits,
            use_symbols=symbols,
            no_ambiguous=no_amb,
        )
        print(f"  Mot de passe généré : {pwd}")
        print(f"  Entropie : {entropy_bits(pwd)} bits — {strength(pwd)}")
    else:
        pwd = getpass.getpass("  Mot de passe : ")
        if not pwd:
            _err("Le mot de passe ne peut pas être vide.")
            return 1

    try:
        entry = Entry(
            service=service, username=username,
            password=pwd, url=url, notes=notes, tags=tags,
        )
        vault.add(entry)
        vault.save(password)
        _ok(f"Entrée ajoutée : {service}")
    except EntryExistsError as e:
        _err(str(e))
        return 1
    return 0


def cmd_get(args, cfg: CagouleConfig) -> int:
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, _ = _open_vault(vault_dir)

    try:
        entry = vault.get(args.service)
    except EntryNotFoundError as e:
        _err(str(e))
        return 1

    print()
    _sep()
    print(entry.display(show_password=args.show))
    _sep()
    return 0


def cmd_copy(args, cfg: CagouleConfig) -> int:
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, _ = _open_vault(vault_dir)

    try:
        entry = vault.get(args.service)
    except EntryNotFoundError as e:
        _err(str(e))
        return 1

    text  = entry.username if args.username else entry.password
    label = "username" if args.username else "mot de passe"

    if not text:
        _err(f"Le champ '{label}' est vide pour {entry.service}.")
        return 1

    no_clear = getattr(args, "no_clear", False)

    if _copy_with_autoclear(text, cfg, no_clear_flag=no_clear):
        _ok(f"{label.capitalize()} de '{entry.service}' copié dans le presse-papier.")
    else:
        _err("Impossible d'accéder au presse-papier.")
        _info("Installez xclip, xsel ou wl-copy (Linux) pour cette fonctionnalité.")
        return 1
    return 0


def cmd_list(args, cfg: CagouleConfig) -> int:
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, _ = _open_vault(vault_dir)

    entries = vault.list_all(tag=args.tag)

    if not entries:
        _info("Le coffre est vide." if not args.tag else f"Aucune entrée avec le tag '{args.tag}'.")
        return 0

    print()
    _sep()
    print(f"  {'SERVICE':<20} {'USERNAME':<30} URL")
    _sep("·")
    for e in entries:
        print(e.summary())
    _sep()
    print(f"  {len(entries)} entrée(s)")
    return 0


def cmd_search(args, cfg: CagouleConfig) -> int:
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, _ = _open_vault(vault_dir)

    results = vault.search(args.query)

    if not results:
        _info(f"Aucun résultat pour '{args.query}'.")
        return 0

    print()
    _sep()
    print(f"  Résultats pour '{args.query}' :")
    _sep("·")
    for e in sorted(results, key=lambda x: x.service):
        print(e.summary())
    _sep()
    print(f"  {len(results)} résultat(s)")
    return 0


def cmd_edit(args, cfg: CagouleConfig) -> int:
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, password = _open_vault(vault_dir)

    try:
        entry = vault.get(args.service)
    except EntryNotFoundError as e:
        _err(str(e))
        return 1

    print()
    _sep()
    print(f"  Édition de : {entry.service}")
    print(f"  (Entrée vide = garder la valeur actuelle)")
    _sep("·")

    changes = {}

    if args.username is not None:
        changes["username"] = args.username
    else:
        val = input(f"  Username [{entry.username or '—'}] : ").strip()
        if val:
            changes["username"] = val

    if args.password:
        changes["password"] = args.password
    elif args.generate:
        pwd = generate(length=args.length, use_symbols=args.symbols)
        print(f"  Nouveau mot de passe généré : {pwd}")
        changes["password"] = pwd
    else:
        val = getpass.getpass(f"  Mot de passe [garder actuel] : ")
        if val:
            changes["password"] = val

    if args.url is not None:
        changes["url"] = args.url
    else:
        val = input(f"  URL [{entry.url or '—'}] : ").strip()
        if val:
            changes["url"] = val

    if args.notes is not None:
        changes["notes"] = args.notes
    else:
        val = input(f"  Notes [{entry.notes or '—'}] : ").strip()
        if val:
            changes["notes"] = val

    if not changes:
        _info("Aucune modification.")
        return 0

    try:
        vault.update(args.service, **changes)
        vault.save(password)
        _ok(f"Entrée '{args.service}' mise à jour ({', '.join(changes.keys())}).")
    except VaultError as e:
        _err(str(e))
        return 1
    return 0


def cmd_remove(args, cfg: CagouleConfig) -> int:
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, password = _open_vault(vault_dir)

    try:
        entry = vault.get(args.service)
    except EntryNotFoundError as e:
        _err(str(e))
        return 1

    if not args.yes:
        print(f"\n  Supprimer '{entry.service}' ({entry.username}) ?")
        confirm = input("  Confirmer [oui/N] : ").strip().lower()
        if confirm not in ("oui", "yes", "o", "y"):
            _info("Suppression annulée.")
            return 0

    try:
        vault.remove(args.service)
        vault.save(password)
        _ok(f"Entrée '{args.service}' supprimée.")
    except VaultError as e:
        _err(str(e))
        return 1
    return 0


def cmd_generate(args, cfg: CagouleConfig) -> int:
    # Priorité CLI > config TOML
    length  = args.length  if args.length != 16 else cfg.generator.default_length
    symbols = args.symbols or cfg.generator.use_symbols
    no_amb  = args.no_ambiguous or cfg.generator.no_ambiguous

    try:
        pwd = generate(
            length=length,
            use_upper=not args.no_upper,
            use_digits=not args.no_digits,
            use_symbols=symbols,
            no_ambiguous=no_amb,
        )
    except ValueError as e:
        _err(str(e))
        return 1

    bits = entropy_bits(pwd)
    qual = strength(pwd)

    print()
    print(f"  {pwd}")
    print()
    print(f"  Longueur  : {len(pwd)} caractères")
    print(f"  Entropie  : {bits} bits")
    print(f"  Force     : {qual}")

    if args.copy:
        no_clear = getattr(args, "no_clear", False)
        if _copy_with_autoclear(pwd, cfg, no_clear_flag=no_clear):
            _ok("Copié dans le presse-papier.")
        else:
            _err("Presse-papier non disponible.")
    return 0


def cmd_passwd(args, cfg: CagouleConfig) -> int:
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir

    print("\n  Changement du mot de passe maître")
    _sep()
    old_password = _get_password("Ancien mot de passe : ")

    try:
        vault = Vault.open(old_password, vault_dir)
    except VaultAuthError:
        _err("Ancien mot de passe incorrect.")
        return 1
    except VaultNotFoundError as e:
        _err(str(e))
        return 1

    new_password = _get_password_confirmed("Nouveau mot de passe maître : ")

    try:
        vault.save(new_password)
        _ok("Mot de passe maître changé avec succès.")
    except Exception as e:
        _err(f"Erreur lors du rechiffrement : {e}")
        return 1
    return 0


def cmd_export(args, cfg: CagouleConfig) -> int:
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, _ = _open_vault(vault_dir)

    out = Path(args.output)
    if out.exists() and not args.force:
        _err(f"Le fichier {out} existe déjà. Utilisez --force pour écraser.")
        return 1

    if not args.no_warning:
        print("\n  ⚠  ATTENTION : l'export contient les mots de passe en CLAIR.")
        confirm = input("  Continuer ? [oui/N] : ").strip().lower()
        if confirm not in ("oui", "yes", "o", "y"):
            _info("Export annulé.")
            return 0

    try:
        vault.export_json(out, include_passwords=not args.no_passwords)
        _ok(f"Exporté vers {out} ({vault.count} entrée(s)).")
        if not args.no_passwords:
            _info("Protégez ce fichier — il contient vos mots de passe en clair.")
    except Exception as e:
        _err(f"Erreur d'export : {e}")
        return 1
    return 0


def cmd_import(args, cfg: CagouleConfig) -> int:
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, password = _open_vault(vault_dir)

    src = Path(args.input)
    if not src.exists():
        _err(f"Fichier introuvable : {src}")
        return 1

    try:
        imported, skipped = vault.import_json(src, overwrite=args.overwrite)
        vault.save(password)
        _ok(f"Import terminé : {imported} importée(s), {skipped} ignorée(s).")
        if skipped > 0:
            _info("Utilisez --overwrite pour écraser les entrées existantes.")
    except Exception as e:
        _err(f"Erreur d'import : {e}")
        return 1
    return 0


def cmd_info(args, cfg: CagouleConfig) -> int:
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault_path = vault_dir / "vault.cgl1"
    config_path = vault_dir / "config.json"

    print()
    _sep()
    print("  cagoule-pass — Informations du coffre")
    _sep("·")

    if not vault_path.exists():
        _info(f"Aucun coffre dans {vault_dir}")
        _info("Créez-en un avec : cagoule-pass init")
        return 0

    size = vault_path.stat().st_size
    print(f"  Dossier   : {vault_dir}")
    print(f"  Fichier   : {vault_path.name}")
    print(f"  Taille    : {size} octets")
    print(f"  Format    : CGL1 (chiffrement CAGOULE)")

    if config_path.exists():
        import json
        config = json.loads(config_path.read_text())
        print(f"  Créé le   : {config.get('created', '?')}")
        print(f"  Version   : {config.get('version', '?')}")

    _sep("·")
    _info("Utilisez 'cagoule-pass list' (avec mot de passe) pour voir les entrées.")
    _sep()
    return 0


def cmd_config(args, cfg: CagouleConfig) -> int:
    """Affiche la configuration active."""
    print()
    _sep()
    print("  cagoule-pass — Configuration active")
    _sep("·")

    source = cfg._source or CagouleConfig._default_path()
    print(f"  Fichier   : {source}")

    try:
        from .config import tomllib as _tl
        parser_info = "tomllib (stdlib)" if _tl is not None and _tl.__name__ == "tomllib" else \
                      "tomli (backport)" if _tl is not None else "⚠ absent (défauts uniquement)"
        print(f"  Parser    : {parser_info}")
    except Exception:
        pass

    _sep("·")
    print(f"  [vault]")
    print(f"    dir                    = {cfg.vault.dir}")
    print(f"  [clipboard]")
    print(f"    clear_after_seconds    = {cfg.clipboard.clear_after_seconds}")
    print(f"    no_clear               = {cfg.clipboard.no_clear}")
    print(f"    → auto-effacement actif: {cfg.clipboard.should_clear}")
    print(f"  [generator]")
    print(f"    default_length         = {cfg.generator.default_length}")
    print(f"    use_symbols            = {cfg.generator.use_symbols}")
    print(f"    no_ambiguous           = {cfg.generator.no_ambiguous}")
    _sep()
    return 0


# ─── Parser ───────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cagoule-pass",
        description="cagoule-pass — Gestionnaire de mots de passe chiffré avec CAGOULE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  cagoule-pass init\n"
            "  cagoule-pass add github -u monuser --generate\n"
            "  cagoule-pass get github --show\n"
            "  cagoule-pass copy github\n"
            "  cagoule-pass list\n"
            "  cagoule-pass generate --length 20 --symbols --copy\n"
        ),
    )

    # ── Option --version (feature v1.2) ───────────────────────────────────────
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Afficher la version et quitter"
    )

    parser.add_argument(
        "--dir", metavar="DOSSIER",
        help=f"Dossier du coffre (défaut depuis config TOML ou {DEFAULT_VAULT_DIR})"
    )
    parser.add_argument(
        "--config", metavar="FICHIER",
        help="Chemin du fichier de configuration TOML"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── init ──────────────────────────────────────────────────────────────────
    sub.add_parser("init", help="Créer un nouveau coffre chiffré")

    # ── add ───────────────────────────────────────────────────────────────────
    p_add = sub.add_parser("add", help="Ajouter une entrée")
    p_add.add_argument("service", help="Nom du service (ex: github)")
    p_add.add_argument("-u", "--username", default="", help="Identifiant")
    p_add.add_argument("-p", "--password", default="", help="Mot de passe (déconseillé en CLI)")
    p_add.add_argument("--url",   default="", help="URL associée")
    p_add.add_argument("--notes", default="", help="Notes libres")
    p_add.add_argument("--tags",  default="", help="Tags séparés par virgule")
    p_add.add_argument("-g", "--generate", action="store_true", help="Générer le mot de passe")
    p_add.add_argument("-l", "--length", type=int, default=16, help="Longueur (avec --generate)")
    p_add.add_argument("--symbols",      action="store_true",  help="Inclure les symboles")
    p_add.add_argument("--no-upper",     action="store_true",  help="Sans majuscules")
    p_add.add_argument("--no-digits",    action="store_true",  help="Sans chiffres")
    p_add.add_argument("--no-ambiguous", action="store_true",  help="Sans caractères ambigus")

    # ── get ───────────────────────────────────────────────────────────────────
    p_get = sub.add_parser("get", help="Afficher une entrée")
    p_get.add_argument("service", help="Nom du service")
    p_get.add_argument("--show", action="store_true", help="Afficher le mot de passe en clair")

    # ── copy ──────────────────────────────────────────────────────────────────
    p_copy = sub.add_parser("copy", help="Copier le mot de passe dans le presse-papier")
    p_copy.add_argument("service", help="Nom du service")
    p_copy.add_argument("--username", action="store_true", help="Copier l'username au lieu du mot de passe")
    p_copy.add_argument("--no-clear", action="store_true", help="Ne pas effacer le presse-papier automatiquement")

    # ── list ──────────────────────────────────────────────────────────────────
    p_list = sub.add_parser("list", help="Lister les entrées")
    p_list.add_argument("--tag", help="Filtrer par tag")

    # ── search ────────────────────────────────────────────────────────────────
    p_search = sub.add_parser("search", help="Rechercher des entrées")
    p_search.add_argument("query", help="Terme de recherche")

    # ── edit ──────────────────────────────────────────────────────────────────
    p_edit = sub.add_parser("edit", help="Modifier une entrée existante")
    p_edit.add_argument("service", help="Nom du service")
    p_edit.add_argument("-u", "--username", default=None)
    p_edit.add_argument("-p", "--password", default="")
    p_edit.add_argument("--url",   default=None)
    p_edit.add_argument("--notes", default=None)
    p_edit.add_argument("-g", "--generate", action="store_true")
    p_edit.add_argument("-l", "--length", type=int, default=16)
    p_edit.add_argument("--symbols", action="store_true")

    # ── remove ────────────────────────────────────────────────────────────────
    p_rm = sub.add_parser("remove", help="Supprimer une entrée", aliases=["rm", "delete"])
    p_rm.add_argument("service", help="Nom du service")
    p_rm.add_argument("-y", "--yes", action="store_true", help="Ne pas demander confirmation")

    # ── generate ──────────────────────────────────────────────────────────────
    p_gen = sub.add_parser("generate", help="Générer un mot de passe sécurisé", aliases=["gen"])
    p_gen.add_argument("-l", "--length",       type=int, default=16)
    p_gen.add_argument("-s", "--symbols",      action="store_true")
    p_gen.add_argument("--no-upper",           action="store_true")
    p_gen.add_argument("--no-digits",          action="store_true")
    p_gen.add_argument("--no-ambiguous",       action="store_true")
    p_gen.add_argument("-c", "--copy",         action="store_true", help="Copier dans le presse-papier")
    p_gen.add_argument("--no-clear",           action="store_true", help="Ne pas effacer le presse-papier auto")

    # ── passwd ────────────────────────────────────────────────────────────────
    sub.add_parser("passwd", help="Changer le mot de passe maître")

    # ── export ────────────────────────────────────────────────────────────────
    p_exp = sub.add_parser("export", help="Exporter le coffre en JSON")
    p_exp.add_argument("output", help="Fichier de sortie (.json)")
    p_exp.add_argument("-f", "--force",        action="store_true", help="Écraser si existant")
    p_exp.add_argument("--no-passwords",       action="store_true", help="Exclure les mots de passe")
    p_exp.add_argument("--no-warning",         action="store_true")

    # ── import ────────────────────────────────────────────────────────────────
    p_imp = sub.add_parser("import", help="Importer depuis un JSON")
    p_imp.add_argument("input", help="Fichier source (.json)")
    p_imp.add_argument("--overwrite", action="store_true", help="Écraser les entrées existantes")

    # ── info ──────────────────────────────────────────────────────────────────
    sub.add_parser("info", help="Informations sur le coffre")

    # ── config ────────────────────────────────────────────────────────────────
    sub.add_parser("config", help="Afficher la configuration active")

    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args   = parser.parse_args(argv)

    # ── Chargement de la configuration TOML (feature v1.2) ───────────────────
    config_path = Path(args.config) if getattr(args, "config", None) else None
    cfg = CagouleConfig.load(config_path)

    dispatch = {
        "init":     cmd_init,
        "add":      cmd_add,
        "get":      cmd_get,
        "copy":     cmd_copy,
        "list":     cmd_list,
        "search":   cmd_search,
        "edit":     cmd_edit,
        "remove":   cmd_remove,
        "rm":       cmd_remove,
        "delete":   cmd_remove,
        "generate": cmd_generate,
        "gen":      cmd_generate,
        "passwd":   cmd_passwd,
        "export":   cmd_export,
        "import":   cmd_import,
        "info":     cmd_info,
        "config":   cmd_config,
    }

    try:
        return dispatch[args.command](args, cfg)
    except KeyboardInterrupt:
        print("\n  Interrompu.", file=sys.stderr)
        return 130
    except Exception as e:
        _err(f"Erreur inattendue : {e}")
        import traceback
        if os.environ.get("CAGOULE_DEBUG"):
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())