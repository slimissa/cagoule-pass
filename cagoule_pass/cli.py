"""
cli.py — Interface ligne de commande cagoule-pass v1.5.

Nouveautés v1.5 :
    - Gestion TOTP (2FA) : ajout, affichage, QR code
    - Gestion SSH Keys : génération, import, export, agent
    - Interface TUI (Textual) : cagoule-pass tui

Commandes existantes (v1.2) :
    init, add, get, copy, list, search, edit, remove, generate,
    passwd, export, import, info, config

Nouvelles commandes v1.5 :
    totp add <service> --secret <BASE32> [--issuer ISSUER] [--account ACCOUNT]
    totp show <service>                    # Affiche le code TOTP actuel
    totp qr <service>                      # Génère QR code
    ssh add <name> --generate [--algo Ed25519|RSA-4096] [--comment COMMENT]
    ssh import <name> --key <path>         # Importe clé privée existante
    ssh export <name> [--output-dir DIR]   # Exporte vers ~/.ssh/
    ssh list                               # Liste les clés SSH
    ssh show <name>                        # Affiche détails clé SSH
    ssh add-to-agent <name>                # Ajoute à ssh-agent
    ssh remove-from-agent <fingerprint>    # Supprime de ssh-agent
    tui                                    # Lance l'interface TUI
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
        try:
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(text.encode("utf-8"))
            return p.returncode == 0
        except FileNotFoundError:
            pass
        try:
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE, shell=True)
            p.communicate(text.encode("utf-8"))
            return p.returncode == 0
        except Exception:
            pass
    except Exception:
        pass
    return False


def _schedule_clipboard_clear(delay_seconds: int) -> threading.Thread:
    def _clear() -> None:
        time.sleep(delay_seconds)
        _clipboard_copy("")
    t = threading.Thread(target=_clear, daemon=True)
    t.start()
    return t


def _copy_with_autoclear(text: str, cfg: CagouleConfig, no_clear_flag: bool = False) -> bool:
    if not _clipboard_copy(text):
        return False

    skip_clear = no_clear_flag or cfg.clipboard.no_clear
    delay = cfg.clipboard.clear_after_seconds

    if not skip_clear and delay > 0:
        _info(f"Auto-effacement du presse-papier dans {delay}s.")
        t = _schedule_clipboard_clear(delay)
        t.join()
    else:
        _info("Presse-papier non effacé automatiquement (--no-clear ou config).")
    return True


# ─── Commandes existantes (v1.2) ─────────────────────────────────────────────

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
    url = args.url or input("  URL (optionnel) : ").strip()
    notes = args.notes or input("  Notes (optionnel) : ").strip()
    tags = [t.strip() for t in (args.tags or "").split(",") if t.strip()]

    if args.password:
        pwd = args.password
    elif args.generate:
        length = args.length if args.length != 16 else cfg.generator.default_length
        symbols = args.symbols or cfg.generator.use_symbols
        no_amb = args.no_ambiguous or cfg.generator.no_ambiguous
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

    text = entry.username if args.username else entry.password
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
    tag = getattr(args, "tag", None)
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, _ = _open_vault(vault_dir)

    # Récupérer le tag depuis args (peut ne pas exister dans les versions anciennes)
    tag = getattr(args, 'tag', None)
    entries = vault.list_all(tag=tag)

    if not entries:
        _info("Le coffre est vide." if not tag else f"Aucune entrée avec le tag '{tag}'.")
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
    length = args.length if args.length != 16 else cfg.generator.default_length
    symbols = args.symbols or cfg.generator.use_symbols
    no_amb = args.no_ambiguous or cfg.generator.no_ambiguous

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


# ─── Nouvelles commandes v1.5 ────────────────────────────────────────────────

def cmd_totp_add(args, cfg: CagouleConfig) -> int:
    """Ajoute une configuration TOTP à une entrée existante."""
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, password = _open_vault(vault_dir)

    try:
        entry = vault.get(args.service)
    except EntryNotFoundError as e:
        _err(str(e))
        return 1

    from .totp import TOTPEntry

    secret = args.secret.upper().replace(" ", "").replace("-", "")
    issuer = args.issuer or entry.service
    account = args.account or entry.username or args.service

    totp = TOTPEntry(
        issuer=issuer,
        account=account,
        secret=secret,
        digits=args.digits,
        period=args.period,
        algorithm=args.algorithm,
    )

    entry.update(totp=totp.to_dict())
    vault.save(password)

    _ok(f"TOTP ajouté à '{args.service}'")
    _info(f"Issuer: {issuer}")
    _info(f"Account: {account}")
    return 0


def cmd_totp_show(args, cfg: CagouleConfig) -> int:
    """Affiche le code TOTP actuel pour un service."""
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, _ = _open_vault(vault_dir)

    try:
        entry = vault.get(args.service)
    except EntryNotFoundError as e:
        _err(str(e))
        return 1

    if not entry.has_totp:
        _err(f"Aucune configuration TOTP pour '{args.service}'.")
        _info("Ajoutez-en une avec : cagoule-pass totp add")
        return 1

    from .totp import generate_code, time_remaining

    code = generate_code(entry.totp_entry)
    remaining = time_remaining(entry.totp_entry)

    print()
    _sep()
    print(f"  🔐 TOTP pour {args.service}")
    _sep("·")
    print(f"  Code     : {code[:3]} {code[3:]}")
    print(f"  Expire dans : {remaining} secondes")
    _sep()
    return 0


def cmd_totp_qr(args, cfg: CagouleConfig) -> int:
    """Génère un QR code pour le TOTP."""
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, _ = _open_vault(vault_dir)

    try:
        entry = vault.get(args.service)
    except EntryNotFoundError as e:
        _err(str(e))
        return 1

    if not entry.has_totp:
        _err(f"Aucune configuration TOTP pour '{args.service}'.")
        return 1

    uri = entry.totp_entry.to_uri()
    print()
    _sep()
    print(f"  📱 QR Code pour {args.service}")
    _sep("·")
    print(f"  URI: {uri}")
    print()

    try:
        import segno
        qr = segno.make(uri)
        print(qr.to_str())
        _ok("QR code affiché ci-dessus.")
    except ImportError:
        _info("Installez 'segno' pour afficher le QR code : pip install segno")
        _info(f"Vous pouvez aussi utiliser : {uri}")

    _sep()
    return 0


def cmd_ssh_add(args, cfg: CagouleConfig) -> int:
    """Ajoute une clé SSH à une entrée existante."""
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, password = _open_vault(vault_dir)

    try:
        entry = vault.get(args.name)
    except EntryNotFoundError as e:
        _err(str(e))
        return 1

    from .ssh import SSHKeyPair

    if args.generate:
        pair = SSHKeyPair.generate(
            algorithm=args.algo,
            comment=args.comment or f"{args.name}@cagoule-pass"
        )
        _ok(f"Clé SSH {args.algo} générée")
    elif args.key:
        pair = SSHKeyPair.from_file(args.key, comment=args.comment)
        _ok(f"Clé SSH importée depuis {args.key}")
    else:
        _err("Spécifiez --generate ou --key")
        return 1

    entry.update(ssh_key=pair.to_dict())
    vault.save(password)

    _ok(f"Clé SSH ajoutée à '{args.name}'")
    _info(f"Empreinte : {pair.fingerprint}")
    return 0


def cmd_ssh_export(args, cfg: CagouleConfig) -> int:
    """Exporte une clé SSH vers le système de fichiers."""
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, _ = _open_vault(vault_dir)

    try:
        entry = vault.get(args.name)
    except EntryNotFoundError as e:
        _err(str(e))
        return 1

    if not entry.has_ssh_key:
        _err(f"Aucune clé SSH pour '{args.name}'.")
        return 1

    priv, pub = entry.ssh_key_pair.export_to_files(
        output_dir=args.output_dir or "~/.ssh",
        overwrite=args.force,
    )
    _ok(f"Clé privée : {priv}")
    _ok(f"Clé publique : {pub}")
    return 0


def cmd_ssh_list(args, cfg: CagouleConfig) -> int:
    """Liste toutes les entrées avec clés SSH."""
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, _ = _open_vault(vault_dir)

    entries = [e for e in vault.list_all() if e.has_ssh_key]

    if not entries:
        _info("Aucune clé SSH dans le coffre.")
        return 0

    print()
    _sep()
    print("  🔑 Clés SSH dans le coffre")
    _sep("·")
    for e in entries:
        k = e.ssh_key_pair
        print(f"  {e.service:<20} {k.algorithm:<12} {k.fingerprint[:30]}...")
    _sep()
    print(f"  {len(entries)} clé(s)")
    return 0


def cmd_ssh_show(args, cfg: CagouleConfig) -> int:
    """Affiche les détails d'une clé SSH."""
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, _ = _open_vault(vault_dir)

    try:
        entry = vault.get(args.name)
    except EntryNotFoundError as e:
        _err(str(e))
        return 1

    if not entry.has_ssh_key:
        _err(f"Aucune clé SSH pour '{args.name}'.")
        return 1

    print()
    _sep()
    print(f"  🔑 Clé SSH : {args.name}")
    _sep("·")
    print(entry.ssh_key_pair.display(show_private=args.show_private))
    _sep()
    return 0


def cmd_ssh_add_to_agent(args, cfg: CagouleConfig) -> int:
    """Ajoute une clé SSH à l'agent SSH."""
    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    vault, _ = _open_vault(vault_dir)

    try:
        entry = vault.get(args.name)
    except EntryNotFoundError as e:
        _err(str(e))
        return 1

    if not entry.has_ssh_key:
        _err(f"Aucune clé SSH pour '{args.name}'.")
        return 1

    import subprocess
    proc = subprocess.Popen(
        ["ssh-add", "-"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    proc.communicate(entry.ssh_key_pair.private_key_pem.encode())
    if proc.returncode == 0:
        _ok(f"Clé SSH ajoutée à l'agent")
    else:
        _err("Impossible d'ajouter la clé à l'agent")
        return 1
    return 0


def cmd_ssh_remove_from_agent(args, cfg: CagouleConfig) -> int:
    """Supprime une clé SSH de l'agent."""
    import subprocess
    proc = subprocess.run(
        ["ssh-add", "-d", args.fingerprint],
        capture_output=True,
    )
    if proc.returncode == 0:
        _ok(f"Clé SSH supprimée de l'agent")
    else:
        _err("Impossible de supprimer la clé de l'agent")
        return 1
    return 0


def cmd_tui(args, cfg: CagouleConfig) -> int:
    """Lance l'interface TUI."""
    try:
        from .tui import launch_tui
    except ImportError as e:
        _err(f"Impossible de charger l'interface TUI: {e}")
        _info("Installez textual : pip install textual")
        return 1
    except Exception as e:
        _err(f"Erreur inattendue lors de l'import: {e}")
        import traceback
        traceback.print_exc()
        return 1

    vault_dir = Path(args.dir) if args.dir else cfg.vault.vault_dir
    try:
        launch_tui(vault_dir)
    except Exception as e:
        _err(f"Erreur lors du lancement de la TUI: {e}")
        import traceback
        traceback.print_exc()
        return 1
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
            "  cagoule-pass totp add github --secret JBSWY3DP...\n"
            "  cagoule-pass ssh add work --generate --algo Ed25519\n"
            "  cagoule-pass tui\n"
        ),
    )

    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Afficher la version et quitter"
    )
    parser.add_argument(
        "--dir", metavar="DOSSIER",
        help="Dossier du coffre (défaut depuis config TOML)"
    )
    parser.add_argument(
        "--config", metavar="FICHIER",
        help="Chemin du fichier de configuration TOML"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── Commandes existantes ─────────────────────────────────────────────────
    sub.add_parser("init", help="Créer un nouveau coffre chiffré")
    sub.add_parser("get", help="Afficher une entrée")
    sub.add_parser("list", help="Lister les entrées")
    sub.add_parser("search", help="Rechercher des entrées")
    sub.add_parser("passwd", help="Changer le mot de passe maître")
    sub.add_parser("info", help="Informations sur le coffre")
    sub.add_parser("config", help="Afficher la configuration active")

    # add
    p_add = sub.add_parser("add", help="Ajouter une entrée")
    p_add.add_argument("service", help="Nom du service")
    p_add.add_argument("-u", "--username", default="")
    p_add.add_argument("-p", "--password", default="")
    p_add.add_argument("--url", default="")
    p_add.add_argument("--notes", default="")
    p_add.add_argument("--tags", default="")
    p_add.add_argument("-g", "--generate", action="store_true")
    p_add.add_argument("-l", "--length", type=int, default=16)
    p_add.add_argument("--symbols", action="store_true")
    p_add.add_argument("--no-upper", action="store_true")
    p_add.add_argument("--no-digits", action="store_true")
    p_add.add_argument("--no-ambiguous", action="store_true")

    # copy
    p_copy = sub.add_parser("copy", help="Copier dans le presse-papier")
    p_copy.add_argument("service", help="Nom du service")
    p_copy.add_argument("--username", action="store_true")
    p_copy.add_argument("--no-clear", action="store_true")

    # edit
    p_edit = sub.add_parser("edit", help="Modifier une entrée")
    p_edit.add_argument("service", help="Nom du service")
    p_edit.add_argument("-u", "--username", default=None)
    p_edit.add_argument("-p", "--password", default="")
    p_edit.add_argument("--url", default=None)
    p_edit.add_argument("--notes", default=None)
    p_edit.add_argument("-g", "--generate", action="store_true")
    p_edit.add_argument("-l", "--length", type=int, default=16)
    p_edit.add_argument("--symbols", action="store_true")

    # remove
    p_rm = sub.add_parser("remove", aliases=["rm", "delete"], help="Supprimer une entrée")
    p_rm.add_argument("service", help="Nom du service")
    p_rm.add_argument("-y", "--yes", action="store_true")

    # generate
    p_gen = sub.add_parser("generate", aliases=["gen"], help="Générer un mot de passe")
    p_gen.add_argument("-l", "--length", type=int, default=16)
    p_gen.add_argument("-s", "--symbols", action="store_true")
    p_gen.add_argument("--no-upper", action="store_true")
    p_gen.add_argument("--no-digits", action="store_true")
    p_gen.add_argument("--no-ambiguous", action="store_true")
    p_gen.add_argument("-c", "--copy", action="store_true")
    p_gen.add_argument("--no-clear", action="store_true")

    # export
    p_exp = sub.add_parser("export", help="Exporter en JSON")
    p_exp.add_argument("output", help="Fichier de sortie")
    p_exp.add_argument("-f", "--force", action="store_true")
    p_exp.add_argument("--no-passwords", action="store_true")
    p_exp.add_argument("--no-warning", action="store_true")

    # import
    p_imp = sub.add_parser("import", help="Importer depuis JSON")
    p_imp.add_argument("input", help="Fichier source")
    p_imp.add_argument("--overwrite", action="store_true")

    # ── Nouvelles commandes TOTP ─────────────────────────────────────────────
    p_totp_add = sub.add_parser("totp", help="Gestion TOTP (2FA)")
    totp_sub = p_totp_add.add_subparsers(dest="totp_cmd", required=True)

    p_totp_add_cmd = totp_sub.add_parser("add", help="Ajouter TOTP")
    p_totp_add_cmd.add_argument("service", help="Nom du service")
    p_totp_add_cmd.add_argument("--secret", required=True, help="Secret Base32")
    p_totp_add_cmd.add_argument("--issuer", default="", help="Nom du service (issuer)")
    p_totp_add_cmd.add_argument("--account", default="", help="Nom du compte")
    p_totp_add_cmd.add_argument("--digits", type=int, default=6, choices=[6, 8])
    p_totp_add_cmd.add_argument("--period", type=int, default=30, choices=[30, 60])
    p_totp_add_cmd.add_argument("--algorithm", default="SHA1", choices=["SHA1", "SHA256", "SHA512"])

    totp_sub.add_parser("show", help="Afficher le code TOTP").add_argument("service", help="Nom du service")
    totp_sub.add_parser("qr", help="Générer QR code").add_argument("service", help="Nom du service")

    # ── Nouvelles commandes SSH ──────────────────────────────────────────────
    p_ssh = sub.add_parser("ssh", help="Gestion des clés SSH")
    ssh_sub = p_ssh.add_subparsers(dest="ssh_cmd", required=True)

    p_ssh_add = ssh_sub.add_parser("add", help="Ajouter une clé SSH")
    p_ssh_add.add_argument("name", help="Nom de la clé")
    p_ssh_add.add_argument("--generate", action="store_true", help="Générer une nouvelle clé")
    p_ssh_add.add_argument("--algo", default="Ed25519", choices=["Ed25519", "RSA-4096", "RSA-2048"])
    p_ssh_add.add_argument("--key", help="Chemin vers une clé privée existante")
    p_ssh_add.add_argument("--comment", default="", help="Commentaire")

    p_ssh_export = ssh_sub.add_parser("export", help="Exporter une clé SSH")
    p_ssh_export.add_argument("name", help="Nom de la clé")
    p_ssh_export.add_argument("--output-dir", default="~/.ssh", help="Dossier de destination")
    p_ssh_export.add_argument("--force", action="store_true", help="Écraser si existant")

    ssh_sub.add_parser("list", help="Lister les clés SSH")
    p_ssh_show = ssh_sub.add_parser("show", help="Afficher les détails d'une clé")
    p_ssh_show.add_argument("name", help="Nom de la clé")
    p_ssh_show.add_argument("--show-private", action="store_true", help="Afficher la clé privée")

    p_ssh_agent = ssh_sub.add_parser("add-to-agent", help="Ajouter à ssh-agent")
    p_ssh_agent.add_argument("name", help="Nom de la clé")

    p_ssh_rm_agent = ssh_sub.add_parser("remove-from-agent", help="Supprimer de ssh-agent")
    p_ssh_rm_agent.add_argument("fingerprint", help="Empreinte de la clé")

    # ── Commande TUI ─────────────────────────────────────────────────────────
    sub.add_parser("tui", help="Lancer l'interface textuelle (TUI)")

    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config_path = Path(args.config) if getattr(args, "config", None) else None
    cfg = CagouleConfig.load(config_path)

    # Dispatch des commandes
    if args.command == "totp":
        if args.totp_cmd == "add":
            return cmd_totp_add(args, cfg)
        elif args.totp_cmd == "show":
            return cmd_totp_show(args, cfg)
        elif args.totp_cmd == "qr":
            return cmd_totp_qr(args, cfg)
    elif args.command == "ssh":
        if args.ssh_cmd == "add":
            return cmd_ssh_add(args, cfg)
        elif args.ssh_cmd == "export":
            return cmd_ssh_export(args, cfg)
        elif args.ssh_cmd == "list":
            return cmd_ssh_list(args, cfg)
        elif args.ssh_cmd == "show":
            return cmd_ssh_show(args, cfg)
        elif args.ssh_cmd == "add-to-agent":
            return cmd_ssh_add_to_agent(args, cfg)
        elif args.ssh_cmd == "remove-from-agent":
            return cmd_ssh_remove_from_agent(args, cfg)
    elif args.command == "tui":
        return cmd_tui(args, cfg)

    # Commandes existantes
    dispatch = {
        "init": cmd_init,
        "add": cmd_add,
        "get": cmd_get,
        "copy": cmd_copy,
        "list": cmd_list,
        "search": cmd_search,
        "edit": cmd_edit,
        "remove": cmd_remove,
        "rm": cmd_remove,
        "delete": cmd_remove,
        "generate": cmd_generate,
        "gen": cmd_generate,
        "passwd": cmd_passwd,
        "export": cmd_export,
        "import": cmd_import,
        "info": cmd_info,
        "config": cmd_config,
    }

    try:
        return dispatch[args.command](args, cfg)
    except KeyboardInterrupt:
        print("\n  Interrompu.", file=sys.stderr)
        return 130
    except Exception as e:
        _err(f"Erreur inattendue : {e}")
        if os.environ.get("CAGOULE_DEBUG"):
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())