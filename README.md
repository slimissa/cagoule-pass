# 🔐 cagoule-pass

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/cagoule-pass)](https://pypi.org/project/cagoule-pass/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-138%20passing-brightgreen)](tests/)
[![CI](https://img.shields.io/github/actions/workflow/status/slimissa/cagoule-pass/pypi-publish.yml)](https://github.com/slimissa/cagoule-pass/actions)

**Gestionnaire de mots de passe CLI chiffré avec [CAGOULE](https://github.com/slimissa/CAGOULE).**

Chaque coffre est un fichier `.cgl1` chiffré par CAGOULE (ChaCha20-Poly1305 + couche algébrique Z/pZ + Argon2id KDF). Support natif du TOTP/2FA (RFC 6238), des clés SSH (Ed25519/RSA-4096) et d'une interface TUI complète.

> ⚠️ **Avertissement** : CAGOULE est une implémentation cryptographique académique originale, non auditée par des tiers. Ne pas utiliser en production sur des systèmes critiques sans audit de sécurité indépendant.

---

## Installation

```bash
pip install cagoule-pass
```

**Avec support QR codes** :
```bash
pip install "cagoule-pass[qr]"
```

**Depuis les sources** :
```bash
git clone https://github.com/slimissa/cagoule-pass
cd cagoule-pass
pip install -e ".[dev]"
```

---

## Démarrage rapide

```bash
# 1. Créer un coffre
cagoule-pass init

# 2. Ajouter une entrée avec mot de passe généré
cagoule-pass add github -u slimissa --generate --length 24 --symbols

# 3. Récupérer une entrée
cagoule-pass get github --show

# 4. Copier dans le presse-papier (auto-effacement 30s)
cagoule-pass copy github

# 5. Lancer l'interface TUI
cagoule-pass tui
```

---

## Commandes

### Gestion du coffre

| Commande | Description |
|----------|-------------|
| `init` | Créer un nouveau coffre chiffré |
| `info` | Informations sur le coffre |
| `passwd` | Changer le mot de passe maître |
| `export <fichier>` | Exporter en JSON (avertissement mots de passe en clair) |
| `import <fichier>` | Importer depuis un JSON exporté |
| `config` | Afficher la configuration active |

### Gestion des entrées

| Commande | Description |
|----------|-------------|
| `add <service>` | Ajouter une entrée |
| `get <service>` | Afficher une entrée |
| `edit <service>` | Modifier une entrée |
| `remove <service>` | Supprimer une entrée |
| `list [--tag TAG]` | Lister toutes les entrées |
| `search <query>` | Rechercher (service, username, URL, tags) |
| `copy <service>` | Copier dans le presse-papier |
| `generate` | Générer un mot de passe seul |

### TOTP / 2FA

| Commande | Description |
|----------|-------------|
| `totp-add <service>` | Configurer le TOTP pour un service |
| `totp-code <service>` | Afficher le code TOTP live |
| `totp-uri <service>` | Afficher l'URI `otpauth://` (QR code) |

### Clés SSH

| Commande | Description |
|----------|-------------|
| `ssh-gen <service>` | Générer une paire de clés SSH |
| `ssh-add <service>` | Importer une clé SSH existante |
| `ssh-pub <service>` | Afficher la clé publique |
| `ssh-export <service>` | Exporter vers `~/.ssh/` |

### Interface

| Commande | Description |
|----------|-------------|
| `tui` | Lancer l'interface TUI (Textual) |

---

## Exemples

### Mots de passe

```bash
# Ajouter avec options complètes
cagoule-pass add aws \
  -u admin@mycompany.com \
  --generate --length 32 --symbols --no-ambiguous \
  --url https://console.aws.amazon.com \
  --tags "cloud,pro"

# Copier sans auto-effacement
cagoule-pass copy aws --no-clear

# Rechercher
cagoule-pass search aws
cagoule-pass list --tag pro

# Générer un mot de passe seul
cagoule-pass generate --length 20 --symbols --copy
```

### TOTP / 2FA

```bash
# Ajouter via URI otpauth:// (depuis votre application 2FA)
cagoule-pass totp-add github \
  --uri "otpauth://totp/GitHub:slimissa?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"

# Ajouter manuellement (secret Base32 fourni par le service)
cagoule-pass totp-add github --secret JBSWY3DPEHPK3PXP --issuer GitHub

# Code live avec barre de progression
cagoule-pass totp-code github

# Code unique (pour scripts)
cagoule-pass totp-code github --once

# Code unique + copie automatique
cagoule-pass totp-code github --once --copy

# Exporter l'URI (pour migrer vers une autre appli)
cagoule-pass totp-uri github
```

### Clés SSH

```bash
# Générer une clé Ed25519 (recommandé)
cagoule-pass ssh-gen myserver --algorithm Ed25519 --comment "user@laptop"

# Générer RSA-4096
cagoule-pass ssh-gen legacyserver --algorithm RSA-4096

# Importer une clé existante
cagoule-pass ssh-add myserver --key-file ~/.ssh/id_ed25519

# Afficher la clé publique (à copier dans authorized_keys)
cagoule-pass ssh-pub myserver

# Copier la clé publique dans le presse-papier
cagoule-pass ssh-pub myserver --copy

# Exporter vers ~/.ssh/
cagoule-pass ssh-export myserver --output-dir ~/.ssh --filename id_myserver
```

### Configuration TOML

Le fichier `~/.cagoule-pass/config.toml` est créé automatiquement :

```toml
[vault]
dir = "~/.cagoule-pass"

[clipboard]
clear_after_seconds = 30   # 0 = désactivé
no_clear = false

[generator]
default_length = 16
use_symbols = false
no_ambiguous = false
```

Afficher la configuration active :
```bash
cagoule-pass config
```

---

## Interface TUI

```bash
cagoule-pass tui
```

**Raccourcis clavier :**

| Touche | Action |
|--------|--------|
| `/` | Rechercher en temps réel |
| `Enter` | Ouvrir l'entrée sélectionnée |
| `n` | Nouvelle entrée |
| `r` | Rafraîchir le coffre |
| `?` | Aide |
| `q` | Quitter |
| `Escape` | Fermer / effacer recherche |

L'écran de détail affiche le code TOTP en temps réel avec barre de progression si un secret est configuré.

---

## Sécurité

### Pipeline cryptographique

```
Mot de passe maître
        │
        ▼
   Argon2id KDF
   (t=3, m=64MB, p=1)
        │
        ▼
   Clé dérivée 256 bits
        │
        ├── Couche CAGOULE (CBC sur Z/pZ)
        │
        ▼
   ChaCha20-Poly1305 AEAD
        │
        ▼
   Fichier .cgl1
```

### Propriétés

- **Chiffrement** : ChaCha20-Poly1305 (256 bits, AEAD)
- **KDF** : Argon2id (résistant GPU/ASIC, paramètres OWASP)
- **Diffusion** : Couche algébrique originale CAGOULE sur Z/pZ
- **Génération** : `os.urandom()` avec rejection sampling (pas de modulo bias)
- **TOTP** : RFC 6238 implémenté en stdlib pure (hmac + hashlib)
- **SSH** : Clés stockées chiffrées dans le coffre CGL1
- **Presse-papier** : Auto-effacement après 30s (configurable)
- **Écriture** : Atomique (fichier temporaire + rename POSIX)
- **Mot de passe maître** : Jamais stocké, jamais loggé

---

## Structure du coffre

```
~/.cagoule-pass/
├── vault.cgl1      ← coffre chiffré (format CGL1)
└── config.toml     ← configuration (créé automatiquement)
```

### Format d'une entrée

```json
{
  "service":  "github",
  "username": "slimissa",
  "password": "••••••••",
  "url":      "https://github.com",
  "notes":    "",
  "tags":     ["dev", "pro"],
  "totp":     { "secret": "••••", "issuer": "GitHub", "digits": 6, "period": 30 },
  "ssh_key":  { "algorithm": "Ed25519", "fingerprint": "SHA256:...", "..." : "..." },
  "created":  "2026-04-20T10:00:00Z",
  "updated":  "2026-04-20T12:15:00Z"
}
```

---

## Tests

```bash
# Lancer tous les tests
pytest tests/ -v

# Avec couverture
pytest tests/ --cov=cagoule_pass --cov-report=term-missing
```

**Couverture :**

| Module | Tests | Périmètre |
|--------|-------|-----------|
| `test_entry.py` | 11 | Modèle, sérialisation, timestamps |
| `test_generator.py` | 14 | CSPRNG, entropie, force |
| `test_vault.py` | 24 | Init, CRUD, persistance, passwd |
| `test_config.py` | 15 | TOML load, defaults, corrompu |
| `test_totp.py` | 30 | RFC 6238, SHA1/256/512, URI |
| `test_ssh.py` | 10 | Ed25519, RSA, export, chmod |
| Autres | 34 | CLI, TUI, intégration, QR |
| **Total** | **138** | **100 % passants** |

---

## Dépendances

| Package | Version | Usage |
|---------|---------|-------|
| `cagoule` | ≥ 1.5.0 | Chiffrement CGL1 (obligatoire) |
| `cryptography` | ≥ 40.0.0 | Génération clés SSH |
| `textual` | ≥ 0.50.0 | Interface TUI |
| `tomli` | ≥ 1.1.0 | TOML parser (Python < 3.11 uniquement) |
| `qrcode` | ≥ 7.0 | QR codes TOTP (optionnel) |

---

## Développement

```bash
# Installer en mode développement
pip install -e ".[dev]"

# Lancer les tests
pytest

# Générer la documentation
pdoc cagoule_pass -o docs/

# Builder le package
python -m build
twine check dist/*
```

---

## Licence

MIT — voir [LICENSE](LICENSE)

---

## Auteur

**Slim Issa** — GitHub : [@slimissa](https://github.com/slimissa)  
Kairouan, Tunisie — Avril 2026

Partie de l'écosystème **QuantOS** — une plateforme de calcul intégrant la finance quantitative à chaque couche.

---

*cagoule-pass — parce que vos mots de passe méritent une vraie cryptographie.*