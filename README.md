# cagoule-pass

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Gestionnaire de mots de passe en ligne de commande, chiffré avec CAGOULE.**

Chaque coffre est un fichier `.cgl1` chiffré par CAGOULE (ChaCha20-Poly1305 + couche algébrique Z/pZ). Le mot de passe maître ne quitte jamais votre machine.

---

## Installation

```bash
pip install cagoule-pass
```

## Démarrage rapide

```bash
# 1. Créer un coffre
cagoule-pass init

# 2. Ajouter une entrée (mot de passe généré automatiquement)
cagoule-pass add github -u monuser --generate --length 20 --symbols

# 3. Récupérer une entrée
cagoule-pass get github --show

# 4. Copier le mot de passe dans le presse-papier
cagoule-pass copy github

# 5. Lister toutes les entrées
cagoule-pass list
```

---

## Commandes

| Commande | Description |
|----------|-------------|
| `init` | Créer un nouveau coffre |
| `add <service>` | Ajouter une entrée |
| `get <service>` | Afficher une entrée |
| `copy <service>` | Copier le mot de passe |
| `list` | Lister toutes les entrées |
| `search <query>` | Rechercher |
| `edit <service>` | Modifier une entrée |
| `remove <service>` | Supprimer une entrée |
| `generate` | Générer un mot de passe seul |
| `passwd` | Changer le mot de passe maître |
| `export <fichier>` | Exporter en JSON |
| `import <fichier>` | Importer depuis JSON |
| `info` | Informations sur le coffre |

## Options communes

```bash
# Dossier personnalisé
cagoule-pass --dir /chemin/vault list

# Générer un mot de passe fort
cagoule-pass generate --length 24 --symbols --no-ambiguous --copy

# Ajouter avec URL et tags
cagoule-pass add github -u user --generate --url https://github.com --tags "dev,pro"
```

## Sécurité

- Chiffrement : **CAGOULE v1.5+ (CGL1)** — ChaCha20-Poly1305 + CBC interne sur Z/pZ
- KDF : **Argon2id** (t=3, m=64MB) — résistant aux attaques par GPU
- Stockage : `~/.cagoule-pass/vault.cgl1` — un seul fichier chiffré
- Écriture **atomique** (fichier temporaire + rename) — pas de corruption partielle
- Mot de passe maître : jamais stocké, jamais logué

> ⚠️ Basé sur CAGOULE qui est à usage académique. Ne pas utiliser en production sans audit.

## Structure du coffre

```
~/.cagoule-pass/
├── vault.cgl1     ← coffre chiffré (format CGL1)
└── config.json    ← métadonnées non-sensibles (version, date)
```
