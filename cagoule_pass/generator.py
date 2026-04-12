"""
generator.py — Générateur de mots de passe sécurisé.

Utilise os.urandom() comme source d'entropie (CSPRNG du système).
Garantit la présence d'au moins un caractère de chaque catégorie demandée.
"""

from __future__ import annotations

import math
import os
import string


# ─── Alphabets ────────────────────────────────────────────────────────────────

LOWER   = string.ascii_lowercase       # a-z
UPPER   = string.ascii_uppercase       # A-Z
DIGITS  = string.digits                # 0-9
SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"

# Caractères ambigus à exclure si --no-ambiguous
AMBIGUOUS = "0OoIl1"


def _secure_choice(alphabet: str) -> str:
    """Sélection uniforme et non biaisée depuis un alphabet via os.urandom."""
    n = len(alphabet)
    # Rejection sampling pour éviter le modulo bias
    limit = (256 // n) * n
    while True:
        byte = os.urandom(1)[0]
        if byte < limit:
            return alphabet[byte % n]


def generate(
    length:       int  = 16,
    use_upper:    bool = True,
    use_digits:   bool = True,
    use_symbols:  bool = False,
    no_ambiguous: bool = False,
) -> str:
    """
    Génère un mot de passe aléatoire sécurisé.

    Args:
        length       : longueur du mot de passe (min 4)
        use_upper    : inclure les majuscules
        use_digits   : inclure les chiffres
        use_symbols  : inclure les symboles spéciaux
        no_ambiguous : exclure les caractères ambigus (0, O, l, I, 1...)

    Returns:
        str : mot de passe généré

    Raises:
        ValueError : si length < 4 ou alphabet vide
    """
    if length < 4:
        raise ValueError(f"Longueur minimale : 4 caractères (reçu {length})")

    # Construire l'alphabet
    alphabet = LOWER
    required: list[str] = []

    if use_upper:
        alphabet += UPPER
        required.append(UPPER)

    if use_digits:
        alphabet += DIGITS
        required.append(DIGITS)

    if use_symbols:
        alphabet += SYMBOLS
        required.append(SYMBOLS)

    # Exclure les caractères ambigus si demandé
    if no_ambiguous:
        alphabet = "".join(c for c in alphabet if c not in AMBIGUOUS)
        required = [
            "".join(c for c in cat if c not in AMBIGUOUS)
            for cat in required
        ]
        required = [cat for cat in required if cat]  # retirer les vides

    if not alphabet:
        raise ValueError("L'alphabet est vide après filtrage.")

    # S'assurer qu'il y a assez de place pour les caractères requis
    if len(required) >= length:
        raise ValueError(
            f"Longueur ({length}) insuffisante pour inclure tous les types de caractères requis."
        )

    # Générer le mot de passe
    # 1. Un caractère obligatoire de chaque catégorie requise
    forced = [_secure_choice(cat) for cat in required]

    # 2. Remplir le reste
    rest = [_secure_choice(alphabet) for _ in range(length - len(forced))]

    # 3. Mélanger (Fisher-Yates via os.urandom)
    password = forced + rest
    for i in range(len(password) - 1, 0, -1):
        j = int.from_bytes(os.urandom(2), "big") % (i + 1)
        password[i], password[j] = password[j], password[i]

    return "".join(password)


def entropy_bits(password: str) -> float:
    """
    Estime l'entropie du mot de passe en bits.

    Formule : log2(|alphabet|^longueur) = longueur × log2(|alphabet|)
    Note : estimation basée sur la taille de l'alphabet détecté.
    """
    has_lower   = any(c in LOWER   for c in password)
    has_upper   = any(c in UPPER   for c in password)
    has_digit   = any(c in DIGITS  for c in password)
    has_symbol  = any(c in SYMBOLS for c in password)

    pool = 0
    if has_lower:  pool += len(LOWER)
    if has_upper:  pool += len(UPPER)
    if has_digit:  pool += len(DIGITS)
    if has_symbol: pool += len(SYMBOLS)

    if pool == 0:
        return 0.0

    return round(len(password) * math.log2(pool), 1)


def strength(password: str) -> str:
    """Retourne une évaluation qualitative de la force du mot de passe."""
    bits = entropy_bits(password)
    if bits < 28:  return "Très faible ⚠️"
    if bits < 36:  return "Faible ⚠️"
    if bits < 60:  return "Moyen ✓"
    if bits < 80:  return "Fort ✓✓"
    return "Très fort ✓✓✓"
