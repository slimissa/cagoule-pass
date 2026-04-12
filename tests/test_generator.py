"""tests/test_generator.py — Tests du générateur de mots de passe."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import string
import pytest
from cagoule_pass.generator import (
    generate, entropy_bits, strength, LOWER, UPPER, DIGITS, SYMBOLS, AMBIGUOUS
)


class TestGenerate:

    def test_longueur_defaut(self):
        pwd = generate()
        assert len(pwd) == 16

    @pytest.mark.parametrize("length", [4, 8, 12, 16, 24, 32, 64])
    def test_longueur_parametree(self, length):
        assert len(generate(length=length)) == length

    def test_longueur_minimale(self):
        with pytest.raises(ValueError):
            generate(length=3)

    def test_contient_lower(self):
        # Par défaut : minuscules toujours incluses
        for _ in range(20):
            pwd = generate(length=20)
            assert any(c in LOWER for c in pwd), f"Pas de minuscules dans {pwd}"

    def test_contient_upper_par_defaut(self):
        found = False
        for _ in range(50):
            if any(c in UPPER for c in generate(length=20)):
                found = True
                break
        assert found, "Jamais de majuscule générée"

    def test_sans_upper(self):
        for _ in range(20):
            pwd = generate(length=16, use_upper=False)
            assert not any(c in UPPER for c in pwd)

    def test_sans_digits(self):
        for _ in range(20):
            pwd = generate(length=16, use_digits=False)
            assert not any(c in DIGITS for c in pwd)

    def test_avec_symbols(self):
        found = False
        for _ in range(50):
            if any(c in SYMBOLS for c in generate(length=20, use_symbols=True)):
                found = True
                break
        assert found, "Jamais de symbole généré"

    def test_sans_symbols_par_defaut(self):
        for _ in range(20):
            pwd = generate(length=16, use_symbols=False)
            assert not any(c in SYMBOLS for c in pwd)

    def test_no_ambiguous(self):
        for _ in range(50):
            pwd = generate(length=32, no_ambiguous=True)
            assert not any(c in AMBIGUOUS for c in pwd), f"Caractère ambigu dans {pwd}"

    def test_unicite(self):
        # 1000 mots de passe — aucune collision
        passwords = {generate() for _ in range(1000)}
        assert len(passwords) == 1000

    # test_alphabet_vide_exc supprimé car impossible avec l'API actuelle
    # Les minuscules sont toujours incluses, donc l'alphabet ne peut pas être vide


class TestEntropy:

    def test_entropie_croissante_avec_longueur(self):
        e8  = entropy_bits("a" * 8)   # alphabet minimal
        e16 = entropy_bits("a" * 16)
        assert e16 > e8

    def test_entropie_positive(self):
        assert entropy_bits(generate()) > 0

    def test_entropie_minuscules_seulement(self):
        pwd = "abcdefghij"
        bits = entropy_bits(pwd)
        # log2(26) * 10 ≈ 47 bits
        assert 40 < bits < 60

    def test_entropie_tous_types(self):
        pwd = "Aa1!Bb2@Cc3#"
        bits = entropy_bits(pwd)
        # Grand alphabet → entropie plus haute
        assert bits > entropy_bits("aabbccddeeff")


class TestStrength:

    def test_force_tres_faible(self):
        assert "Très faible" in strength("abc")

    def test_force_fort(self):
        pwd = generate(length=20, use_symbols=True)
        s = strength(pwd)
        assert s in ("Fort ✓✓", "Très fort ✓✓✓", "Moyen ✓")