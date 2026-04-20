"""
widgets — Widgets réutilisables pour l'interface TUI cagoule-pass v1.5.

Exports :
    - TOTPWidget : Widget live pour l'affichage des codes TOTP avec barre de progression
"""

from .totp_widget import TOTPWidget

__all__ = [
    "TOTPWidget",
]