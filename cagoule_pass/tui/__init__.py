"""
tui — Interface Text User Interface pour cagoule-pass v1.5.

Basée sur Textual (https://textual.textualize.io).

Usage :
    from cagoule_pass.tui import launch_tui
    launch_tui(vault_dir=Path("~/.cagoule-pass").expanduser())

Ou via CLI :
    cagoule-pass tui
"""

from .app import launch_tui, CagoulePassApp

__all__ = ["launch_tui", "CagoulePassApp"]