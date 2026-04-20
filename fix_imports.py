import re
import os

files = [
    "cagoule_pass/tui/screens/add_screen.py",
    "cagoule_pass/tui/screens/delete_screen.py",
    "cagoule_pass/tui/screens/edit_screen.py",
    "cagoule_pass/tui/screens/qrcode_screen.py",
]

for f in files:
    if not os.path.exists(f):
        continue
    
    with open(f, 'r') as file:
        content = file.read()
    
    # Ajouter ComposeResult si manquant
    if 'ComposeResult' in content and 'from textual.app import ComposeResult' not in content:
        content = content.replace(
            'from textual.widgets import',
            'from textual.app import ComposeResult\nfrom textual.widgets import'
        )
        print(f"Fixé: {f}")
    
    with open(f, 'w') as file:
        file.write(content)

print("Terminé!")
