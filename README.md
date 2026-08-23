# Hub Sécurité (Linux)

> **WIP** — encore en développement.  
> **WIP** — still in development.

Audit+, durcissement, FileGuard, certificats, RepoRadar, secrets, permissions.

**1.3.3** — [releases](https://github.com/Mr-Aurevo-X/Hub-Securite-Linux/releases) · GPL-3.0-or-later · © 2026 Mr-Aurevo-X

Matrice : Arch/Cachy (pacman), Mint/Ubuntu (apt), Fedora (dnf), openSUSE (zypper). Local-first, pas de sync auto des dépôts.

---

## Français

### Installer (Flatpak)

Prérequis : [Flatpak](https://flatpak.org/setup/) + runtime GNOME 49 (installé automatiquement depuis Flathub au premier `flatpak install`).

```bash
rm -f org.mraurevox.HubSecurite.flatpak
wget --no-continue -O org.mraurevox.HubSecurite.flatpak \
  https://github.com/Mr-Aurevo-X/Hub-Securite-Linux/releases/download/v1.3.3/org.mraurevox.HubSecurite.flatpak
flatpak install --user -y --reinstall ./org.mraurevox.HubSecurite.flatpak
wget --no-continue -O INSTALLER-RACCOURCI-FLATPAK.sh \
  https://github.com/Mr-Aurevo-X/Hub-Securite-Linux/releases/download/v1.3.3/INSTALLER-RACCOURCI-FLATPAK.sh
bash ./INSTALLER-RACCOURCI-FLATPAK.sh
flatpak run org.mraurevox.HubSecurite
```

Dev sans installer : `bash LANCER.sh`

### Ce que ça fait

- Audit et durcissement local
- FileGuard (chemins suivis)
- Certificats, RepoRadar (pacman / apt / dnf / zypper)
- Secrets (dossier courant, défaut `$HOME`) et permissions

### Ce que ça ne fait pas

Pas de télémétrie, pas d’install automatique, pas de canal Flathub.  
L’audit peut joindre les miroirs de paquets.

### Confidentialité

Local-first. Vérif. GitHub au démarrage (désactivable). Pas d’install auto.  
Texte : [LEGAL.md](LEGAL.md) — dans l’app : mentions légales.

---

## English

Audit+, hardening, FileGuard, certificates, RepoRadar, secrets, permissions.

Matrix: Arch/Cachy (pacman), Mint/Ubuntu (apt), Fedora (dnf), openSUSE (zypper). Local-first, no auto repo sync.

### Install (Flatpak)

```bash
rm -f org.mraurevox.HubSecurite.flatpak
wget --no-continue -O org.mraurevox.HubSecurite.flatpak \
  https://github.com/Mr-Aurevo-X/Hub-Securite-Linux/releases/download/v1.3.3/org.mraurevox.HubSecurite.flatpak
flatpak install --user -y --reinstall ./org.mraurevox.HubSecurite.flatpak
wget --no-continue -O INSTALLER-RACCOURCI-FLATPAK.sh \
  https://github.com/Mr-Aurevo-X/Hub-Securite-Linux/releases/download/v1.3.3/INSTALLER-RACCOURCI-FLATPAK.sh
bash ./INSTALLER-RACCOURCI-FLATPAK.sh
flatpak run org.mraurevox.HubSecurite
```

Local dev: `bash LANCER.sh`

No telemetry, no auto-install. Audit may contact package mirrors. See [LEGAL.md](LEGAL.md).

---

## Soutien (optionnel) / Support (optional)

Si le boulot te plaît, un café — sinon profite.  
If you like the work, a coffee — otherwise just enjoy it.

[![Discord](https://img.shields.io/badge/Discord-Mr--Aurevo--X-5865F2?style=for-the-badge&logo=discord&logoColor=white&labelColor=050807)](https://discord.com/users/406891052516114442)
[![PayPal](https://img.shields.io/badge/PayPal-Donate-39ff14?style=for-the-badge&logo=paypal&logoColor=00f0ff&labelColor=050807)](https://www.paypal.com/paypalme/aurevo1)
[![Revolut](https://img.shields.io/badge/Revolut-mr__aurevo__x-00f0ff?style=for-the-badge&logo=revolut&logoColor=39ff14&labelColor=050807)](https://revolut.me/mr_aurevo_x)

---

Copyright © 2026 Mr-Aurevo-X — GPL-3.0-or-later
