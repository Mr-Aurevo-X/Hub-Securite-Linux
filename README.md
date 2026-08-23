# Hub Sécurité (Linux)

> **Dépôt privé** — plateforme Linux Mr-Aurevo-X (GTK 4 + Uni-UI).  
> **Private repo** — Mr-Aurevo-X Linux platform (GTK 4 + Uni-UI).

---

## Français

Audit+, durcissement, FileGuard, certificats, RepoRadar, secrets, permissions. Repo Linux dédié.

Matrice : Arch/Cachy (pacman), Mint/Ubuntu (apt), Fedora (dnf), openSUSE (zypper). Local-first, pas de sync auto des dépôts. QA manuelle Mint/Fedora quand la machine est là : scan audit, Appliquer fw, Radar sources, FileGuard chemins.

- **GitHub** : `Mr-Aurevo-X/Hub-Securite-Linux` (privé)
- **Plateforme** : voir [linux-platform](https://github.com/Mr-Aurevo-X/linux-platform)

## Installation / Install

```bash
flatpak install --user -y https://github.com/Mr-Aurevo-X/Hub-Securite-Linux/releases/latest/download/org.mraurevox.HubSecurite.flatpak
flatpak run org.mraurevox.HubSecurite
```

Dev local :

```bash
bash LANCER.sh
```


### Confidentialité

Local-first, pas de télémétrie. Vérif. GitHub au démarrage (désactivable). L'audit peut joindre les miroirs de paquets. Pas d'install auto.

---

## English

Audit+, hardening, FileGuard, certificates, RepoRadar, secrets, permissions. Dedicated Linux repo.

Matrix: Arch/Cachy (pacman), Mint/Ubuntu (apt), Fedora (dnf), openSUSE (zypper). Local-first, no auto repo sync.

- **GitHub**: `Mr-Aurevo-X/Hub-Securite-Linux` (private)
- **Platform**: see [linux-platform](https://github.com/Mr-Aurevo-X/linux-platform)

### Privacy

Local-first, no telemetry. Startup GitHub check (can be disabled). Audit may contact package mirrors. No auto-install.

---

Copyright © 2026 Mr-Aurevo-X
