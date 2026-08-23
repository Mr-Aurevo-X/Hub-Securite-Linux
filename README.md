# Hub Sécurité (Linux)

> **Dépôt privé** — reste privé pour le moment. Pas de canal public / Flathub.  
> **Private repo** — stays private for now. No public channel / Flathub.

**Version : 1.3.0** — tag `v1.3.0`

---

## Français

Audit+, durcissement, FileGuard, certificats, RepoRadar, secrets, permissions.

Matrice : Arch/Cachy (pacman), Mint/Ubuntu (apt), Fedora (dnf), openSUSE (zypper). Local-first, pas de sync auto des dépôts.

- **GitHub** : `Mr-Aurevo-X/Hub-Securite-Linux` (privé)
- **Plateforme** : [linux-platform](https://github.com/Mr-Aurevo-X/linux-platform)

### Install (privé — `gh` authentifié)

Les URL `releases/latest/download/…` **ne marchent pas** tant que le dépôt est privé. Il faut [GitHub CLI](https://cli.github.com/) connecté au compte.

```bash
gh release download v1.3.0 -R Mr-Aurevo-X/Hub-Securite-Linux \
  -p 'org.mraurevox.HubSecurite.flatpak' \
  -p 'INSTALLER-RACCOURCI-FLATPAK.sh'
flatpak install --user -y --reinstall ./org.mraurevox.HubSecurite.flatpak
bash ./INSTALLER-RACCOURCI-FLATPAK.sh
flatpak run org.mraurevox.HubSecurite
```

Dev local (clone) :

```bash
bash LANCER.sh
```

### 1.3.0

- Audit et RepoRadar : une API MAJ lecture seule (pacman / apt-check / dnf cache / zypper `--no-refresh`)
- RepoRadar : `yum.repos.d` + `zypp/repos.d`, orphelins dnf/zypper, empty states honnêtes
- FileGuard : chemins suivis visibles
- Durcissement : 3 actions toujours sur la page + journal
- Secrets : dossier courant affiché (défaut `$HOME`)

### Confidentialité

Local-first, pas de télémétrie. Vérif. GitHub au démarrage (désactivable) — **inutile tant que le dépôt est privé** (API publique). L'audit peut joindre les miroirs de paquets. Pas d'install auto.

---

## English

Audit+, hardening, FileGuard, certificates, RepoRadar, secrets, permissions.

Matrix: Arch/Cachy (pacman), Mint/Ubuntu (apt), Fedora (dnf), openSUSE (zypper). Local-first, no auto repo sync.

- **GitHub**: `Mr-Aurevo-X/Hub-Securite-Linux` (private)
- **Platform**: [linux-platform](https://github.com/Mr-Aurevo-X/linux-platform)

### Install (private — authenticated `gh`)

Anonymous `releases/latest/download/…` URLs **do not work** while the repo is private.

```bash
gh release download v1.3.0 -R Mr-Aurevo-X/Hub-Securite-Linux \
  -p 'org.mraurevox.HubSecurite.flatpak' \
  -p 'INSTALLER-RACCOURCI-FLATPAK.sh'
flatpak install --user -y --reinstall ./org.mraurevox.HubSecurite.flatpak
bash ./INSTALLER-RACCOURCI-FLATPAK.sh
flatpak run org.mraurevox.HubSecurite
```

Local dev: `bash LANCER.sh`

### Privacy

Local-first, no telemetry. Startup GitHub check (can be disabled) is a no-op on a private repo without a token. Audit may contact package mirrors. No auto-install.

---

Copyright © 2026 Mr-Aurevo-X
