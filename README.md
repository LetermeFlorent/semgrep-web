# STV — Scanner de sécurité local

Interface web locale qui scanne un dossier de code avec **13 analyses de sécurité** lancées **en parallèle**, sans compte ni cloud. Tout tourne dans un conteneur Docker ; tes disques sont montés en **lecture seule**.

## Les 13 analyses

| Analyse | Outil | Détecte | Coché défaut |
|---|---|---|---|
| Code | Semgrep (règles `auto`) | injections, eval, patterns dangereux | oui |
| Versions | maison | dépendances obsolètes | oui |
| Secrets | Gitleaks | clés API, tokens, credentials | oui |
| CVE | Trivy + OSV.dev | vulnérabilités connues des dépendances | oui |
| Config / IaC | Trivy | mauvaises configs Docker/K8s/Terraform | oui |
| Licences | Trivy | licences à risque (GPL/AGPL…) | oui |
| Fichiers sensibles | maison | `.env`, `id_rsa`, `.pem`, dumps SQL… | oui |
| Secrets historique git | Gitleaks (mode git) | secrets commités puis effacés (restent dans l'historique) | oui |
| Permissions | maison | fichiers world-writable, clés lisibles | oui |
| Dockerfile | Hadolint | mauvaises pratiques d'image | oui |
| Python SAST | Bandit + pip-audit | failles Python + CVE PyPI | non |
| Rust CVE | cargo-audit | advisories RustSec (via `Cargo.lock`) | non |
| Java CVE | Trivy | CVE des deps Java (pom.xml, jar, gradle) | non |

Les 3 scans par langage (Python/Rust/Java) ne sont pas cochés par défaut : coche-les selon la techno du projet.

## Fonctionnalités

- **Scans parallèles** — chaque scan ouvre un onglet, plusieurs dossiers à la fois
- **Progression live** par analyse (SSE), pourcentage global
- **Déduplication** des findings entre scanners
- **États** par finding : ouvert / ignoré / résolu (persistés)
- **Historique + diff** — compare un scan au précédent (nouveaux / disparus)
- **Export** : JSON, SARIF 2.1, CSV, rapport HTML imprimable (→ PDF)
- **Mode CI** : endpoint synchrone avec verdict pass/fail (HTTP 422 si seuil dépassé)
- Multi-disques (Windows), thème auto clair/sombre

## Lancer

Windows (monte automatiquement les disques disponibles) :

```
start.bat
```

Ou manuellement :

```
docker compose up -d --build
```

Puis ouvre http://localhost:5001

> `start.bat` génère `docker-compose.override.yml` avec les lettres de lecteur présentes, montées en lecture seule sous `/host/<lettre>`. Les emplacements autorisés au scan sont définis dans **Paramètres** (par défaut `F:\`, `W:\`).

## Monter des disques / dossiers dans Docker

Le conteneur ne voit que ce que tu montes. Chaque disque (ou dossier) doit être monté sous `/host/<lettre>` en **lecture seule** (`:ro`).

**Windows — automatique** : `start.bat` détecte les lettres de lecteur présentes et génère `docker-compose.override.yml`, ex :

```yaml
services:
  semgrep-ui:
    volumes:
      - "C:/:/host/c:ro"
      - "W:/:/host/w:ro"
```

**Manuel** — ajoute tes montages dans un `docker-compose.override.yml` :

```yaml
services:
  semgrep-ui:
    volumes:
      # un disque entier
      - "D:/:/host/d:ro"
      # ou un seul dossier (Linux/macOS)
      - "/home/moi/projets:/host/projets:ro"
```

**Sans compose** (`docker run`) :

```
docker run -d -p 5001:5000 -v "W:/:/host/w:ro" -v stv-state:/state semgrep-web
```

> Règle : la partie après `:/host/` définit le nom vu dans l'app. Une lettre de lecteur (`w`) → chemin `W:\...`. Ensuite, autorise ces emplacements dans **Paramètres** (au premier lancement l'app te les propose automatiquement).

## Usage

Tape un chemin (ex `W:\monprojet`), coche les analyses, clique **Lancer**. Les résultats s'affichent par sévérité (Critique / Moyen / Info) ; boutons d'export en haut de la liste.

## Mode CI

Scan synchrone exploitable en pipeline (renvoie `200` si sous le seuil, `422` sinon) :

```
GET /ci?path=W:\monprojet&scans=semgrep,secrets,cve&fail_on=ERROR
```

Paramètres : `scans` (liste, défaut = toutes), `fail_on` = `ERROR` | `WARNING` | `INFO` | `NONE`.

## Stack

Flask (Python 3.12) · Semgrep · Trivy · Gitleaks · Hadolint · Bandit · pip-audit · cargo-audit · OSV.dev — le tout conteneurisé. Aucune écriture sur les disques scannés (montés `:ro`). État (config, historique, statuts) dans un volume Docker `stv-state`.

## Fichiers

| Fichier | Rôle |
|---|---|
| `app.py` | serveur Flask + UI + orchestration des scans |
| `scanners.py` | secrets, CVE, IaC, licences, fichiers sensibles |
| `verscan.py` | versions de dépendances + OSV |
| `Dockerfile` | image (installe Trivy, Gitleaks, Semgrep) |
| `start.bat` | démarrage Windows + montage des disques |
