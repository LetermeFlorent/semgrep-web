# STV — Scanner de sécurité local

Interface web locale qui scanne un dossier de code avec **7 analyses de sécurité** lancées **en parallèle**, sans compte ni cloud. Tout tourne dans un conteneur Docker ; tes disques sont montés en **lecture seule**.

## Les 7 analyses

| Analyse | Outil | Détecte |
|---|---|---|
| Code | Semgrep (règles `auto`) | injections, eval, patterns dangereux |
| Versions | maison | dépendances obsolètes |
| Secrets | Gitleaks | clés API, tokens, credentials |
| CVE | Trivy + OSV.dev | vulnérabilités connues des dépendances |
| Config / IaC | Trivy | mauvaises configs Docker/K8s/Terraform |
| Licences | Trivy | licences à risque (GPL/AGPL…) |
| Fichiers sensibles | maison | `.env`, `id_rsa`, `.pem`, dumps SQL… |

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

## Usage

Tape un chemin (ex `W:\monprojet`), coche les analyses, clique **Lancer**. Les résultats s'affichent par sévérité (Critique / Moyen / Info) ; boutons d'export en haut de la liste.

## Mode CI

Scan synchrone exploitable en pipeline (renvoie `200` si sous le seuil, `422` sinon) :

```
GET /ci?path=W:\monprojet&scans=semgrep,secrets,cve&fail_on=ERROR
```

Paramètres : `scans` (liste, défaut = toutes), `fail_on` = `ERROR` | `WARNING` | `INFO` | `NONE`.

## Stack

Flask (Python 3.12) · Semgrep · Trivy · Gitleaks · OSV.dev — le tout conteneurisé. Aucune écriture sur les disques scannés (montés `:ro`). État (config, historique, statuts) dans un volume Docker `stv-state`.

## Fichiers

| Fichier | Rôle |
|---|---|
| `app.py` | serveur Flask + UI + orchestration des scans |
| `scanners.py` | secrets, CVE, IaC, licences, fichiers sensibles |
| `verscan.py` | versions de dépendances + OSV |
| `Dockerfile` | image (installe Trivy, Gitleaks, Semgrep) |
| `start.bat` | démarrage Windows + montage des disques |
