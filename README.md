# stv

Web UI locale pour scanner un dossier de code avec Semgrep.

- Interface web sans login
- Choisis un dossier local, clique Scan, vois les vulnérabilités
- Thème auto light/dark
- Progression du scan en direct (SSE)

## Lancer

```
docker compose up -d --build
```

Ouvre http://localhost:5001

## Usage

Tape un chemin de dossier (ex `F:\monprojet`), clique **Scanner**.

## Stack

Flask + Semgrep, conteneurisé. `F:\` monté en lecture seule dans le conteneur.
