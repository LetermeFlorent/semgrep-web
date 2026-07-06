---
name: docker-dev
description: Rebuild, montage disques et tests headless du conteneur semgrep-ui sur cette machine Windows (Bash cassé). À utiliser dès qu'on touche au code Docker/Flask de semgrep-web.
---

# Environnement Docker de semgrep-web (Windows)

Pièges rencontrés sur cette machine, et la façon qui marche.

## 1. Le Bash tool est CASSÉ (fork cygwin 0xC0000142)
Utiliser **PowerShell** pour tout. PowerShell n'a pas de heredoc `<<'EOF'`.
Pour passer un multi-ligne à un exe : here-string PowerShell `@'...'@` (le `'@` final en colonne 0).

## 2. Rebuild du conteneur — TOUJOURS avec l'override
Les disques Windows sont montés via `docker-compose.override.yml` (généré par `start.bat`).
Ne PAS lancer `docker compose -f docker-compose.yml ...` → ça ignore l'override → `/host` vide → scans en 400 "dossier introuvable".

```powershell
docker compose --project-directory "W:\semgrep-web" up -d --build
```

Vérifier le montage : `docker exec semgrep-ui sh -c "ls /host/w"`.
Un chemin `W:\x` devient `/host/w/x` dans le conteneur (map_path).

## 3. Valider la syntaxe Python sans python hôte
Python n'est pas installé sur l'hôte. Passer par le conteneur :

```powershell
docker cp app.py semgrep-ui:/tmp/a.py; docker exec semgrep-ui python -c "import ast;ast.parse(open('/tmp/a.py').read());print('OK')"
```

## 4. Tests headless (sans Flask/Docker de prod)
Image jetable montée sur le code :

```powershell
docker run --rm -v "W:\semgrep-web:/code" -w /code python:3.12-slim sh -c "python tests/test_characterization.py && python tests/test_versions.py"
```

## 5. Test fonctionnel end-to-end : endpoint /ci (synchrone)
`/start` est async (SSE). Pour un test scriptable, utiliser `/ci` qui bloque et renvoie counts + verdict :

```powershell
Invoke-WebRequest "http://localhost:5001/ci?path=W:\semgrep-web\_tst&scans=hadolint,python&fail_on=NONE" -UseBasicParsing
```
`fail_on=NONE` → toujours 200, lire `.Content` (JSON counts). Sinon 422 si seuil dépassé (catch l'exception).

## 6. Dossiers de test jetables
Les créer sous `W:\semgrep-web\_tst*/` (gitignored) côté HÔTE en PowerShell — PAS via `docker exec` sous /host (read-only). Nettoyer à la fin : `Remove-Item -Recurse -Force`.
