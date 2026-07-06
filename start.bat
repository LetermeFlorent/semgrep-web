@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo === stv : demarrage ===

REM --- Verifie Docker (lance Docker Desktop en arriere-plan si absent) ---
docker version >nul 2>&1
if errorlevel 1 (
  echo Docker ne repond pas. Lancement de Docker Desktop en arriere-plan...
  powershell -NoProfile -WindowStyle Hidden -Command "Start-Process '%ProgramFiles%\Docker\Docker\Docker Desktop.exe' -WindowStyle Hidden" >nul 2>&1
  echo Attente du demarrage de Docker...
  :waitdocker
  timeout /t 3 >nul
  docker version >nul 2>&1
  if errorlevel 1 goto waitdocker
)

echo Docker OK. Generation des montages disques disponibles...

REM --- Genere un override avec seulement les lecteurs qui existent (lettre minuscule cote conteneur) ---
powershell -NoProfile -Command ^
  "$l=@('services:','  semgrep-ui:','    volumes:');" ^
  "Get-PSDrive -PSProvider FileSystem | ?{ $_.Root -match '^[A-Za-z]:\\$' } | %%{ $d=$_.Name.Substring(0,1); $l += '      - \"'+$d.ToUpper()+':/:/host/'+$d.ToLower()+':ro\"' };" ^
  "Set-Content -Path 'docker-compose.override.yml' -Value $l -Encoding ascii"

echo Nettoyage ancien conteneur...
docker rm -f semgrep-ui >nul 2>&1

echo Build + up du conteneur...
docker compose up -d --build
if errorlevel 1 (
  echo ERREUR: docker compose a echoue.
  pause
  exit /b 1
)

REM --- Attend que le web reponde ---
echo Attente du serveur web...
:waitweb
timeout /t 2 >nul
powershell -NoProfile -Command "try{ (Invoke-WebRequest -UseBasicParsing http://localhost:5001 -TimeoutSec 3) | Out-Null; exit 0 }catch{ exit 1 }" >nul 2>&1
if errorlevel 1 goto waitweb

echo.
echo ============================================
echo   stv est pret : http://localhost:5001
echo ============================================
echo.
start "" "http://localhost:5001"

endlocal
