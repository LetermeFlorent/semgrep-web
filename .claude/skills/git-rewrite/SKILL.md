---
name: git-rewrite
description: Réécrire des messages de commit sur cette machine Windows où git filter-branch/rebase interactif échouent (fork cygwin). Utiliser quand il faut nettoyer des trailers ou messages de commits déjà faits.
---

# Réécrire des commits quand filter-branch est cassé

Sur cette machine, `git filter-branch` et `git rebase -i` **échouent** (fork cygwin
`0xC0000142`, mêmes que le Bash tool). Ne pas les utiliser.

## Méthode qui marche : commit-tree

Recréer les commits à partir de leur arbre (contenu inchangé), avec un message propre.
Exemple : retirer un trailer `Co-Authored-By` des 2 derniers commits, base = `<BASE>`.

```powershell
$t1 = git rev-parse '<sha1>^{tree}'      # arbre du 1er commit à recréer
$t2 = git rev-parse '<sha2>^{tree}'      # arbre du 2e
$msg1 = @'
Titre commit 1

Corps sans le trailer.
'@
$msg2 = @'
Titre commit 2

Corps sans le trailer.
'@
$c1 = $msg1 | git commit-tree $t1 -p <BASE>
$c2 = $msg2 | git commit-tree $t2 -p $c1
git reset --hard $c2
```

## Vérifs avant push
```powershell
# le trailer a bien disparu (doit valoir 0)
((git log <BASE>..HEAD --format="%B") -match "Co-Authored").Count
# l'arbre final est identique à l'ancien HEAD (aucun code perdu ; 0 = identique)
(git diff <ancien_HEAD> HEAD --stat | Measure-Object).Count
```
Puis `git push --force-with-lease origin main`.

## Notes
- Les here-strings `@'...'@` gardent le texte littéral (pas d'expansion `$`). Le `'@` de
  fermeture doit être en colonne 0.
- L'auteur/committer restent ceux configurés (`git config user.name/email`) — vérifier
  avec `git log --format="%an <%ae>"` qu'aucun "claude" ne traîne.
- Un `@claude` sur la page GitHub "Contributors" après nettoyage = cache de rendu ;
  l'API (`gh api repos/<o>/<r>/contributors`) est la source de vérité.
