# Writeup : Root-Me, Flash - Authentification

| | |
|---|---|
| **Catégorie** | Cracking / Reverse engineering |
| **Fichier** | `RootMe.swf` (Flash, version 14) |
| **Outils** | Python 3, JPEXS Free Flash Decompiler (FFDec), Ruffle |
| **Mot de passe** | `141432434322` |

---

## 1. Résumé

Le challenge présente une application Flash : un pavé de 4 carrés numérotés de 1 à 4. Il faut trouver la bonne séquence de clics pour être authentifié.

Le SWF fourni n'est qu'un **chargeur** : il contient un second SWF chiffré par XOR. Une fois ce SWF interne déchiffré et décompilé, on comprend que chaque clic construit une chaîne de caractères, dont le **MD5 de l'inverse** est envoyé à la page. La page compare ce hash à une valeur fixe. Comme l'espace de recherche est minuscule, on retrouve la chaîne par force brute, puis on remonte à la séquence de clics, qui est le mot de passe.

---

## 2. Contexte : Flash n'existe plus

Le plugin Adobe Flash Player n'est plus disponible depuis fin 2020. Plutôt que d'essayer de le réinstaller, deux approches sont possibles :

- **Analyse statique** avec un décompilateur (FFDec) : c'est ce qui résout le challenge.
- **Émulation** avec [Ruffle](https://ruffle.rs) (extension de navigateur) pour afficher le SWF et cliquer sur les boutons, utile pour la validation finale.

---

## 3. Analyse du SWF d'origine

### 3.1 Identification

```
$ file RootMe.swf
RootMe.swf: Macromedia Flash data (compressed), version 14
```

La signature `CWS` indique un SWF compressé en zlib. On le décompresse en gardant les 8 premiers octets de l'en-tête (signature, version, taille) :

```python
import zlib

d = open('RootMe.swf', 'rb').read()
raw = zlib.decompress(d[8:])
open('out.swf', 'wb').write(b'FWS' + d[3:8] + raw)
```

### 3.2 Extraction des chaînes

Un `strings` sur le contenu décompressé révèle des indices importants :

```
RootMe_EmbeddedSWF
ByteArrayAsset
rootmeifyoucan
XOR
charCodeAt
Loader
loadBytes
```

On comprend le mécanisme sans même décompiler :

- `EmbeddedSWF` et `ByteArrayAsset` : un fichier binaire est embarqué dans le SWF.
- `XOR`, `charCodeAt` et la chaîne `rootmeifyoucan` : ce binaire est déchiffré par XOR avec la clé `rootmeifyoucan`.
- `Loader.loadBytes` : le résultat est ensuite chargé et exécuté comme un nouveau SWF.

---

## 4. Extraction du SWF interne

Le binaire embarqué se trouve dans un tag **`DefineBinaryData`** (type 87). Ses données commencent après 6 octets : 2 octets pour l'identifiant du caractère, puis 4 octets réservés.

```python
import struct

raw = open('out.swf', 'rb').read()

# Taille du RECT de l'en-tête, puis frame rate + frame count
nbits = raw[8] >> 3
rect = (5 + nbits * 4 + 7) // 8
pos = 8 + rect + 4

key = b'rootmeifyoucan'

while pos < len(raw):
    header = struct.unpack('<H', raw[pos:pos + 2])[0]
    tag_type, length = header >> 6, header & 0x3f
    pos += 2
    if length == 0x3f:                       # tag "long"
        length = struct.unpack('<I', raw[pos:pos + 4])[0]
        pos += 4
    if tag_type == 87:                       # DefineBinaryData
        data = raw[pos + 6:pos + length]
        dec = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        open('inner.swf', 'wb').write(dec)
    pos += length
```

Le résultat commence par `CWS` : c'est un autre SWF compressé. On le décompresse comme à l'étape 3.1 pour obtenir `inner_raw.swf`.

---

## 5. Décompilation du SWF interne

On ouvre `inner_raw.swf` dans **FFDec** (ou en ligne de commande) :

```
java -jar ffdec-cli.jar -export script src inner_raw.swf
```

Le dossier `src/scripts/` contient :

- `Main3.as` : la logique de l'application (c'est ce qui nous intéresse) ;
- `com/hurlant/crypto/hash/MD5.as` et `IHash.as` : une implémentation d'MD5 en ActionScript ;
- `com/hurlant/util/Hex.as` : des utilitaires hexadécimaux.

### 5.1 Les 4 carrés

Le constructeur de `Main3` dessine 4 carrés de 50x50 pixels en grille 2x2, avec un chiffre dans chacun :

```
┌─────┐ ┌─────┐
│  1  │ │  2  │
└─────┘ └─────┘
┌─────┐ ┌─────┐
│  3  │ │  4  │
└─────┘ └─────┘
```

Le constructeur définit 4 couleurs stockées en entiers. Trois d'entre elles servent de **valeurs de calcul** dans le gestionnaire de clic (section suivante) :

| Carré | Variable lue par le gestionnaire | Valeur décimale |
|---|---|---|
| 1 (haut-gauche) | `_9AkQo` | `11266775` |
| 2 (haut-droite) | `_YrqkY` | `11146309` |
| 3 (bas-gauche) | `_CKDjY` | `7884889` |
| 4 (bas-droite) | aucune (retour arrière) | n/a |

Attention : le carré 3 lit `_CKDjY`, qui est la couleur de remplissage du carré 4 (le dessin et la logique ne suivent pas le même ordre). C'est un piège de lecture : il faut suivre les variables réellement utilisées dans le `switch`, pas l'ordre visuel.

### 5.2 Le gestionnaire de clic

La méthode `_1pFaN` est appelée à chaque clic. Voici sa logique simplifiée :

```actionscript
switch (param1.currentTarget) {
    case carre1:
        _loc2_ = (this._9AkQo >> 16 & 0xFF).toString(16).toUpperCase();
        this._e4G79 += _loc2_;
        break;
    case carre2:
        _loc2_ = (this._YrqkY >> 8 & 0xFF).toString(16).toUpperCase();
        this._e4G79 += _loc2_;
        break;
    case carre3:
        _loc2_ = (this._CKDjY & 0xFF).toString(16).toUpperCase();
        this._e4G79 += _loc2_;
        break;
    case carre4:
        if (this._e4G79.length > 1) {
            this._e4G79 = this._e4G79.slice(0, -1);
        }
}

var hash = MD5.hash(inverse(this._e4G79));

if (this._e4G79.length >= 12) {
    ExternalInterface.call("l1", Hex.fromArray(hash));
    this._e4G79 = "";
}
```

On en déduit :

1. Chaque carré 1, 2 ou 3 **ajoute un octet en hexadécimal** (en majuscules) à une chaîne.
2. Le carré 4 **efface le dernier caractère** (si la chaîne en compte plus d'un).
3. Dès que la chaîne atteint **12 caractères ou plus**, le **MD5 de la chaîne inversée** est envoyé à la fonction JavaScript `l1` de la page, puis la chaîne est remise à zéro.

### 5.3 Valeurs ajoutées par chaque carré

Un petit calcul des opérations binaires :

```python
format((11266775 >> 16) & 0xFF, 'X')   # carré 1 -> 'AB'
format((11146309 >>  8) & 0xFF, 'X')   # carré 2 -> '14'
format(  7884889        & 0xFF, 'X')   # carré 3 -> '59'
```

| Carré | Effet |
|---|---|
| 1 | ajoute `AB` |
| 2 | ajoute `14` |
| 3 | ajoute `59` |
| 4 | retour arrière (supprime 1 caractère) |

Remarque : le retour arrière retire **un caractère**, pas un bloc entier. On peut donc couper un bloc en deux (`AB` devient `A`, `14` devient `1`, `59` devient `5`).

---

## 6. La fonction `l1` côté page

`ExternalInterface.call("l1", hash)` n'appelle pas une fonction du SWF : elle exécute la fonction JavaScript `l1` définie **dans la page web**. Elle ne se trouve donc pas dans FFDec, mais dans le code source de la page du challenge (`Ctrl+U`, puis recherche de `l1`).

En lisant ce code, on trouve le hash MD5 attendu :

```
dbbcd6ee441aa6d2889e6e3cae6adebe
```

Si le hash envoyé par le SWF est égal à celui-ci, la page affiche « Authentication success ».

---

## 7. Retrouver la chaîne par force brute

On cherche une chaîne `s` telle que `MD5(inverse(s)) == dbbcd6ee441aa6d2889e6e3cae6adebe`.

### 7.1 Espace de recherche

La chaîne est une concaténation de **jetons**. Les jetons possibles sont les 3 blocs complets et leurs versions coupées par le retour arrière :

```
AB   14   59   A   1   5
```

(Un bloc coupé à zéro caractère n'est pas possible : le retour arrière ne s'applique pas à une chaîne d'un seul caractère, et un bloc supprimé en entier revient à ne pas l'avoir saisi.)

La chaîne a une longueur de **12 ou 13** caractères au moment de l'envoi : 12 si le dernier clic ajoute un caractère à 11, 13 si c'est un bloc de 2 caractères ajouté à 11. L'espace est donc très petit.

### 7.2 Script

```python
import hashlib

target = "dbbcd6ee441aa6d2889e6e3cae6adebe"
tokens = ["AB", "14", "59", "A", "1", "5"]
found = []

def rec(s):
    if len(s) in (12, 13):
        if hashlib.md5(s[::-1].encode()).hexdigest() == target:
            found.append(s)
    if len(s) >= 13:
        return
    for t in tokens:
        rec(s + t)

rec("")
print(found)
```

Résultat :

```
['AA5915591414']
```

On peut vérifier à la main :

```python
>>> import hashlib
>>> hashlib.md5("AA5915591414"[::-1].encode()).hexdigest()
'dbbcd6ee441aa6d2889e6e3cae6adebe'
```

(Un premier essai avec uniquement des blocs entiers, sans retour arrière, ne donne aucun résultat : c'est ce qui indique qu'il faut utiliser le carré 4.)

---

## 8. Retrouver la séquence de clics

Il reste à décomposer `AA5915591414` en clics, en tenant compte du retour arrière :

```
AA 59 1 5 59 14 14
```

| Clics | Chaîne obtenue | Explication |
|---|---|---|
| 1, 4 | `A` | `AB` puis suppression du `B` |
| 1, 4 | `AA` | idem |
| 3 | `AA59` | bloc `59` |
| 2, 4 | `AA591` | `14` puis suppression du `4` |
| 3, 4 | `AA5915` | `59` puis suppression du `9` |
| 3 | `AA591559` | bloc `59` |
| 2 | `AA59155914` | bloc `14` |
| 2 | `AA5915591414` | bloc `14`, 12 caractères atteints : envoi du hash |

La séquence complète des carrés cliqués est donc :

```
1, 4, 1, 4, 3, 2, 4, 3, 4, 3, 2, 2
```

---

## 9. Validation

En cliquant cette séquence sur le pavé (avec Ruffle dans le navigateur), la page affiche **« Authentication success »**.

Le mot de passe à valider sur Root-Me est la suite des numéros de carrés cliqués, concaténés :

```
141432434322
```

Remarque : le mot de passe n'est donc **pas** la chaîne intermédiaire `AA5915591414` ni le hash, mais la séquence de chiffres des carrés cliqués.

---

## 10. Résumé de la chaîne d'attaque

```
RootMe.swf
   │  décompression zlib + lecture des chaînes
   ▼
SWF chargeur + binaire embarqué
   │  XOR avec la clé "rootmeifyoucan"
   ▼
inner_raw.swf  (classe Main3)
   │  décompilation (FFDec)
   ▼
Logique : clic -> octet hex, retour arrière, MD5(inverse) envoyé à l1
   │  lecture du code JS de la page
   ▼
Hash cible : dbbcd6ee441aa6d2889e6e3cae6adebe
   │  force brute sur les jetons {AB, 14, 59, A, 1, 5}
   ▼
Chaîne : AA5915591414
   │  décomposition en clics
   ▼
Mot de passe : 141432434322
```

---

## 11. Leçons retenues

- **Un SWF peut en cacher un autre.** Les chaînes `Loader`, `loadBytes`, `XOR` et une clé en clair sont le signe d'un chargement de code chiffré.
- **Chercher le code JavaScript de la page** quand on voit `ExternalInterface.call` : la fonction appelée n'est pas dans le SWF.
- **Réduire l'espace de recherche avant de forcer.** Comprendre que seuls 3 blocs fixes existent (plus leurs troncatures) rend la force brute instantanée.
- **Le détail du retour arrière compte** : il supprime un caractère, pas un bloc, ce qui élargit les jetons possibles.
- **Se méfier de l'hypothèse de départ.** La première recherche, limitée aux blocs entiers, ne donnait rien : relire le code a permis de corriger l'hypothèse.

## 12. Outils

- [JPEXS Free Flash Decompiler](https://github.com/jindrapetrik/jpexs-decompiler) : décompilation ActionScript.
- [Ruffle](https://ruffle.rs) : émulateur Flash pour exécuter le SWF.
- Python 3 : décompression, déchiffrement XOR et force brute.
