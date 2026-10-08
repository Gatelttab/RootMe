# Solutions Root-Me

Mes writeups et scripts de résolution des challenges [Root-Me](https://www.root-me.org/fr/Challenges/), rangés selon les catégories du site.

> ⚠️ **Dépôt à garder privé.** Les solutions contiennent les flags en clair, et la charte Root-Me interdit de diffuser les solutions.

## Progression

| Catégorie | Root-Me | Résolus |
|-----------|---------|:-------:|
| [App - Script](App-Script/) | [lien](https://www.root-me.org/fr/Challenges/App-Script/) | 0 |
| [App - Système](App-Systeme/) | [lien](https://www.root-me.org/fr/Challenges/App-Systeme/) | 0 |
| [Cracking](Cracking/) | [lien](https://www.root-me.org/fr/Challenges/Cracking/) | 0 |
| [Cryptanalyse](Cryptanalyse/) | [lien](https://www.root-me.org/fr/Challenges/Cryptanalyse/) | 0 |
| [Forensic](Forensic/) | [lien](https://www.root-me.org/fr/Challenges/Forensic/) | 0 |
| [Programmation](Programmation/) | [lien](https://www.root-me.org/fr/Challenges/Programmation/) | 0 |
| [Réaliste](Realiste/) | [lien](https://www.root-me.org/fr/Challenges/Realiste/) | 0 |
| [Réseau](Reseau/) | [lien](https://www.root-me.org/fr/Challenges/Reseau/) | 0 |
| [Stéganographie](Steganographie/) | [lien](https://www.root-me.org/fr/Challenges/Steganographie/) | 0 |
| [Web - Client](Web-Client/) | [lien](https://www.root-me.org/fr/Challenges/Web-Client/) | 0 |
| [Web - Serveur](Web-Serveur/) | [lien](https://www.root-me.org/fr/Challenges/Web-Serveur/) | 0 |

## Organisation

Chaque challenge a son propre dossier dans sa catégorie :

```
<Catégorie>/<Nom-du-challenge>/
├── README.md     # writeup (copié depuis TEMPLATE.md)
├── solve.py      # scripts éventuels
└── ...           # captures, fichiers annexes
```

Conventions :

- Le nom du dossier reprend le nom du challenge en kebab-case, sans accents ni espaces (ex. `Web-Serveur/HTML-Code-source/`).
- Le writeup part de [TEMPLATE.md](TEMPLATE.md).
- Une fois le challenge ajouté, mettre à jour le tableau du `README.md` de la catégorie et le compteur ci-dessus.
- Les fichiers volumineux téléchargés depuis Root-Me (binaires, archives, dumps) vont dans un sous-dossier `_downloads/`, ignoré par git.
