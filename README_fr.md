# ⚡ MITRE Navigator Score Analyzer

## 🌐 Langues

- 🇬🇧 English: [README.md](README.md)
- 🇫🇷 Français: [README_fr.md](README_fr.md)

---

> *« Faites confiance aux données, pas à l’interface. »*

---

## 🧠 Présentation

**MITRE Navigator Score Analyzer** est un outil Python léger conçu pour analyser les couches JSON exportées depuis MITRE ATT&CK Navigator.

Il permet d’extraire, trier et valider les techniques en fonction de leur score combiné — aidant ainsi les analystes à dépasser les ambiguïtés visuelles pour adopter une **analyse basée sur les données**.

---

## 🎯 Fonctionnalités

* 🔍 Extraction des techniques ayant un score valide à partir du JSON ATT&CK Navigator
* 📊 Identification des techniques et sous-techniques avec les scores les plus élevés
* 📈 Tri des résultats par score (décroissant)
* 🧬 Distinction entre techniques et sous-techniques
* 🔗 Génération automatique des liens Atomic Red Team
* 🏷️ Enrichissement avec les noms officiels MITRE ATT&CK depuis les sources MITRE officielles
* 📁 Export des résultats en CSV
* 📝 Génération de rapports Markdown de synthèse en complément de la sortie console et CSV
* ⚡ Utilisation en ligne de commande pour une analyse rapide

---

## ⚙️ Installation

```bash
git clone https://github.com/your-username/mitre-navigator-score-analyzer.git
cd mitre-navigator-score-analyzer
```

## 🚀 Utilisation

### Linux / macOS

```bash
python3 mitre_score_analyzer.py --file example_layer.json --top 10 --csv
python3 mitre_score_analyzer.py --file example_layer.json --csv --output reports/example.csv
python3 mitre_score_analyzer.py --file example_layer.json --top 10 --csv --markdown
python3 mitre_score_analyzer.py --file example_layer.json --top 10 --csv --markdown --lookup-names
```

### Windows

```bash
py mitre_score_analyzer.py --file example_layer.json --top 10 --csv
py mitre_score_analyzer.py --file example_layer.json --csv --output reports\example.csv
py mitre_score_analyzer.py --file example_layer.json --top 10 --csv --markdown --markdown-output reports\example.md
py mitre_score_analyzer.py --file example_layer.json --top 10 --csv --markdown --lookup-names
```

---

### Paramètres

| Argument | Description                                  |
| -------- | -------------------------------------------- |
| `--file` | Chemin vers le fichier JSON MITRE Navigator  |
| `--top`  | Nombre de techniques à afficher (défaut : 4) |
| `--csv`  | Exporter les résultats en CSV                |
| `--output` | Chemin CSV personnalisé (nécessite `--csv`) |
| `--markdown` | Générer un rapport Markdown de synthèse |
| `--markdown-output` | Chemin Markdown personnalisé (nécessite `--markdown`) |
| `--lookup-names` | Rechercher les noms des techniques depuis les sources ATT&CK officielles de MITRE |
| `--attack-domain` | Domaine ATT&CK pour la recherche : `enterprise`, `mobile` ou `ics` |
| `--lookup-timeout` | Délai maximum en secondes pour les requêtes de recherche ATT&CK |

Lorsque `--csv` est utilisé sans `--output`, l'analyseur exporte vers :

```text
output/<nom-du-fichier-source>_top_techniques.csv
```

Lorsque `--markdown` est utilisé sans `--markdown-output`, l'analyseur exporte vers :

```text
output/<nom-du-fichier-source>_report.md
```

Le fichier Markdown est pensé comme une synthèse partageable en complément de la sortie console, et peut être généré en même temps que l'export CSV.

Lorsque `--lookup-names` est activé, l'analyseur tente d'enrichir la sortie console, le CSV et le rapport Markdown avec les noms officiels ATT&CK récupérés depuis les sources TAXII et STIX officielles de MITRE. Si ces sources sont indisponibles, l'analyse continue sans les noms.

---

## 📂 Exemple de sortie

```text
======================================================================
Analyseur JSON MITRE ATT&CK Navigator
======================================================================
Fichier analysé : example_layer.json.json
Nombre total de techniques scorées : 52
Score maximal observé : 14

Top 4 des techniques :

1. T1059.001 | execution | score=14 | Sous-technique
   Atomic Red Team : https://github.com/redcanaryco/atomic-red-team/...

2. T1021.001 | lateral-movement | score=14 | Sous-technique
   Atomic Red Team : https://github.com/redcanaryco/atomic-red-team/...
```

---

## 🧩 Pourquoi cet outil ?

MITRE ATT&CK Navigator est puissant — mais son interface peut être trompeuse :

* Les sous-techniques sont cachées par défaut
* Les dégradés de couleur ne reflètent pas toujours la priorité réelle
* L’interprétation manuelle peut entraîner des erreurs

Cet outil permet :

> ✅ Une validation objective
> ✅ Une analyse reproductible
> ✅ Une priorisation précise

---

## 🛠️ Cas d’utilisation

* 🎓 Travaux académiques
* 🛡️ Analyse SOC et priorisation des techniques
* 🔎 Validation de couches MITRE ATT&CK
* ⚙️ Automatisation des workflows de modélisation de menace

---

## 🧪 Méthodologie

Cet outil suit une approche simple et robuste :

1. Analyse du fichier JSON Navigator
2. Extraction des techniques avec score numérique
3. Tri par score décroissant
4. Identification des scores les plus élevés
5. Enrichissement avec les références Atomic Red Team

---

## 🧬 Exemple de workflow

```text
MITRE Navigator → Export JSON → Analyse → Top techniques → Rapport
```

---

## 📁 Structure du projet

```text
mitre-navigator-score-analyzer/
├── README.md                     # 🇬🇧 Documentation principale (anglais)
├── README_fr.md                  # 🇫🇷 Documentation (français)
├── mitre_score_analyzer.py       # Script principal d’analyse
├── requirements.txt              # Dépendances Python (optionnel)
├── sample/
│   └── example_layer.json        # Exemple de fichier JSON MITRE Navigator
├── output/
│   └── example_top_techniques.csv # Exemple de fichier généré
└── .gitignore                   # Fichiers ignorés par Git
```

---

## ⚡ Améliorations futures

* [ ] Valider automatiquement l’existence des tests Atomic Red Team
* [ ] Générer un rapport Markdown
* [ ] Ajouter la récupération des noms/descriptions via API MITRE
* [ ] Interface web (Streamlit ?)

---

## 👩‍💻 Auteur

**CyberJess**

---

## 🧠 Philosophie

> « Se fier uniquement à l’interface, c’est risquer de manquer l’essentiel. »

---

## 📜 Licence

Licence MIT — utilisez-le, modifiez-le, améliorez-le.

---

## 🌌 Note finale

Ce projet est né d’une observation simple :

> L’interface n’est pas la vérité.
> Les données le sont.

---

✨ *Restez curieux. Restez analytiques. Restez dangereux.*
