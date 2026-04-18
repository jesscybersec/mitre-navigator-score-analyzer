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
* 📁 Export des résultats en CSV
* ⚡ Utilisation en ligne de commande pour une analyse rapide

---

## ⚙️ Installation

```bash
git clone https://github.com/your-username/mitre-navigator-score-analyzer.git
cd mitre-navigator-score-analyzer
```

## 🚀 Utilisation

### Linux / macOS

```bash id="qk2z7n"
python3 mitre_score_analyzer.py --file example_layer.json --top 10 --csv
```

### Windows

```bash id="m3j5ax"
py mitre_score_analyzer.py --file example_layer.json --top 10 --csv
```

---

### Paramètres

| Argument | Description                                  |
| -------- | -------------------------------------------- |
| `--file` | Chemin vers le fichier JSON MITRE Navigator  |
| `--top`  | Nombre de techniques à afficher (défaut : 4) |
| `--csv`  | Exporter les résultats en CSV                |

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
├── README.md              # 🇬🇧 Main documentation (English)
├── README_fr.md           # 🇫🇷 Documentation (French)
├── mitre_score_analyzer.py
├── requirements.txt       # Python dependencies (optional)
├── sample/
│   └── example_layer.json # Sample MITRE Navigator export
├── output/
│   └── top_techniques.csv # Example output (generated)
└── docs/
    └── screenshots/       # Optional: tool or result screenshots
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
