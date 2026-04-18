# ⚡ MITRE Navigator Score Analyzer

## 🌐 Languages

- 🇬🇧 English: [README.md](README.md)
- 🇫🇷 Français: [README_fr.md](README_fr.md)

---

> *“Trust the data, not the interface.”*

---

## 🧠 Overview

**MITRE Navigator Score Analyzer** is a lightweight Python tool designed to analyze JSON layers exported from the MITRE ATT&CK Navigator.

It extracts, ranks, and validates techniques based on their combined score — helping analysts move beyond visual ambiguity and into **data-driven threat analysis**.

---

## 🎯 Features

* 🔍 Extract techniques with valid scores from ATT&CK Navigator JSON
* 📊 Identify highest-scoring techniques and sub-techniques
* 📈 Sort results by score (descending)
* 🧬 Distinguish techniques vs sub-techniques
* 🔗 Generate Atomic Red Team links automatically
* 📁 Export results to CSV
* ⚡ CLI-based for fast analysis

---

## ⚙️ Installation

```bash
git clone https://github.com/your-username/mitre-navigator-score-analyzer.git
cd mitre-navigator-score-analyzer
```

## 🚀 Usage

### Linux / macOS

```bash
python3 mitre_score_analyzer.py --file layer.json --top 10 --csv
```

### Windows

```bash
py mitre_score_analyzer.py --file layer.json --top 10 --csv
```

---

### Parameters

| Argument | Description                                      |
| -------- | ------------------------------------------------ |
| `--file` | Path to MITRE Navigator JSON file                |
| `--top`  | Number of top techniques to display (default: 4) |
| `--csv`  | Export results to CSV                            |

---

## 📂 Example Output

```text
======================================================================
MITRE ATT&CK Navigator JSON Analyzer
======================================================================
File analyzed: example_layer.json
Total scored techniques: 52
Max score observed: 14

Top 4 techniques:

1. T1059.001 | execution | score=14 | Sub-technique
   Atomic Red Team: https://github.com/redcanaryco/atomic-red-team/...

2. T1021.001 | lateral-movement | score=14 | Sub-technique
   Atomic Red Team: https://github.com/redcanaryco/atomic-red-team/...
```

---

## 🧩 Why this tool?

The MITRE ATT&CK Navigator is powerful — but its interface can be misleading:

* Sub-techniques are hidden by default
* Visual gradients do not always reflect true priority
* Manual interpretation can lead to errors

This tool ensures:

> ✅ Objective validation
> ✅ Reproducible analysis
> ✅ Accurate prioritization

---

## 🛠️ Use Cases

* 🎓 Academic work
* 🛡️ SOC analysis and technique prioritization
* 🔎 Validation of ATT&CK Navigator layers
* ⚙️ Automation of threat modeling workflows

---

## 🧪 Methodology

This tool follows a simple but robust approach:

1. Parse Navigator JSON layer
2. Extract techniques with numeric scores
3. Sort by score (descending)
4. Identify highest scoring entries
5. Enrich with Atomic Red Team references

---

## 🧬 Example Workflow

```text
MITRE Navigator → Export JSON → Analyzer → Top Techniques → Report
```

---

## 📁 Project Structure

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

## ⚡ Future Improvements

* [ ] Validate existence of Atomic Red Team tests automatically
* [ ] Generate Markdown report
* [ ] Add MITRE technique name lookup via API
* [ ] Web interface (Streamlit?)

---

## 👩‍💻 Author

**CyberJess**

---

## 🧠 Philosophy

> “If you rely only on what you see, you will miss what matters.”

---

## 📜 License

MIT License — use it, break it, improve it.

---

## 🌌 Final Note

This project was born from a simple realization:

> The interface is not the truth.
> The data is.

---

✨ *Stay curious. Stay analytical. Stay dangerous.*
