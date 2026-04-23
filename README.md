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
* 🏷️ Enrich techniques with official MITRE ATT&CK names from MITRE-hosted data sources
* 📁 Export results to CSV
* 📝 Generate Markdown summary reports alongside console and CSV output
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

### Parameters

| Argument | Description                                      |
| -------- | ------------------------------------------------ |
| `--file` | Path to MITRE Navigator JSON file                |
| `--top`  | Number of top techniques to display (default: 4) |
| `--csv`  | Export results to CSV                            |
| `--output` | Custom CSV export path (requires `--csv`)      |
| `--markdown` | Generate a Markdown summary report          |
| `--markdown-output` | Custom Markdown report path (requires `--markdown`) |
| `--lookup-names` | Look up technique names from official MITRE ATT&CK data sources |
| `--attack-domain` | ATT&CK domain for name lookup: `enterprise`, `mobile`, or `ics` |
| `--lookup-timeout` | Timeout in seconds for ATT&CK name lookup requests |

When `--csv` is used without `--output`, the analyzer exports to:

```text
output/<input-file-name>_top_techniques.csv
```

When `--markdown` is used without `--markdown-output`, the analyzer exports to:

```text
output/<input-file-name>_report.md
```

The Markdown file is intended as a summary companion to the normal console output and can be generated alongside the CSV export for a more shareable report.

When `--lookup-names` is enabled, the analyzer attempts to enrich the console, CSV, and Markdown outputs with official ATT&CK technique names from MITRE's official TAXII and STIX sources. If those sources are unavailable, the analysis continues without names.

---

## 📂 Example Output

```text
======================================================================
MITRE ATT&CK Navigator JSON Analyzer
======================================================================
Analyzed file: example_layer.json
Total scored techniques: 172
Maximum score observed: 12

Top 3 techniques :

1. T1036.005 | defense-evasion | score=12 | Sub-technique
   Atomic Red Team: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md

2. T1059.001 | execution | score=12 | Sub-technique
   Atomic Red Team: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md

3. T1021.001 | lateral-movement | score=9 | Sub-technique
   Atomic Red Team: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md

CSV export created: output\example_layer_top_techniques.csv
Markdown report created: output\example_layer_report.md
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
├── README.md                     # 🇬🇧 Main documentation (English)
├── README_fr.md                  # 🇫🇷 Documentation (French)
├── example_layer.json            # Sample MITRE Navigator JSON file
├── mitre_score_analyzer.py       # Main analysis script
├── requirements.txt              # Python dependencies (optional)
├── output/
│   ├── example_top_techniques.csv # Example CSV output
│   └── example_report.md          # Example Markdown summary
└── .gitignore                   # Ignore generated files
```

---

## ⚡ Future Improvements

* [x] Validate existence of Atomic Red Team tests automatically
* [x] Generate Markdown report
* [x] Add MITRE technique name lookup via API
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
