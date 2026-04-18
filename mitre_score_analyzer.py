import json
import csv
import argparse
from pathlib import Path
from typing import Any


def is_subtechnique(technique_id: str) -> bool:
    """Retourne True si l'identifiant correspond à une sous-technique MITRE."""
    return "." in technique_id


def build_atomic_link(technique_id: str) -> str:
    """
    Génère le lien Atomic Red Team attendu pour une technique ou sous-technique.
    Cela ne garantit pas que la page existe, mais fournit le chemin standard.
    """
    return (
        "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/"
        f"{technique_id}/{technique_id}.md"
    )


def load_layer(json_file: Path) -> dict[str, Any]:
    """Charge le fichier JSON exporté depuis MITRE ATT&CK Navigator."""
    with json_file.open("r", encoding="utf-8") as f:
        return json.load(f)


def extract_scored_techniques(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extrait uniquement les techniques ayant un score numérique."""
    techniques = data.get("techniques", [])
    scored = []

    for tech in techniques:
        score = tech.get("score")
        if isinstance(score, (int, float)):
            scored.append(
                {
                    "techniqueID": tech.get("techniqueID", "UNKNOWN"),
                    "tactic": tech.get("tactic", ""),
                    "score": score,
                    "is_subtechnique": is_subtechnique(tech.get("techniqueID", "")),
                    "atomic_link": build_atomic_link(tech.get("techniqueID", "")),
                }
            )

    return scored


def sort_by_score(scored: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Trie les techniques par score décroissant, puis par ID."""
    return sorted(scored, key=lambda x: (-x["score"], x["techniqueID"]))


def export_csv(rows: list[dict[str, Any]], output_file: Path) -> None:
    """Exporte les résultats dans un fichier CSV."""
    with output_file.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "techniqueID",
                "tactic",
                "score",
                "is_subtechnique",
                "atomic_link",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyse un fichier JSON MITRE ATT&CK Navigator et affiche les techniques avec les scores les plus élevés."
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Chemin vers le fichier JSON exporté depuis ATT&CK Navigator",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=4,
        help="Nombre de résultats à afficher (défaut: 4)",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Exporter les résultats triés en CSV",
    )

    args = parser.parse_args()
    json_file = Path(args.file)

    if not json_file.exists():
        raise FileNotFoundError(f"Fichier introuvable : {json_file}")

    data = load_layer(json_file)
    scored = extract_scored_techniques(data)

    if not scored:
        print("Aucune technique avec score n'a été trouvée.")
        return

    sorted_techniques = sort_by_score(scored)
    max_score = sorted_techniques[0]["score"]
    top_n = sorted_techniques[: args.top]

    print("=" * 70)
    print("MITRE ATT&CK Navigator JSON Analyzer")
    print("=" * 70)
    print(f"Fichier analysé : {json_file.name}")
    print(f"Nombre total de techniques scorées : {len(scored)}")
    print(f"Score maximal observé : {max_score}")
    print()

    print(f"Top {args.top} techniques :")
    for i, tech in enumerate(top_n, start=1):
        nature = "Sous-technique" if tech["is_subtechnique"] else "Technique"
        print(
            f"{i}. {tech['techniqueID']} | {tech['tactic']} | "
            f"score={tech['score']} | {nature}"
        )
        print(f"   Atomic Red Team : {tech['atomic_link']}")

    if args.csv:
        output_file = Path("top_techniques.csv")
        export_csv(sorted_techniques, output_file)
        print()
        print(f"Export CSV créé : {output_file}")


if __name__ == "__main__":
    main()