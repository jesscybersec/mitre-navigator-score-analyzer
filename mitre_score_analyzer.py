import json
import csv
import argparse
import sys
from pathlib import Path
from typing import Any
from urllib import error, request


ATTACK_TAXII_COLLECTIONS = {
    "enterprise": "95ecc380-afe9-11e4-9b6c-751b66dd541e",
    "mobile": "2f669986-b40b-4423-b720-4396ca6a462b",
    "ics": "02c3ef24-9cd4-48f3-a99f-b74ce24f1d34",
}

ATTACK_STIX_DATASETS = {
    "enterprise": "enterprise-attack/enterprise-attack.json",
    "mobile": "mobile-attack/mobile-attack.json",
    "ics": "ics-attack/ics-attack.json",
}


def is_subtechnique(technique_id: str) -> bool:
    """Return True when the identifier matches a MITRE sub-technique."""
    return "." in technique_id


def build_atomic_link(technique_id: str) -> str:
    """
    Build the expected Atomic Red Team link for a technique or sub-technique.
    This does not guarantee the page exists, but provides the standard path.
    """
    return (
        "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/"
        f"{technique_id}/{technique_id}.md"
    )


def positive_int(value: str) -> int:
    """Validate that a CLI argument is a strictly positive integer."""
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def build_attack_taxii_url(domain: str) -> str:
    """Build the official ATT&CK TAXII URL for a given domain."""
    collection_id = ATTACK_TAXII_COLLECTIONS[domain]
    return f"https://cti-taxii.mitre.org/stix/collections/{collection_id}/objects/"


def build_attack_stix_url(domain: str) -> str:
    """Build the official ATT&CK STIX dataset URL for a given domain."""
    dataset_path = ATTACK_STIX_DATASETS[domain]
    return (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        f"{dataset_path}"
    )


def load_layer(json_file: Path) -> dict[str, Any]:
    """Load a JSON file exported from MITRE ATT&CK Navigator."""
    with json_file.open("r", encoding="utf-8") as f:
        return json.load(f)


def extract_scored_techniques(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract only techniques that have a numeric score."""
    techniques = data.get("techniques", [])
    scored = []

    for tech in techniques:
        score = tech.get("score")
        if isinstance(score, (int, float)):
            scored.append(
                {
                    "techniqueID": tech.get("techniqueID", "UNKNOWN"),
                    "technique_name": "",
                    "tactic": tech.get("tactic", ""),
                    "score": score,
                    "is_subtechnique": is_subtechnique(tech.get("techniqueID", "")),
                    "atomic_link": build_atomic_link(tech.get("techniqueID", "")),
                }
            )

    return scored


def sort_by_score(scored: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort techniques by descending score, then by ID."""
    return sorted(scored, key=lambda x: (-x["score"], x["techniqueID"]))


def export_csv(rows: list[dict[str, Any]], output_file: Path) -> None:
    """Export the results to a CSV file."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "techniqueID",
                "technique_name",
                "tactic",
                "score",
                "is_subtechnique",
                "atomic_link",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def default_output_path(json_file: Path) -> Path:
    """Build the default CSV output path from the JSON file name."""
    return Path("output") / f"{json_file.stem}_top_techniques.csv"


def external_attack_id(stix_object: dict[str, Any]) -> str | None:
    """Extract the external ATT&CK identifier from a STIX object."""
    for reference in stix_object.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def fetch_technique_name_map(domain: str, timeout: int) -> dict[str, str]:
    """Fetch ATT&CK technique names from an official MITRE source."""
    payload: dict[str, Any] | None = None
    last_error: Exception | None = None

    for url in (build_attack_taxii_url(domain), build_attack_stix_url(domain)):
        try:
            with request.urlopen(url, timeout=timeout) as response:
                payload = json.load(response)
            break
        except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            payload = None
            last_error = exc

    if payload is None:
        raise error.URLError(f"no official ATT&CK source responded: {last_error}")

    name_map: dict[str, str] = {}
    for stix_object in payload.get("objects", []):
        if stix_object.get("type") != "attack-pattern":
            continue
        if stix_object.get("revoked") or stix_object.get("x_mitre_deprecated"):
            continue

        attack_id = external_attack_id(stix_object)
        name = stix_object.get("name")
        if attack_id and name:
            name_map[attack_id] = name

    return name_map


def enrich_with_technique_names(
    rows: list[dict[str, Any]], technique_names: dict[str, str]
) -> list[dict[str, Any]]:
    """Add ATT&CK technique names to analyzed results."""
    enriched_rows = []
    for row in rows:
        enriched_row = dict(row)
        enriched_row["technique_name"] = technique_names.get(row["techniqueID"], "")
        enriched_rows.append(enriched_row)
    return enriched_rows


def render_markdown_report(
    json_file: Path,
    total_scored: int,
    max_score: int | float,
    top_limit: int,
    top_rows: list[dict[str, Any]],
    csv_output: Path | None = None,
) -> str:
    """Build a summary Markdown report from the analyzed results."""
    lines = [
        "# MITRE ATT&CK Navigator Summary Report",
        "",
        "## Summary",
        "",
        f"- Source file: `{json_file.name}`",
        f"- Total scored techniques: `{total_scored}`",
        f"- Maximum score observed: `{max_score}`",
        f"- Top results requested: `{top_limit}`",
        f"- Techniques shown in report: `{len(top_rows)}`",
        "",
        "## Outputs",
        "",
        "- Console output: enabled",
        f"- CSV export: `{csv_output}`" if csv_output else "- CSV export: not generated",
        "- Markdown report: this summary file",
        "",
        "## Top Techniques Summary",
        "",
        "| Rank | Technique ID | Name | Tactic | Score | Type | Atomic Red Team |",
        "| ---- | ------------ | ---- | ------ | ----- | ---- | --------------- |",
    ]

    for index, tech in enumerate(top_rows, start=1):
        nature = "Sub-technique" if tech["is_subtechnique"] else "Technique"
        technique_name = tech["technique_name"] or "-"
        lines.append(
            f"| {index} | {tech['techniqueID']} | {technique_name} | "
            f"{tech['tactic']} | {tech['score']} | {nature} | "
            f"[Link]({tech['atomic_link']}) |"
        )

    return "\n".join(lines) + "\n"


def export_markdown(report: str, output_file: Path) -> None:
    """Export the Markdown report to a file."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(report, encoding="utf-8")


def default_markdown_output_path(json_file: Path) -> Path:
    """Build the default Markdown output path from the JSON file name."""
    return Path("output") / f"{json_file.stem}_report.md"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze a MITRE ATT&CK Navigator JSON file and display the "
            "highest-scoring techniques."
        )
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Path to the JSON file exported from ATT&CK Navigator",
    )
    parser.add_argument(
        "--top",
        type=positive_int,
        default=4,
        help="Number of results to display (default: 4)",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Export the sorted results to CSV",
    )
    parser.add_argument(
        "--output",
        help="Path of the CSV file to generate (usable only with --csv)",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Generate a Markdown report",
    )
    parser.add_argument(
        "--markdown-output",
        help="Path of the Markdown file to generate (usable only with --markdown)",
    )
    parser.add_argument(
        "--lookup-names",
        action="store_true",
        help="Look up MITRE ATT&CK technique names from official MITRE sources",
    )
    parser.add_argument(
        "--attack-domain",
        choices=sorted(ATTACK_TAXII_COLLECTIONS),
        default="enterprise",
        help="ATT&CK domain to use for name lookup (default: enterprise)",
    )
    parser.add_argument(
        "--lookup-timeout",
        type=positive_int,
        default=15,
        help="Maximum timeout in seconds for ATT&CK name lookup (default: 15)",
    )

    args = parser.parse_args()
    json_file = Path(args.file)

    if not json_file.exists():
        raise FileNotFoundError(f"File not found: {json_file}")
    if args.output and not args.csv:
        parser.error("--output requires --csv")
    if args.markdown_output and not args.markdown:
        parser.error("--markdown-output requires --markdown")

    try:
        data = load_layer(json_file)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON file: {json_file}") from exc

    scored = extract_scored_techniques(data)

    if not scored:
        print("No scored techniques were found.")
        return

    if args.lookup_names:
        try:
            technique_names = fetch_technique_name_map(
                domain=args.attack_domain,
                timeout=args.lookup_timeout,
            )
            scored = enrich_with_technique_names(scored, technique_names)
        except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(
                "Warning: unable to retrieve ATT&CK names from official MITRE "
                f"sources ({exc}). Continuing without names.",
                file=sys.stderr,
            )

    sorted_techniques = sort_by_score(scored)
    max_score = sorted_techniques[0]["score"]
    top_n = sorted_techniques[: args.top]
    displayed_count = len(top_n)

    print("=" * 70)
    print("MITRE ATT&CK Navigator JSON Analyzer")
    print("=" * 70)
    print(f"Analyzed file: {json_file.name}")
    print(f"Total scored techniques: {len(scored)}")
    print(f"Maximum score observed: {max_score}")
    print()

    print(f"Top {displayed_count} techniques :")
    for i, tech in enumerate(top_n, start=1):
        nature = "Sub-technique" if tech["is_subtechnique"] else "Technique"
        technique_label = (
            f"{tech['techniqueID']} ({tech['technique_name']})"
            if tech["technique_name"]
            else tech["techniqueID"]
        )
        print(
            f"{i}. {technique_label} | {tech['tactic']} | "
            f"score={tech['score']} | {nature}"
        )
        print(f"   Atomic Red Team: {tech['atomic_link']}")

    csv_output_file = None

    if args.csv:
        csv_output_file = Path(args.output) if args.output else default_output_path(json_file)
        export_csv(sorted_techniques, csv_output_file)
        print()
        print(f"CSV export created: {csv_output_file}")

    if args.markdown:
        markdown_output = (
            Path(args.markdown_output)
            if args.markdown_output
            else default_markdown_output_path(json_file)
        )
        markdown_report = render_markdown_report(
            json_file=json_file,
            total_scored=len(scored),
            max_score=max_score,
            top_limit=args.top,
            top_rows=top_n,
            csv_output=csv_output_file,
        )
        export_markdown(markdown_report, markdown_output)
        print()
        print(f"Markdown report created: {markdown_output}")


if __name__ == "__main__":
    main()
