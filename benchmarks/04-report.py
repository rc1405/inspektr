#!/usr/bin/env python3
"""04-report.py — Generate Markdown summary report and CSV exports from analysis JSON.

Reads structured JSON reports produced by 03-analyze.py and generates:
  - results/reports/summary.md  (Markdown report)
  - results/reports/*.csv       (CSV exports)

Stdlib only — no third-party dependencies.
"""

import argparse
import csv
import io
import json
import os
import sys


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SBOM_TOOLS = ["syft", "trivy", "inspektr"]
VULN_SBOM_SCANNERS = ["grype", "trivy", "inspektr"]
VULN_DIRECT_TOOLS = ["trivy", "inspektr"]

PERF_METRICS = ["wall_clock_seconds", "max_rss_kb", "cpu_time_seconds"]
PERF_STAT_FIELDS = ["mean", "median", "stddev", "min", "max", "n"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(path):
    """Load a JSON file, returning None on failure."""
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _fmt(val, decimals=2):
    """Format a numeric value for display."""
    if val is None:
        return "N/A"
    if isinstance(val, float):
        return f"{val:.{decimals}f}"
    return str(val)


def _pct(part, total):
    """Return percentage string."""
    if not total:
        return "0.0%"
    return f"{part / total * 100:.1f}%"


def _write_csv(path, headers, rows):
    """Write a CSV file."""
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)


def _md_table(headers, rows):
    """Build a Markdown table string."""
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Data Loading
# ---------------------------------------------------------------------------

def load_all_data(results_dir, reports_dir):
    """Load all JSON data files. Returns a dict of data sections."""
    data = {}

    # Environment
    data["environment"] = _load_json(os.path.join(results_dir, "environment.json"))

    # Performance
    data["performance"] = _load_json(os.path.join(reports_dir, "performance.json"))

    # Aggregates
    data["aggregates"] = _load_json(os.path.join(reports_dir, "aggregates.json"))

    # Discover image slugs from sbom report files
    slugs = []
    if os.path.isdir(reports_dir):
        for fname in sorted(os.listdir(reports_dir)):
            if fname.startswith("sbom_") and fname.endswith(".json") and fname != "sbom_performance.csv":
                slug = fname[len("sbom_"):-len(".json")]
                slugs.append(slug)
    data["slugs"] = slugs

    # Per-image reports
    data["sbom"] = {}
    data["vuln_sbom"] = {}
    data["vuln_direct"] = {}
    for slug in slugs:
        data["sbom"][slug] = _load_json(os.path.join(reports_dir, f"sbom_{slug}.json"))
        data["vuln_sbom"][slug] = _load_json(os.path.join(reports_dir, f"vuln_sbom_{slug}.json"))
        data["vuln_direct"][slug] = _load_json(os.path.join(reports_dir, f"vuln_direct_{slug}.json"))

    return data


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

def export_csvs(reports_dir, data):
    """Write all CSV exports."""
    slugs = data["slugs"]

    # --- SBOM Completeness ---
    rows = []
    for slug in slugs:
        report = data["sbom"].get(slug)
        if not report:
            continue
        per_tool = report.get("per_tool", {})
        for tool in SBOM_TOOLS:
            count = per_tool.get(tool, {}).get("package_count", 0)
            rows.append([slug, tool, count])
    _write_csv(
        os.path.join(reports_dir, "sbom_completeness.csv"),
        ["image", "generator", "total_packages"],
        rows,
    )

    # --- SBOM Overlap ---
    rows = []
    for slug in slugs:
        report = data["sbom"].get(slug)
        if not report:
            continue
        o = report.get("overlap", {})
        rows.append([
            slug,
            o.get("all_three", 0),
            o.get("syft_trivy_only", 0),
            o.get("syft_inspektr_only", 0),
            o.get("trivy_inspektr_only", 0),
            o.get("syft_only", 0),
            o.get("trivy_only", 0),
            o.get("inspektr_only", 0),
            o.get("union_total", 0),
        ])
    _write_csv(
        os.path.join(reports_dir, "sbom_overlap.csv"),
        ["image", "all_three", "syft+trivy_only", "syft+inspektr_only",
         "trivy+inspektr_only", "syft_only", "trivy_only", "inspektr_only", "union"],
        rows,
    )

    # --- Vuln SBOM Findings ---
    rows = []
    for slug in slugs:
        report = data["vuln_sbom"].get(slug)
        if not report:
            continue
        by_source = report.get("by_sbom_source", {})
        for sbom_source in SBOM_TOOLS:
            source_data = by_source.get(sbom_source, {})
            overlap = source_data.get("overlap", {})
            for scanner in VULN_SBOM_SCANNERS:
                total = overlap.get(f"{scanner}_total", 0)
                rows.append([slug, sbom_source, scanner, total])
    _write_csv(
        os.path.join(reports_dir, "vuln_sbom_findings.csv"),
        ["image", "sbom_source", "scanner", "total_vulns"],
        rows,
    )

    # --- Vuln SBOM Overlap ---
    rows = []
    for slug in slugs:
        report = data["vuln_sbom"].get(slug)
        if not report:
            continue
        by_source = report.get("by_sbom_source", {})
        for sbom_source in SBOM_TOOLS:
            source_data = by_source.get(sbom_source, {})
            o = source_data.get("overlap", {})
            rows.append([
                slug, sbom_source,
                o.get("all_three", 0),
                o.get("grype_trivy_only", 0),
                o.get("grype_inspektr_only", 0),
                o.get("trivy_inspektr_only", 0),
                o.get("grype_only", 0),
                o.get("trivy_only", 0),
                o.get("inspektr_only", 0),
                o.get("union_total", 0),
            ])
    _write_csv(
        os.path.join(reports_dir, "vuln_sbom_overlap.csv"),
        ["image", "sbom_source", "all_three", "grype+trivy_only",
         "grype+inspektr_only", "trivy+inspektr_only", "grype_only",
         "trivy_only", "inspektr_only", "union"],
        rows,
    )

    # --- Vuln Direct Findings ---
    rows = []
    for slug in slugs:
        report = data["vuln_direct"].get(slug)
        if not report:
            continue
        o = report.get("overlap", {})
        for tool in VULN_DIRECT_TOOLS:
            total = o.get(f"{tool}_total", 0)
            rows.append([slug, tool, total])
    _write_csv(
        os.path.join(reports_dir, "vuln_direct_findings.csv"),
        ["image", "scanner", "total_vulns"],
        rows,
    )

    # --- Vuln Direct Overlap ---
    rows = []
    for slug in slugs:
        report = data["vuln_direct"].get(slug)
        if not report:
            continue
        o = report.get("overlap", {})
        rows.append([
            slug,
            o.get("both", 0),
            o.get("trivy_only", 0),
            o.get("inspektr_only", 0),
            o.get("union_total", 0),
        ])
    _write_csv(
        os.path.join(reports_dir, "vuln_direct_overlap.csv"),
        ["image", "both", "trivy_only", "inspektr_only", "union"],
        rows,
    )

    # --- Performance CSVs ---
    perf = data.get("performance") or {}

    # SBOM Performance
    rows = []
    sbom_gen = perf.get("sbom_gen", {})
    for tool in SBOM_TOOLS:
        tool_data = sbom_gen.get(tool, {})
        for slug in slugs:
            stats = tool_data.get(slug, {})
            for metric in PERF_METRICS:
                rows.append([
                    slug, tool, metric,
                    _fmt(stats.get(f"{metric}_mean")),
                    _fmt(stats.get(f"{metric}_median")),
                    _fmt(stats.get(f"{metric}_stddev")),
                    _fmt(stats.get(f"{metric}_min")),
                    _fmt(stats.get(f"{metric}_max")),
                    stats.get(f"{metric}_n", 0),
                ])
    _write_csv(
        os.path.join(reports_dir, "sbom_performance.csv"),
        ["image", "generator", "metric", "mean", "median", "stddev", "min", "max", "n"],
        rows,
    )

    # Vuln SBOM Performance
    rows = []
    vuln_sbom_perf = perf.get("vuln_sbom", {})
    for scanner in VULN_SBOM_SCANNERS:
        scanner_data = vuln_sbom_perf.get(scanner, {})
        for sbom_source in SBOM_TOOLS:
            source_data = scanner_data.get(sbom_source, {})
            for slug in slugs:
                stats = source_data.get(slug, {})
                for metric in PERF_METRICS:
                    rows.append([
                        slug, sbom_source, scanner, metric,
                        _fmt(stats.get(f"{metric}_mean")),
                        _fmt(stats.get(f"{metric}_median")),
                        _fmt(stats.get(f"{metric}_stddev")),
                        _fmt(stats.get(f"{metric}_min")),
                        _fmt(stats.get(f"{metric}_max")),
                        stats.get(f"{metric}_n", 0),
                    ])
    _write_csv(
        os.path.join(reports_dir, "vuln_sbom_performance.csv"),
        ["image", "sbom_source", "scanner", "metric", "mean", "median", "stddev", "min", "max", "n"],
        rows,
    )

    # Vuln Direct Performance
    rows = []
    vuln_direct_perf = perf.get("vuln_direct", {})
    for tool in VULN_DIRECT_TOOLS:
        tool_data = vuln_direct_perf.get(tool, {})
        for slug in slugs:
            stats = tool_data.get(slug, {})
            for metric in PERF_METRICS:
                rows.append([
                    slug, tool, metric,
                    _fmt(stats.get(f"{metric}_mean")),
                    _fmt(stats.get(f"{metric}_median")),
                    _fmt(stats.get(f"{metric}_stddev")),
                    _fmt(stats.get(f"{metric}_min")),
                    _fmt(stats.get(f"{metric}_max")),
                    stats.get(f"{metric}_n", 0),
                ])
    _write_csv(
        os.path.join(reports_dir, "vuln_direct_performance.csv"),
        ["image", "scanner", "metric", "mean", "median", "stddev", "min", "max", "n"],
        rows,
    )


# ---------------------------------------------------------------------------
# Markdown Report Generation
# ---------------------------------------------------------------------------

def _section_environment(env):
    """Generate Environment section."""
    lines = ["## 1. Environment", ""]
    if not env:
        lines.append("_No environment data available._")
        return "\n".join(lines)

    lines.append(f"- **Date:** {env.get('timestamp', 'N/A')}")
    lines.append(f"- **OS:** {env.get('os', 'N/A')}")
    lines.append(f"- **Kernel:** {env.get('uname', 'N/A').split()[2] if env.get('uname') else 'N/A'}")
    lines.append(f"- **CPU:** {env.get('cpu_model', 'N/A')}")
    lines.append(f"- **Memory:** {str(env.get('memory_total_mb', 'N/A')) + ' MB' if env.get('memory_total_mb') else 'N/A'}")
    lines.append("")

    # Tool versions
    versions = env.get("tool_versions", {})
    if versions:
        lines.append("### Tool Versions")
        lines.append("")
        for tool, ver in sorted(versions.items()):
            lines.append(f"- **{tool}:** {ver}")
        lines.append("")

    # Image list
    images = env.get("images", [])
    if images:
        lines.append("### Images")
        lines.append("")
        for img in images:
            lines.append(f"- `{img}`")
        lines.append("")

    return "\n".join(lines)


def _section_executive_summary(data):
    """Generate Executive Summary section."""
    lines = ["## 2. Executive Summary", ""]
    agg = data.get("aggregates") or {}

    # SBOM Generation summary
    sbom_agg = agg.get("sbom_generation", {})
    sbom_totals = sbom_agg.get("totals_per_tool", {})
    sbom_overlap = sbom_agg.get("overlap_totals", {})
    sbom_union = sbom_overlap.get("union_total", 0)

    lines.append("### SBOM Generation (all images combined)")
    lines.append("")
    headers = ["Tool", "Total Packages", "% of Union"]
    rows = []
    for tool in SBOM_TOOLS:
        total = sbom_totals.get(tool, 0)
        rows.append([tool, total, _pct(total, sbom_union)])
    rows.append(["**Union**", sbom_union, "100.0%"])
    rows.append(["**All Three Agree**", sbom_overlap.get("all_three", 0),
                  _pct(sbom_overlap.get("all_three", 0), sbom_union)])
    lines.append(_md_table(headers, rows))
    lines.append("")

    # Vuln SBOM summary
    vuln_sbom_agg = agg.get("vuln_sbom", {})
    if vuln_sbom_agg:
        lines.append("### Vulnerability Scanning from SBOM (all images combined)")
        lines.append("")
        for sbom_source in SBOM_TOOLS:
            source_data = vuln_sbom_agg.get(sbom_source, {})
            overlap = source_data.get("overlap_totals", {})
            union = overlap.get("union_total", 0)
            lines.append(f"**SBOM Source: {sbom_source}**")
            lines.append("")
            headers = ["Scanner", "Total Vulns", "% of Union"]
            rows = []
            for scanner in VULN_SBOM_SCANNERS:
                total = overlap.get(f"{scanner}_total", 0)
                rows.append([scanner, total, _pct(total, union)])
            rows.append(["**Union**", union, "100.0%"])
            rows.append(["**All Three Agree**", overlap.get("all_three", 0),
                          _pct(overlap.get("all_three", 0), union)])
            lines.append(_md_table(headers, rows))
            lines.append("")

    # Vuln Direct summary
    vuln_direct_agg = agg.get("vuln_direct", {})
    direct_overlap = vuln_direct_agg.get("overlap_totals", {})
    direct_union = direct_overlap.get("union_total", 0)

    lines.append("### Direct Vulnerability Scanning (all images combined)")
    lines.append("")
    headers = ["Scanner", "Total Vulns", "% of Union"]
    rows = []
    for tool in VULN_DIRECT_TOOLS:
        total = direct_overlap.get(f"{tool}_total", 0)
        rows.append([tool, total, _pct(total, direct_union)])
    rows.append(["**Union**", direct_union, "100.0%"])
    rows.append(["**Both Agree**", direct_overlap.get("both", 0),
                  _pct(direct_overlap.get("both", 0), direct_union)])
    lines.append(_md_table(headers, rows))
    lines.append("")

    return "\n".join(lines)


def _section_sbom_results(data):
    """Generate SBOM Generation Results section."""
    lines = ["## 3. SBOM Generation Results", ""]
    slugs = data["slugs"]

    # Per-image package counts
    lines.append("### Package Counts per Image")
    lines.append("")
    headers = ["Image"] + [t.capitalize() for t in SBOM_TOOLS] + ["Union"]
    rows = []
    for slug in slugs:
        report = data["sbom"].get(slug)
        if not report:
            continue
        per_tool = report.get("per_tool", {})
        overlap = report.get("overlap", {})
        row = [slug]
        for tool in SBOM_TOOLS:
            row.append(per_tool.get(tool, {}).get("package_count", 0))
        row.append(overlap.get("union_total", 0))
        rows.append(row)
    lines.append(_md_table(headers, rows))
    lines.append("")

    # Overlap analysis
    lines.append("### Overlap Analysis")
    lines.append("")
    headers = ["Image", "All Three", "Syft+Trivy", "Syft+Inspektr",
               "Trivy+Inspektr", "Syft Only", "Trivy Only", "Inspektr Only", "Union"]
    rows = []
    for slug in slugs:
        report = data["sbom"].get(slug)
        if not report:
            continue
        o = report.get("overlap", {})
        rows.append([
            slug,
            o.get("all_three", 0),
            o.get("syft_trivy_only", 0),
            o.get("syft_inspektr_only", 0),
            o.get("trivy_inspektr_only", 0),
            o.get("syft_only", 0),
            o.get("trivy_only", 0),
            o.get("inspektr_only", 0),
            o.get("union_total", 0),
        ])
    lines.append(_md_table(headers, rows))
    lines.append("")

    # Performance
    lines.append("### Performance (Wall Clock, seconds)")
    lines.append("")
    perf = (data.get("performance") or {}).get("sbom_gen", {})
    headers = ["Image"] + [f"{t} (mean)" for t in SBOM_TOOLS]
    rows = []
    for slug in slugs:
        row = [slug]
        for tool in SBOM_TOOLS:
            stats = perf.get(tool, {}).get(slug, {})
            row.append(_fmt(stats.get("wall_clock_seconds_mean")))
        rows.append(row)
    lines.append(_md_table(headers, rows))
    lines.append("")

    return "\n".join(lines)


def _section_vuln_sbom_results(data):
    """Generate Vuln Scanning from SBOM Results section."""
    lines = ["## 4. Vulnerability Scanning from SBOM Results", ""]
    slugs = data["slugs"]

    for sbom_source in SBOM_TOOLS:
        lines.append(f"### SBOM Source: {sbom_source}")
        lines.append("")

        # Overlap per image
        lines.append("#### Overlap Analysis")
        lines.append("")
        headers = ["Image", "All Three", "Grype+Trivy", "Grype+Inspektr",
                   "Trivy+Inspektr", "Grype Only", "Trivy Only", "Inspektr Only", "Union"]
        rows = []
        for slug in slugs:
            report = data["vuln_sbom"].get(slug)
            if not report:
                continue
            source_data = report.get("by_sbom_source", {}).get(sbom_source, {})
            o = source_data.get("overlap", {})
            rows.append([
                slug,
                o.get("all_three", 0),
                o.get("grype_trivy_only", 0),
                o.get("grype_inspektr_only", 0),
                o.get("trivy_inspektr_only", 0),
                o.get("grype_only", 0),
                o.get("trivy_only", 0),
                o.get("inspektr_only", 0),
                o.get("union_total", 0),
            ])
        lines.append(_md_table(headers, rows))
        lines.append("")

        # Severity breakdowns
        lines.append("#### Severity Breakdown per Scanner")
        lines.append("")
        for slug in slugs:
            report = data["vuln_sbom"].get(slug)
            if not report:
                continue
            source_data = report.get("by_sbom_source", {}).get(sbom_source, {})
            sev_by_scanner = source_data.get("severity_by_scanner", {})
            if not sev_by_scanner:
                continue

            # Collect all severity levels across scanners
            all_sevs = set()
            for scanner_sevs in sev_by_scanner.values():
                all_sevs.update(scanner_sevs.keys())
            sev_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
            sevs = [s for s in sev_order if s in all_sevs]
            sevs += sorted(all_sevs - set(sev_order))

            if not sevs:
                continue

            lines.append(f"**{slug}**")
            lines.append("")
            headers = ["Scanner"] + sevs + ["Total"]
            rows = []
            for scanner in VULN_SBOM_SCANNERS:
                scanner_sevs = sev_by_scanner.get(scanner, {})
                row = [scanner]
                total = 0
                for sev in sevs:
                    count = scanner_sevs.get(sev, 0)
                    row.append(count)
                    total += count
                row.append(total)
                rows.append(row)
            lines.append(_md_table(headers, rows))
            lines.append("")

        # Performance
        lines.append("#### Performance (Wall Clock, seconds)")
        lines.append("")
        perf = (data.get("performance") or {}).get("vuln_sbom", {})
        headers = ["Image"] + [f"{s} (mean)" for s in VULN_SBOM_SCANNERS]
        rows = []
        for slug in slugs:
            row = [slug]
            for scanner in VULN_SBOM_SCANNERS:
                stats = perf.get(scanner, {}).get(sbom_source, {}).get(slug, {})
                row.append(_fmt(stats.get("wall_clock_seconds_mean")))
            rows.append(row)
        lines.append(_md_table(headers, rows))
        lines.append("")

    return "\n".join(lines)


def _section_vuln_direct_results(data):
    """Generate Direct Vuln Scanning Results section."""
    lines = ["## 5. Direct Vulnerability Scanning Results", ""]
    slugs = data["slugs"]

    # Overlap per image
    lines.append("### Overlap Analysis")
    lines.append("")
    headers = ["Image", "Both", "Trivy Only", "Inspektr Only", "Union"]
    rows = []
    for slug in slugs:
        report = data["vuln_direct"].get(slug)
        if not report:
            continue
        o = report.get("overlap", {})
        rows.append([
            slug,
            o.get("both", 0),
            o.get("trivy_only", 0),
            o.get("inspektr_only", 0),
            o.get("union_total", 0),
        ])
    lines.append(_md_table(headers, rows))
    lines.append("")

    # Severity breakdowns
    lines.append("### Severity Breakdown per Scanner")
    lines.append("")
    for slug in slugs:
        report = data["vuln_direct"].get(slug)
        if not report:
            continue
        sev_by_tool = report.get("severity_by_tool", {})
        if not sev_by_tool:
            continue

        all_sevs = set()
        for tool_sevs in sev_by_tool.values():
            all_sevs.update(tool_sevs.keys())
        sev_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
        sevs = [s for s in sev_order if s in all_sevs]
        sevs += sorted(all_sevs - set(sev_order))

        if not sevs:
            continue

        lines.append(f"**{slug}**")
        lines.append("")
        headers = ["Scanner"] + sevs + ["Total"]
        rows = []
        for tool in VULN_DIRECT_TOOLS:
            tool_sevs = sev_by_tool.get(tool, {})
            row = [tool]
            total = 0
            for sev in sevs:
                count = tool_sevs.get(sev, 0)
                row.append(count)
                total += count
            row.append(total)
            rows.append(row)
        lines.append(_md_table(headers, rows))
        lines.append("")

    # Performance
    lines.append("### Performance (Wall Clock, seconds)")
    lines.append("")
    perf = (data.get("performance") or {}).get("vuln_direct", {})
    headers = ["Image"] + [f"{t} (mean)" for t in VULN_DIRECT_TOOLS]
    rows = []
    for slug in slugs:
        row = [slug]
        for tool in VULN_DIRECT_TOOLS:
            stats = perf.get(tool, {}).get(slug, {})
            row.append(_fmt(stats.get("wall_clock_seconds_mean")))
        rows.append(row)
    lines.append(_md_table(headers, rows))
    lines.append("")

    return "\n".join(lines)


def _section_raw_data_index(reports_dir):
    """Generate Raw Data Index section."""
    lines = ["## 6. Raw Data Index", ""]
    lines.append("All JSON reports and CSV exports are located in the reports directory:")
    lines.append("")

    if os.path.isdir(reports_dir):
        for fname in sorted(os.listdir(reports_dir)):
            if fname.endswith(".json") or fname.endswith(".csv") or fname.endswith(".md"):
                lines.append(f"- `reports/{fname}`")
    lines.append("")

    return "\n".join(lines)


def generate_markdown(data, reports_dir):
    """Generate the full Markdown report."""
    sections = [
        "# Benchmark Summary Report",
        "",
        _section_environment(data.get("environment")),
        _section_executive_summary(data),
        _section_sbom_results(data),
        _section_vuln_sbom_results(data),
        _section_vuln_direct_results(data),
        _section_raw_data_index(reports_dir),
    ]
    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate Markdown summary report and CSV exports from analysis JSON."
    )
    parser.add_argument(
        "--results-dir",
        default=None,
        help="Path to results directory (default: results/ relative to script location)",
    )
    args = parser.parse_args()

    if args.results_dir:
        results_dir = os.path.abspath(args.results_dir)
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        results_dir = os.path.join(script_dir, "results")

    if not os.path.isdir(results_dir):
        print(f"Error: results directory not found: {results_dir}", file=sys.stderr)
        sys.exit(1)

    reports_dir = os.path.join(results_dir, "reports")
    if not os.path.isdir(reports_dir):
        print(f"Error: reports directory not found: {reports_dir}", file=sys.stderr)
        print("Has 03-analyze.py been run?", file=sys.stderr)
        sys.exit(1)

    # Load all data
    print("Loading analysis data...")
    data = load_all_data(results_dir, reports_dir)
    slugs = data["slugs"]

    if not slugs:
        print("No image slugs found in reports. Has 03-analyze.py been run?", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(slugs)} image slug(s): {', '.join(slugs)}")

    # Export CSVs
    print("Exporting CSVs...")
    export_csvs(reports_dir, data)
    print("  Wrote sbom_completeness.csv")
    print("  Wrote sbom_overlap.csv")
    print("  Wrote vuln_sbom_findings.csv")
    print("  Wrote vuln_sbom_overlap.csv")
    print("  Wrote vuln_direct_findings.csv")
    print("  Wrote vuln_direct_overlap.csv")
    print("  Wrote sbom_performance.csv")
    print("  Wrote vuln_sbom_performance.csv")
    print("  Wrote vuln_direct_performance.csv")

    # Generate Markdown report
    print("Generating Markdown report...")
    md = generate_markdown(data, reports_dir)
    md_path = os.path.join(reports_dir, "summary.md")
    with open(md_path, "w") as f:
        f.write(md)
    print(f"  Wrote {md_path}")

    print("Report generation complete.")


if __name__ == "__main__":
    main()
