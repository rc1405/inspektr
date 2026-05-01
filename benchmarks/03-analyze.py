#!/usr/bin/env python3
"""03-analyze.py — Analyze benchmark results and produce structured JSON reports.

Reads raw scan output from results/, normalizes findings, computes overlaps,
performance statistics, and writes structured JSON reports.

Stdlib only — no third-party dependencies.
"""

import argparse
import json
import math
import os
import re
import sys
from urllib.parse import unquote


# ---------------------------------------------------------------------------
# SBOM Normalization
# ---------------------------------------------------------------------------

def _normalize_purl(purl):
    """Normalize a PURL for cross-tool comparison.

    - Strip qualifiers (?arch=..., &distro=...)
    - Percent-decode (%2B → +)
    - Lowercase (Go module paths are case-sensitive but PURLs should be compared case-insensitively)
    - Strip Debian epoch prefix from version (1:2.38.1 → 2.38.1)
    """
    base = purl.split("?")[0]
    base = unquote(base)
    base = base.lower()
    base = re.sub(r"@\d+:", "@", base)
    return base


def normalize_cyclonedx_packages(cdx_json):
    """Extract packages from CycloneDX JSON.

    Returns a set of normalized PURL strings for cross-tool comparison.
    Skips components without a PURL (operating-system entries, etc.).
    """
    packages = set()
    components = cdx_json.get("components", [])
    for comp in components:
        purl = comp.get("purl", "")
        if not purl:
            continue
        packages.add(_normalize_purl(purl))
    return packages


# ---------------------------------------------------------------------------
# Vulnerability Normalization
# ---------------------------------------------------------------------------

def _normalize_cve_id(cve_id):
    """Normalize a CVE identifier for cross-tool comparison.

    Strips ecosystem prefixes: DEBIAN-CVE-2024-1234 → CVE-2024-1234
    """
    # Extract embedded CVE from prefixed IDs
    idx = cve_id.find("-CVE-")
    if idx >= 0:
        return cve_id[idx + 1:]
    return cve_id


def normalize_grype_vulns(grype_json):
    """Normalize Grype vulnerability JSON output.

    Returns (vulns_set, severities_dict) where vulns_set contains CVE ID
    strings. Package names are excluded from the comparison key because
    tools use different conventions (binary vs source package names) for
    the same vulnerability.
    """
    vulns = set()
    severities = {}
    matches = grype_json.get("matches", [])
    for match in matches:
        vuln = match.get("vulnerability", {})
        cve_id = _normalize_cve_id(vuln.get("id", ""))
        severity = vuln.get("severity", "Unknown")

        if cve_id:
            vulns.add(cve_id)
            severities[cve_id] = severity.capitalize()
    return vulns, severities


def normalize_trivy_vulns(trivy_json):
    """Normalize Trivy vulnerability JSON output.

    Returns (vulns_set, severities_dict) where vulns_set contains CVE ID
    strings.
    """
    vulns = set()
    severities = {}
    results = trivy_json.get("Results", [])
    for result in results:
        for v in result.get("Vulnerabilities", []) or []:
            cve_id = _normalize_cve_id(v.get("VulnerabilityID", ""))
            severity = v.get("Severity", "Unknown")

            if cve_id:
                vulns.add(cve_id)
                severities[cve_id] = severity.capitalize()
    return vulns, severities


_SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "NONE": 1,
    "UNKNOWN": 0,
}


def _pick_highest_severity(candidates):
    """Given an iterable of severity strings, return the most severe one.

    Inspektr records a per-source assessment (OSV, NVD, etc.) for each vuln,
    and the sources may disagree. For reporting we collapse to whichever is
    most severe — matches how downstream tooling and humans usually interpret
    multi-source data.
    """
    best = "Unknown"
    best_rank = -1
    for sev in candidates:
        if not sev:
            continue
        rank = _SEVERITY_RANK.get(sev.upper(), 0)
        if rank > best_rank:
            best_rank = rank
            best = sev.capitalize()
    return best


def normalize_inspektr_vulns(inspektr_json):
    """Normalize Inspektr vulnerability JSON output.

    Returns (vulns_set, severities_dict) where vulns_set contains CVE ID
    strings.
    """
    vulns = set()
    severities = {}
    for v in inspektr_json.get("vulnerabilities", []):
        cve_id = _normalize_cve_id(v.get("id", ""))

        assessments = v.get("assessments") or {}
        severity = _pick_highest_severity(
            a.get("severity") for a in assessments.values() if isinstance(a, dict)
        )

        if cve_id:
            vulns.add(cve_id)
            severities[cve_id] = severity
    return vulns, severities


# Lookup table for normalizer per scanner name
VULN_NORMALIZERS = {
    "grype": normalize_grype_vulns,
    "trivy": normalize_trivy_vulns,
    "inspektr": normalize_inspektr_vulns,
}


# ---------------------------------------------------------------------------
# Overlap Computation
# ---------------------------------------------------------------------------

def compute_three_way_overlap(set_a, set_b, set_c, label_a, label_b, label_c):
    """Compute three-way set overlap statistics.

    Returns a dict with all_three, each pair-only, each single-only, and totals.
    """
    all_three = set_a & set_b & set_c
    ab_only = (set_a & set_b) - set_c
    ac_only = (set_a & set_c) - set_b
    bc_only = (set_b & set_c) - set_a
    a_only = set_a - set_b - set_c
    b_only = set_b - set_a - set_c
    c_only = set_c - set_a - set_b
    union = set_a | set_b | set_c

    return {
        "all_three": len(all_three),
        f"{label_a}_{label_b}_only": len(ab_only),
        f"{label_a}_{label_c}_only": len(ac_only),
        f"{label_b}_{label_c}_only": len(bc_only),
        f"{label_a}_only": len(a_only),
        f"{label_b}_only": len(b_only),
        f"{label_c}_only": len(c_only),
        f"{label_a}_total": len(set_a),
        f"{label_b}_total": len(set_b),
        f"{label_c}_total": len(set_c),
        "union_total": len(union),
    }


def compute_two_way_overlap(set_a, set_b, label_a, label_b):
    """Compute two-way set overlap statistics.

    Returns a dict with both, each single-only, and totals.
    """
    both = set_a & set_b
    a_only = set_a - set_b
    b_only = set_b - set_a
    union = set_a | set_b

    return {
        "both": len(both),
        f"{label_a}_only": len(a_only),
        f"{label_b}_only": len(b_only),
        f"{label_a}_total": len(set_a),
        f"{label_b}_total": len(set_b),
        "union_total": len(union),
    }


def severity_breakdown(vuln_set, severities):
    """Count vulnerabilities by severity level within a set."""
    counts = {}
    for cve_id in vuln_set:
        sev = severities.get(cve_id, "Unknown")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Performance Statistics
# ---------------------------------------------------------------------------

def _stddev(values, mean):
    """Population standard deviation."""
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def compute_perf_stats(timing_files):
    """Compute performance statistics from a list of timing JSON file paths.

    Returns dict with mean/median/stddev/min/max for wall_clock_seconds,
    max_rss_kb, and cpu_time_seconds (user + system).
    """
    wall_clocks = []
    rss_values = []
    cpu_times = []

    for tf in timing_files:
        try:
            with open(tf, "r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue

        # Skip failed runs
        if data.get("exit_code", 0) != 0:
            continue

        wall_clocks.append(float(data.get("wall_clock_seconds", 0)))
        rss_values.append(float(data.get("max_rss_kb", 0)))
        user_t = float(data.get("user_time_seconds", 0))
        sys_t = float(data.get("system_time_seconds", 0))
        cpu_times.append(user_t + sys_t)

    def stats_for(values, label):
        if not values:
            return {f"{label}_mean": None, f"{label}_median": None,
                    f"{label}_stddev": None, f"{label}_min": None,
                    f"{label}_max": None, f"{label}_n": 0}
        values_sorted = sorted(values)
        n = len(values_sorted)
        mean = sum(values_sorted) / n
        if n % 2 == 1:
            median = values_sorted[n // 2]
        else:
            median = (values_sorted[n // 2 - 1] + values_sorted[n // 2]) / 2
        return {
            f"{label}_mean": round(mean, 4),
            f"{label}_median": round(median, 4),
            f"{label}_stddev": round(_stddev(values_sorted, mean), 4),
            f"{label}_min": round(min(values_sorted), 4),
            f"{label}_max": round(max(values_sorted), 4),
            f"{label}_n": n,
        }

    result = {}
    result.update(stats_for(wall_clocks, "wall_clock_seconds"))
    result.update(stats_for(rss_values, "max_rss_kb"))
    result.update(stats_for(cpu_times, "cpu_time_seconds"))
    return result


# ---------------------------------------------------------------------------
# File Discovery
# ---------------------------------------------------------------------------

def discover_image_slugs(results_dir):
    """Scan raw/sbom-gen/ to find all image slugs."""
    sbom_gen_dir = os.path.join(results_dir, "raw", "sbom-gen")
    slugs = set()
    if not os.path.isdir(sbom_gen_dir):
        return sorted(slugs)

    for tool_name in os.listdir(sbom_gen_dir):
        tool_dir = os.path.join(sbom_gen_dir, tool_name)
        if not os.path.isdir(tool_dir):
            continue
        for slug in os.listdir(tool_dir):
            slug_dir = os.path.join(tool_dir, slug)
            if os.path.isdir(slug_dir):
                slugs.add(slug)

    return sorted(slugs)


def _load_json(path):
    """Load a JSON file, returning None on failure."""
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _find_timing_files(base_dir, pattern_parts):
    """Find all run_*.json timing files under a specific path."""
    target_dir = os.path.join(base_dir, *pattern_parts)
    if not os.path.isdir(target_dir):
        return []
    files = []
    for fname in os.listdir(target_dir):
        if fname.startswith("run_") and fname.endswith(".json"):
            files.append(os.path.join(target_dir, fname))
    return sorted(files)


# ---------------------------------------------------------------------------
# Main Analysis Functions
# ---------------------------------------------------------------------------

SBOM_TOOLS = ["syft", "trivy", "inspektr"]
VULN_SBOM_SCANNERS = ["grype", "trivy", "inspektr"]
VULN_DIRECT_TOOLS = ["trivy", "inspektr"]


def analyze_sbom_generation(results_dir, slugs):
    """Analyze SBOM generation: load run_1 from each tool, normalize, overlap."""
    reports = {}
    for slug in slugs:
        tool_packages = {}
        for tool in SBOM_TOOLS:
            path = os.path.join(results_dir, "raw", "sbom-gen", tool, slug, "run_1.json")
            data = _load_json(path)
            if data is not None:
                tool_packages[tool] = normalize_cyclonedx_packages(data)
            else:
                tool_packages[tool] = set()

        overlap = compute_three_way_overlap(
            tool_packages.get("syft", set()),
            tool_packages.get("trivy", set()),
            tool_packages.get("inspektr", set()),
            "syft", "trivy", "inspektr",
        )

        # Add per-tool counts
        per_tool = {}
        for tool in SBOM_TOOLS:
            per_tool[tool] = {"package_count": len(tool_packages.get(tool, set()))}

        reports[slug] = {
            "image_slug": slug,
            "overlap": overlap,
            "per_tool": per_tool,
        }

    return reports


def analyze_vuln_sbom(results_dir, slugs):
    """Analyze vuln scanning from SBOM: 3x3 matrix of scanner x sbom_source."""
    reports = {}
    for slug in slugs:
        slug_report = {"image_slug": slug, "by_sbom_source": {}}

        for sbom_source in SBOM_TOOLS:
            scanner_vulns = {}
            all_severities = {}

            for scanner in VULN_SBOM_SCANNERS:
                path = os.path.join(
                    results_dir, "raw", "vuln-sbom", scanner, sbom_source, slug, "run_1.json"
                )
                data = _load_json(path)
                if data is not None:
                    normalizer = VULN_NORMALIZERS[scanner]
                    vulns, sevs = normalizer(data)
                    scanner_vulns[scanner] = vulns
                    all_severities.update(sevs)
                else:
                    scanner_vulns[scanner] = set()

            overlap = compute_three_way_overlap(
                scanner_vulns.get("grype", set()),
                scanner_vulns.get("trivy", set()),
                scanner_vulns.get("inspektr", set()),
                "grype", "trivy", "inspektr",
            )

            # Severity breakdowns per scanner
            sev_breakdowns = {}
            for scanner in VULN_SBOM_SCANNERS:
                sev_breakdowns[scanner] = severity_breakdown(
                    scanner_vulns.get(scanner, set()), all_severities
                )

            slug_report["by_sbom_source"][sbom_source] = {
                "overlap": overlap,
                "severity_by_scanner": sev_breakdowns,
            }

        reports[slug] = slug_report

    return reports


def analyze_vuln_direct(results_dir, slugs):
    """Analyze direct vuln scanning: trivy vs inspektr."""
    reports = {}
    for slug in slugs:
        tool_vulns = {}
        all_severities = {}

        for tool in VULN_DIRECT_TOOLS:
            path = os.path.join(results_dir, "raw", "vuln-direct", tool, slug, "run_1.json")
            data = _load_json(path)
            if data is not None:
                normalizer = VULN_NORMALIZERS[tool]
                vulns, sevs = normalizer(data)
                tool_vulns[tool] = vulns
                all_severities.update(sevs)
            else:
                tool_vulns[tool] = set()

        overlap = compute_two_way_overlap(
            tool_vulns.get("trivy", set()),
            tool_vulns.get("inspektr", set()),
            "trivy", "inspektr",
        )

        sev_breakdowns = {}
        for tool in VULN_DIRECT_TOOLS:
            sev_breakdowns[tool] = severity_breakdown(
                tool_vulns.get(tool, set()), all_severities
            )

        reports[slug] = {
            "image_slug": slug,
            "overlap": overlap,
            "severity_by_tool": sev_breakdowns,
        }

    return reports


def analyze_performance(results_dir, slugs):
    """Compute perf stats for all categories."""
    perf = {"sbom_gen": {}, "vuln_sbom": {}, "vuln_direct": {}}
    timing_base = os.path.join(results_dir, "timing")

    # SBOM gen: timing/sbom-gen/{tool}/{slug}/run_*.json
    for tool in SBOM_TOOLS:
        perf["sbom_gen"][tool] = {}
        for slug in slugs:
            files = _find_timing_files(timing_base, ["sbom-gen", tool, slug])
            perf["sbom_gen"][tool][slug] = compute_perf_stats(files)

    # Vuln SBOM: timing/vuln-sbom/{scanner}/{sbom_source}/{slug}/run_*.json
    for scanner in VULN_SBOM_SCANNERS:
        perf["vuln_sbom"][scanner] = {}
        for sbom_source in SBOM_TOOLS:
            perf["vuln_sbom"][scanner][sbom_source] = {}
            for slug in slugs:
                files = _find_timing_files(
                    timing_base, ["vuln-sbom", scanner, sbom_source, slug]
                )
                perf["vuln_sbom"][scanner][sbom_source][slug] = compute_perf_stats(files)

    # Vuln direct: timing/vuln-direct/{tool}/{slug}/run_*.json
    for tool in VULN_DIRECT_TOOLS:
        perf["vuln_direct"][tool] = {}
        for slug in slugs:
            files = _find_timing_files(timing_base, ["vuln-direct", tool, slug])
            perf["vuln_direct"][tool][slug] = compute_perf_stats(files)

    return perf


def compute_aggregates(sbom_reports, vuln_sbom_reports, vuln_direct_reports):
    """Compute cross-image aggregate totals and overlap percentages."""
    aggregates = {
        "sbom_generation": {},
        "vuln_sbom": {},
        "vuln_direct": {},
    }

    # --- SBOM generation aggregates ---
    total_per_tool = {tool: 0 for tool in SBOM_TOOLS}
    total_overlap_keys = {}

    for slug, report in sbom_reports.items():
        overlap = report.get("overlap", {})
        for key, val in overlap.items():
            if isinstance(val, int):
                total_overlap_keys[key] = total_overlap_keys.get(key, 0) + val
        for tool in SBOM_TOOLS:
            total_per_tool[tool] += report.get("per_tool", {}).get(tool, {}).get("package_count", 0)

    aggregates["sbom_generation"]["totals_per_tool"] = total_per_tool
    aggregates["sbom_generation"]["overlap_totals"] = total_overlap_keys
    union_total = total_overlap_keys.get("union_total", 0)
    if union_total > 0:
        aggregates["sbom_generation"]["all_three_pct"] = round(
            total_overlap_keys.get("all_three", 0) / union_total * 100, 2
        )
    else:
        aggregates["sbom_generation"]["all_three_pct"] = 0.0

    # --- Vuln SBOM aggregates (per sbom_source) ---
    for sbom_source in SBOM_TOOLS:
        source_totals = {}
        for slug, report in vuln_sbom_reports.items():
            source_data = report.get("by_sbom_source", {}).get(sbom_source, {})
            overlap = source_data.get("overlap", {})
            for key, val in overlap.items():
                if isinstance(val, int):
                    source_totals[key] = source_totals.get(key, 0) + val

        union_total = source_totals.get("union_total", 0)
        pct = round(source_totals.get("all_three", 0) / union_total * 100, 2) if union_total > 0 else 0.0
        aggregates["vuln_sbom"][sbom_source] = {
            "overlap_totals": source_totals,
            "all_three_pct": pct,
        }

    # --- Vuln direct aggregates ---
    direct_totals = {}
    for slug, report in vuln_direct_reports.items():
        overlap = report.get("overlap", {})
        for key, val in overlap.items():
            if isinstance(val, int):
                direct_totals[key] = direct_totals.get(key, 0) + val

    union_total = direct_totals.get("union_total", 0)
    pct = round(direct_totals.get("both", 0) / union_total * 100, 2) if union_total > 0 else 0.0
    aggregates["vuln_direct"]["overlap_totals"] = direct_totals
    aggregates["vuln_direct"]["both_pct"] = pct

    return aggregates


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyze benchmark results and produce structured JSON reports."
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
    os.makedirs(reports_dir, exist_ok=True)

    # Discover image slugs
    slugs = discover_image_slugs(results_dir)
    if not slugs:
        print("No image slugs found. Has 02-scan.sh been run?", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(slugs)} image slug(s): {', '.join(slugs)}")

    # 1. SBOM generation analysis
    print("Analyzing SBOM generation...")
    sbom_reports = analyze_sbom_generation(results_dir, slugs)
    for slug, report in sbom_reports.items():
        out_path = os.path.join(reports_dir, f"sbom_{slug}.json")
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  Wrote {out_path}")

    # 2. Vuln SBOM analysis
    print("Analyzing vulnerability scanning from SBOM...")
    vuln_sbom_reports = analyze_vuln_sbom(results_dir, slugs)
    for slug, report in vuln_sbom_reports.items():
        out_path = os.path.join(reports_dir, f"vuln_sbom_{slug}.json")
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  Wrote {out_path}")

    # 3. Vuln direct analysis
    print("Analyzing direct vulnerability scanning...")
    vuln_direct_reports = analyze_vuln_direct(results_dir, slugs)
    for slug, report in vuln_direct_reports.items():
        out_path = os.path.join(reports_dir, f"vuln_direct_{slug}.json")
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  Wrote {out_path}")

    # 4. Performance analysis
    print("Analyzing performance...")
    perf_report = analyze_performance(results_dir, slugs)
    perf_path = os.path.join(reports_dir, "performance.json")
    with open(perf_path, "w") as f:
        json.dump(perf_report, f, indent=2)
    print(f"  Wrote {perf_path}")

    # 5. Aggregates
    print("Computing aggregates...")
    aggregates = compute_aggregates(sbom_reports, vuln_sbom_reports, vuln_direct_reports)
    agg_path = os.path.join(reports_dir, "aggregates.json")
    with open(agg_path, "w") as f:
        json.dump(aggregates, f, indent=2)
    print(f"  Wrote {agg_path}")

    print("Analysis complete.")


if __name__ == "__main__":
    main()
