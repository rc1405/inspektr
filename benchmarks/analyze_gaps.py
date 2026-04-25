#!/usr/bin/env python3
"""
Analyze package gaps between inspektr and trivy across 5 images.
"""

import json
import re
from urllib.parse import unquote
from pathlib import Path

BASE = Path("/home/rcote/rust-projects/looking_glass/benchmarks/results/raw/sbom-gen")

IMAGES = [
    "grafana_grafana_10.4.0",
    "node_20",
    "postgres_16",
    "python_3.12",
    "redis_7.2",
]


def normalize_purl(purl: str) -> str:
    """Normalize a PURL for comparison: lowercase, strip qualifiers, decode %, strip deb epoch."""
    if not purl:
        return ""
    # Strip qualifiers (everything after ?)
    purl = purl.split("?")[0]
    # Decode percent-encoding
    purl = unquote(purl)
    # Lowercase
    purl = purl.lower()
    # Strip deb epoch: pkg:deb/...@1:2.3.4 -> pkg:deb/...@2.3.4
    purl = re.sub(r'@\d+:', '@', purl)
    return purl


def extract_purls(sbom_path: Path) -> dict[str, str]:
    """
    Extract purls from a CycloneDX SBOM. Returns dict of normalized_purl -> original_purl.
    """
    with open(sbom_path) as f:
        data = json.load(f)

    purls = {}
    components = data.get("components", [])
    for comp in components:
        purl = comp.get("purl", "")
        if purl:
            norm = normalize_purl(purl)
            purls[norm] = purl
    return purls


def purl_type(purl: str) -> str:
    """Extract the type from a PURL string."""
    m = re.match(r'pkg:([^/]+)/', purl)
    return m.group(1) if m else "unknown"


def analyze_image(image: str):
    inspektr_path = BASE / "inspektr" / image / "run_1.json"
    trivy_path = BASE / "trivy" / image / "run_1.json"

    if not inspektr_path.exists():
        print(f"  [MISSING] inspektr SBOM not found: {inspektr_path}")
        return
    if not trivy_path.exists():
        print(f"  [MISSING] trivy SBOM not found: {trivy_path}")
        return

    inspektr_purls = extract_purls(inspektr_path)
    trivy_purls = extract_purls(trivy_path)

    trivy_only = {norm: orig for norm, orig in trivy_purls.items() if norm not in inspektr_purls}

    print(f"\n{'='*70}")
    print(f"IMAGE: {image}")
    print(f"  inspektr packages: {len(inspektr_purls)}")
    print(f"  trivy packages:    {len(trivy_purls)}")
    print(f"  trivy-only (missing from inspektr): {len(trivy_only)}")

    if not trivy_only:
        print("  No gaps!")
        return

    # Group by purl type
    by_type: dict[str, list[tuple[str, str]]] = {}
    for norm, orig in sorted(trivy_only.items()):
        t = purl_type(orig)
        by_type.setdefault(t, []).append((norm, orig))

    for ptype, items in sorted(by_type.items()):
        print(f"\n  -- {ptype} ({len(items)} packages) --")
        for norm, orig in items:
            # For deb: check if it might be an epoch or encoding difference
            if ptype == "deb":
                # Check if the package name exists in inspektr under a different encoding
                # Extract name@version from norm
                m = re.search(r'/([^/]+)@', norm)
                pkg_name = m.group(1) if m else ""
                # Find matching inspektr purls with same name
                matches = [k for k in inspektr_purls if f'/{pkg_name}@' in k or f'/{pkg_name}?' in k]
                if matches:
                    print(f"    {orig}")
                    print(f"      -> name match in inspektr: {inspektr_purls[matches[0]]}")
                    print(f"         (likely encoding/epoch difference)")
                else:
                    # Check if norm has arch qualifier stripped - maybe inspektr has it with different name
                    # Also check without architecture suffix
                    print(f"    {orig}")
                    print(f"      -> not found in inspektr (truly missing deb package)")
            elif ptype == "golang":
                # Check if the package name exists with a replace-directive alias
                m = re.search(r'pkg:golang/(.+)@', norm)
                mod_path = m.group(1) if m else ""
                # Check if there's a similar path in inspektr
                matches = [k for k in inspektr_purls if mod_path in k]
                if matches:
                    print(f"    {orig}")
                    print(f"      -> similar path in inspektr: {inspektr_purls[matches[0]]}")
                    print(f"         (possible replace directive alias)")
                else:
                    # Check if it's stdlib or a well-known alias
                    if "stdlib" in norm:
                        print(f"    {orig}")
                        print(f"      -> stdlib entry (may not be cataloged by inspektr)")
                    else:
                        print(f"    {orig}")
                        print(f"      -> not found in inspektr")
            else:
                print(f"    {orig}")
                print(f"      -> type: {ptype}")

    # Summary / root cause categorization
    print(f"\n  ROOT CAUSE SUMMARY for {image}:")
    for ptype, items in sorted(by_type.items()):
        if ptype == "deb":
            # Categorize each
            epoch_diff = []
            truly_missing = []
            for norm, orig in items:
                m = re.search(r'/([^/]+)@', norm)
                pkg_name = m.group(1) if m else ""
                matches = [k for k in inspektr_purls if f'/{pkg_name}@' in k]
                if matches:
                    epoch_diff.append(orig)
                else:
                    truly_missing.append(orig)
            if epoch_diff:
                print(f"    deb/encoding-epoch-diff ({len(epoch_diff)}): {[p.split('/')[-1] for p in epoch_diff]}")
            if truly_missing:
                print(f"    deb/truly-missing ({len(truly_missing)}): {[p.split('/')[-1] for p in truly_missing]}")
        elif ptype == "golang":
            stdlib = [orig for norm, orig in items if "stdlib" in norm]
            aliased = []
            missing = []
            for norm, orig in items:
                if "stdlib" in norm:
                    continue
                m = re.search(r'pkg:golang/(.+)@', norm)
                mod_path = m.group(1) if m else ""
                matches = [k for k in inspektr_purls if mod_path in k]
                if matches:
                    aliased.append(orig)
                else:
                    missing.append(orig)
            if stdlib:
                print(f"    golang/stdlib-not-cataloged ({len(stdlib)})")
            if aliased:
                print(f"    golang/replace-alias ({len(aliased)}): {[p.split('/')[-1].split('@')[0] for p in aliased]}")
            if missing:
                print(f"    golang/truly-missing ({len(missing)}): {[p.split('golang/')[-1] for p in missing]}")
        else:
            print(f"    {ptype}/other ({len(items)}): {[orig.split('/')[-1] for norm, orig in items]}")


def main():
    print("Inspektr vs Trivy: Package Gap Analysis")
    print("Normalization: lowercase, strip qualifiers, decode %-encoding, strip deb epoch")

    for image in IMAGES:
        analyze_image(image)

    print(f"\n{'='*70}")
    print("Analysis complete.")


if __name__ == "__main__":
    main()
