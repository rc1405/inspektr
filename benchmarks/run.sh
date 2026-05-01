#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================================="
echo "  Benchmark: inspektr vs grype/syft vs trivy"
echo "=============================================="
echo ""

# Pass through environment overrides
export BENCHMARK_NUM_RUNS="${BENCHMARK_NUM_RUNS:-}"
export BENCHMARK_IMAGES="${BENCHMARK_IMAGES:-}"

echo "Phase 1: Setup"
echo "----------------------------------------------"
"${SCRIPT_DIR}/01-setup.sh"
echo ""

echo "Phase 2: Scan"
echo "----------------------------------------------"
"${SCRIPT_DIR}/02-scan.sh"
echo ""

echo "Phase 3: Analyze"
echo "----------------------------------------------"
python3 "${SCRIPT_DIR}/03-analyze.py"
echo ""

echo "Phase 4: Report"
echo "----------------------------------------------"
python3 "${SCRIPT_DIR}/04-report.py"
echo ""

echo "=============================================="
echo "  Benchmark complete!"
echo "  Results: ${SCRIPT_DIR}/results/reports/"
echo "=============================================="
