#!/usr/bin/env bash
# 02-scan.sh — Run all benchmark scans with timing capture
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.sh"

REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
INSPEKTR_BIN="${REPO_ROOT}/target/release/inspektr_cli"

# Allow overrides via environment
NUM_RUNS="${BENCHMARK_NUM_RUNS:-$NUM_RUNS}"
if [[ -n "${BENCHMARK_IMAGES:-}" ]]; then
    IFS=',' read -ra IMAGES <<< "$BENCHMARK_IMAGES"
fi

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

drop_caches() {
    if [[ -w /proc/sys/vm/drop_caches ]]; then
        sync
        echo 3 > /proc/sys/vm/drop_caches
    else
        echo "  [info] Cannot drop caches (not root) — skipping"
    fi
}

timed_run() {
    local timing_output="$1"
    shift
    local timing_stderr
    timing_stderr="$(mktemp)"

    local exit_code=0
    /usr/bin/time -v "$@" 2>"${timing_stderr}" || exit_code=$?

    local wall_clock user_time sys_time max_rss error_msg
    wall_clock="$(grep -oP 'Elapsed \(wall clock\) time.*: \K.*' "${timing_stderr}" || echo "0:00.00")"
    user_time="$(grep -oP 'User time \(seconds\): \K.*' "${timing_stderr}" || echo "0")"
    sys_time="$(grep -oP 'System time \(seconds\): \K.*' "${timing_stderr}" || echo "0")"
    max_rss="$(grep -oP 'Maximum resident set size \(kbytes\): \K.*' "${timing_stderr}" || echo "0")"

    # Convert wall clock (h:mm:ss or m:ss.ss) to seconds
    local wall_seconds=0
    if [[ "$wall_clock" =~ ^([0-9]+):([0-9]+):([0-9.]+)$ ]]; then
        wall_seconds=$(echo "${BASH_REMATCH[1]}*3600 + ${BASH_REMATCH[2]}*60 + ${BASH_REMATCH[3]}" | bc)
    elif [[ "$wall_clock" =~ ^([0-9]+):([0-9.]+)$ ]]; then
        wall_seconds=$(echo "${BASH_REMATCH[1]}*60 + ${BASH_REMATCH[2]}" | bc)
    fi

    error_msg=""
    if [[ $exit_code -ne 0 ]]; then
        # Capture non-time lines from stderr as error
        error_msg="$(grep -v -E '(Command being timed|User time|System time|Percent of CPU|Elapsed|Maximum resident|Average |Major |Minor |Voluntary|Involuntary|Swaps|File system|Socket|Signals|Page size|Exit status)' "${timing_stderr}" | head -5 | tr '\n' ' ')"
    fi

    # Ensure numeric values have leading zeros (bc outputs ".17" not "0.17")
    wall_seconds="$(printf '%g' "${wall_seconds}" 2>/dev/null || echo "0")"
    user_time="$(printf '%g' "${user_time}" 2>/dev/null || echo "0")"
    sys_time="$(printf '%g' "${sys_time}" 2>/dev/null || echo "0")"

    mkdir -p "$(dirname "${timing_output}")"
    cat > "${timing_output}" <<ENDJSON
{
  "wall_clock_seconds": ${wall_seconds},
  "max_rss_kb": ${max_rss},
  "user_time_seconds": ${user_time},
  "system_time_seconds": ${sys_time},
  "exit_code": ${exit_code},
  "error": $(printf '%s' "${error_msg}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo '""')
}
ENDJSON

    rm -f "${timing_stderr}"
    return 0  # always succeed — caller checks the JSON
}

run_scan() {
    local category="$1"
    local tool="$2"
    local image="$3"
    local run_num="$4"
    local output_file="$5"
    local sbom_file="${6:-}"

    mkdir -p "$(dirname "${output_file}")"

    local slug
    slug="$(slugify_image "$image")"

    # Build timing path
    local timing_file
    if [[ "$category" == "vuln-sbom" ]]; then
        # Extract sbom_source from output path: .../vuln-sbom/{scanner}/{sbom_source}/{slug}/...
        local sbom_source
        sbom_source="$(echo "${output_file}" | grep -oP 'vuln-sbom/[^/]+/\K[^/]+')"
        timing_file="${RESULTS_DIR}/timing/vuln-sbom/${tool}/${sbom_source}/${slug}/run_${run_num}.json"
    else
        timing_file="${RESULTS_DIR}/timing/${category}/${tool}/${slug}/run_${run_num}.json"
    fi

    echo "  [${category}] ${tool} | ${slug} | run ${run_num}"

    # Clear trivy scan cache before each trivy run so timing isn't inflated
    if [[ "${tool}" == "trivy" ]]; then
        trivy clean --scan-cache 2>/dev/null || true
    fi

    case "${category}:${tool}" in
        sbom-gen:syft)
            timed_run "${timing_file}" syft "${image}" -o cyclonedx-json --file "${output_file}"
            ;;
        sbom-gen:trivy)
            timed_run "${timing_file}" trivy image "${image}" --format cyclonedx --skip-db-update --output "${output_file}"
            ;;
        sbom-gen:inspektr)
            timed_run "${timing_file}" "${INSPEKTR_BIN}" sbom "${image}" --format cyclonedx --output "${output_file}"
            ;;
        vuln-sbom:grype)
            timed_run "${timing_file}" grype "sbom:${sbom_file}" -o json --file "${output_file}"
            ;;
        vuln-sbom:trivy)
            timed_run "${timing_file}" trivy sbom "${sbom_file}" --format json --skip-db-update --output "${output_file}"
            ;;
        vuln-sbom:inspektr)
            timed_run "${timing_file}" "${INSPEKTR_BIN}" vuln --sbom "${sbom_file}" --format json --output "${output_file}"
            ;;
        vuln-direct:trivy)
            timed_run "${timing_file}" trivy image "${image}" --format json --skip-db-update --output "${output_file}"
            ;;
        vuln-direct:inspektr)
            timed_run "${timing_file}" "${INSPEKTR_BIN}" vuln "${image}" --format json --output "${output_file}"
            ;;
        *)
            echo "  [WARNING] Unknown category:tool ${category}:${tool} — skipping"
            return 0
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Category 1: SBOM Generation
# ---------------------------------------------------------------------------
echo "=== Category 1: SBOM Generation ==="

for image in "${IMAGES[@]}"; do
    slug="$(slugify_image "$image")"
    for tool in "${SBOM_GENERATORS[@]}"; do
        for run in $(seq 1 "${NUM_RUNS}"); do
            drop_caches
            output="${RESULTS_DIR}/raw/sbom-gen/${tool}/${slug}/run_${run}.json"
            run_scan "sbom-gen" "${tool}" "${image}" "${run}" "${output}" || {
                echo "  [WARNING] ${tool} failed for ${slug} run ${run} — continuing"
            }
        done
    done
done

# ---------------------------------------------------------------------------
# Category 2: Vuln Scanning from SBOM (3x3 matrix)
# ---------------------------------------------------------------------------
echo "=== Category 2: Vulnerability Scanning from SBOM ==="

for image in "${IMAGES[@]}"; do
    slug="$(slugify_image "$image")"
    for sbom_source in "${SBOM_GENERATORS[@]}"; do
        # Use run_1 SBOM from Category 1 as input
        sbom_file="${RESULTS_DIR}/raw/sbom-gen/${sbom_source}/${slug}/run_1.json"
        if [[ ! -f "${sbom_file}" ]]; then
            echo "  [WARNING] SBOM not found: ${sbom_file} — skipping vuln-sbom scans for ${sbom_source}/${slug}"
            continue
        fi
        for scanner in "${VULN_SCANNERS_SBOM[@]}"; do
            for run in $(seq 1 "${NUM_RUNS}"); do
                drop_caches
                output="${RESULTS_DIR}/raw/vuln-sbom/${scanner}/${sbom_source}/${slug}/run_${run}.json"
                run_scan "vuln-sbom" "${scanner}" "${image}" "${run}" "${output}" "${sbom_file}" || {
                    echo "  [WARNING] ${scanner} failed for ${sbom_source}/${slug} run ${run} — continuing"
                }
            done
        done
    done
done

# ---------------------------------------------------------------------------
# Category 3: Direct Vuln Scanning
# ---------------------------------------------------------------------------
echo "=== Category 3: Direct Vulnerability Scanning ==="

for image in "${IMAGES[@]}"; do
    slug="$(slugify_image "$image")"
    for tool in "${VULN_SCANNERS_DIRECT[@]}"; do
        for run in $(seq 1 "${NUM_RUNS}"); do
            drop_caches
            output="${RESULTS_DIR}/raw/vuln-direct/${tool}/${slug}/run_${run}.json"
            run_scan "vuln-direct" "${tool}" "${image}" "${run}" "${output}" || {
                echo "  [WARNING] ${tool} failed for ${slug} run ${run} — continuing"
            }
        done
    done
done

echo "=== All scans complete ==="
echo "Results in: ${RESULTS_DIR}"
