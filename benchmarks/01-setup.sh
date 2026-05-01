#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.sh"

REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"

mkdir -p "${RESULTS_DIR}"

# Ensure install directory exists
mkdir -p "${INSTALL_DIR}"

# --- Tool verification / installation ---

check_version() {
    local tool="$1" expected="$2" actual="$3"
    if [[ "${actual}" != *"${expected}"* ]]; then
        echo "ERROR: ${tool} version mismatch. Expected ${expected}, got: ${actual}"
        return 1
    fi
    echo "OK: ${tool} version ${expected}"
}

# Grype
if command -v grype &>/dev/null; then
    GRYPE_ACTUAL=$(grype version 2>/dev/null | grep "^Version:" | awk '{print $2}' || grype version --output json 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin)['version'])" 2>/dev/null || echo "unknown")
    check_version "grype" "${GRYPE_VERSION}" "${GRYPE_ACTUAL}" || {
        echo "Installing grype ${GRYPE_VERSION}..."
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "${INSTALL_DIR}" "v${GRYPE_VERSION}"
    }
else
    echo "Installing grype ${GRYPE_VERSION}..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "${INSTALL_DIR}" "v${GRYPE_VERSION}"
fi

# Syft
if ! command -v syft &>/dev/null; then
    echo "Installing syft (latest)..."
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "${INSTALL_DIR}"
else
    echo "OK: syft found at $(command -v syft)"
fi

# Trivy
if command -v trivy &>/dev/null; then
    TRIVY_ACTUAL=$(trivy version --format json 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin)['Version'])" 2>/dev/null || trivy version 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    check_version "trivy" "${TRIVY_VERSION}" "${TRIVY_ACTUAL}" || {
        echo "Installing trivy ${TRIVY_VERSION}..."
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "${INSTALL_DIR}" "v${TRIVY_VERSION}"
    }
else
    echo "Installing trivy ${TRIVY_VERSION}..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "${INSTALL_DIR}" "v${TRIVY_VERSION}"
fi

# Inspektr — build from repo
echo "Building inspektr from source..."
(cd "${REPO_ROOT}" && cargo build --release)
INSPEKTR_BIN="${REPO_ROOT}/target/release/inspektr_cli"
if [[ ! -f "${INSPEKTR_BIN}" ]]; then
    echo "ERROR: inspektr binary not found at ${INSPEKTR_BIN}"
    exit 1
fi
echo "OK: inspektr built at ${INSPEKTR_BIN}"

# --- Pull images ---

echo ""
echo "Pulling pinned images..."
for image in "${IMAGES[@]}"; do
    echo "  Pulling ${image}..."
    docker pull "${image}" || {
        echo "ERROR: Failed to pull ${image}"
        exit 1
    }
done
echo "All images pulled."

# --- Pre-fetch vulnerability databases ---

echo ""
echo "Pre-fetching vulnerability databases..."

echo "  grype db update..."
grype db update

echo "  trivy db download..."
trivy image --download-db-only 2>/dev/null || trivy --download-db-only 2>/dev/null || echo "WARN: trivy db download may have failed"

echo "  inspektr db update..."
"${INSPEKTR_BIN}" db update

# --- Record environment metadata ---

echo ""
echo "Recording environment metadata..."

python3 -c "
import json, subprocess, platform, os

def cmd(args):
    try:
        return subprocess.check_output(args, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return 'unknown'

env = {
    'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'os': platform.platform(),
    'uname': cmd(['uname', '-a']),
    'cpu_model': open('/proc/cpuinfo').read().split('model name')[1].split('\n')[0].strip(': \t') if os.path.exists('/proc/cpuinfo') else cmd(['sysctl', '-n', 'machdep.cpu.brand_string']),
    'cpu_count': os.cpu_count(),
    'memory_total_mb': round(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024**2)),
    'docker_version': cmd(['docker', 'version', '--format', '{{.Server.Version}}']),
    'tool_versions': {
        'grype': cmd(['grype', 'version']),
        'syft': cmd(['syft', 'version']),
        'trivy': cmd(['trivy', 'version']),
        'inspektr': cmd(['${INSPEKTR_BIN}', '--version']),
    },
    'images': $(python3 -c "import json; print(json.dumps([img for img in '''${IMAGES[*]}'''.split()]))")
}

os.makedirs('${RESULTS_DIR}', exist_ok=True)
with open('${RESULTS_DIR}/environment.json', 'w') as f:
    json.dump(env, f, indent=2)
print('  Saved to ${RESULTS_DIR}/environment.json')
"

echo ""
echo "Setup complete."
