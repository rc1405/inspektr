#!/usr/bin/env bash
# Benchmark configuration — single source of truth

# Install location for tools (grype, syft, trivy)
INSTALL_DIR="${HOME}/bin"
export PATH="${INSTALL_DIR}:${PATH}"

# Tool groupings per category
SBOM_GENERATORS=("syft" "trivy" "inspektr")
VULN_SCANNERS_SBOM=("grype" "trivy" "inspektr")
VULN_SCANNERS_DIRECT=("trivy" "inspektr")

# Number of runs per tool per image
NUM_RUNS=1

# Target images — pinned to SHA256 digests for reproducibility
# Digests resolved on 2026-04-10
IMAGES=(
    "alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"
    "ubuntu:22.04@sha256:eb29ed27b0821dca09c2e28b39135e185fc1302036427d5f4d70a41ce8fd7659"
    "node:20@sha256:8789e1e0752d81088a085689c04fdb7a5b16e8102e353118a4b049bbf05db8ac"
    "python:3.12@sha256:4dfb72bded96c77f01b5aca3038afa3797832b167480261a84baa29414566a52"
    "golang:1.22@sha256:1cf6c45ba39db9fd6db16922041d074a63c935556a05c5ccb62d181034df7f02"
    "nginx:latest@sha256:7f0adca1fc6c29c8dc49a2e90037a10ba20dc266baaed0988e9fb4d0d8b85ba0"
    "elasticsearch:8.13.0@sha256:9d1cd1491778aceca4490de7ec9f205c3633a277df15473e1ea507d13a5270c6"
    "redis:7.2@sha256:27e0239308d65d349a9ab04b41ffe67598d65aea6c15da5a330673ff7f949868"
    "mongo:7.0@sha256:45d9c9b48aa1b56b5e3a9f906763fe432f376abb3bc2832438022b6d2534e4fe"
    "postgres:16@sha256:5a65324fe84dc41709ff914e90b07f3e2f577073ed27bf917d4873aca0c9ec51"
    "rabbitmq:3.13@sha256:87178a0ee3e2f52980ba356d38646ed1056705ff2d5ff281f8965456eaa0c1e3"
    "grafana/grafana:10.4.0@sha256:f9811e4e687ffecf1a43adb9b64096c50bc0d7a782f8608530f478b6542de7d5"
)

# Tool versions
GRYPE_VERSION="0.111.0"
TRIVY_VERSION="0.69.3"
# syft: latest stable at install time
# inspektr: built from this repo (cargo build --release)

# Helper: slugify an image name for filesystem-safe directory names
slugify_image() {
    echo "$1" | sed 's/@sha256:.*//; s|[/:]|_|g'
}
