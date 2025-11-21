#!/usr/bin/env bash
set -euo pipefail

IMAGE_TAG="ghidra-mcp-builder"
CONTAINER_ID=""

cleanup() {
  if [[ -n "${CONTAINER_ID}" ]]; then
    docker rm "${CONTAINER_ID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# 1. Ghidra URL & Version ermitteln (Robust via Python)
echo "Resolving latest Ghidra version..."
read -r LATEST_URL GHIDRA_VERSION <<< $(python3 -c '
import json, sys, re
from urllib.request import urlopen, Request

try:
    # GitHub API Request
    req = Request("https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest")
    with urlopen(req) as r:
        data = json.load(r)
    
    # Find ZIP URL
    zip_url = next((a["browser_download_url"] for a in data.get("assets", []) 
                   if a["browser_download_url"].endswith(".zip") and "PUBLIC" in a["browser_download_url"]), None)
    
    if not zip_url:
        sys.exit(1)

    # Extract Version (e.g. 11.4.2)
    m = re.search(r"ghidra_([0-9.]+)_PUBLIC", zip_url)
    version = m.group(1) if m else "11.4.2"
    
    print(f"{zip_url} {version}")

except Exception:
    sys.exit(1)
')

if [[ -z "${LATEST_URL:-}" ]]; then
    echo "Error: Could not resolve Ghidra URL. API might be rate-limited."
    # Fallback falls API failt
    LATEST_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.2_build/ghidra_11.4.2_PUBLIC_20250826.zip"
    GHIDRA_VERSION="11.4.2"
    echo "Using Fallback: $GHIDRA_VERSION"
fi

echo "Target: Ghidra $GHIDRA_VERSION"
echo "URL:    $LATEST_URL"

# 2. Docker Build (Patching passiert intern via ARG)
echo "Building Docker image..."
docker build \
    -f Dockerfile.build \
    -t "${IMAGE_TAG}" \
    --build-arg GHIDRA_ZIP_URL="${LATEST_URL}" \
    --build-arg GHIDRA_VERSION="${GHIDRA_VERSION}" \
    .

# 3. Artefakt extrahieren
echo "Extracting artifact..."
CONTAINER_ID=$(docker create "${IMAGE_TAG}")
mkdir -p target
# Kopiere alle JARs aus target, ignoriere Fehler falls keine da sind (sollte nicht passieren bei success)
docker cp "${CONTAINER_ID}:/workspace/target/." target/

# Bereinigung (Original-sources und classes entfernen, wir wollen nur das JAR)
find target -maxdepth 1 -not -name "*.jar" -not -name "target" -delete 2>/dev/null || true

JAR_PATH=$(ls target/GhidraMCP*.jar | head -n 1)
echo "--------------------------------------------------"
echo "Build Success! Artifact available at:"
echo "$JAR_PATH"
echo "--------------------------------------------------"
