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

echo "Building Docker image (${IMAGE_TAG})..."
LATEST_URL=$(python - <<'PY'
import json
import re
import sys
from urllib.request import urlopen

RELEASES_URL = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"

with urlopen(RELEASES_URL) as resp:
    data = json.load(resp)

assets = data.get("assets", [])
zip_url = None
for asset in assets:
    url = asset.get("browser_download_url", "")
    if url.endswith(".zip") and "ghidra_" in url and "PUBLIC" in url:
        zip_url = url
        break

if not zip_url:
    raise SystemExit("Unable to locate Ghidra release ZIP URL")

print(zip_url)
PY
)

if [[ -z "${LATEST_URL}" ]]; then
  echo "Failed to resolve latest Ghidra download URL" >&2
  exit 1
fi

echo "Using Ghidra download URL: ${LATEST_URL}"

GHIDRA_VERSION=$(python - <<'PY'
import re
import sys

url = sys.argv[1]
match = re.search(r"ghidra_([0-9]+\.[0-9]+\.[0-9]+)_PUBLIC", url)
print(match.group(1) if match else "11.4.2")
PY
"${LATEST_URL}")

if [[ -z "${GHIDRA_VERSION}" ]]; then
  GHIDRA_VERSION="11.4.2"
fi

python - <<'PY'
import pathlib
import re
import sys

pom_path = pathlib.Path("pom.xml")
new_version = sys.argv[1]
text = pom_path.read_text(encoding="utf-8")
updated, count = re.subn(r"(<ghidra\.version>)([^<]+)(</ghidra\.version>)", r"\1" + new_version + r"\3", text, count=1)
if count:
    pom_path.write_text(updated, encoding="utf-8")
else:
    raise SystemExit("Unable to update ghidra.version in pom.xml")
PY
"${GHIDRA_VERSION}"

echo "Updated pom.xml ghidra.version to ${GHIDRA_VERSION}"

docker build -f Dockerfile.build -t "${IMAGE_TAG}" --build-arg GHIDRA_ZIP_URL="${LATEST_URL}" .

echo "Creating temporary container..."
CONTAINER_ID=$(docker create "${IMAGE_TAG}")

mkdir -p target

echo "Extracting built JAR from container..."
docker cp "${CONTAINER_ID}:/workspace/target" .

cleanup
trap - EXIT

JAR_PATH=$(ls -1 target/GhidraMCP-*.jar | head -n 1)
echo "Build artifact copied to: ${JAR_PATH}"
