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
docker build -f Dockerfile.build -t "${IMAGE_TAG}" .

echo "Creating temporary container..."
CONTAINER_ID=$(docker create "${IMAGE_TAG}")

mkdir -p target

echo "Extracting built JAR from container..."
docker cp "${CONTAINER_ID}:/workspace/target" .

cleanup
trap - EXIT

JAR_PATH=$(ls -1 target/GhidraMCP-*.jar | head -n 1)
echo "Build artifact copied to: ${JAR_PATH}"
