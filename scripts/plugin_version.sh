#!/usr/bin/env bash
# Prints the plugin version derived from git, so every plugin change yields a new number.
#
#   <base>.<N>                  clean tree, N = commits touching the plugin (src/, pom.xml)
#   <base>.<N+1>-dev.<stamp>    uncommitted plugin changes; stamp = build time (UTC)
#
# <base> (major.minor) is set by hand in pom.xml as <plugin.version.base>.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE=$(sed -n 's|.*<plugin.version.base>\(.*\)</plugin.version.base>.*|\1|p' pom.xml | head -n 1)
if [[ -z "$BASE" ]]; then
  echo "plugin_version.sh: <plugin.version.base> missing in pom.xml" >&2
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "${BASE}.0-nogit"
  exit 0
fi

PATHS=(src pom.xml)
COUNT=$(git rev-list --count HEAD -- "${PATHS[@]}")

if [[ -n "$(git status --porcelain -- "${PATHS[@]}")" ]]; then
  echo "${BASE}.$((COUNT + 1))-dev.$(date -u +%Y%m%d%H%M%S)"
else
  echo "${BASE}.${COUNT}"
fi
