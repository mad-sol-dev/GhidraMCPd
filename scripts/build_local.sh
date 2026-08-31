#!/usr/bin/env bash
# Build the Ghidra extension with nothing but a JDK.
#
# The canonical build is Maven (see pom.xml) or Docker (build_docker.sh).  This
# script exists for the machine that has neither: it compiles against an
# installed Ghidra and assembles the same ZIP layout the assembly descriptor
# produces --  GhidraMCP/extension.properties, GhidraMCP/Module.manifest and
# GhidraMCP/lib/GhidraMCP.jar -- so the result installs exactly like the Maven
# artifact.
#
# Usage:
#   GHIDRA_DIR=/path/to/ghidra_11.4.2_PUBLIC scripts/build_local.sh
#   scripts/build_local.sh --compile-only     # syntax check, no ZIP
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPILE_ONLY=0
[ "${1:-}" = "--compile-only" ] && COMPILE_ONLY=1

VERSION="$(sed -n 's:.*<version>\(.*\)</version>.*:\1:p' pom.xml | head -1)"
OUT="$ROOT/target"
CLASSES="$OUT/local-classes"

# Ghidra 11.4.2 layout.  SoftwareModeling lives under Framework and Base under
# Features -- the reverse of what one would guess from the other seven.
JARS=(
  "Ghidra/Framework/Generic/lib/Generic.jar"
  "Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar"
  "Ghidra/Framework/Project/lib/Project.jar"
  "Ghidra/Framework/Docking/lib/Docking.jar"
  "Ghidra/Features/Decompiler/lib/Decompiler.jar"
  "Ghidra/Framework/Utility/lib/Utility.jar"
  "Ghidra/Features/Base/lib/Base.jar"
  "Ghidra/Framework/Gui/lib/Gui.jar"
)

CP=""
if [ -n "${GHIDRA_DIR:-}" ]; then
  echo "Ghidra: $GHIDRA_DIR"
  for rel in "${JARS[@]}"; do
    path="$GHIDRA_DIR/$rel"
    [ -f "$path" ] || { echo "missing jar: $path" >&2; exit 1; }
    CP="$CP:$path"
  done
else
  # Fall back to the vendored jars, which are enough to compile but are not
  # tied to the Ghidra the extension will run in.
  echo "Ghidra: (GHIDRA_DIR unset -- compiling against lib/)"
  for jar in "$ROOT"/lib/*.jar; do CP="$CP:$jar"; done
fi
CP="${CP#:}"

rm -rf "$CLASSES"
mkdir -p "$CLASSES"
mapfile -t SOURCES < <(find src/main/java -name '*.java')
javac -nowarn -proc:none --release 17 -cp "$CP" -d "$CLASSES" "${SOURCES[@]}"
echo "compiled ${#SOURCES[@]} sources -> $(find "$CLASSES" -name '*.class' | wc -l) classes"

if [ "$COMPILE_ONLY" = 1 ]; then
  echo "compile-only: no jar, no zip"
  exit 0
fi

# The jar carries src/main/resources alongside the classes, minus App.class,
# with the hand-written manifest -- the same three rules the jar plugin applies.
rm -f "$CLASSES"/com/lauriewired/App.class
cp -r src/main/resources/extension.properties src/main/resources/Module.manifest "$CLASSES/"
jar --create --file "$OUT/GhidraMCP.jar" \
    --manifest src/main/resources/META-INF/MANIFEST.MF \
    -C "$CLASSES" .

STAGE="$OUT/local-zip/GhidraMCP"
rm -rf "$OUT/local-zip"
mkdir -p "$STAGE/lib"
cp src/main/resources/extension.properties src/main/resources/Module.manifest "$STAGE/"
cp "$OUT/GhidraMCP.jar" "$STAGE/lib/"

ZIP="$OUT/GhidraMCP-$VERSION.zip"
rm -f "$ZIP"
(cd "$OUT/local-zip" && zip -qr "$ZIP" GhidraMCP)
echo "built $ZIP"
unzip -l "$ZIP"
