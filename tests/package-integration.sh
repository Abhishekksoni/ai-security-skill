#!/usr/bin/env zsh
# Verification script for local npm pack & install integration testing

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMP_DIR="$PROJECT_ROOT/tests/scratch/temp-project"

echo "=== 1. Compiling and Packaging ==="
cd "$PROJECT_ROOT"
npm run build
TARBALL_FILE="$(npm pack | tail -n 1)"
TARBALL_PATH="$PROJECT_ROOT/$TARBALL_FILE"

echo "=== 2. Creating separate temporary directory ==="
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

echo "=== 3. Initializing and installing local package ==="
echo '{
  "name": "temp-project",
  "version": "1.0.0",
  "dependencies": {
    "openai": "^4.0.0"
  }
}' > package.json

echo 'eval(process.argv[2]);' > index.ts

npm install "$TARBALL_PATH"

echo "=== 4. Executing scan commands ==="
npx ai-security-skill scan
npx ai-security-skill findings

echo "=== 5. Cleaning up ==="
rm -rf "$TEMP_DIR"
rm -f "$TARBALL_PATH"

echo "=== Verification complete! ==="
