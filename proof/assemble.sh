#!/usr/bin/env bash
# proof/assemble.sh — refresh provenance + MANIFEST for this committed bundle.
# Frozen evidence (lineage log, capture, R1/R2/R5 artifacts) is already in
# proof/ and is not regenerated from outside this repository.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROOF="$ROOT/proof"
export PATH="/usr/local/go/bin:${PATH:-}"

{
  echo "# Provenance — blockbrew proof bundle"
  echo "assembled_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo: https://github.com/hashhog/blockbrew"
  echo "branch: $(git rev-parse --abbrev-ref HEAD)"
  echo "commit: $(git rev-parse HEAD)"
  echo "commit_short: $(git rev-parse --short=12 HEAD)"
  echo "subject: $(git log -1 --format=%s | cut -c1-120)"
  echo "tree_clean: $([ -z "$(git status --porcelain)" ] && echo yes || echo NO)"
  if [ -x "$ROOT/blockbrew" ]; then
    echo "binary: blockbrew"
    echo "binary_sha256: $(sha256sum "$ROOT/blockbrew" | awk '{print $1}')"
  else
    echo "binary: blockbrew (not present; gitignored)"
    echo "binary_sha256: (rebuild with go build -o blockbrew ./cmd/blockbrew)"
  fi
  echo "toolchain: $(go version 2>/dev/null || echo 'go not on PATH')"
  echo "target: Linux amd64"
  echo "build: go build -o blockbrew ./cmd/blockbrew"
  echo "deploy_pin: 5ccdd59596ec35882e51a5f777dea29fe415f587"
  echo "deploy_sha256: 4ba0d7c4dbb7c4a902cafd8380782dee495024e52e9270315bb869262ac7ede1"
  echo
  echo "# Honest caveats"
  echo "The attested binary is the promoted pin (deploy/blockbrew/MANIFEST"
  echo "sha256=4ba0d7c4…, commit 5ccdd59), which is byte-identical to the live"
  echo "mainnet unit's /proc/<pid>/exe at assembly. Go embeds build metadata;"
  echo "a different Go, libc, or build path is expected to produce different"
  echo "bytes. Behavioural re-runs (R1 shim, in-repo R5 tests) are the stronger"
  echo "check. See REPRODUCIBLE-BUILD.md."
  echo "This script refreshes provenance + MANIFEST only. Frozen evidence in"
  echo "r1/ r2/ r4/ r5/ is not regenerated from outside this repository."
  echo "R4 for HEAD is DISPUTED — do not rewrite provenance to claim Validated."
} > "$PROOF/provenance.txt"

# Hash every file except MANIFEST itself, stable order.
( cd "$PROOF" && find . -type f ! -name MANIFEST.sha256 | sed 's|^\./||' | LC_ALL=C sort \
    | xargs -d '\n' sha256sum > MANIFEST.sha256 )

echo "assemble: $PROOF"
echo "  files: $(find "$PROOF" -type f | wc -l)"
echo "  manifest: $(wc -l < "$PROOF/MANIFEST.sha256") hashes"
