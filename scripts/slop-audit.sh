#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

FILES=(
  "crates/services/hushd/src/api/eval.rs"
  "crates/services/hushd/src/api/check.rs"
  "crates/services/hushd/src/api/webhooks.rs"
  "packages/policy/clawdstrike-policy/src/async/retry.ts"
  "packages/policy/clawdstrike-policy/src/async/runtime.ts"
  "packages/policy/clawdstrike-policy/src/async/http.ts"
  "packages/policy/clawdstrike-policy/src/policy/loader.legacy.test.ts"
)

failed=0

check_absent() {
  local label="$1"
  local pattern="$2"
  if rg -n --pcre2 "$pattern" "${FILES[@]}"; then
    echo "slop-audit: ${label} found"
    failed=1
  fi
}

check_absent "silent fallback defaulting" "unwrap_or_default\\(|unwrap_or\\(0\\)"
check_absent "ignored audit writes" "let\\s+_=\\s+state\\.(audit_v2|ledger)\\.record"
check_absent "legacy deterministic retry jitter" "\\(attempt\\s*\\*\\s*17\\)\\s*%\\s*97"
check_absent "shallow truthiness assertions in policy package tests" "toBeDefined\\(|toBeTruthy\\("

if [[ "$failed" -ne 0 ]]; then
  echo "slop-audit: failed"
  exit 1
fi

echo "slop-audit: clean"
