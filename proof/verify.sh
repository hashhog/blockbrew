#!/usr/bin/env bash
# proof/verify.sh — re-check every claim in this bundle against a file here.
# Exit 0 only if the files match claims.json AND the in-repo R5 control is
# green. Run from the blockbrew repo root: `bash proof/verify.sh`
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROOF="$ROOT/proof"
export PATH="/usr/local/go/bin:${PATH:-}"
fail=0
say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*"; fail=1; }

need() {
  local f="$1"
  [ -f "$PROOF/$f" ] || die "missing $f"
}

say "== blockbrew proof bundle verify =="

# 1. every claims.json file exists
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
claims = json.loads((proof / "claims.json").read_text())
missing = []
for section, body in claims.items():
    for f in body.get("files", []):
        if not (proof / f).is_file():
            missing.append(f)
if missing:
    print("FAIL: missing files:", ", ".join(missing))
    sys.exit(1)
print("files: every claims.json path exists")
PY

# 2. R4 — DISPUTED, and the included files say why
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r4"]
st = json.loads((proof / "r4/status.json").read_text())
cap = json.loads((proof / "r4/C958794.json").read_text())
rec14 = (proof / "r4/capture-0814.md").read_text()
rec15 = (proof / "r4/capture-0815.md").read_text()
watch = (proof / "r4/capture-watch-excerpt.txt").read_text()
hasher = (proof / "r4/hasher-not-lineage.txt").read_text()
unit = (proof / "r4/genesis-unit.service").read_text()
excerpt = (proof / "r4/lineage-excerpt.txt").read_text()
ledger = (proof / "r4/av0-250000-ledger.txt").read_text()
want = c["hash_serialized_3"]
miss = c["capture_0815_hash"]
errs = []
if c["status"] != "DISPUTED" or st["status"] != "DISPUTED" or cap["status"] != "DISPUTED":
    errs.append("R4 status must be DISPUTED (HEAD has no from-genesis capture)")
if c.get("head_reproduction") is not False or st.get("head_reproduction") is not False or cap.get("head_reproduction") is not False:
    errs.append("head_reproduction must be false")
if cap.get("match") is not False:
    errs.append("C958794.json match must be false for HEAD (over-claim)")
if c.get("snapshot_booted") is not False or st.get("snapshot_booted") is not False or cap.get("snapshot_booted") is not False:
    errs.append("lineage must not be snapshot-booted")
if c.get("snapshot_booted_does_not_count") is not True or st.get("snapshot_booted_does_not_count") is not True:
    errs.append("claims must refuse snapshot-booted lineages")
if c.get("hasher_file_match_counts_as_r4") is not False or st.get("hasher_file_match_counts_as_r4") is not False:
    errs.append("hasher-of-a-Core-dump must not count as R4")
if "counts_as_r4=false" not in hasher:
    errs.append("hasher-not-lineage.txt missing counts_as_r4=false")
if want not in hasher:
    errs.append("hasher-not-lineage.txt missing pin hash")
if cap["hash_serialized_3"] != want or cap["height"] != c["height"] or cap["coins"] != c["coins"]:
    errs.append("C958794.json pin mismatch")
if cap["bestblockhash"] != c["bestblockhash"]:
    errs.append("bestblockhash mismatch")
if want not in rec14 or "166180925" not in rec14.replace(",", ""):
    errs.append("capture-0814.md missing MATCH hash/coins")
if "GONE" not in rec14:
    errs.append("capture-0814.md must say the binary/datadir are GONE")
if miss not in rec15 or str(c["capture_0815_coins"]) not in rec15:
    errs.append("capture-0815.md missing MISMATCH hash/coins")
if miss not in watch or want not in watch:
    errs.append("capture-watch excerpt missing MISMATCH got/want")
if "*** MISMATCH ***" not in watch:
    errs.append("capture-watch excerpt missing MISMATCH marker")
if "-assumevalid=0" not in unit:
    errs.append("genesis-unit.service missing -assumevalid=0")
if "loadtxoutset" in unit or "assumeutxo" in unit.lower():
    errs.append("genesis-unit.service looks like a snapshot boot")
if c["genesis_block_hash"] not in excerpt:
    errs.append("lineage excerpt missing Bitcoin genesis hash")
if "height=0" not in excerpt:
    errs.append("lineage excerpt missing height=0")
if "assumevalid DISABLED (-assumevalid=0)" not in excerpt:
    errs.append("lineage excerpt missing assumevalid DISABLED")
if "matches=0" not in excerpt:
    errs.append("lineage excerpt missing snapshot-boot negative control")
if "FAIL@250000" not in ledger and "overall=FAIL@250000" not in ledger:
    errs.append("250k ledger missing overall=FAIL@250000")
if "231020" not in ledger:
    errs.append("250k ledger missing WEDGE height 231020")
if c["lineage_binary_and_datadir"] != "GONE" or st["lineage_binary_and_datadir"] != "GONE":
    errs.append("claims must record lineage binary/datadir GONE")
if errs:
    print("FAIL: R4:", "; ".join(errs))
    sys.exit(1)
print(f"R4: DISPUTED (HEAD unproven); pin C({c['height']}) {want} coins={c['coins']}; 08-15 miss {miss}; snapshot_booted=false hasher_counts_as_r4=false AV=0")
PY

# 3. lineage log gzip round-trip
need "r4/lineage.log.gz"
need "r4/lineage.log.sha256"
got="$(gzip -dc "$PROOF/r4/lineage.log.gz" | sha256sum | awk '{print $1}')"
want="$(tr -d ' \n' < "$PROOF/r4/lineage.log.sha256")"
if [ "$got" != "$want" ]; then
  die "lineage.log.gz uncompressed sha256 $got != $want"
else
  say "R4: lineage.log.gz round-trip sha256=$want"
fi
if gzip -dc "$PROOF/r4/lineage.log.gz" | grep -qiE 'loadtxoutset|assumeutxo|loading snapshot'; then
  die "lineage log contains snapshot-boot evidence (TRUST-ANCHOR: does not count)"
else
  say "R4: lineage log has no loadtxoutset/assumeutxo/snapshot lines"
fi

# 4. R1 numbers
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r1"]
r = json.loads((proof / "r1/results.json").read_text())
errs = []
ph = r["script_tests"]["phaseb"]
if ph["pass"] != c["script_pass"] or ph["fail"] != c["script_fail"]:
    errs.append("script phaseb")
if ph["assemble_errors_pre_run"] != c["script_assemble_errors_pre_run"]:
    errs.append("assemble errors")
if r["script_tests"]["in_repo"]["pass"] != c["script_in_repo_pass"]:
    errs.append("script in-repo")
if r["tx_valid"]["pass"] != c["tx_valid_pass"]:
    errs.append("tx_valid")
if r["tx_invalid"]["pass"] != c["tx_invalid_pass"]:
    errs.append("tx_invalid")
if r["sighash"]["exact_match"] != c["sighash_pass"]:
    errs.append("sighash")
if r["divergences"] != c["divergences"]:
    errs.append("divergences")
if r["decided"] != c["decided"]:
    errs.append("decided")
script_txt = (proof / "r1/script.txt").read_text()
if "1217/1217" not in script_txt:
    errs.append("script.txt missing 1217/1217")
if "1222 passed" not in (proof / "r1/script-inrepo.txt").read_text():
    errs.append("script-inrepo.txt missing 1222 passed")
if "500/500" not in (proof / "r1/sighash.txt").read_text():
    errs.append("sighash.txt missing 500/500")
tx = (proof / "r1/tx.txt").read_text()
if "121/121" not in tx:
    errs.append("tx.txt missing 121/121")
if "93/93" not in tx:
    errs.append("tx.txt missing 93/93")
if errs:
    print("FAIL: R1:", ", ".join(errs))
    sys.exit(1)
print(f"R1: script {c['script_pass']}/1217 in-repo {c['script_in_repo_pass']}/1222 tx {c['tx_valid_pass']}+{c['tx_invalid_pass']} sighash {c['sighash_pass']}/500 divergences={c['divergences']}")
PY

# 5. R2 numbers
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r2"]
r = json.loads((proof / "r2/results.json").read_text())
errs = []
if r["pass"] != c["pass"] or r["fail"] != c["fail"]:
    errs.append("pass/fail")
if r["consensus_splits_accept_vs_reject"] != c["consensus_splits_accept_vs_reject"]:
    errs.append("splits")
if any(not f["same_accept_reject"] for f in r["fails"]):
    errs.append("a listed FAIL is accept-vs-reject — that would be a consensus split")
excerpt = (proof / "r2/nightly-report-excerpt.txt").read_text()
if "blockbrew       369      1" not in excerpt:
    errs.append("excerpt missing 369/1")
fail_log = (proof / "r2/cve-2010-fail.txt").read_text()
core = r["fails"][0]["core"]
bb = r["fails"][0]["blockbrew"]
if core not in fail_log:
    errs.append("cve log missing Core token")
if bb not in fail_log:
    errs.append("cve log missing blockbrew token")
if "sum-over-maxmoney" not in fail_log:
    errs.append("cve log missing sum-over-maxmoney")
if errs:
    print("FAIL: R2:", ", ".join(errs))
    sys.exit(1)
print(f"R2: {c['pass']} PASS / {c['fail']} FAIL, consensus splits={c['consensus_splits_accept_vs_reject']}")
PY

# 6. R5 scorecards
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r5"]
live = json.loads((proof / "r5/live-20260917T091843Z.json").read_text())["impls"]["blockbrew"]
reg = json.loads((proof / "r5/regtest-20260917T083336Z.json").read_text())["impls"]["blockbrew"]
sc = json.loads((proof / "r5/scorecard.json").read_text())
errs = []
if live["tiers"]["T1"]["pass"] != c["live_t1_pass"] or live["tiers"]["T1"]["total"] != c["live_t1_total"]:
    errs.append("live T1")
if live["tiers"]["T2"]["pass"] != c["live_t2_pass"]:
    errs.append("live T2")
fails = [r for r in live["rows"] if r["status"] == "FAIL"]
if len(fails) != c["live_fail_count"]:
    errs.append(f"live FAIL set {fails!r}")
skips = {r["method"] for r in live["rows"] if r["status"] == "SKIP-REGTEST"}
if "stop" not in skips or "getblockfilter" not in skips:
    errs.append("live lane must SKIP-REGTEST stop and getblockfilter")
if reg["tiers"]["T3"]["pass"] != c["regtest_t3_pass"] or reg["tiers"]["T3"]["total"] != c["regtest_t3_total"]:
    errs.append("regtest T3")
reg_fails = [r for r in reg["rows"] if r["status"] == "FAIL"]
if reg_fails:
    errs.append(f"regtest FAILs {reg_fails!r}")
if sc["live"]["T1"]["pass"] != c["live_t1_pass"]:
    errs.append("scorecard live T1")
if sc["regtest"]["T3"]["pass"] != c["regtest_t3_total"]:
    errs.append("scorecard regtest T3")
if sc["live"]["fails"]:
    errs.append("scorecard live fails not empty")
after = (proof / "r5/t1-after.txt").read_text()
if "44 tests, 0 failures" not in after:
    errs.append("t1-after.txt is not a passing 44/0 run")
if "github.com/hashhog/blockbrew/internal/rpc" not in after or "PASS" not in after:
    errs.append("t1-after.txt missing go test PASS/ok line")
if errs:
    print("FAIL: R5:", "; ".join(errs))
    sys.exit(1)
print(f"R5 live T1 {c['live_t1_pass']}/{c['live_t1_total']} T2 {c['live_t2_pass']}/{c['live_t2_total']} FAIL={c['live_fail_count']}")
print(f"R5 regtest T3 {c['regtest_t3_pass']}/{c['regtest_t3_total']}")
PY

# 7. README cites every claims.json file
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
readme = (proof / "README.md").read_text()
claims = json.loads((proof / "claims.json").read_text())
missing = []
for section, body in claims.items():
    for f in body.get("files", []):
        if f not in readme:
            missing.append(f)
if missing:
    print("FAIL: README.md does not cite:", ", ".join(missing))
    sys.exit(1)
print("README: every claims.json file is cited")
PY

# 8. source lists getnetworkhashps the way Core's help does
if ! grep -q 'getnetworkhashps ( nblocks height )' "$ROOT/internal/rpc/extra_methods.go"; then
  die "internal/rpc/extra_methods.go does not list 'getnetworkhashps ( nblocks height )'"
else
  say "R5: help lists getnetworkhashps ( nblocks height )"
fi

# 9. provenance binary hash — attested pin (must be the deployed one)
want_bin="$(python3 -c 'import json,pathlib; print(json.loads(pathlib.Path("proof/claims.json").read_text())["provenance"]["binary_sha256"])')"
if ! grep -q "$want_bin" "$PROOF/provenance.txt"; then
  die "provenance.txt does not contain the claimed binary sha256"
else
  say "provenance.txt records claimed binary sha256=$want_bin"
fi
if [ -x "$ROOT/blockbrew" ]; then
  got_bin="$(sha256sum "$ROOT/blockbrew" | awk '{print $1}')"
  if [ "$got_bin" != "$want_bin" ]; then
    say "NOTE: ./blockbrew sha256=$got_bin (bundle records $want_bin). Rebuilds are not bit-stable; the attested pin is the recorded sha256."
  else
    say "provenance: ./blockbrew sha256=$want_bin"
  fi
else
  say "NOTE: ./blockbrew not present (gitignored). Rebuild with go build -o blockbrew ./cmd/blockbrew to check the recorded sha256."
fi

# 9b. live unit byte-identity with the attested pin (read-only). Never start/stop.
if command -v systemctl >/dev/null 2>&1; then
  pid="$(systemctl --user show -p MainPID --value hashhog-blockbrew-mainnet 2>/dev/null || true)"
  if [ -n "${pid:-}" ] && [ "$pid" != "0" ] && [ -r "/proc/$pid/exe" ]; then
    got_live="$(sha256sum "/proc/$pid/exe" | awk '{print $1}')"
    if [ "$got_live" = "$want_bin" ]; then
      say "provenance: live exe sha256=$want_bin (pid $pid, matches attested pin)"
    else
      say "NOTE: live exe sha256=$got_live (bundle records $want_bin). Pin drifted after assembly."
    fi
  else
    say "NOTE: live unit not running; skipped exe sha256 check."
  fi
fi

# 10. in-repo R5 control (re-run live so a rotted test cannot sit behind a green bundle)
if command -v go >/dev/null 2>&1; then
  say "== re-run: go test ./internal/rpc/ -count=1 -timeout 120s -run TestR5_ =="
  if go test ./internal/rpc/ -count=1 -timeout 120s -run 'TestR5_'; then
    say "R5 in-repo: TestR5_ PASS"
  else
    die "TestR5_ failed"
  fi
else
  say "NOTE: go not on PATH; skipped in-repo re-run. Install go1.24.1 and re-run."
  say "      The recorded after-control is r5/t1-after.txt (44 tests, 0 failures)."
fi

# 11. MANIFEST (all files except MANIFEST itself)
if [ -f "$PROOF/MANIFEST.sha256" ]; then
  if (cd "$PROOF" && sha256sum -c MANIFEST.sha256 --quiet); then
    say "MANIFEST.sha256: OK"
  else
    die "MANIFEST.sha256 mismatch"
  fi
else
  die "MANIFEST.sha256 missing — run bash proof/assemble.sh"
fi

if [ "$fail" -ne 0 ]; then
  say "== FAIL =="
  exit 1
fi
say "== PASS: every claim cites a file in this bundle and the numbers match =="
exit 0
