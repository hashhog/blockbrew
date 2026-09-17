# blockbrew proof bundle

A skeptical Bitcoin engineer should be able to check this node without
trusting a narrative. This directory is that check: every claim below
names a file in this directory, and `bash proof/verify.sh` re-checks
those files (and re-runs the in-repo controls).

It claims **only what the included files show.**

## How to check

From the blockbrew repository root:

```
bash proof/verify.sh
```

That is the control. It exits 0 only if every claim in `claims.json`
matches a file here, R4 stays DISPUTED (no HEAD from-genesis capture;
snapshot boots and hasher-of-a-dump refused), the lineage log is a
from-genesis AV=0 run (not a snapshot boot), and the in-repo R5 suite
is green.

Re-running the heavy instruments (from-genesis IBD, full R2 corpus, live
R5 probe) needs the commands in `r4/command.txt`, `r1/command.txt`,
`r2/command.txt`, `r5/command.txt`. Those take days / hours / a running
node. The files here are the captured results of those commands.

## What each file proves

### Provenance — `provenance.txt`

The parent commit this bundle was assembled on (`5ccdd59`), the sha256 of
the **deployed** binary (`4ba0d7c4dbb7c4a902cafd8380782dee495024e52e9270315bb869262ac7ede1`),
and the toolchain (go1.24.1 linux/amd64). That sha256 is byte-identical to
the promoted pin and, at assembly, to the live unit's `/proc/<pid>/exe`.
**Does not prove** bit-exact reproducible builds across toolchains — see
`REPRODUCIBLE-BUILD.md`.

### R4 from-genesis lineage — `r4/` — DISPUTED

TRUST-ANCHOR rule, applied without weakening: a reproduction of C(H)
counts only if the chainstate at H descends from a genesis→H validation
with scripts on (`assumevalid=0`) executed by this node's own validation
code. **Snapshot-booted lineages do not count.** Re-hashing a Core
dumptxoutset file does not count. A MATCH whose binary and datadir are
gone does not count for HEAD.

`r4/status.json` says `DISPUTED`. `r4/C958794.json` records the pin and
both captures with `match=false` for HEAD.

| file | what it proves | what it does not prove |
|---|---|---|
| `r4/status.json` | The claim: R4 is DISPUTED. `head_reproduction=false`, `snapshot_booted_does_not_count=true`, `hasher_file_match_counts_as_r4=false`. | A C(H) hash for HEAD. There isn't one. |
| `r4/C958794.json` | The pin: height 958794, bestblock `000000000000000000015eaadd989e4f09ff75b643a128dc7bdf6070431d7d0e`, `hash_serialized_3` `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0`, 166,180,925 coins. Plus the 08-14 MATCH (GONE) and 08-15 MISMATCH (`24ec9202…7a5a`, 166,180,926). | That this tree's binary built the set. |
| `r4/capture-0814.md` | The 08-14 MATCH receipt on a retired genesis-rig process. | HEAD. The binary and datadir are GONE. |
| `r4/capture-0815.md` | The 08-15 MISMATCH, adjudicated as crash-recovery re-applying spent coinbase 958187. | A hasher bug. |
| `r4/capture-watch-excerpt.txt` | Freeze at 958794 on 08-08; `*** MISMATCH ***` on 08-15 with both hashes. | The 08-14 MATCH (that capture is not in this log). |
| `r4/hasher-not-lineage.txt` | 7387f315 stream-hashes Core's dump and MATCHES the pin. `counts_as_r4=false`. | From-genesis UTXO-hash identity. |
| `r4/genesis-unit.service` | The launch command: `-assumevalid=0`, `-connect=127.0.0.1:28620` (capped blk-replay), datadir `/home/work/genesis-ibd/blockbrew`, no loadtxoutset. | That a stranger can re-run it without that datadir and the capped feeder. The datadir is gone. |
| `r4/lineage.log.gz` | The lineage receipt of the retired rig: start at height 0 on Bitcoin's genesis hash `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`, `assumevalid DISABLED (-assumevalid=0)`, no `loadtxoutset`/`assumeutxo`/`snapshot` lines, flush at height 958794. Uncompressed sha256 is `r4/lineage.log.sha256`; gzip sha256 is `r4/lineage.log.gz.sha256`. | Blocks after 958794. That HEAD built this set. |
| `r4/lineage-excerpt.txt` | The load-bearing lines of that log, for a reader who does not want to gunzip 352,022 lines. | Completeness — the gzip is the receipt. |
| `r4/av0-250000-ledger.txt` and `r4/av0-250000-ledger.jsonl` | A **pre-fix** AV=0 genesis→250,000 replay: `overall=FAIL@250000`, WEDGE at 231020 (empty-scriptPubKey, DIV-blockbrew-001). | C(958794). A post-fix 250k pass — that exists as prose only, no ledger file. |
| `r4/command.txt` | What a real HEAD reproduction would take. | That anyone has done it on this tree. |

### R1 interpreter — `r1/`

Core's script/tx/sighash vectors through blockbrew's own `VerifyScript` /
CheckTransaction / legacy SignatureHash.

| file | what it proves | what it does not prove |
|---|---|---|
| `r1/results.json` | phaseb script 1217/1217 (5 assemble errors pre-run), in-repo script 1222/1222, tx_valid 121/121, tx_invalid 93/93, sighash 500/500, 0 divergences. CHARTER 1,936 vectors, 1,931 decided via phaseb. | Reason-string parity (482 informational reject-reason mismatches on script; decision still correct). |
| `r1/script.txt`, `r1/script-inrepo.txt`, `r1/tx.txt`, `r1/sighash.txt` | The raw harness summaries that `results.json` was taken from. | A stranger's re-run of the phaseb arms — that is `r1/command.txt`. |

### R2 validator — `r2/`

Adversarial corpus, accept/reject vs live `bitcoind`.

| file | what it proves | what it does not prove |
|---|---|---|
| `r2/results.json` | 369 PASS / 1 FAIL / 0 ERR of the nightly 370-entry sweep (99.7%). The FAIL is reject-vs-reject with a different reason string. `consensus_splits_accept_vs_reject: 0`. | Error-code / reject-token identity with Core. `sum-over-maxmoney` still differs on *why* it rejects. |
| `r2/nightly-report-excerpt.txt` | The nightly report row those numbers were copied from. | A clean classifier: the 10-impl report has an accounting gap on split counts; the one blockbrew FAIL log was read directly. |
| `r2/cve-2010-fail.txt` | The FAIL log: Core `reject:bad-txns-txouttotal-toolarge`, blockbrew `reject:rejected`, both REJECT. | Token identity. |

### R5 operator RPC — `r5/`

| file | what it proves | what it does not prove |
|---|---|---|
| `r5/live-20260917T091843Z.json` | Live lane 2026-09-17T09:18Z on pin `5ccdd59`: T1 45/46, T2 40/41, FAIL=0. `stop` and `getblockfilter` are SKIP-REGTEST. | Wallet behaviour on the live lane (T3 is SKIP-REGTEST there). |
| `r5/regtest-20260917T083336Z.json` | Regtest lane: T1 1/1, T2 1/1, T3 16/16, 18 methods scored, 0 FAIL. | Wallet behaviour outside the 16-method T3 subset. |
| `r5/t1-after.txt` | In-repo `go test ./internal/rpc/ -run TestR5_`: 44 tests, 0 failures. | A live `r5_probe.py` remaining green after a later pin. |
| `r5/scorecard.json` | The numbers above in one place, each pointing at the artifact. | Anything not in those artifacts. |
| `r5/command.txt` | How to re-run the live/regtest probes. | That this run did. |

## What is NOT proven here

- **R4 for HEAD.** DISPUTED. The 08-14 MATCH is a retired binary; the datadir
  is gone. The 08-15 capture is +1 coin from crash-recovery. The hasher test
  is not a lineage. Do not call this node Validated.
- **Tip parity is not consensus evidence.** The live node matching Core's
  tip proves serialization, PoW, headers-first sync and UTXO bookkeeping
  on the assumevalid-skipped prefix. R1/R2/R4 are the consensus proof.
- **Blocks after 958794** have no from-genesis UTXO-hash capture.
- **Snapshot-boot / assumeUTXO activation** is not a substitute for the
  lineage above.
- **Bitcoin Core fullblocktests, stale-block replay, BIP90 asserts,
  bitcoinfuzz.** Not in this bundle.
- **Fund custody.** Do not send money to this node. See `SECURITY.md`.
- **That a stranger can replay the 10.9-day genesis IBD** without the
  datadir, the capped feeder, and the original binary. They can check
  the log; they cannot cheaply reproduce it.

## TRUST-ANCHOR, applied

A snapshot-booted range (`range-runner.sh` CLOSED rows) is **not** in
this bundle as R4 evidence. Those boots start from a Core-format UTXO
snapshot; counting them as from-genesis would be circular. Hashing
Core's `utxo-958794.dat` through this node's hasher is the same circular
shape. The R4 files above are the retired-rig log + both captures, marked
DISPUTED for HEAD.
