# Changelog

## v1.0.2 — 2026-09-13

- bee96ce test: stop prune_one_MiB hanging the cmd/blockbrew package
- 7387f31 test: third C(958794) capture via streaming snapshot hasher
- 007eb9c feat: getpeerinfo reports per-peer synced_headers/synced_blocks
- d76963e fix: persist loadtxoutset so a restart keeps the snapshot tip
- c1de01e fix(p2p): stall resets must not wipe RetryCount so stallRecoveryPlan can escalate
- fd19099 build: stop tracking the two verifyscript_shim binaries


## v1.0.2 — 2026-09-13

Changes since `v1.0.0`:

- test: third C(958794) capture — stream-hash of Core's dumptxoutset matches `29692050…7af0` over 166,180,925 coins; the 08-15 +1 was crash-recovery, not the hasher
- feat: getpeerinfo reports per-peer synced_headers/synced_blocks instead of -1 stubs
- fix(p2p): stall resets keep RetryCount so stallRecoveryPlan can escalate
- bf18c02 docs: say the cited paths are private before the claims that rest on them
- d1c4d39 fix: RPC block submission must vouch min-pow-checked, as Core does
- 5028ab3 fix: make a loaded snapshot the active chain view
- 6ea4132 feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot

