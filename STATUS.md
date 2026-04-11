# Blockbrew Status

## IBD flag fix (L1-7c) — ready to restart on next scheduled maintenance

The `initialblockdownload` semantic bug is fixed in this branch.  The fix
latches `ibdActive` to `true` at `NewSyncManager` creation time and only
latches it to `false` (irreversibly) once `updateIBDStatus()` confirms that
the chain tip's block timestamp is within 24 hours of wall-clock time.  This
matches Bitcoin Core's `m_cached_is_ibd` / `UpdateIBDStatus()` in
`validation.cpp`.

Do **not** restart the mainnet `blockbrew` instance until the next scheduled
maintenance window.  At that point:

1. Stop the existing mainnet blockbrew process (scheduled downtime only).
2. Pull this branch / the merged `master` into the production checkout.
3. Rebuild: `cargo build --release` is not needed here; blockbrew is Go —
   run `go build ./cmd/blockbrew`.
4. Restart blockbrew with the existing data directory and flags.
5. Verify: `curl -s http://localhost:<rpc-port>/ -d '{"method":"getblockchaininfo"}' | jq .result.initialblockdownload`
   should return `true` immediately after restart and `false` once the tip
   age drops below 24 h.
