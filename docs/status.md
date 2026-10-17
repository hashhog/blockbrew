# Status: how to check it yourself

Each row of the README status table, and how to reproduce it from this repository.

## Unit tests

```bash
make test
```

runs `go test ./...` over every package. All packages are expected to pass. The full run
takes several minutes; `internal/storage` and `internal/consensus` are the slow ones.

Go creates test scratch directories under `$TMPDIR`. One test in `cmd/blockbrew` binds a
Unix socket there, so a `$TMPDIR` longer than about 55 characters makes it fail with
`bind: invalid argument`.

Some tests are skipped on purpose. Their skip message names a gap against Bitcoin Core
that a test pins but the code does not yet close. To list them:

```bash
go test -count=1 -v ./internal/... 2>&1 | grep -- '--- SKIP' | sort | uniq | head -50
```

A few of those skips are older than later fixes to the same code, so read a skip as
"this was a gap when the test was written", not as a current bug report.

## Core's script and sighash vectors

From a Bitcoin Core source checkout (any recent version; the files are in
`src/test/data/`):

```bash
go run ./cmd/script_test  /path/to/bitcoin/src/test/data/script_tests.json
go run ./cmd/sighash_test /path/to/bitcoin/src/test/data/sighash.json
```

Expected: `1222 passed, 0 failed` for `script_tests.json` (the skipped entries are comment
lines) and `Passed: 500  Failed: 0` for `sighash.json`. Counts change as Core adds vectors.

## UTXO-set hash at height 958,794

The UTXO set at a given height has one correct `hash_serialized_3`; at mainnet height
958,794 (block `000000000000000000015eaadd989e4f09ff75b643a128dc7bdf6070431d7d0e`) it is
`29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` over 166,180,925
coins. You can get both numbers from Bitcoin Core with `gettxoutsetinfo` at that height.

Two ways to check blockbrew against it:

1. **The hasher, from Core's snapshot file.** Create `utxo-958794.dat` with Core's
   `dumptxoutset` (rollback to 958,794), then:

   ```bash
   BLOCKBREW_C958794_DUMP=/path/to/utxo-958794.dat \
     go test ./internal/consensus/ -count=1 -timeout 45m -run TestHashSnapshotFile_C958794 -v
   ```

   This reads every coin in Core's file with blockbrew's own serializer and hasher and
   checks the hash, coin count and base block. Without the file the test is skipped. It
   tests the hashing code, not blockbrew's validation.

2. **The validator, from genesis.** Sync a mainnet node with `-assumevalid=0` (every
   script checked) past 958,794. `hash_serialized_3` is only reported for the current
   tip, as in Core, so roll the tip back with `invalidateblock` on the block at 958,795,
   read the hash, then undo it:

   ```bash
   RPC() { curl -s --user "$(cat "$COOKIE")" -d "{\"method\":\"$1\",\"params\":$2}" "$URL"; }
   COOKIE=~/.blockbrew/.cookie URL=http://127.0.0.1:8332/
   NEXT=$(RPC getblockhash '[958795]' | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
   RPC invalidateblock "[\"$NEXT\"]"
   RPC gettxoutsetinfo '["hash_serialized_3"]'
   RPC reconsiderblock "[\"$NEXT\"]"
   ```

   The same commands work on a regtest node (set `COOKIE`, `URL` and the height to match).
   A from-genesis mainnet sync takes days and has not been repeated on the current code.

## RPC

`help` on a running node lists the methods; [rpc.md](rpc.md) lists all 143 dispatched
methods and the known differences from Core. The quick start in the README exercises the
RPC on regtest.

## Known limitations

- The UTXO cache flush is not serialised against block connection. A flush started by an
  RPC (for example `scantxoutset`) while a block is being rejected, or a reorg is failing,
  can persist coin changes from the rejected state. The tip and block hashes stay
  correct. Reproduced by the skipped probes in
  `internal/consensus/flush_race_gap_test.go`; fixing it needs a transaction boundary
  between flushing and connecting.
- `-reindex` is not implemented; the node refuses to start with it.
- `loadtxoutset` / `-load-snapshot` load a snapshot, but activating it and validating
  the background chain is not covered by an end-to-end test in this repository.
- Compact blocks (BIP-152) are partial: see the skipped tests in
  `internal/p2p/w112_compact_blocks_test.go` and `internal/p2p/w126_bip152_test.go`.
- No `-rpcauth` or `-rpcallowip`; see [rpc.md](rpc.md#known-differences-from-core).
- The wallet has not been audited. Do not hold real funds in it.
