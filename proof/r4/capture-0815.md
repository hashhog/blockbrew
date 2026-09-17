# T2 capture — blockbrew — 2026-08-15 MISMATCH (adjudicated)

**blockbrew did not reproduce C(958794) on this capture.** Do not tag from it.

| field | value |
|---|---|
| captured (UTC) | 2026-08-15T12:56:23Z (watch: 2026-08-15T08:56:23-04:00) |
| height | 958794 |
| bestblockhash | `000000000000000000015eaadd989e4f09ff75b643a128dc7bdf6070431d7d0e` |
| hash_serialized_3 | `24ec9202799b6eafbee0a931fb6f4ac543c0e520652cbae594cec6c3168e7a5a` |
| coins | 166180926 (+1 vs the pin) |

Watch line (also in `r4/capture-watch-excerpt.txt`):

```
blockbrew: *** MISMATCH *** got=24ec9202799b6eafbee0a931fb6f4ac543c0e520652cbae594cec6c3168e7a5a want=29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0
```

## Adjudication (not a hasher miss)

23 minutes earlier the rig restarted on a marker-lag build with chain state at
height 958000 while coins on disk were already at 958794. Recovery replayed
794 blocks. 791 logged `ADOPTED already-applied`. **Three did not: 958187,
958693, 958762** — all coinbase-only (`nTx=1`). Re-applying 958187's already-spent
coinbase is exactly +1 coin.

Pinned in-repo by `TestRecoveryDoesNotResurrectSpentCoinbase`. This capture
measured a mutated chainstate, not the 08-14 MATCH set.

R4 for HEAD remains DISPUTED because the MATCH binary and datadir are gone.
