# T2 capture — blockbrew — 2026-08-14 MATCH (retired binary)

**blockbrew reproduced C(958794) on a genesis-rig process that no longer exists.**

| field | value |
|---|---|
| captured (UTC) | 2026-08-14T18:20:25Z |
| height | 958794 |
| bestblockhash | `000000000000000000015eaadd989e4f09ff75b643a128dc7bdf6070431d7d0e` |
| hash_serialized_3 | `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` |
| coins | 166180925 |

Lineage of that process: from-genesis, `assumevalid DISABLED (-assumevalid=0)`,
fed by the capped blk-replay-server on `127.0.0.1:28620`. The launch unit is
`r4/genesis-unit.service`. The lineage log is `r4/lineage.log.gz`.

Verified twice at the time: the node's own `dumptxoutset` `txoutset_hash`,
and a Core-format dump hashed independently. `record-t2-reproduction.sh
--commit` wrote the TRUST-ANCHOR row.

## What this does not prove

The matching capture's **binary and datadir are GONE**. This tree (HEAD, pin
`5ccdd59`) has not re-run genesis→958794. CHARTER R4 for this node stays
**DISPUTED** until a new from-genesis reproduction exists for HEAD.
Snapshot-booted ranges and hashing Core's `utxo-958794.dat` do not substitute.
