# Changelog

## v1.0.0 (unreleased)

Changes since `v0.1.0-rc2`:

- 57b7a0c test: flip 28 stale W108/W117/W124/W125/W141 pins to Core's behaviour
- aa5d3d1 fix: GBT sizelimit = MAX_BLOCK_SERIALIZED_SIZE; empty-vin package guard; prune child Depends on parent removal
- a17b3b7 docs: LICENSE, Go toolchain version in README (release hygiene)
- 0af8bce fix(rpc): implement the dispatcher arity check every handler already defers to
- 7b406e7 fix(test): consensus vector suite could not find its vectors
- cdfdbd2 fix(rpc): the integer conversion runs before the lookup, and disconnectnode accepts a null address
- 18e7e94 fix(p2p): never join a peer's own goroutines from its message handlers
- acb3b97 fix(rpc): read integer arguments at Core's width, and honour the ones we read
- 58761f5 fix(rpc): createrawtransaction ignored the `version` argument
- a9d4ef2 fix(rpc): submitblock decode failure reports Core's token, not the decoder's own text
- 9898faf fix(rpc): createrawtransaction — contradiction check, sequence isNum guard, ParseHashV wording
- 72a193d fix(rpc): createrawtransaction rejects replaceable=true contradicted by its sequences
- 7303d6a fix(rpc): createrawtransaction range-checks vout and locktime; Core error codes
- dd308e8 fix(sync): do not charge an escalating stall penalty to a request never issued (#75)
- bd5e363 test: BIP-68 intra-block prevHeight pins (discharges the e461f5a promise)
- fbdc292 feat(shim): checkblock MTP context — BIP-113 finality + time-based BIP-68 locks
- 7fd53a2 fix(rpc): getchaintips reports the VALIDATED tip as active + TestPreciousBlock setup (#43 blockbrew slice)
- a457b8a fix: seqlock disable-arm zeroes prevHeights + at-tip headers from any peer + deterministic SendMessage drop
- 9f5e845 test(consensus): work-vs-length chain-selection pins on RecalculateBestTip (#47)
- e461f5a fix(consensus): ConnectBlock's BIP-68 prevHeights defaults CONSERVATIVE on cache miss (#53)
- 586fdac fix(p2p): SendMessage reports drops; requestBlocks reverts dropped getdata — the chronic tip-stall root cause
- dec8a0e fix(sync,rpc): tip fetch-wedge #73 — stall handler starved its own retry; submitblock duplicate must still activate
- 7009b2b fix(p2p): G18 appends real chain_start LocatorEntries, not the bare hash
- ea0b59f fix(consensus): interleave disconnect per tx in DisconnectBlockUTXOs
- aff2a6b fix(rpc): submitblock must not answer "duplicate" for a known HEADER

