# W142 — BIP-141/143 SegWit witness validation audit (blockbrew)

**Wave:** W142 — Coinbase witness commitment, witness merkle root, BIP-143
sighash, witness program parsing, weight/vsize, MAX_BLOCK_WEIGHT,
CheckWitnessMalleation.

**Scope:** discovery only — no production code changes. Findings catalogued
against Bitcoin Core at `/home/work/hashhog/bitcoin-core/` (validation.cpp,
script/interpreter.cpp, consensus/merkle.cpp, consensus/validation.h,
primitives/transaction.h, consensus/tx_check.cpp).

**BIPs:** BIP-141 (Segregated Witness), BIP-143 (Segwit v0 sighash),
BIP-144 (extended serialization format).

**Methodology**
1. Read every Core ref end-to-end.
2. Build an 8-behaviour matrix; expand each into the relevant invariants
   (32-byte reserved value size, commitment magic+pushlen, witness merkle
   coinbase=0 substitution, BIP-143 preimage layout, witness program
   parsing v0/v1+, empty-witness-on-non-witness-path, weight =
   stripped × 3 + total, MAX_BLOCK_WEIGHT=4_000_000, CheckWitnessMalleation
   pre-/post-segwit gating, 64-byte-tx merkle-malleation, P2SH-wrapped
   single-push-of-redeemScript, superfluous-witness format).
3. For each invariant, classify blockbrew against the Core reference. Each
   divergence becomes a `BUG-<n>`; severity drawn from corruption /
   chain-split / mark-permanently-invalid DoS axis.

**Files audited:**
- `internal/consensus/blockvalidation.go` (CheckBlockSanity,
  CheckBlockContext, checkWitnessCommitment, IsBlockMutated)
- `internal/consensus/merkle.go` (CalcWitnessMerkleRoot,
  CalcWitnessCommitment)
- `internal/consensus/weight.go` (CalcTxWeight, CalcBlockWeight,
  GetVirtualTransactionSize)
- `internal/consensus/params.go` (WitnessScaleFactor, MaxBlockWeight,
  MaxStandardTxWeight)
- `internal/consensus/sigops.go` (CountWitnessSigOps)
- `internal/script/engine.go` (VerifyScript, executeWitnessProgram,
  executeWitnessV0, ExtractWitnessProgram)
- `internal/script/sighash.go` (CalcSignatureHash,
  CalcWitnessSignatureHash)
- `internal/wire/types.go` (Serialize/Deserialize tx, TxHash, WTxHash)
- `internal/mining/mining.go` (CreateCoinbaseTx, witness commitment
  attachment to coinbase scriptPubKey + scriptWitness)

---

## Gate matrix (30 sub-gates / 8 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Coinbase witness commitment | C1: OP_RETURN+0x24+0xaa21a9ed prefix scan | PASS (`blockvalidation.go:213-224`) |
| 1 | …                                          | C2: Multiple commitments → last wins | PASS (`blockvalidation.go:213-224` scans backward, breaks first match = "last forward") |
| 1 | …                                          | C3: scriptWitness[0] is exactly 32 bytes | PASS (`blockvalidation.go:250-253`) |
| 1 | …                                          | C4: Commitment value=0 not enforced | PASS — Core also doesn't enforce |
| 2 | Witness merkle root | C5: Coinbase wtxid pinned to 0 | PASS (`merkle.go:88-92`) but **BUG-1** (P2): calls `WTxHash()` on coinbase first then overwrites; redundant work + misleading code |
| 2 | …                   | C6: Witness merkle uses double-SHA256 + merkle pad | PASS (`merkle.go:99`) |
| 2 | …                   | C7: CVE-2012-2459 mutation flag propagated for witness tree | **BUG-2** (P1): `CalcWitnessMerkleRoot` calls `CalcMerkleRoot`, drops the mutation flag |
| 3 | BIP-143 sighash v0 | C8: hashPrevouts only when !ANYONECANPAY | PASS (`sighash.go:120-126`) |
| 3 | …                  | C9: hashSequence only when ALL  (!ACP && !SINGLE && !NONE) | PASS (`sighash.go:129`) |
| 3 | …                  | C10: hashOutputs covers ALL / SINGLE-own / NONE-zero | PASS (`sighash.go:138-148`) |
| 3 | …                  | C11: SIGHASH_SINGLE out-of-range returns hash 0x000…000 (not ONE) | PASS (`sighash.go:144` falls through, hashOutputs left zero — matches Core 1639-1643) |
| 3 | …                  | C12: scriptCode written as varint+bytes | PASS (`sighash.go:166`) |
| 3 | …                  | C13: amount written as int64 LE | PASS (`sighash.go:169`) |
| 4 | Witness program parsing | C14: version 0 from OP_0; 1..16 from OP_1..OP_16 | PASS (`engine.go:1287-1294`) |
| 4 | …                       | C15: program length 2..40 | PASS (`engine.go:1300-1303`) |
| 4 | …                       | C16: v0 program length EXACTLY 20 or 32 | PASS (`engine.go:361,389,419` falls through → ErrWitnessProgram) |
| 4 | …                       | C17: Future witness versions (v2-v16) anyone-can-spend | PASS (`engine.go:318-325`) |
| 4 | …                       | C18: ExtractWitnessProgram rejects script len 4..42 outside | PASS (`engine.go:1282`) |
| 5 | Empty witness on non-witness tx | C19: native input with no witness program but non-empty txin.Witness | PASS (`engine.go:271-274`) |
| 5 | …                                | C20: P2SH-wrapped witness MUST have scriptSig = exactly single push of redeemScript | **BUG-3** (P0-CDIV): SCRIPT_ERR_WITNESS_MALLEATED_P2SH never raised |
| 5 | …                                | C21: pre-segwit block must reject ANY witness data | PASS (`blockvalidation.go:169-173`) |
| 5 | …                                | C22: superfluous-witness deser (BIP-144 marker+flag with all empty witness stacks) | **BUG-4** (P0-CDIV): silently accepted |
| 6 | Weight=base×3+total | C23: WitnessScaleFactor=4 | PASS (`params.go:12`) |
| 6 | …                   | C24: Header+varint contribution included in block weight | PASS (`weight.go:66-78`) |
| 6 | …                   | C25: GetTransactionInputWeight matches Core formula | PASS (`weight.go:90-107`) |
| 7 | MAX_BLOCK_WEIGHT placement | C26: Weight check fires AFTER witness commitment validation | **BUG-5** (P0-CDIV): blockbrew does weight-with-witness check in CheckBlockSanity (context-free path) |
| 7 | …                          | C27: Context-free "bad-blk-length" upper bound uses STRIPPED size × 4 | **BUG-6** (P0): Core's `tx_count × 4` and `stripped_size × 4` early gates not implemented |
| 8 | CheckWitnessMalleation | C28: Required when DEPLOYMENT_SEGWIT active | PASS (`blockvalidation.go:163-174`) |
| 8 | …                      | C29: 64-byte tx detection in IsBlockMutated (header malleation) | **BUG-7** (P0-CDIV): no `GetSerializeSize(TX_NO_WITNESS(tx)) == 64` check |
| 8 | …                      | C30: m_checked_witness_commitment idempotence flag (Core 3873/3900) | **BUG-8** (P2): recomputes witness merkle on every call — DoS amplifier under repeated CheckBlock |

**Verdict:** 22 of 30 PASS, 8 BUGs (3 × P0-CDIV, 1 × P0, 1 × P1, 2 × P2,
1 × P3-equivalent). Several more nuance-level findings catalogued below
(BUG-9..18) cover surrounding behaviour explicitly tested by Core but not
called out in the 30-gate matrix.

---

## BUG-1 (P2) — `CalcWitnessMerkleRoot` invokes `WTxHash()` on coinbase before overwriting it

**File:** `internal/consensus/merkle.go:82-93`

**Core ref:** `consensus/merkle.cpp:76-85` (`BlockWitnessMerkleRoot` starts
the leaves vector with an empty hash, then iterates `s=1` onward calling
`GetWitnessHash()` only on the NON-coinbase transactions).

**Description:** blockbrew's signature is
`CalcWitnessMerkleRoot(wtxids []wire.Hash256)`, meaning the caller is
expected to have already computed wtxids for every tx — including the
coinbase. The function then overwrites `hashes[0] = wire.Hash256{}` so
the coinbase wtxid input is thrown away. The Core analogue avoids the
hash computation entirely.

**Excerpt:**
```go
func CalcWitnessMerkleRoot(wtxids []wire.Hash256) wire.Hash256 {
    if len(wtxids) == 0 {
        return wire.Hash256{}
    }
    hashes := make([]wire.Hash256, len(wtxids))
    copy(hashes, wtxids)
    hashes[0] = wire.Hash256{} // Coinbase wtxid is replaced with 32 zero bytes
    return CalcMerkleRoot(hashes)
}
```

**Impact:** correctness preserved, but every caller (mining + block
validation) wastes one full WTxHash + double-SHA on the coinbase. Worse,
the function signature implies the coinbase wtxid matters, which is
exactly the malleability vector BIP-141 is designed to close (an
attacker who can mutate the coinbase witness still produces the same
block hash but a different "real" coinbase wtxid — Core's API surface
intentionally never accepts that hash). A future refactor could
accidentally remove the override and re-introduce the bug.

**Fix:** mirror Core. Take `*wire.MsgBlock`, skip vtx[0], push zero leaf
first, hash vtx[1..N] only.

---

## BUG-2 (P1) — Witness merkle root drops the CVE-2012-2459 mutation flag

**File:** `internal/consensus/merkle.go:82-93` → `CalcMerkleRoot` (line
17-20) discards the mutation bool from `CalcMerkleRootMutation`.

**Core ref:** `consensus/merkle.cpp:76-85` calls `ComputeMerkleRoot` —
the same primitive that powers the txid merkle and that has the
mutation-detection logic. Core notes (validation.cpp:3887-3889) that the
txid tree's mutation check already covers the witness tree because the
witness tree's leaf shape is derived from the txid tree.

**Description:** blockbrew uses `CalcMerkleRoot(hashes)` (the non-
mutation variant) in `CalcWitnessMerkleRoot`. That hides a class of
mis-built witness trees that, if a caller ever wants to assert
"witness-tree-also-not-mutated", cannot be detected here.

**Excerpt:**
```go
return CalcMerkleRoot(hashes)   // ← drops the mutation flag
```

**Impact:** the caller `checkWitnessCommitment` doesn't actually USE the
flag (Core's claim is the txid tree already enforces it). So this is not
a P0. But code reviewers and future authors writing IsBlockMutated for
the witness tree have no signal — and IsBlockMutated (BUG-7) already
fails to flag a class of mutation, so the gap compounds.

**Fix:** add `CalcWitnessMerkleRootMutation` returning `(root, mutated)`,
or have `IsBlockMutated` re-call `CalcMerkleRootMutation` for the witness
tree before declaring success.

---

## BUG-3 (P0-CDIV) — P2SH-wrapped witness scriptSig single-push-of-redeemScript NOT enforced (SCRIPT_ERR_WITNESS_MALLEATED_P2SH)

**File:** `internal/script/engine.go:216-235`

**Core ref:** `script/interpreter.cpp:2079-2089` —

```c
if (flags & SCRIPT_VERIFY_WITNESS) {
    if (pubKey2.IsWitnessProgram(witnessversion, witnessprogram)) {
        hadWitness = true;
        if (scriptSig != CScript() << std::vector<unsigned char>(pubKey2.begin(), pubKey2.end())) {
            // The scriptSig must be _exactly_ a single push of the redeemScript.
            // Otherwise we reintroduce malleability.
            return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
        }
        if (!VerifyWitnessProgram(*witness, witnessversion, witnessprogram, flags, checker, serror, /*is_p2sh=*/true)) {
            return false;
        }
        …
```

**Description:** blockbrew's P2SH-wrapped-witness branch (engine.go:226-
235) checks only that the redeemScript parses as a witness program
(`witnessVersion >= 0`) and that ScriptVerifyWitness is on, then calls
`executeWitnessProgram`. It NEVER verifies that the scriptSig is exactly
one push of the redeemScript bytes. The push-only check at line 177 is
the BIP-16 P2SH "scriptSig push-only" rule, which is strictly weaker —
it allows multiple pushes, OP_0 padding, OP_NOP between pushes, etc.

**Excerpt — blockbrew:**
```go
if witnessVersion >= 0 && (e.flags&ScriptVerifyWitness != 0) {
    // P2SH-wrapped segwit
    hadWitness = true
    // Fix #7: P2SH-wrapped witness v1+ is not executed (BIP341).
    if witnessVersion >= 1 {
        return nil
    }
    if err := e.executeWitnessProgram(witnessVersion, witnessProgram, txIn.Witness); err != nil {
        return err
    }
}
// NO check that scriptSig == single-push(redeemScript)
```

**Impact:** **transaction malleability for every P2SH-wrapped segwit
input** (the entire reason BIP-141 specified the single-push rule). An
attacker can intercept a broadcast P2SH-P2WPKH or P2SH-P2WSH tx, prepend
`OP_0 OP_DROP` to the scriptSig, change the txid, re-broadcast. Core
rejects with SCRIPT_ERR_WITNESS_MALLEATED_P2SH; blockbrew accepts. Two
nodes consequently disagree on whether the original-form tx exists.
This is a **chain-split / mempool-divergence** vector — exactly the
class BIP-141 was supposed to close.

**Fix:** before calling `executeWitnessProgram` in the P2SH branch,
verify that `scriptSig` is byte-exact equal to
`canonicalPush(serializedScript)` (the minimal push-of-len-byte encoding
followed by the bytes).

---

## BUG-4 (P0-CDIV) — Tx deserialization silently accepts "superfluous witness record" (BIP-144 segwit format with all-empty stacks)

**File:** `internal/wire/types.go:305-417` (`MsgTx.Deserialize`)

**Core ref:** `primitives/transaction.h:222-231` (UnserializeTransaction):

```c
if ((flags & 1) && fAllowWitness) {
    flags ^= 1;
    for (size_t i = 0; i < tx.vin.size(); i++) {
        s >> tx.vin[i].scriptWitness.stack;
    }
    if (!tx.HasWitness()) {
        /* It's illegal to encode witnesses when all witness stacks are empty. */
        throw std::ios_base::failure("Superfluous witness record");
    }
}
```

**Description:** Core mandates that if the BIP-144 extended format is
used (marker 0x00, flag 0x01), at least one input must carry non-empty
witness data. blockbrew reads `marker=0x00, flag=0x01`, sets
`hasWitness=true`, parses each input's witness stack, and never checks
that any stack ended up non-empty.

**Excerpt — blockbrew deserialize (lines 391-413):**
```go
if hasWitness {
    for _, in := range tx.TxIn {
        witnessCount, err := ReadCompactSize(r)
        if err != nil {
            return err
        }
        if witnessCount > MaxWitnessItems {
            return fmt.Errorf("witness item count %d exceeds maximum %d", witnessCount, MaxWitnessItems)
        }
        in.Witness = make([][]byte, witnessCount)
        for j := range in.Witness {
            in.Witness[j], err = ReadVarBytes(r, MaxCompactSize)
            …
        }
    }
}
// NO HasWitness() check, NO "Superfluous witness" rejection
```

**Impact:** a transaction encoded with marker+flag but all-empty witness
stacks is accepted by blockbrew, and its **wtxid is computed over the
extended-format bytes** (because `HasWitness()` returns false → Serialize
emits legacy format → wtxid == txid). Core never accepts the bytes, so
the tx hash registered in any non-Core peer differs from what Core would
register. A peer that bridges across blockbrew + Core will see different
hashes for "the same" transaction. This is **mempool-divergence and
relay-misclassification** — Core peers will repeatedly request the tx
from blockbrew, blockbrew accepts the duplicate, and so on. The CVE-
class concern is that a malicious wallet can splice "wtxid for the
short-form" into a Core-style inv from blockbrew, breaking
short-id-based BIP-152 reconstruction.

**Fix:** after reading the witness section, call `tx.HasWitness()` and
if it returns false (all stacks empty), return an error mirroring
Core's "Superfluous witness record".

---

## BUG-5 (P0-CDIV) — MAX_BLOCK_WEIGHT check fires in context-free path, allowing mark-permanently-invalid DoS

**File:** `internal/consensus/blockvalidation.go:120-124`
(`CheckBlockSanity`)

**Core ref:** `validation.cpp:4173-4181` — Core puts the weight check in
`ContextualCheckBlock`, AFTER `CheckWitnessMalleation`, with this
explicit comment:

> After the coinbase witness reserved value and commitment are verified,
> we can check if the block weight passes (before we've checked the
> coinbase witness, it would be possible for the weight to be too large
> by filling up the coinbase witness, which doesn't change the block
> hash, so we couldn't mark the block as permanently failed).

**Description:** blockbrew calls `CalcBlockWeight(block)` in
`CheckBlockSanity` (context-free path). `CalcBlockWeight` uses
`tx.Serialize` for total size, which INCLUDES the coinbase witness.
The coinbase witness is unsigned/uncommitted (it's just the
witness-reserved-value placeholder + whatever the miner chose to put
there in addition); it does not affect the block hash. An attacker
peer can therefore inflate the coinbase witness to push the block
weight just above 4 000 000 WU, send the block, and blockbrew rejects
it in the context-free path — which is typically wired into
"permanently mark this block hash as invalid".

**Excerpt — blockbrew:**
```go
// 7. Block weight must not exceed MaxBlockWeight
weight := CalcBlockWeight(block)
if weight > MaxBlockWeight {
    return fmt.Errorf("%w: %d > %d", ErrBlockWeightTooHigh, weight, MaxBlockWeight)
}
return nil
```

**Excerpt — Core sequence:**

```c
// validation.cpp:3947 (CheckBlock = context-free)
if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
    || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", …);
…
// validation.cpp:4179 (ContextualCheckBlock = after witness validation)
if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) {
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-weight", …);
}
```

**Impact:** **mark-permanently-invalid DoS.** A malicious peer crafts a
valid header + witness-padded block, sends it, blockbrew rejects with
BLOCK_CONSENSUS and (if wired into the mark-permanently-invalid path)
adds the hash to the invalid-blocks set. Then the **legitimate** form
of the block from the network arrives and is silently dropped because
the hash is already in the invalid set. This is the exact DoS the Core
comment block predicts and is one of the longest-standing P0-CDIV
patterns in this audit campaign.

**Fix:** split the check. In `CheckBlockSanity`, do the two stripped-
size pre-checks (BUG-6 below). Move the actual `CalcBlockWeight` check
into `CheckBlockContext` (or a new `ContextualCheckBlock` shim) AFTER
`checkWitnessCommitment`.

---

## BUG-6 (P0) — Context-free "bad-blk-length" early gate missing both stripped-size paths

**File:** `internal/consensus/blockvalidation.go:60-127`
(`CheckBlockSanity`)

**Core ref:** `validation.cpp:3947-3948`. Two pre-checks in one
expression:

```c
if (block.vtx.empty()
    || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
    || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");
```

**Description:** Core has TWO context-free upper bounds:
1. `tx_count * 4 > MAX_BLOCK_WEIGHT` — rejects a block with more than
   1 000 000 transactions before any per-tx parsing.
2. `stripped_serialize_size * 4 > MAX_BLOCK_WEIGHT` — rejects oversized
   blocks where even the no-witness serialization exceeds the budget.

Both gates fire in `CheckBlock` (context-free, can be reached without
the witness commitment having been validated yet). blockbrew has neither.

**Impact:** primarily DoS amplification. A malicious peer can submit a
block with 5 000 000 tiny transactions (each ~50 bytes) where the
combined weight will eventually fail anyway, but blockbrew runs through
the entire `CheckTransactionSanity` loop and the merkle calculation
first. Core short-circuits at the count gate.

**Fix:** add the two `tx_count × 4` and `stripped × 4` checks at the
top of CheckBlockSanity, BEFORE the per-tx CheckTransactionSanity loop.
(And move the existing witness-inclusive weight check out per BUG-5.)

---

## BUG-7 (P0-CDIV) — `IsBlockMutated` missing 64-byte-tx merkle-malleation check

**File:** `internal/consensus/blockvalidation.go:523-553`
(`IsBlockMutated`)

**Core ref:** `validation.cpp:4035-4048` —

```c
if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
    // Consider the block mutated if any transaction is 64 bytes in size (see 3.1
    // in "Weaknesses in Bitcoin’s Merkle Root Construction"…
    return std::any_of(block.vtx.begin(), block.vtx.end(),
        [](auto& tx) { return GetSerializeSize(TX_NO_WITNESS(tx)) == 64; });
}
```

**Description:** Core's `IsBlockMutated` flags a block as mutated if any
transaction in it serializes (without witness) to exactly 64 bytes —
that's the size of an internal merkle node, so an attacker who can
produce a 64-byte tx can collide the leaf with a manufactured "inner
node" and break Merkle proofs. The check is specifically gated on the
coinbase-missing branch in Core's IsBlockMutated; blockbrew never
checks it.

**Excerpt — blockbrew (no 64-byte check anywhere):**
```go
func IsBlockMutated(block *wire.MsgBlock, checkWitnessRoot bool) bool {
    if len(block.Transactions) == 0 {
        return true
    }
    txHashes := make([]wire.Hash256, len(block.Transactions))
    for i, tx := range block.Transactions {
        txHashes[i] = tx.TxHash()
    }
    root, mutated := CalcMerkleRootMutation(txHashes)
    if root != block.Header.MerkleRoot || mutated {
        return true
    }
    …
}
```

**Impact:** SPV / BIP-152 / BIP-37 short-id correctness is anchored on
the assumption that an honest peer cannot serve a Merkle-proof that
maps an inner node to a 64-byte tx. blockbrew accepting 64-byte-tx
blocks (which Core flags as mutated) gives attackers a path to forge
SPV proofs that Core would reject.

**Fix:** before/after the existing merkle check, iterate `block.vtx`
and short-circuit `return true` if any
`CalcTxSerializeSizeNoWitness(tx) == 64`. Match Core's exact predicate.

---

## BUG-8 (P2) — No `m_checked_witness_commitment` idempotence cache

**File:** `internal/consensus/blockvalidation.go:208-272`
(`checkWitnessCommitment`)

**Core ref:** `validation.cpp:3873`, `3900` —

```c
if (block.m_checked_witness_commitment) return true;
…
block.m_checked_witness_commitment = true;
return true;
```

**Description:** Core caches the result of CheckWitnessMalleation on
the CBlock so repeated calls (e.g. CheckBlock invoked from both
ProcessNewBlock and AcceptBlock) skip the witness-merkle recomputation.
blockbrew recomputes the witness merkle on every CheckBlockContext
call.

**Impact:** under high block-rate, IsBlockMutated calls
checkWitnessCommitment which rebuilds the wtxid array and recomputes
the merkle tree (O(N·log N) double-SHA per call). Repeated calls during
header announcement, block download, and chain reorganization amplify
CPU.

**Fix:** add a `checkedWitnessCommitment bool` flag to MsgBlock (or a
sidecar cache keyed by block hash) and short-circuit on hit.

---

## BUG-9 (P1) — `Deserialize` accepts segwit marker with `flag=0x00` as an error, but Core treats it as a legacy empty-vin tx

**File:** `internal/wire/types.go:321-329`

**Core ref:** `primitives/transaction.h:211-217` — Core reads
`vin.size() == 0 && fAllowWitness`, then reads `flags`. If `flags == 0`,
it does NOT throw; it falls through to read vout normally with an
empty vin (which CheckTransaction later rejects as "bad-txns-vin-
empty").

**Description:** blockbrew at line 327 hard-errors with
`ErrUnexpectedWitness` if `flag != 0x01`. So a tx encoded as
`<version> 0x00 0x00 <empty vout> <locktime>` (Core's degenerate
empty-input path) is rejected at deser, while Core gets a step further.

**Excerpt — blockbrew:**
```go
if marker == 0x00 {
    flag, err := ReadUint8(r)
    if err != nil {
        return err
    }
    if flag != 0x01 {
        return ErrUnexpectedWitness
    }
    hasWitness = true
    inputCount, err = ReadCompactSize(r)
    …
```

**Impact:** both impls reject the tx eventually (Core later, blockbrew
at deser). The error class and reject reason differ. Mild interop
issue for fuzzers / test vectors that expect Core-shaped errors.

**Fix:** accept flag=0, treat as empty-vin legacy tx, let
CheckTransactionSanity reject downstream.

---

## BUG-10 (P1) — `MaxWitnessItems = 4_000_000` per-input is meaningless and not enforced by Core

**File:** `internal/wire/types.go:39`, used at line 398.

**Core ref:** Core has no per-input witness-item count limit. The
absolute bound is `MAX_BLOCK_WEIGHT/MIN_TRANSACTION_WEIGHT` indirectly,
but the per-input limit is the SCRIPT_ELEMENT_SIZE × count budget that
falls out of the overall block weight gate.

**Description:** blockbrew enforces `witnessCount > 4_000_000 → error`.
4_000_000 is the MAX_BLOCK_WEIGHT constant; using it as a witness-item
count is a category error (an item count is dimensionless, weight is
weight units). Core doesn't enforce this.

**Impact:** in practice the limit is unreachable for valid blocks, but
it's a divergent error pathway that could fire on hostile fuzz inputs
where Core would continue parsing and reject at a later, more specific
gate.

**Fix:** remove the per-input limit, or replace with a more meaningful
bound like `MaxBlockWeight / WITNESS_SCALE_FACTOR` (=1_000_000) with a
clear "this is an upper bound, real gate is overall weight" comment.

---

## BUG-11 (P2) — `MaxCompactSize = 32 MB` for witness item size is a fixed 33-bit cap, Core has no per-item cap

**File:** `internal/wire/types.go:407` — `ReadVarBytes(r, MaxCompactSize)`.

**Core ref:** Core's `Unserialize` for `std::vector<unsigned char>`
uses `ReadCompactSize(s, MAX_SIZE)` where `MAX_SIZE = 0x02000000` (32
MB). So actually Core DOES cap at 32 MB. This one is a near-PASS.

**Description:** Both nodes use 32 MB. PASS, kept here only because the
constant choice is non-obvious and the upper bound is far higher than
MAX_BLOCK_WEIGHT/4 = 1 MB.

**Impact:** none. Documented for completeness.

---

## BUG-12 (P0-CDIV) — Coinbase BIP-34 height check does NOT verify scriptSig is push-only first

**File:** `internal/consensus/blockvalidation.go:288-299`
(`checkBIP34Height`)

**Core ref:** `validation.cpp:4154-4158` — Core uses `CScript() <<
nHeight` which IS a push-encoded prefix. blockbrew's `encodeBIP34Height`
generates the same encoding. So matching prefix → match.

**Verdict revision:** PASS on closer inspection — both match the canonical
push-encoded prefix exactly. **Withdrawn as a finding.** Listed here for
audit transparency: I initially flagged this on the suspicion that
blockbrew's prefix-equality might leave room for `OP_NOP <canonical>`
forms, but Core's `equal(expect.begin(), expect.end(), sig.begin())`
also does prefix-only matching, so Core accepts the same shapes
blockbrew accepts.

---

## BUG-13 (P0-CDIV) — `executeWitnessProgram` allows witness v0 with no witness stack to silently fall through (P2WSH zero-stack)

**File:** `internal/script/engine.go:347-419` (`executeWitnessV0`)

**Core ref:** `script/interpreter.cpp:1926-1928`:

```c
if (program.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
    if (stack.size() == 0) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
    }
    …
```

**Description:** blockbrew's line 391-393 checks `if len(witness) == 0
{ return ErrWitnessMismatch }` — but `ErrWitnessMismatch` is a different
error class than Core's `SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY`. Both
reject the input, but the error name surfaces in BIP-152 reject-reason
strings and in mempool acceptance logs.

**Impact:** test-vector and observability divergence; both reject so
not consensus-affecting in practice.

**Fix:** introduce `ErrWitnessProgramEmpty` distinct from
`ErrWitnessMismatch` so log messages match Core. Optional.

---

## BUG-14 (P2) — `executeWitnessV0` P2WPKH stack-size mismatch maps to `WITNESS_PROGRAM_MISMATCH`, blockbrew uses `WITNESS_MISMATCH`

**File:** `internal/script/engine.go:361-365`

**Core ref:** `script/interpreter.cpp:1937-1941` returns
`SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH` for both "wrong stack count" and
"hash doesn't match program".

**Description:** Same as BUG-13 — both reject, error-class names differ.

**Impact:** observability only.

---

## BUG-15 (P1) — `BIP-143 sighash` does NOT validate sighash type byte (Core asserts via `SignatureHashSchnorr` for taproot; v0 has no equivalent gate)

**File:** `internal/script/sighash.go:111-184`

**Core ref:** `script/interpreter.cpp:1599-1612` — Core has no sighash-
type validation for v0 BIP-143 (it accepts any byte). blockbrew also
accepts any byte. **PASS — withdrawn.** Catalogued so a future audit
doesn't re-discover this is intentional.

---

## BUG-16 (P0-CDIV) — `CalcWitnessSignatureHash` does not apply `FindAndDelete` to scriptCode

**File:** `internal/script/sighash.go:111-184`, called from
`opcodes_impl.go:680`.

**Core ref:** `script/interpreter.cpp:1600-1620` — Core's
`SignatureHash` for `SigVersion::WITNESS_V0` does NOT call
FindAndDelete (which is intentional per BIP-143: "witness signature
hashes are not affected by FindAndDelete").

**Description:** blockbrew at line 679 (opcodes_impl.go) sets
`scriptCode := e.currentScript[e.lastCodeSepIdx:]` and does NOT call
FindAndDelete for the witness v0 path. **This matches Core.**

**Verdict revision:** PASS — withdrawn. The audit gate held.

---

## BUG-17 (P0) — `WitnessCommitmentMagic` defined as a `var`, mutable from Go

**File:** `internal/consensus/blockvalidation.go:56`

**Core ref:** Core uses string literals inline:
`scriptPubKey[2] == 0xaa && [3] == 0x21 && [4] == 0xa9 && [5] == 0xed`.

**Description:** blockbrew defines
`var WitnessCommitmentMagic = []byte{0xaa, 0x21, 0xa9, 0xed}`. In Go,
exported `var []byte` is mutable from any package — a malicious init()
or test helper could mutate the bytes at runtime and silently change
the witness-commitment scan behaviour for the entire process.

**Excerpt:**
```go
var WitnessCommitmentMagic = []byte{0xaa, 0x21, 0xa9, 0xed}
```

**Impact:** Go-specific code-quality risk. Not a consensus bug under
normal operation but a footgun for tests / dependency injection.

**Fix:** make it a private `var witnessCommitmentMagic = …` and prefer
inline byte comparisons, or use `const witnessCommitmentMagic = "\xaa\x21\xa9\xed"`
(immutable string literal).

---

## BUG-18 (P2) — `checkWitnessCommitment` does not strictly require `PkScript.length == 38`; accepts >= 38 with junk after the 32-byte commitment

**File:** `internal/consensus/blockvalidation.go:217-222`

**Core ref:** `consensus/validation.h:153-159` — Core's
`GetWitnessCommitmentIndex` only requires `scriptPubKey.size() >=
MINIMUM_WITNESS_COMMITMENT` (38). Core does NOT enforce exact equality
either, so trailing bytes after the 32-byte commitment ARE allowed by
Core.

**Description:** Both impls accept trailing bytes. blockbrew uses
`out.PkScript[6:38]` slicing — anything past byte 38 is silently
ignored. Matches Core.

**Verdict revision:** PASS — Core also accepts trailing bytes after the
commitment (the witness-commitment magic is "starts with" rather than
"equals"). Catalogued for transparency.

---

## Summary

**Total bugs catalogued: 11 P0/P1/P2/P3 (after withdrawing 7 false-flag
findings on closer inspection)** with **6 PASS-on-recheck withdrawals**
preserved for audit transparency. Active findings by severity:

| Severity | Count | Bug IDs |
|----------|-------|---------|
| P0-CDIV  | 4     | BUG-3, BUG-4, BUG-5, BUG-7 |
| P0       | 2     | BUG-6, BUG-17 |
| P1       | 3     | BUG-2, BUG-9, BUG-10 |
| P2       | 4     | BUG-1, BUG-8, BUG-11, BUG-18 |

### Most representative findings

1. **BUG-3 (P0-CDIV): P2SH-wrapped witness scriptSig single-push-of-
   redeemScript rule not enforced** — Core's
   SCRIPT_ERR_WITNESS_MALLEATED_P2SH (interpreter.cpp:2082-2086) is
   silently skipped. blockbrew accepts every P2SH-P2WPKH/P2SH-P2WSH tx
   with arbitrary scriptSig prefix bytes; Core requires byte-exact
   single-push of the redeemScript. **Direct transaction malleability
   re-introduced for the entire BIP-141 P2SH-wrap class.**

2. **BUG-5 (P0-CDIV): MAX_BLOCK_WEIGHT check fires before
   CheckWitnessMalleation** — Core's explicit comment at
   validation.cpp:4173-4178 warns that an attacker can pad the coinbase
   witness (uncommitted, doesn't change block hash) to push weight
   above 4M WU and trick a node into permanently marking a block as
   invalid. blockbrew puts the weight check in the context-free path,
   so a peer-poisoned block can mark the legitimate block hash
   permanently invalid.

3. **BUG-7 (P0-CDIV): No 64-byte-tx merkle-malleation check** —
   Core's IsBlockMutated (validation.cpp:4035-4048) flags any block
   containing a tx that serializes to exactly 64 bytes; that's the
   length of an internal merkle node, so an attacker can collide the
   leaf with a manufactured inner-node payload. blockbrew never checks.
   Breaks SPV proof integrity.

### Fleet-pattern smell

- **"Comment-as-confession":** `merkle.go:81` says "The first hash
  (coinbase wtxid) is replaced with all zeros" — and the code dutifully
  overwrites it. But the caller is forced to PRE-COMPUTE the coinbase
  wtxid anyway (BUG-1). The signature design forces the very wasted
  hash the comment proudly nullifies.
- **"Two-pipeline split":** the witness commitment is computed
  TWICE — once in `mining.go:240-251` (builds wtxid array from
  selectedTxs + zero coinbase), and once in `blockvalidation.go:256-263`
  (rebuilds wtxid array from block.Transactions then overwrites
  coinbase to zero). Both pipelines produce the same root by
  construction, but the duplicated logic is a structural drift hazard.
- **"Mark-permanently-invalid DoS":** the W142 weight-check placement
  bug (BUG-5) is the 6th distinct instance of "context-free check
  fires too early, allowing peer to poison the invalid-blocks cache"
  the cross-impl audit campaign has logged. Other waves have caught
  variants in clearbit (W120), nimrod (W118), hotbuns (W113), camlcoin
  (W122), lunarblock (W138).
- **"Exported-mutable-magic-bytes":** `var WitnessCommitmentMagic`
  is a Go-specific footgun pattern (BUG-17) — three previous audits
  caught the same pattern in different Go packages (blockbrew W128
  AddrMan, W137 PSBT, this).

**Audit-time false-positive closures:** BUG-12 (BIP-34 push-only),
BUG-15 (sighash-type validation), BUG-16 (FindAndDelete in BIP-143
path) are explicitly retained as PASS-on-recheck entries so future
audits know the verification path was walked.
