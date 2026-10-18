# RPC reference

blockbrew serves Bitcoin Core-style JSON-RPC over HTTP on the RPC port (see
[running.md](running.md)). Method names, positional parameters and result fields follow
Core. Pass `params` as a JSON array: named parameters (a JSON object) and batch requests
(a JSON array of requests) are not supported.

## Calling it

Authentication is HTTP Basic auth, with either the cookie written at startup to
`<datadir>[/<network>]/.cookie` (user `__cookie__`) or `-rpcuser`/`-rpcpassword`:

```bash
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" \
  -d '{"jsonrpc":"1.0","id":1,"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/
```

Calls for a specific wallet go to `/wallet/<name>`, as in Core:

```bash
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"createwallet","params":["demo"]}' http://127.0.0.1:18443/
ADDR=$(curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"getnewaddress","params":[]}' http://127.0.0.1:18443/wallet/demo | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d "{\"method\":\"generatetoaddress\",\"params\":[101,\"$ADDR\"]}" http://127.0.0.1:18443/ > /dev/null
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"getbalance","params":[]}' http://127.0.0.1:18443/wallet/demo
```

`help` lists the methods, grouped as below, and `help <method>` prints one method's
usage.

## REST

With `-rest`, unauthenticated read-only endpoints are served under `/rest/` on the RPC
port: `block/<hash>`, `block/notxdetails/<hash>`, `tx/<txid>`, `headers/<count>/<hash>`,
`blockhashbyheight/<height>`, `chaininfo.json`, `mempool/info.json`,
`mempool/contents.json`, `getutxos/...`, `blockfilter/...` and `blockfilterheaders/...`,
each with a `.json`, `.hex` or `.bin` suffix as in Core.

```bash
curl -s http://127.0.0.1:18443/rest/chaininfo.json
```

## Methods

143 methods are dispatched (`internal/rpc/server.go`, `dispatch`). "In `help`" says
whether `help` lists the method; 28 dispatched methods are missing from `help`.

### Blockchain

| Method | In `help` | Notes |
|---|---|---|
| `dumptxoutset` | no |  |
| `flushchainstate` | no | hidden in Core too |
| `getbestblockhash` | yes |  |
| `getblock` | yes |  |
| `getblockchaininfo` | yes |  |
| `getblockcount` | yes |  |
| `getblockfilter` | yes | needs `-blockfilterindex` |
| `getblockfrompeer` | yes |  |
| `getblockhash` | yes |  |
| `getblockheader` | yes |  |
| `getblockstats` | yes |  |
| `getchainstates` | yes |  |
| `getchaintips` | yes |  |
| `getchaintxstats` | yes |  |
| `getdeploymentinfo` | yes |  |
| `getdifficulty` | yes |  |
| `getindexinfo` | yes |  |
| `getsyncstate` | yes | blockbrew only: header/block sync progress |
| `gettxout` | yes |  |
| `gettxoutproof` | yes |  |
| `gettxoutsetinfo` | yes |  |
| `gettxspendingprevout` | yes | confirmed spends need `-txospenderindex` |
| `invalidateblock` | no |  |
| `loadtxoutset` | no | snapshot activation is not covered by an end-to-end test in this repo |
| `preciousblock` | yes |  |
| `pruneblockchain` | yes |  |
| `reconsiderblock` | no |  |
| `scanblocks` | yes |  |
| `scantxoutset` | yes |  |
| `verifychain` | yes |  |
| `verifytxoutproof` | yes |  |
| `waitforblock` | yes |  |
| `waitforblockheight` | yes |  |
| `waitfornewblock` | yes |  |

### Control

| Method | In `help` | Notes |
|---|---|---|
| `getinfo` | yes | not in current Core (removed in v0.16) |
| `getmemoryinfo` | yes |  |
| `getrpcinfo` | yes |  |
| `help` | yes |  |
| `logging` | yes |  |
| `stop` | yes |  |
| `uptime` | yes |  |

### Mining

| Method | In `help` | Notes |
|---|---|---|
| `generate` | no | not in current Core; regtest only |
| `generateblock` | no | regtest only |
| `generatetoaddress` | no | regtest only |
| `generatetodescriptor` | no | regtest only |
| `getblocktemplate` | yes |  |
| `getmininginfo` | yes |  |
| `getnetworkhashps` | yes |  |
| `getprioritisedtransactions` | yes |  |
| `prioritisetransaction` | yes |  |
| `submitblock` | yes |  |
| `submitblockbatch` | no | blockbrew only: submit several blocks in one call |
| `submitheader` | yes |  |

### Network

| Method | In `help` | Notes |
|---|---|---|
| `addnode` | yes |  |
| `addpeeraddress` | no | hidden (test-only) in Core too |
| `clearbanned` | yes |  |
| `disconnectnode` | yes |  |
| `getaddednodeinfo` | yes |  |
| `getaddrmaninfo` | yes |  |
| `getconnectioncount` | yes |  |
| `getnettotals` | yes |  |
| `getnetworkinfo` | yes |  |
| `getnodeaddresses` | yes |  |
| `getpeerinfo` | yes |  |
| `listbanned` | yes |  |
| `ping` | yes |  |
| `setban` | yes |  |
| `setnetworkactive` | yes |  |

### Transaction

| Method | In `help` | Notes |
|---|---|---|
| `analyzepsbt` | yes |  |
| `combinepsbt` | yes |  |
| `combinerawtransaction` | yes |  |
| `converttopsbt` | yes |  |
| `createpsbt` | yes |  |
| `createrawtransaction` | yes |  |
| `decodepsbt` | yes |  |
| `decoderawtransaction` | yes |  |
| `decodescript` | yes |  |
| `descriptorprocesspsbt` | yes |  |
| `finalizepsbt` | yes |  |
| `fundrawtransaction` | no |  |
| `getrawtransaction` | yes | confirmed transactions need `-txindex` |
| `joinpsbts` | yes |  |
| `sendrawtransaction` | yes |  |
| `signmessage` | yes |  |
| `signmessagewithprivkey` | yes |  |
| `signrawtransactionwithkey` | yes |  |
| `signrawtransactionwithwallet` | no |  |
| `utxoupdatepsbt` | yes |  |
| `verifymessage` | yes |  |

### Fee Estimation

| Method | In `help` | Notes |
|---|---|---|
| `estimaterawfee` | yes |  |
| `estimatesmartfee` | yes |  |

### Util

| Method | In `help` | Notes |
|---|---|---|
| `createmultisig` | yes |  |
| `deriveaddresses` | yes |  |
| `getdescriptorinfo` | yes |  |
| `validateaddress` | yes |  |

### Mempool

| Method | In `help` | Notes |
|---|---|---|
| `dumpmempool` | yes |  |
| `getmempoolancestors` | yes |  |
| `getmempooldescendants` | yes |  |
| `getmempoolentry` | yes |  |
| `getmempoolinfo` | yes |  |
| `getorphantxs` | yes |  |
| `getrawmempool` | yes |  |
| `importmempool` | yes |  |
| `loadmempool` | yes |  |
| `savemempool` | yes |  |
| `submitpackage` | yes |  |
| `testmempoolaccept` | yes |  |

### Wallet

| Method | In `help` | Notes |
|---|---|---|
| `backupwallet` | yes |  |
| `bumpfee` | no |  |
| `createwallet` | yes |  |
| `dumpprivkey` | no | legacy-wallet method |
| `encryptwallet` | yes |  |
| `getaddressesbylabel` | no |  |
| `getaddressinfo` | yes |  |
| `getbalance` | yes |  |
| `getbalances` | yes |  |
| `getmnemonic` | yes | blockbrew only: BIP-39 mnemonic of an HD wallet |
| `getnewaddress` | yes |  |
| `getpayjoinrequest` | no | blockbrew only: BIP-78 receiver |
| `gettransaction` | no |  |
| `getwalletinfo` | yes |  |
| `importdescriptors` | no |  |
| `importprivkey` | no | legacy-wallet method |
| `listlabels` | no |  |
| `listlockunspent` | no |  |
| `listtransactions` | yes |  |
| `listunspent` | yes |  |
| `listwalletdir` | no |  |
| `listwallets` | yes |  |
| `loadwallet` | yes |  |
| `lockunspent` | no |  |
| `psbtbumpfee` | no |  |
| `rescanblockchain` | no |  |
| `restorewallet` | yes |  |
| `send` | yes |  |
| `sendpayjoinrequest` | no | blockbrew only: BIP-78 sender |
| `sendtoaddress` | yes |  |
| `setlabel` | no |  |
| `unloadwallet` | yes |  |
| `walletcreatefundedpsbt` | yes |  |
| `walletlock` | yes |  |
| `walletpassphrase` | yes |  |
| `walletprocesspsbt` | yes |  |
## Known differences from Core

- No `-rpcauth` and no `-rpcallowip`. Access control is the bind address plus one
  user/password pair or the cookie.
- If the cookie file cannot be written and no `-rpcpassword` is set, the RPC server accepts
  every request. Set `-rpcpassword` if the datadir may be read-only. This is pinned by a
  skipped test in `internal/rpc/w140_http_rpcauth_test.go`.
- Error codes and messages do not match Core on every error path. Several are recorded as
  skipped tests in `internal/mempool/w120_rbf_test.go` and `internal/rpc`; some of those
  skips predate later fixes, so rerun them before relying on one.
- Named parameters and JSON-RPC batch requests are rejected (`-32602 Invalid parameters`
  and `-32700 Parse error`); Core accepts both.
- Methods marked "blockbrew only" above have no Core equivalent.
