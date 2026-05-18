# W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch (blockbrew)

**Wave**: W140 (DISCOVERY, not fix)
**Date**: 2026-05-18
**Impl**: blockbrew (Go)
**Scope**: HTTP server surface (`net/http` ServeMux + ListenAndServe[TLS]),
JSON-RPC envelope dispatch (`handleRPC`), credential check (`checkAuth` —
plain user/pass + `__cookie__`), cookie file (`GenerateCookie` /
`DeleteCookie`), TLS termination (`TLSCertFile`/`TLSKeyFile`), wallet-path
extraction (`/wallet/<name>`), REST registration. Bitcoin Core authority:
`bitcoin-core/src/httpserver.cpp`, `httpserver.h`, `httprpc.cpp`,
`rpc/request.cpp` (cookie), `share/rpcauth/rpcauth.py` (HMAC line format),
`rpc/server.cpp` (whitelist).
**Verdict**: **BUGS FOUND** — **22 distinct bug IDs** (W140-BUG-1 ..
W140-BUG-22), including **2 P0-SEC** (open-on-empty-creds bypass; cookie
file world-readable race during non-atomic write on a non-private datadir),
**6 P1-MISSING/SEC** (no HMAC `-rpcauth`, no `-rpcallowip` ACL — both
already catalogued under W124 BUG-14/15 and re-confirmed here, no
`-rpcwhitelist`, no work-queue cap, no per-connection cap, no constant-time
credential compare), and **14 MED/LOW** parity gaps (no batch RPC, no
JSON-RPC 2.0 version, no notification 204 response, no HTTP status code
mapping per RPC error code, no `-rpcservertimeout`, no `-rpccookiefile`
path override, no `-rpccookieperms`, no `MAX_HEADERS_SIZE`-equivalent,
brute-force delay missing, `Connection: close` on every reply (handler
correctness, but anti-pattern), wallet-path scope leak in dispatch,
TLS-cert reload-on-SIGHUP absent, no localhost forced-bind when neither
`-rpcbind` nor `-rpcallowip` is set vs. Core's "default to loopback" guard
rail, no `-rpcservertimeout` setter).

## Bitcoin Core references

- `bitcoin-core/src/httpserver.cpp`
  - `InitHTTPAllowList()` (line 148): builds CIDR list from `-rpcallowip`,
    always prepends `127.0.0.1/8` + `::1/128` so loopback works even
    without any allow-IP entries.
  - `ClientAllowed(netaddr)` (line 137): early reject — returns 403 BEFORE
    auth check. Applied in `http_request_cb` (line 217).
  - `HTTPBindAddresses()` (line 309): **critical guard rail** — if either
    `-rpcallowip` OR `-rpcbind` is empty, refuses the operator's bind set
    and falls back to `[::1]:port` + `127.0.0.1:port` (with a warning
    log). This prevents accidental public-IP exposure when the operator
    typoes one of the two flags.
  - `MAX_HEADERS_SIZE = 8192` (line 51) — caps inbound HTTP request line +
    headers; enforced via `evhttp_set_max_headers_size`.
  - `evhttp_set_max_body_size(http, MAX_SIZE)` (line 410) — Core caps
    body at MAX_SIZE (32 MiB).
  - `g_max_queue_depth = max(-rpcworkqueue, 1)` (line 419) — drops
    inbound requests with HTTP 503 when the work-queue depth exceeds the
    cap (line 257).
  - `DEFAULT_HTTP_THREADS=16` / `DEFAULT_HTTP_WORKQUEUE=64` /
    `DEFAULT_HTTP_SERVER_TIMEOUT=30` (`httpserver.h:20-28`).
  - `http_request_cb`: early reject `UNKNOWN` method with `HTTP_BAD_METHOD`
    (line 225).
- `bitcoin-core/src/httprpc.cpp`
  - `CheckUserAuthorized(user, pass)` (line 63): walks `g_rpcauth`,
    `TimingResistantEqual` on both the username AND the HMAC-SHA256 hash.
    Constant-time.
  - `RPCAuthorized` (line 84): parses `Authorization: Basic <b64>`, splits
    on first `':'`, returns `CheckUserAuthorized`.
  - `HTTPReq_JSONRPC` (line 104):
    - POST-only enforcement (`HTTP_BAD_METHOD` for any non-POST).
    - On auth fail: `UninterruptibleSleep(250ms)` brute-force deter,
      then 401 + `WWW-Authenticate: Basic realm="jsonrpc"`.
    - **Batch RPC supported** (line 174): `valRequest.isArray()` → run each
      and collect results; per-request whitelist check.
    - **JSON-RPC 2.0 supported** (`jreq.parse` sets `m_json_version`
      based on `"jsonrpc"` field: `"1.0"` → V1_LEGACY, `"2.0"` → V2).
    - **Notifications** (line 167): when `IsNotification()` returns true
      (no `id` in V2 request), reply `HTTP_NO_CONTENT` (204).
    - **HTTP status code mapping** (`JSONErrorReply` line 41):
      `RPC_INVALID_REQUEST` → `HTTP_BAD_REQUEST` (400);
      `RPC_METHOD_NOT_FOUND` → `HTTP_NOT_FOUND` (404); everything else →
      `HTTP_INTERNAL_SERVER_ERROR` (500).
    - **Whitelist support** (`g_rpc_whitelist` line 38, `-rpcwhitelist=user:method,…`
      + `-rpcwhitelistdefault`): per-user method allow-list, 403 on
      mismatch.
  - `InitRPCAuthentication` (line 240):
    - `-rpcauth=<user>:<salt>$<hash>` parsed into `g_rpcauth` (line 290);
      multiple entries supported.
    - Plain `-rpcpassword` gets HMAC-hashed at startup with a fresh
      16-byte salt before storage (line 276) — the **runtime** never
      compares against plaintext.
    - When no `-rpcpassword` AND no `-rpcauth`: `GenerateAuthCookie`
      generates a random 32-byte secret and writes
      `.cookie` (user = `__cookie__`).
- `bitcoin-core/src/rpc/request.cpp`
  - `GenerateAuthCookie` (line 100): writes to `<datadir>/.cookie.tmp`
    with umask-0077 perms, then `RenameOver(tmp, final)` — **atomic
    rename**, so readers never see partial content.
  - `-rpccookieperms=<owner|group|all>` (line 130) — explicit mode override.
  - `-rpccookiefile=<path>` (line 88) — path override; relative paths
    resolved against `-datadir`.
  - `-norpccookiefile` (line 89) disables cookie generation entirely.
  - `DeleteAuthCookie` (line 167): only deletes when `g_generated_cookie`
    set by `GenerateAuthCookie`, so we never remove a foreign cookie file.
- `bitcoin-core/share/rpcauth/rpcauth.py` — the operator-side tool that
  generates `rpcauth=<user>:<salt>$<hash>` lines. The format pinned here
  is what `InitRPCAuthentication`'s splitter at line 293-302 expects:
  `<user>:<32-hex-salt>$<64-hex-HMAC_SHA256(salt, password)>`.

## Source under audit

- `internal/rpc/server.go` — entire file. The HTTP server, handler
  registration, `RPCConfig`, `checkAuth`, `GenerateCookie`,
  `DeleteCookie`, `dispatch`, `extractWalletName`, `sendResponse`.
- `internal/rpc/rest.go` — REST handler registration (unauthenticated
  by design; relies on bind addr).
- `cmd/blockbrew/main.go:454-466` — RPC CLI flags (`-rpcbind`,
  `-rpcuser`, `-rpcpassword`, `-rpc-tls-cert`, `-rpc-tls-key`,
  `-rpcready-notify`).
- `cmd/blockbrew/main.go:1334-1386` — RPC server build (creates cookie
  file via `rpc.GenerateCookie(cfg.DataDir)`, wires the password into
  the server).
- `cmd/blockbrew/main.go:560-575` — port defaults; `127.0.0.1:<rpcport>`
  loopback fallback when `-rpcbind` is empty (this matches Core's bind
  guard rail, see G6 below).

## Summary

blockbrew implements a minimal Go `net/http`-based JSON-RPC server with
optional TLS termination (FIX-64, W119 closure). The handshake-level
basic-auth flow works for the single-user single-method case and for the
per-process cookie. **The implementation diverges significantly from
Core's HTTP/RPC dispatch surface across 22 distinct gaps**, the most
serious of which are:

1. **P0-SEC**: `checkAuth` opens the door wide when all three of
   `Username`, `Password`, `cookiePassword` are empty (line 476-478).
   On the happy path this never trips (the daemon always calls
   `GenerateCookie` before constructing the server, and main.go warns if
   `-rpcpassword` is empty); however a build-error or runtime
   misconfiguration that fails the cookie write **silently degrades to
   open RPC** — the only signal is a `log.Printf("WARNING: …")` line
   that operators routinely miss. Core has no such "open if empty"
   fallback path; every request without valid basic auth gets 401.
2. **P0-SEC** (file-write race): `GenerateCookie` uses `os.WriteFile`
   without a `.tmp → rename` step. Core writes to `<path>.tmp` first
   and `RenameOver()` swaps it in. On a busy datadir with a tool polling
   the cookie file, blockbrew can serve an empty / partial cookie to
   `os.WriteFile`'s second-step `Write` and the client races onto the
   incomplete file. Severity is bounded because the file is `0600`, but
   the local tool then hits 401 and may retry-loop until the write
   completes.
3. **P1-SEC** (already W124 BUG-14): no `-rpcauth=<user>:<salt>$<hash>`
   HMAC-SHA256 support — plaintext only.
4. **P1-SEC** (already W124 BUG-15): no `-rpcallowip=<subnet>` ACL.
5. **P1-SEC**: no constant-time credential compare. `pass == s.config.Password`
   is `runtime.cmpstring` (variable-time at length, byte-by-byte short-circuit
   at mismatch). On `localhost:<port>` this is largely a paper cut, but
   Core uses `TimingResistantEqual` for both username and password —
   exposed to local-network adversaries when `-rpcbind=0.0.0.0`.
6. **P1**: no work-queue cap / per-connection cap. Go's default
   `net/http.Server` accepts unbounded concurrent goroutines; an
   adversary on localhost (e.g. cross-tenant container) can mount a slow-POST
   DoS that exhausts goroutines / file descriptors. Core caps the work
   queue at 64 (default) via `evhttp_set_max_body_size` + the in-thread-pool
   `g_max_queue_depth` reject path.

Two **MAJOR PARITY GAPS** that don't have a clean SEC label but bite at
client side:

- **No JSON-RPC batch request support** — Core handles `[{…},{…},…]`
  array request envelopes; blockbrew's `json.Decoder.Decode(&req)`
  rejects arrays with a parse error. Batched ETL pipelines that work
  against Core fail against blockbrew.
- **No HTTP status mapping** — Core returns 400/404 for
  `RPC_INVALID_REQUEST` / `RPC_METHOD_NOT_FOUND`; blockbrew returns 200
  for every dispatch, with the error body inside. Wireshark/curl-status
  monitors keyed on status codes will silently miss errors.

The TLS surface (FIX-64) is well-implemented: cert/key pair validated
eagerly, modern `MinVersion: TLS 1.2`, mismatch-rejection if exactly one
of cert/key is set. Two TLS-side gaps remain (no SIGHUP reload; no
listen-only loopback in TLS mode by default).

REST (`/rest/...`) is unauthenticated by design (matches Core); but
because blockbrew also has no `-rpcallowip` filter, a `-rpc-bind=0.0.0.0`
binding exposes REST to the world. The TLS termination is the only
defense for this path today.

## 30-gate audit matrix

| Gate | What the gate asserts | Status | Bug |
|------|----------------------|--------|-----|
| G1  | POST-only enforcement: any non-POST returns 405 (Core: `HTTP_BAD_METHOD`) | PASS | — (server.go:358-361) |
| G2  | `Authorization: Basic` parsing: split on first `:`, base64-decode (Core RPCAuthorized at line 84) | PASS | — (`r.BasicAuth()` is stdlib-correct) |
| G3  | When credentials are configured, missing/wrong basic-auth → 401 + `WWW-Authenticate: Basic realm=…` | PASS | — (server.go:364-368; realm is `blockbrew` not `jsonrpc` — see BUG-17) |
| G4  | `__cookie__` username + correct cookie → success path | PASS | — (server.go:485-488) |
| G5  | All three of Username / Password / cookiePassword empty → **reject**, not allow-all (Core has no such "open" fallback) | **FAIL** | **BUG-1 (P0-SEC)** |
| G6  | When `-rpcbind` is set BUT `-rpcallowip` is empty, refuse the operator's bind set and fall back to localhost (Core httpserver.cpp:319 guard rail) | **MISSING** | BUG-2 (P1-SEC) |
| G7  | `-rpcallowip=<CIDR>` ACL: pre-auth client allow-list (Core ClientAllowed); reject with 403 before checkAuth | **MISSING** | BUG-3 (P1-SEC; W124 BUG-15 re-pin) |
| G8  | `-rpcauth=<user>:<salt>$<hash>` HMAC-SHA256 support: parsed at init, walked in checkAuth, constant-time compare (Core CheckUserAuthorized at line 63) | **MISSING** | BUG-4 (P1-SEC; W124 BUG-14 re-pin) |
| G9  | Multiple `-rpcuser`/`-rpcauth` entries supported (Core takes repeated `-rpcauth` flags) | **MISSING** | BUG-5 (P2; subset of BUG-4) |
| G10 | Plaintext `-rpcpassword` gets HMAC-hashed at init so the running process never compares against plaintext (Core httprpc.cpp:276-288) | **MISSING** | BUG-6 (P2-SEC; plaintext sits in `RPCConfig.Password` for the process lifetime) |
| G11 | Constant-time credential compare to defeat timing side-channels (Core TimingResistantEqual on both username AND password hash) | **FAIL** | **BUG-7 (P1-SEC)** |
| G12 | Brute-force deterrent: 250ms `UninterruptibleSleep` before 401 (Core httprpc.cpp:128) | **MISSING** | BUG-8 (P2-SEC) |
| G13 | Cookie file: atomic write (`<file>.tmp` → `RenameOver`) — readers never see partial content (Core request.cpp:117-128) | **FAIL** | **BUG-9 (P0-SEC)** |
| G14 | Cookie file: `0600` perms; on POSIX, configurable via `-rpccookieperms=<owner|group|all>` (Core line 130) | PARTIAL | BUG-10 (perms hard-coded 0600 — correct default, but no override flag) |
| G15 | Cookie file path: configurable via `-rpccookiefile=<path>` with relative paths resolved against `-datadir` (Core line 88) | **MISSING** | BUG-11 (P3) |
| G16 | `-norpccookiefile` disables cookie generation entirely (Core line 89) | **MISSING** | BUG-12 (P3) |
| G17 | `DeleteCookie` only deletes a cookie this process wrote — not arbitrary `<datadir>/.cookie` files (Core's `g_generated_cookie` guard at request.cpp:139,170) | **FAIL** | BUG-13 (P2-SEC; can blow away another node's cookie if two daemons share a datadir) |
| G18 | JSON-RPC envelope: array request → batch dispatch (Core httprpc.cpp:174 `valRequest.isArray()`) | **MISSING** | BUG-14 (P2-PARITY) |
| G19 | JSON-RPC 2.0 version detection: `"jsonrpc":"2.0"` parsed from envelope; V2 changes error semantics (Core uses JSONRPCVersion enum, lines 213-230 of request.cpp) | **MISSING** | BUG-15 (P3-PARITY) |
| G20 | Notification handling: V2 request with no `id` → HTTP 204 No Content (Core httprpc.cpp:167-170) | **MISSING** | BUG-15 (P3-PARITY, subset) |
| G21 | HTTP status code mapping: `RPC_INVALID_REQUEST` → 400; `RPC_METHOD_NOT_FOUND` → 404; everything else → 500 (Core JSONErrorReply at line 41) | **FAIL** | BUG-16 (P2-PARITY; blockbrew returns 200 with `error` body for every dispatch failure) |
| G22 | `-rpcwhitelist=<user>:<method,…>` per-user method allow-list (Core httprpc.cpp:307-326) | **MISSING** | BUG-17 (P2-SEC) |
| G23 | `WWW-Authenticate` realm string matches Core's `Basic realm="jsonrpc"` for client-tool compatibility | PARTIAL | BUG-18 (P3; blockbrew sends `Basic realm="blockbrew"` — cosmetic, but breaks `bitcoin-cli` `~/.bitcoin/.cookie` autoprobe heuristics that key on realm) |
| G24 | `-rpcservertimeout=<sec>` (Core default 30s) sets the request socket timeout (Core httpserver.cpp:408) | PARTIAL | BUG-19 (P2; blockbrew hard-codes `ReadTimeout: 30s` + `WriteTimeout: 30s` matching the default value but with no CLI flag to tune) |
| G25 | `-rpcworkqueue=N` (Core default 64): reject excess inbound requests with HTTP 503 (Core httpserver.cpp:257) | **MISSING** | BUG-20 (P1) |
| G26 | `-rpcthreads=N` (Core default 16): bounded worker pool. blockbrew relies on Go's unbounded goroutine model | **MISSING** | BUG-21 (P1; subset of BUG-20) |
| G27 | `MAX_HEADERS_SIZE = 8192` cap on inbound header bytes (Core httpserver.cpp:51,409) — bounded `http.Server.MaxHeaderBytes` | **MISSING** | BUG-22 (P2-DOS; Go default is 1 MiB which is much more than Core's 8 KiB; slow-header DoS surface widens) |
| G28 | Reject unknown HTTP methods (`UNKNOWN`) with `HTTP_BAD_METHOD` BEFORE dispatch (Core httpserver.cpp:225) | PASS | — (server.go:358 returns 405 for non-POST; covers G28 by extension because mux only accepts methods Go knows about) |
| G29 | TLS: SIGHUP reload of cert/key (Core has no SIGHUP for HTTP TLS; this is a blockbrew-side feature gap because the daemon SIGHUP plumbing exists for logfile rotation) | PARTIAL | (informational) — blockbrew SIGHUPs only `-logfile` (W124 BUG-4); cert renewal requires daemon restart. Documented, not bug-tracked. |
| G30 | TLS misconfig (exactly one of cert/key set) is a startup error — does NOT silently land on plain HTTP (W119 FIX-64) | PASS | — (server.go:270-275) |

PASS: **5** | PARTIAL: **4** | FAIL/MISSING: **21**

## Bug catalogue

### BUG-1 (P0-SEC) — open-on-empty-creds bypass in `checkAuth`

**Severity**: P0 (SEC — full RPC open to anyone who connects)
**ID**: BLOCKBREW-W140-1
**Location**: `internal/rpc/server.go:474-478`

```go
func (s *Server) checkAuth(r *http.Request) bool {
    // If no credentials are configured at all, allow every request.
    if s.config.Username == "" && s.config.Password == "" && s.cookiePassword == "" {
        return true
    }
    ...
}
```

The three-empty short-circuit at the top of `checkAuth` allow-lists
every request — no basic-auth header check, no cookie check, no IP
filter. The intended use is "developer regtest with no creds set", but
it triggers any time **all three** values are empty strings. The happy
path in `cmd/blockbrew/main.go:1337-1343` calls `rpc.GenerateCookie`
and wires the result into `WithCookiePassword`; if that call returns
an error (datadir unwritable, disk-full, EROFS, etc.) the code
**silently sets `cookiePassword = ""`** and continues:

```go
cookiePassword, err := rpc.GenerateCookie(cfg.DataDir)
if err != nil {
    log.Printf("WARNING: could not write RPC cookie file: %v", err)
    cookiePassword = ""           // ← P0-SEC: ends in open RPC if no rpcpassword
} else {
    log.Printf("RPC cookie written to %s/.cookie", cfg.DataDir)
}
```

Combined with `cmd/blockbrew/main.go:437-439` warning about empty
`-rpcpassword` but not refusing-to-start, a regtest-style
`-rpcpassword=""` + cookie-write-failure puts the daemon in
**listen-and-accept-anything** mode. On default `-rpcbind=127.0.0.1`
this is a local-only exposure; if the operator binds non-loopback
this becomes remote unauth.

**Bitcoin Core**: `httprpc.cpp:111-117` — when `authorization` header
is missing or wrong, the response is **always** 401. There is no
"open" branch.

**Fix path**:

1. Drop the early-return entirely. `checkAuth` should return false when
   the request lacks a valid credential.
2. Make `cmd/blockbrew/main.go:1338-1343` fatal: if neither
   `-rpcpassword` nor a usable cookie is available, `log.Fatalf` instead
   of `log.Printf("WARNING: …")` and continuing.
3. Add a startup invariant: `Server.Start` refuses to bind if all three
   of `cfg.Username/Password/cookiePassword` are empty.

Test pinning the current behavior: see
`internal/rpc/w140_http_rpcauth_test.go::TestW140_BUG01_OpenOnEmptyCreds`.

### BUG-2 (P1-SEC) — no `-rpcbind`/`-rpcallowip` co-required guard

**Severity**: P1 (SEC — accidental public RPC exposure)
**ID**: BLOCKBREW-W140-2
**Location**: `cmd/blockbrew/main.go:563-568` + `internal/rpc/server.go:Start`

Bitcoin Core requires `-rpcbind` AND `-rpcallowip` to **both** be
present before honoring a non-loopback bind — if either is missing,
the bind silently falls back to `[::1]:port` + `127.0.0.1:port` with a
loud warning (`httpserver.cpp:319-327`). This is the single most
important guard against an operator typing `-rpcbind=0.0.0.0` and not
realising they also need an ACL.

blockbrew's `parseFlags` only fills in a default `127.0.0.1` listener
when `-rpcbind` is empty (line 567). If the operator passes
`-rpcbind=0.0.0.0:48343` blockbrew honours it without complaint AND
without any IP-level ACL (BUG-3). Combined with BUG-1's empty-creds
behaviour this is a 3-step path to fully open WAN RPC.

**Fix path**: in `cmd/blockbrew/main.go` after the empty-fallback
block, detect non-loopback bind and refuse to start (or override to
loopback) unless `-rpcallowip` is also provided. Log at WARN level if
the override fires.

### BUG-3 (P1-SEC) — no `-rpcallowip=<CIDR>` ACL (W124 BUG-15 re-confirmed)

**Severity**: P1 (SEC)
**ID**: BLOCKBREW-W140-3 (alias for W124 BUG-15)
**Location**: `internal/rpc/server.go:handleRPC` — `r.RemoteAddr` is
never inspected.

Already catalogued under W124 BUG-15 — re-pinned here because W140 is
the natural place to fix it (`handleRPC` head, pre-auth). Core wires
this in `httpserver.cpp:217` (`ClientAllowed(hreq->GetPeer())`)
**before** `evhttp_set_gencb` invokes the per-prefix handler, so even
REST endpoints (`/rest/...`) get the IP check. blockbrew's REST surface
(`internal/rpc/rest.go`) shares the same lack.

**Fix path**: parse `-rpcallowip` into a `[]*net.IPNet`; in `handleRPC`
and in each REST handler's preamble, reject `r.RemoteAddr` not in the
allow set (loopback always implicit).

### BUG-4 (P1-SEC) — no `-rpcauth=<user>:<salt>$<hash>` HMAC support (W124 BUG-14 re-confirmed)

**Severity**: P1 (SEC)
**ID**: BLOCKBREW-W140-4 (alias for W124 BUG-14)
**Location**: `internal/rpc/server.go:checkAuth`

Already catalogued under W124 BUG-14. Core supports
`-rpcauth=<user>:<salt>$<hmac>` where the operator hashes their
password ahead of time via `share/rpcauth/rpcauth.py` so plaintext
never lands on disk. blockbrew stores only the configured `Password`
plain in `RPCConfig.Password` and compares with `==`. Re-pinned here
because the **shape of the fix** is "add a `[]rpcauth` slice to
`RPCConfig`, parse `<user>:<salt>$<hash>` at init, walk it in
`checkAuth` with `subtle.ConstantTimeCompare` on the HMAC-SHA256".

### BUG-5 (P2) — no support for multiple `-rpcauth` entries

**Severity**: P2 (PARITY)
**ID**: BLOCKBREW-W140-5
**Location**: `cmd/blockbrew/main.go:455-456`

Core takes `-rpcauth` repeatedly (one line per RPC user). blockbrew's
`-rpcuser`/`-rpcpassword` is a single pair. Multi-tenant deployments
(e.g. RPC for the wallet UI + a separate RPC for the block explorer)
cannot represent two users.

**Fix path**: subset of BUG-4 — when adding `-rpcauth`, make it
repeatable via `flag.Var` + a `stringSliceFlag` like blockbrew already
does for `-debug` (`Debug` is `var` Visited).

### BUG-6 (P2-SEC) — plaintext password lives in process memory

**Severity**: P2 (SEC — defense in depth)
**ID**: BLOCKBREW-W140-6
**Location**: `internal/rpc/server.go:RPCConfig.Password`

`s.config.Password` retains the plaintext value for the daemon
lifetime. Core hashes the plaintext at init (httprpc.cpp:276-288)
with a fresh 16-byte salt and stores only the salt+hash in
`g_rpcauth`. A core dump or `/proc/<pid>/mem` snapshot of a Core
daemon does not contain the operator's `-rpcpassword`; a blockbrew
core dump does.

**Fix path**: at server-init time, generate a 16-byte salt and HMAC
the configured `Password`, then zero the plaintext bytes. Store only
the salt+hash. `checkAuth` does the same HMAC and compares
`subtle.ConstantTimeCompare`-style.

### BUG-7 (P1-SEC) — no constant-time credential compare

**Severity**: P1 (SEC — local-network timing attack)
**ID**: BLOCKBREW-W140-7
**Location**: `internal/rpc/server.go:487,491`

```go
if user == "__cookie__" && s.cookiePassword != "" {
    return pass == s.cookiePassword          // ← timing-leaky
}
return user == s.config.Username && pass == s.config.Password
```

Go string `==` is `runtime.cmpstring` — variable-length, byte-by-byte
short-circuit at first mismatch. An adversary on the same `-rpcbind`
network segment can probe candidate passwords character-by-character.

Core uses `TimingResistantEqual` (a hand-rolled XOR loop over the
**whole** byte range regardless of mismatch position) for both the
username compare AND the HMAC compare (`httprpc.cpp:66,77`).

**Fix path**: replace both `==` checks with
`subtle.ConstantTimeCompare([]byte(...), []byte(...)) == 1`.

### BUG-8 (P2-SEC) — no brute-force deterrent sleep on auth failure

**Severity**: P2 (SEC)
**ID**: BLOCKBREW-W140-8
**Location**: `internal/rpc/server.go:364-368`

Core sleeps 250ms before sending the 401 response on auth failure
(`httprpc.cpp:128`). This adds a hard ceiling of ~4 attempts/second
per connection — useful against unauthenticated probes on a
non-loopback bind. blockbrew returns 401 immediately, so an attacker
can shovel thousands of attempts per second per goroutine.

**Fix path**: add a `time.Sleep(250 * time.Millisecond)` between the
`!s.checkAuth(r)` branch and the `http.Error(...)` call. Use a
`time.NewTimer` selectable on `r.Context().Done()` so a client that
hangs up early doesn't waste a goroutine for the full 250ms.

### BUG-9 (P0-SEC) — non-atomic cookie file write race

**Severity**: P0 (SEC — partial-write race, can yield 401 burst or
worse if a tool retries with partial content)
**ID**: BLOCKBREW-W140-9
**Location**: `internal/rpc/server.go:231-243`

```go
func GenerateCookie(datadir string) (string, error) {
    raw := make([]byte, 32)
    if _, err := rand.Read(raw); err != nil { ... }
    password := hex.EncodeToString(raw)
    cookiePath := filepath.Join(datadir, ".cookie")
    content := "__cookie__:" + password
    if err := os.WriteFile(cookiePath, []byte(content), 0600); err != nil { ... }
    return password, nil
}
```

`os.WriteFile` does `open(O_WRONLY|O_CREAT|O_TRUNC) → write → close`.
A client that polls `<datadir>/.cookie` (every `bitcoin-cli` does this
on every invocation) can see:

1. An empty file (between `O_TRUNC` and the first `write` syscall).
2. A partial file (between buffered writes if the kernel splits the
   syscall — rare for 65-byte payloads but possible with `O_DIRECT`).
3. A stale file (if the previous daemon ran with a different cookie
   secret and the new daemon hasn't yet written).

Core writes to `<file>.tmp` first and `RenameOver` (atomic on POSIX) to
swap the new content in.

**Fix path**: rewrite `GenerateCookie` to:

```go
tmpPath := cookiePath + ".tmp"
if err := os.WriteFile(tmpPath, []byte(content), 0600); err != nil { ... }
if err := os.Rename(tmpPath, cookiePath); err != nil { ... }
```

with the tmp-path cleanup on the error branches.

### BUG-10 (P3) — no `-rpccookieperms=<owner|group|all>` flag

**Severity**: P3 (PARITY)
**ID**: BLOCKBREW-W140-10
**Location**: `internal/rpc/server.go:239`

blockbrew hard-codes `0600` (correct default). Core lets the operator
relax this for shared-group deployments via `-rpccookieperms=group`
(0640) or `-rpccookieperms=all` (0644). Some containerised setups need
this (e.g. a sidecar container running as a different user reading
the cookie to call back into the main container).

**Fix path**: add `-rpccookieperms` flag (`owner`|`group`|`all`),
plumb into `GenerateCookie` as a `fs.FileMode` parameter, default `0600`.

### BUG-11 (P3) — no `-rpccookiefile=<path>` override

**Severity**: P3 (PARITY)
**ID**: BLOCKBREW-W140-11
**Location**: `internal/rpc/server.go:237` + `cmd/blockbrew/main.go:1337`

blockbrew hard-codes `<datadir>/.cookie`. Core lets the operator pin
the cookie elsewhere via `-rpccookiefile=<path>` (e.g. on a tmpfs to
avoid disk write of secret material).

**Fix path**: thread through a `CookieFilePath` field on `RPCConfig`,
default empty (= `<datadir>/.cookie`).

### BUG-12 (P3) — no `-norpccookiefile` opt-out

**Severity**: P3 (PARITY)
**ID**: BLOCKBREW-W140-12
**Location**: `cmd/blockbrew/main.go:1337-1343`

Core supports `-norpccookiefile` (line 89 of request.cpp) to disable
cookie generation entirely. Useful for deployments using only
`-rpcauth` and not wanting the cookie file on disk at all.

**Fix path**: add `-rpcnocookiefile` boolean flag; when set, skip
`rpc.GenerateCookie` entirely and skip `WithCookiePassword`.

### BUG-13 (P2-SEC) — `DeleteCookie` blindly deletes any `.cookie`

**Severity**: P2 (SEC — can delete another daemon's cookie if datadirs collide)
**ID**: BLOCKBREW-W140-13
**Location**: `internal/rpc/server.go:247-252` (def) + `cmd/blockbrew/main.go:1582`
(call)

```go
func DeleteCookie(datadir string) {
    cookiePath := filepath.Join(datadir, ".cookie")
    if err := os.Remove(cookiePath); err != nil && !os.IsNotExist(err) { ... }
}
```

If two daemons share a datadir (operator footgun, but happens in
development), the second daemon's `DeleteCookie` on shutdown removes
the first daemon's cookie file. Core guards this with
`g_generated_cookie` (`request.cpp:139,170`) — only delete if we wrote it.

**Fix path**: track a `Server.generatedCookie bool` set by `GenerateCookie`.
`DeleteCookie` should be a method on `*Server` and only act when the
flag is set.

### BUG-14 (P2-PARITY) — no JSON-RPC batch dispatch

**Severity**: P2 (PARITY — common ETL/explorer client pattern)
**ID**: BLOCKBREW-W140-14
**Location**: `internal/rpc/server.go:380-385`

```go
var req RPCRequest
decoder := json.NewDecoder(r.Body)
if err := decoder.Decode(&req); err != nil {
    s.sendError(w, nil, RPCErrParseError, "Parse error")
    return
}
```

`RPCRequest` is a struct, so an array envelope (`[{...},{...}]`) fails
`json.Decode` with `cannot unmarshal array into Go value of type rpc.RPCRequest`.

Core (httprpc.cpp:174-224) walks the array, dispatches each, and
returns a parallel array of responses. Batched clients (electrum,
explorer indexers, monitoring agents) make heavy use of this.

**Fix path**: peek the first non-whitespace byte; if `[`, unmarshal
into `[]RPCRequest`, dispatch each, and `sendResponse` with `[]RPCResponse`.

### BUG-15 (P3-PARITY) — no JSON-RPC 2.0 version handling / notifications

**Severity**: P3 (PARITY)
**ID**: BLOCKBREW-W140-15
**Location**: `internal/rpc/types.go:39-44`, `server.go:handleRPC`

`RPCRequest.JSONRPC` is declared but never inspected. Core branches on
`"1.0"` vs `"2.0"`:

- V2 omits the `error` key on success (V1 includes `error: null`).
- V2 treats requests with no `id` field as **notifications** —
  204 No Content response (`httprpc.cpp:167`).
- V2 changes batch error semantics (always returns 200 + error in body
  rather than 400/404/500).

blockbrew always emits both `result` and `error` keys, even on success
(types.go:RPCResponse — no `omitempty` on Result), and always emits a
JSON body regardless of `id`.

**Fix path**: parse `JSONRPC` field; switch on version in
`sendResponse` and `sendError`. Add `omitempty` to `Result` and
`Error` so a V2 success only emits `result`. Detect `req.ID == nil &&
JSONRPC == "2.0"` for the 204 notification path.

### BUG-16 (P2-PARITY) — HTTP status code is always 200 on dispatch failure

**Severity**: P2 (PARITY)
**ID**: BLOCKBREW-W140-16
**Location**: `internal/rpc/server.go:495-501` (sendResponse) + `502-509` (sendError)

Both `sendResponse` and `sendError` call `w.Header().Set(...)` then
`json.NewEncoder(w).Encode(resp)` — the response status is whatever
`w.WriteHeader` left at default, i.e. **200 OK**. Core maps:

| RPC error code | HTTP status |
|----------------|-------------|
| `RPC_INVALID_REQUEST (-32600)` | `400 Bad Request` |
| `RPC_METHOD_NOT_FOUND (-32601)` | `404 Not Found` |
| anything else (including `-32700 Parse error`) | `500 Internal Server Error` |

Monitoring tools (curl `-fs`, prometheus `nginx_*` exporters, k8s
liveness probes via `httpGet`) treat any 2xx as success and never
notice the dispatch errors. The same problem affects every
`s.sendError(...)` call site in `handleRPC` (line 383, 389) — the
client receives a 200 with `error: { code: -32700, message: "Parse
error" }` body, which curl `-f` does not flag.

**Fix path**: parameterize `sendError` to take an HTTP status,
defaulting to 500. Branch in `handleRPC` on `rpcErr.Code` to set
400/404 where Core would. Add a status arg to `sendResponse` for the
204 notification path (BUG-15).

### BUG-17 (P2-SEC) — no `-rpcwhitelist=<user>:<method,…>` per-user method allow-list

**Severity**: P2 (SEC — granular RBAC missing)
**ID**: BLOCKBREW-W140-17
**Location**: `internal/rpc/server.go:dispatch` — no user/method gate

Core lets the operator scope an RPC user to a specific method set:
`-rpcwhitelist=monitor:getblockcount,getblockhash`. blockbrew has no
notion of "user X is only allowed to call method Y". The single
`Username`/`Password` pair gates everything; cookie auth gates
everything; there is no per-user allow-list and no per-method allow-list.

**Fix path**: extend `RPCConfig` with `Whitelist map[string]map[string]struct{}{}`;
populate from `-rpcwhitelist`; in `dispatch`, before the method switch,
check `if whitelist, ok := s.whitelist[authUser]; ok &&
!whitelist[method] { return 403 }`. Pass `authUser` from `handleRPC`
into `dispatch` (currently the wallet name is plumbed but not the auth
identity).

### BUG-18 (P3) — `WWW-Authenticate` realm differs from Core

**Severity**: P3 (COSMETIC; minor compat risk)
**ID**: BLOCKBREW-W140-18
**Location**: `internal/rpc/server.go:365`

```go
w.Header().Set("WWW-Authenticate", `Basic realm="blockbrew"`)
```

Core uses `Basic realm="jsonrpc"`. Some `bitcoin-cli`-equivalent
clients (e.g. the older `bitcoind-rpc` ruby gem) match the realm
string heuristically to decide whether to autoprobe `<datadir>/.cookie`.

**Fix path**: change the literal to `"Basic realm=\"jsonrpc\""`.
One-line change; zero risk.

### BUG-19 (P2) — no `-rpcservertimeout=<sec>` flag

**Severity**: P2 (PARITY)
**ID**: BLOCKBREW-W140-19
**Location**: `internal/rpc/server.go:298-302`

Read/write timeouts are hard-coded `30 * time.Second`. Core defaults to
30s but exposes `-rpcservertimeout` for tuning (e.g. slow GBT mining
clients on small ARM boxes need more; high-throughput watch nodes use
less). The 10s per-request `context.WithTimeout` (line 372) is a
separate layer; the socket-level 30s is what catches half-open
connections.

**Fix path**: add `-rpcservertimeout` flag, default 30, plumb into
`http.Server.ReadTimeout` + `WriteTimeout`.

### BUG-20 (P1) — no work-queue cap / unbounded goroutine concurrency

**Severity**: P1 (DOS)
**ID**: BLOCKBREW-W140-20
**Location**: `internal/rpc/server.go:Start`

Go's `http.Server` spawns one goroutine per accepted connection — no
cap. A slow-POST attacker (TCP open, byte-trickle headers) can pin
arbitrarily many goroutines, each holding 8 KiB of stack + the
buffered body. Core's bounded thread pool + `g_max_queue_depth`
(`httpserver.cpp:255-258`) returns HTTP 503 with "Work queue depth
exceeded" once the cap is hit.

**Fix path**:

1. Add `-rpcworkqueue` flag (default 64, Core parity).
2. Wrap `handleRPC` in a `chan struct{}` semaphore of that size; on
   acquire-fail, return 503 with `"Work queue depth exceeded"` body.
3. Add `-rpcthreads` (default 16) and use it to size the upstream
   `golang.org/x/sync/semaphore`-style worker pool (or just buffer the
   work-queue at that depth).

### BUG-21 (P1) — no `-rpcthreads` flag (subset of BUG-20)

**Severity**: P1
**ID**: BLOCKBREW-W140-21

See BUG-20 fix path. Distinguished as a separate bug ID because the
Core flag set has both: `-rpcworkqueue` (queue depth, drops on overflow)
and `-rpcthreads` (pool size, queues on overflow). One-flag designs
conflate the two.

### BUG-22 (P2-DOS) — no `MaxHeaderBytes` cap on inbound headers

**Severity**: P2 (DOS — Slowloris-style header attack)
**ID**: BLOCKBREW-W140-22
**Location**: `internal/rpc/server.go:297-302`

```go
s.httpServer = &http.Server{
    Addr:         s.config.ListenAddr,
    Handler:      mux,
    ReadTimeout:  30 * time.Second,
    WriteTimeout: 30 * time.Second,
    // MaxHeaderBytes:  not set; Go default = 1 << 20 = 1 MiB
}
```

Core caps at 8192 bytes (`httpserver.cpp:51,409`). Go's default 1 MiB
is large enough that a single Slowloris connection can sit drip-feeding
header bytes for the full ReadTimeout (30s) and hold a goroutine. With
unbounded goroutines (BUG-20) this is exploitable.

**Fix path**: `s.httpServer.MaxHeaderBytes = 8192` (Core parity). Better
yet: make it a CLI flag, default 8192.

## Cross-impl context

This is the first audit wave on blockbrew's HTTP/RPC surface. W124
caught BUG-14 (no rpcauth) and BUG-15 (no rpcallowip) at the
**operator-experience** level — i.e. "these flags don't exist". W140
re-confirms both and adds 20 more findings spanning the auth flow,
cookie file lifecycle, batch RPC envelope, HTTP status code mapping,
and DoS surface. Some of the W140 bugs are direct subsets of W124
findings (BUG-3 ≡ W124 BUG-15; BUG-4 ≡ W124 BUG-14); they are
re-stated here because the **fix shape** lives in `internal/rpc/server.go`
(where W140 audits), not in `cmd/blockbrew/main.go` (where W124's
audit was rooted).

The W140 P0-SECs (BUG-1, BUG-9) are universal-watch candidates for
the rest of the fleet:

- BUG-1 "open-on-empty-creds" is a recognizable anti-pattern in Go's
  defensive-programming idiom — would not surprise me to find it in
  hotbuns (TypeScript) and ouroboros (Python) where similar empty-string
  null-coalescing tends to appear.
- BUG-9 "non-atomic cookie write" almost certainly recurs in every
  impl that doesn't go through `os.Rename`-style atomic swap. Worth a
  fleet sweep.

## Universal-pattern watch

**P0-SEC#1**: "open RPC on empty credentials" is a Go-idiom risk
(`zero-value-means-permissive`). Sweep candidates: hotbuns (TS),
ouroboros (Python), lunarblock (Lua), camlcoin (OCaml `Option.value
~default:true` mis-uses). Pattern: any RPC entry-point that returns
"allow" when an auth field is its zero value.

**P0-SEC#2**: "non-atomic cookie file write" — every node that writes
`.cookie` via a single-shot `write` syscall instead of
`tmp + rename`. Cross-impl audit candidates: ouroboros (file written
in `auth.py` via `open(...).write(...)` is suspect), camlcoin
(`Out_channel.write_all` is non-atomic), beamchain (`file:write_file`
on the Erlang side likewise).

**Universal P1-PARITY#1**: no `-rpcauth` HMAC support. Already
fleet-wide noted in W124 — re-confirming the same gap on the
RPC-server side is consistent. The fix shape from any impl that has
it (e.g. Bitcoin Core's `share/rpcauth/rpcauth.py` is a 49-line
reference) is portable.

**Universal P1-PARITY#2**: no `-rpcallowip` ACL. Same story — W124
catalog item, fleet-wide.

**Universal P2-PARITY#1**: HTTP status code mapping per RPC error
code. The Core `JSONErrorReply` 400/404/500 mapping is one of those
"obvious in retrospect" details that every from-scratch impl tends
to skip. Candidates: every impl that writes JSON-RPC errors with HTTP
200.

**Universal P2-DOS#1**: Slowloris (no MaxHeaderBytes cap). Every Go /
Node / Python HTTP server that doesn't explicitly set the limit
defaults to "1 MiB-ish" or higher. blockbrew (Go), hotbuns (Bun ≈ 1
MiB) are highly suspect; rustoshi (hyper) ALSO defaults to ~1 MiB
unless `http1::Builder::max_buf_size` is called.

## Pass/fail summary

PASS: 5 / 30 (G1, G2, G3, G4, G28, plus partial-pass G30 for TLS
misconfig handling)
PARTIAL: 4 / 30 (G14 perms-default-correct-no-flag, G19 timeout-correct-no-flag,
G23 wrong realm string, G29 TLS-reload-on-SIGHUP gap as informational)
FAIL / MISSING: 21 / 30

22 distinct bug IDs, of which:
- **2 P0-SEC**: BUG-1 (open-on-empty-creds), BUG-9 (cookie write race)
- **5 P1-SEC**: BUG-2 (no co-required rpcbind/rpcallowip), BUG-3 (no
  rpcallowip), BUG-4 (no rpcauth), BUG-7 (no constant-time compare),
  BUG-20 (no work-queue cap)
- **1 P1-DOS**: BUG-21 (no rpcthreads — pool-size subset of BUG-20)
- **7 P2**: BUG-6 (plaintext password in memory), BUG-8 (no
  brute-force delay), BUG-13 (over-eager cookie delete), BUG-14 (no
  batch RPC), BUG-16 (HTTP status mapping), BUG-17 (no rpcwhitelist),
  BUG-19 (no -rpcservertimeout), BUG-22 (no MaxHeaderBytes cap)
- **5 P3**: BUG-5 (no multiple -rpcauth), BUG-10 (no -rpccookieperms),
  BUG-11 (no -rpccookiefile), BUG-12 (no -norpccookiefile), BUG-15 (no
  JSON-RPC 2.0 + notifications), BUG-18 (wrong WWW-Authenticate realm)

Tests pinning the current behaviour live in
`internal/rpc/w140_http_rpcauth_test.go` (Go test file).
