# blockbrew lag record, 2026-10-05 to 2026-10-18

A record of how far one mainnet blockbrew deployment trailed Bitcoin Core over
14 days. The raw samples come from the maintainers' monitoring and are not
published, so read this as a report, not as something you can reproduce from
this repository.

## Summary
- **No 7-day run at lag 0.** The longest run of passing days was 2 (10-15 and
  10-16). The last day, 10-18, passed.
- **Lag stayed small.** The maximum on any day was 2 to 4 blocks. Days failed
  because the node trailed by 1 to 4 blocks for 15 to 30 minutes at a time, not
  because of long outages.
- **Two wedges.** On 10-08 18:55Z the node sat at height 970517, 2 blocks behind
  Core, and on 10-14 01:00Z at 971325, 3 behind. Both times it was restarted
  automatically after 30 to 35 minutes without progress.
- **No crash loop.** RPC failures appear only on 10-08, two separate samples
  and never two in a row.

## Definitions
- One sample every 5 minutes. "Lag" means blocks behind the highest tip seen
  across the monitored nodes, Core included.
- A day **passes** if it has no run of more than 2 consecutive samples with
  lag above 0 (10 minutes, which allows for block propagation), no run of 3 or
  more failed RPC samples, and no wedge restart.
- Runs are not reset at midnight. A run that crosses midnight counts at its
  full length toward the later day. Samples where the node was not polled are
  skipped and neither break nor extend a run.

## Daily table

| day (UTC) | samples | max lag | samples with lag > 0 | longest lag > 0 run | RPC-fail samples | wedge restarts | verdict |
|---|---|---|---|---|---|---|---|
| 2026-10-05 | 288 | 3 | 51 | 2 | 0 | 0 | PASS |
| 2026-10-06 | 287 | 3 | 49 | 3 | 0 | 0 | FAIL |
| 2026-10-07 | 287 | 2 | 41 | 2 | 0 | 0 | PASS |
| 2026-10-08 | 288 | 3 | 71 | 5 | 2 | 1 | FAIL |
| 2026-10-09 | 287 | 2 | 37 | 3 | 0 | 0 | FAIL |
| 2026-10-10 | 288 | 2 | 43 | 6 | 0 | 0 | FAIL |
| 2026-10-11 | 287 | 4 | 54 | 5 | 0 | 0 | FAIL |
| 2026-10-12 | 288 | 2 | 57 | 5 | 0 | 0 | FAIL |
| 2026-10-13 | 288 | 2 | 59 | 3 | 0 | 0 | FAIL |
| 2026-10-14 | 287 | 4 | 66 | 3 | 0 | 1 | FAIL |
| 2026-10-15 | 288 | 2 | 29 | 2 | 0 | 0 | PASS |
| 2026-10-16 | 288 | 2 | 43 | 2 | 0 | 0 | PASS |
| 2026-10-17 | 287 | 3 | 44 | 3 | 0 | 0 | FAIL |
| 2026-10-18 | 288 | 2 | 27 | 2 | 0 | 0 | PASS |
