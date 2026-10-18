#!/usr/bin/env python3
"""Lag-0 record and nightly attribution for one fleet node (default blockbrew).

Evidence for the "7 days at lag 0 vs Core" and "7 green nightly nights" lines
of DONE.md. Reads files the maxbox cron jobs already write; touches nothing live.

  lag / FAIL samples  <meta>/fleet-monitor-history.jsonl   (tools/fleet-monitor.sh, 5-min cadence,
                      gitignored; NOT in ~/.cache/hashhog-monitor/, which only holds state)
  wedge restarts      ~/.cache/hashhog-monitor/stale-guard-<node>.log   ("WEDGED:" lines)
  nightly arms        <meta>/consensus-diff-artifacts/diffguard-YYYYMMDDT*.log
                      (tools/nightly-differential-guard.sh; each arm's final status line)

Day verdict (lag): PASS iff no run of >STREAK consecutive samples with lag>0
(a single new block is seen by peers before the node, so 1-2 samples of lag 1-4
is propagation, not lag), no run of >=FAIL_RUN consecutive RPC-FAIL samples, and
no stale-guard WEDGED restart. Raw max lag is printed next to it.

Night verdict: GREEN = every arm PASS; DEFERRED = heavy arms skipped by the mem
guard (no evidence either way, does NOT count as green); RED = any other state.
"""
import argparse, collections, glob, json, os, re, sys

NODES = ["rustoshi", "blockbrew", "clearbit", "nimrod", "camlcoin",
         "beamchain", "hotbuns", "ouroboros", "lunarblock", "haskoin"]
STREAK = 2      # samples (10 min) of lag>0 tolerated as block propagation
FAIL_RUN = 3    # consecutive RPC-FAIL samples that count as an outage


def lag_days(history, node):
    days = collections.OrderedDict()
    prev = {"lag": 0, "fail": 0}
    for line in open(history):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        b = r.get("nodes", {}).get(node)
        day = r["ts"][:10]
        d = days.setdefault(day, dict(n=0, max=0, pos=0, streak=0, fails=0, failrun=0, missing=0))
        if b is None:
            d["missing"] += 1
            continue
        d["n"] += 1
        lag = b.get("lag") or 0
        d["max"] = max(d["max"], lag)
        if lag > 0:
            d["pos"] += 1
            prev["lag"] += 1
            d["streak"] = max(d["streak"], prev["lag"])
        else:
            prev["lag"] = 0
        if b.get("status") != "OK":
            d["fails"] += 1
            prev["fail"] += 1
            d["failrun"] = max(d["failrun"], prev["fail"])
        else:
            prev["fail"] = 0
    return days


def wedges(path):
    out = collections.Counter()
    if os.path.exists(path):
        for line in open(path, errors="replace"):
            if "WEDGED:" in line:
                out[line[:10]] += 1
    return out


def node_in(text):
    for n in NODES:
        if n in text:
            return n
    return None


def parse_night(path):
    """-> (arm statuses dict, {arm: sorted node list}, unattributed list)"""
    text = open(path, errors="replace").read()
    arms = {}
    m = re.search(r"^\s+reject=\S+.*$", text, re.M)
    if m:
        arms = dict(kv.split("=", 1) for kv in m.group(0).split())
    attrib = collections.defaultdict(set)
    unattr = []
    # per-arm block = text between the previous summary line and this one
    pos = 0
    for sm in re.finditer(r"^== ([a-z-]+?)(?:-regression)?: .*$", text, re.M):
        arm = sm.group(1).replace("-", "_")
        arm = {"reject_corpora": "reject", "mainnet_replay": "mainnet_replay"}.get(arm, arm)
        block = text[pos:sm.start()]
        pos = sm.end()
        for fm in re.finditer(r"^\s+(?:FAIL|INFRA|STALE)\s+(\S+)(.*)$", block, re.M):
            n = node_in(fm.group(1)) or node_in(fm.group(2)[:60])
            if n:
                attrib[arm].add(n)
            else:
                unattr.append("%s:%s" % (arm, fm.group(1)))
    for am in re.finditer(r"^\s*=> (?:shadow-)?(\w+): (?:ERROR|FAIL)", text, re.M):
        attrib["accept"].add(am.group(1))
    alert = "ALERT written" in text
    return arms, attrib, unattr, alert


def night_rows(artifacts):
    rows = []
    for p in sorted(glob.glob(os.path.join(artifacts, "diffguard-2*.log"))):
        day = re.search(r"diffguard-(\d{4})(\d\d)(\d\d)T", p)
        day = "-".join(day.groups())
        arms, attrib, unattr, alert = parse_night(p)
        bad = {a: s for a, s in arms.items() if s not in ("PASS", "DEFER")}
        if bad:
            verdict = "RED"
        elif any(s == "DEFER" for s in arms.values()):
            verdict = "DEFERRED"
        elif arms:
            verdict = "GREEN"
        else:
            verdict = "NO-STATUS"
        rows.append(dict(day=day, verdict=verdict, arms=arms, bad=bad,
                         attrib={a: sorted(v) for a, v in attrib.items()}, unattr=unattr))
    return rows


def render(node, days, wedge, nights, last):
    o = []
    days = list(days.items())[-last:]
    o.append("## %s lag vs fleet max (fleet-monitor, 5-min samples)\n" % node)
    o.append("| day (UTC) | samples | max lag | lag>0 samples | longest lag>0 run | RPC-FAIL samples | longest FAIL run | wedge restarts | verdict |")
    o.append("|---|---|---|---|---|---|---|---|---|")
    run = best = 0
    for day, d in days:
        w = wedge.get(day, 0)
        ok = d["n"] > 0 and d["streak"] <= STREAK and d["failrun"] < FAIL_RUN and w == 0
        run = run + 1 if ok else 0
        best = max(best, run)
        o.append("| %s | %d | %d | %d | %d | %d | %d | %d | %s |" % (
            day, d["n"], d["max"], d["pos"], d["streak"], d["fails"], d["failrun"], w,
            "PASS" if ok else "FAIL"))
    o.append("\nConsecutive PASS days ending at the last row: **%d** (best run in window: %d).\n" % (run, best))
    o.append("## Nightly differential guard, per arm, attributed to nodes\n")
    o.append("| night | verdict | red arms -> nodes | names %s |" % node)
    o.append("|---|---|---|---|")
    grun = 0
    for n in nights[-last:]:
        red = []
        for a in sorted(n["bad"]):
            who = n["attrib"].get(a)
            red.append("%s=%s -> %s" % (a, n["bad"][a], ",".join(who) if who else "UNATTRIBUTED"))
        if n["unattr"]:
            red.append("unattributed lines: " + ", ".join(n["unattr"]))
        named = any(node in v for v in n["attrib"].values())
        grun = grun + 1 if n["verdict"] == "GREEN" else 0
        o.append("| %s | %s | %s | %s |" % (n["day"], n["verdict"], "; ".join(red) or "-", "yes" if named else "no"))
    o.append("\nConsecutive fleet-GREEN nights ending at the last row: **%d**." % grun)
    return "\n".join(o) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    meta = os.path.expanduser("~/hashhog")
    ap.add_argument("--node", default="blockbrew", choices=NODES)
    ap.add_argument("--history", default=meta + "/fleet-monitor-history.jsonl")
    ap.add_argument("--artifacts", default=meta + "/consensus-diff-artifacts")
    ap.add_argument("--stale-guard-dir", default=os.path.expanduser("~/.cache/hashhog-monitor"))
    ap.add_argument("--days", type=int, default=14)
    a = ap.parse_args(argv)
    for p in (a.history, a.artifacts):
        if not os.path.exists(p):
            sys.exit("missing input: %s" % p)
    days = lag_days(a.history, a.node)
    if not days or not any(d["n"] for d in days.values()):
        sys.exit("no samples for %s in %s" % (a.node, a.history))
    w = wedges(os.path.join(a.stale_guard_dir, "stale-guard-%s.log" % a.node))
    sys.stdout.write(render(a.node, days, w, night_rows(a.artifacts), a.days))


if __name__ == "__main__":
    main()
