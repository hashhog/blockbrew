import json, os, tempfile, unittest
import lag_record as L


def hist(path, rows):
    with open(path, "w") as f:
        for ts, lag, st in rows:
            f.write(json.dumps({"ts": ts, "fleet_max": 1, "nodes": {"blockbrew": {"lag": lag, "status": st}}}) + "\n")


class T(unittest.TestCase):
    def test_streak_and_fail(self):
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "h")
            hist(p, [("2026-10-01T00:00:00Z", 0, "OK"), ("2026-10-01T00:05:00Z", 1, "OK"),
                     ("2026-10-01T00:10:00Z", 1, "OK"), ("2026-10-01T00:15:00Z", 1, "OK"),
                     ("2026-10-01T00:20:00Z", 0, "FAIL"), ("2026-10-02T00:00:00Z", 2, "OK"),
                     ("2026-10-02T00:05:00Z", 0, "OK")])
            d = L.lag_days(p, "blockbrew")
            self.assertEqual((d["2026-10-01"]["max"], d["2026-10-01"]["streak"], d["2026-10-01"]["fails"]), (1, 3, 1))
            self.assertEqual(d["2026-10-02"]["streak"], 1)

    def test_night_attribution(self):
        log = ("== recovery-regression 2026-10-14T09:11:16Z ==\n"
               "  FAIL  hotbuns (exit 1) — RECOVERY hotbuns: FAIL x\n"
               "== recovery-regression: PASS=9 FAIL=1 SKIP=0 INFRA=0 ==\n"
               "  => shadow-rustoshi: ERROR (1 call(s))\n"
               "  reject=PASS accept=NODE_ERR recovery=FAIL\n  ALERT written: x\n")
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "diffguard-20261014T083002Z.log")
            open(p, "w").write(log)
            n = L.night_rows(t)[0]
            self.assertEqual(n["verdict"], "RED")
            self.assertEqual(n["attrib"], {"recovery": ["hotbuns"], "accept": ["rustoshi"]})

    def test_deferred_is_not_green(self):
        with tempfile.TemporaryDirectory() as t:
            open(os.path.join(t, "diffguard-20261009T083001Z.log"), "w").write("  reject=PASS accept=DEFER\n")
            self.assertEqual(L.night_rows(t)[0]["verdict"], "DEFERRED")


if __name__ == "__main__":
    unittest.main()
