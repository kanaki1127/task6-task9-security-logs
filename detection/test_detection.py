"""Test harness for v1 and v2 detection rules."""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from rule_v1 import parse_log, detect_bruteforce_v1
from rule_v2_improved import detect_bruteforce_v2

LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_auth.log")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")


def write_alerts(alerts, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"Total alerts: {len(alerts)}\n\n")
        for a in alerts:
            f.write(str(a) + "\n")


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    entries = parse_log(LOG_PATH)

    v1_alerts = detect_bruteforce_v1(entries)
    v2_alerts = detect_bruteforce_v2(entries)

    print("=" * 60)
    print("v1 alerts")
    print("=" * 60)
    for a in v1_alerts:
        print(a)

    print("\n" + "=" * 60)
    print("v2 alerts")
    print("=" * 60)
    for a in v2_alerts:
        print(a)

    write_alerts(v1_alerts, os.path.join(RESULTS_DIR, "v1_alerts.txt"))
    write_alerts(v2_alerts, os.path.join(RESULTS_DIR, "v2_alerts.txt"))

    def has_alert(alerts, ip, user=None):
        for a in alerts:
            if a["ip"] == ip and (user is None or a.get("user") == user):
                return True
        return False

    print("\n" + "=" * 60)
    print("Test-case summary")
    print("=" * 60)

    cases = [
        ("True positive: 203.0.113.45 / alice",
         has_alert(v1_alerts, "203.0.113.45", "alice"),
         has_alert(v2_alerts, "203.0.113.45", "alice")),
        ("False-positive avoidance: 192.168.1.100",
         not has_alert(v1_alerts, "192.168.1.100"),
         not has_alert(v2_alerts, "192.168.1.100")),
        ("Missed-case recovery: 203.0.113.99 / carol",
         has_alert(v1_alerts, "203.0.113.99", "carol"),
         has_alert(v2_alerts, "203.0.113.99", "carol")),
        ("True negative: 198.51.100.22 / bob",
         not has_alert(v1_alerts, "198.51.100.22", "bob"),
         not has_alert(v2_alerts, "198.51.100.22", "bob")),
    ]

    for name, v1_ok, v2_ok in cases:
        print(f"\n{name}")
        print(f"  v1 expected pass? {v1_ok}")
        print(f"  v2 expected pass? {v2_ok}")


if __name__ == "__main__":
    main()
