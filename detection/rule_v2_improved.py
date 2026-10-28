"""Improved brute-force detection rule (v2).

Changes from v1:
  1. Group failures by (source IP, username) instead of IP alone.
  2. Lower threshold from 5 to 4.
  3. Require the successful login to match the same user and IP.
"""

from datetime import datetime, timedelta
from collections import defaultdict


def parse_log(filepath):
    entries = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ts_str, ip, user, action = [x.strip() for x in line.split(",")]
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            entries.append({"timestamp": ts, "ip": ip, "user": user, "action": action})
    return entries


def detect_bruteforce_v2(entries, fail_threshold=4, fail_window_minutes=5, success_window_minutes=10):
    entries_sorted = sorted(entries, key=lambda x: x["timestamp"])
    failures_by_key = defaultdict(list)
    for e in entries_sorted:
        if e["action"] == "LOGIN_FAILURE":
            failures_by_key[(e["ip"], e["user"])].append(e["timestamp"])

    alerts = []
    for (ip, user), fail_times in failures_by_key.items():
        fail_times.sort()
        i = 0
        while i < len(fail_times):
            window_start = fail_times[i]
            window_end = window_start + timedelta(minutes=fail_window_minutes)
            j = i
            while j < len(fail_times) and fail_times[j] <= window_end:
                j += 1
            count = j - i
            if count >= fail_threshold:
                last_fail = fail_times[j - 1]
                success_end = last_fail + timedelta(minutes=success_window_minutes)
                success_time = None
                for e in entries_sorted:
                    if (e["ip"] == ip and e["user"] == user
                            and e["action"] == "LOGIN_SUCCESS"
                            and last_fail < e["timestamp"] <= success_end):
                        success_time = e["timestamp"]
                        break
                if success_time is not None:
                    alerts.append({
                        "rule": "v2", "ip": ip, "user": user,
                        "fail_window_start": window_start,
                        "fail_window_end": window_end,
                        "num_failures": count,
                        "last_failure": last_fail,
                        "success": success_time,
                    })
                    i = j
                    continue
            i += 1
    return alerts


if __name__ == "__main__":
    log_path = "../data/synthetic_auth.log"
    entries = parse_log(log_path)
    alerts = detect_bruteforce_v2(entries)
    print(f"v2 alerts: {len(alerts)}")
    for a in alerts:
        print(a)
