# Task 9 — v1 Detection Rule Test Results

## Rule (v1)
Alert when >= 5 LOGIN_FAILURE events from the same source IP occur within 5 minutes, followed by a LOGIN_SUCCESS from that IP within 10 minutes of the last failure.

## Test cases

| # | Test case | Expected | v1 actual | Verdict |
|---|---|---|---|---|
| 1 | Brute force 203.0.113.45 / alice | Alert | Alert | True positive |
| 2 | Shared NAT 192.168.1.100 | No alert | Alert | False positive |
| 3 | Short attack 203.0.113.99 / carol | Alert | No alert | Missed case |
| 4 | Slow failures 198.51.100.22 / bob | No alert | No alert | True negative |

## Alerts produced

Total alerts: 2

{'rule': 'v1', 'ip': '203.0.113.45', 'fail_window_start': datetime(2025, 3, 15, 2, 0), 'fail_window_end': datetime(2025, 3, 15, 2, 5), 'num_failures': 6, 'last_failure': datetime(2025, 3, 15, 2, 2, 30), 'success': datetime(2025, 3, 15, 2, 5)}
{'rule': 'v1', 'ip': '192.168.1.100', 'fail_window_start': datetime(2025, 3, 15, 11, 0), 'fail_window_end': datetime(2025, 3, 15, 11, 5), 'num_failures': 6, 'last_failure': datetime(2025, 3, 15, 11, 2, 30), 'success': datetime(2025, 3, 15, 11, 5)}

## Analysis
- **True positive:** 203.0.113.45 shows classic brute force; v1 alerts correctly.
- **False positive:** 192.168.1.100 is a shared internal IP; failures span users and the success is for dave. v1 groups only by IP.
- **Missed case:** 203.0.113.99 has 4 rapid failures + success; v1 threshold of 5 misses it.
- **True negative:** bob's slow failures are correctly ignored.

## Conclusion
v1 is too coarse: IP-only grouping and a high threshold.
