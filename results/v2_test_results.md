# Task 9 — v2 Improved Rule Test Results

## Rule (v2)
Alert when >= 4 LOGIN_FAILURE events for the same (source IP, username) occur within 5 minutes, followed by a LOGIN_SUCCESS for the same (IP, username) within 10 minutes of the last failure.

## Changes from v1
1. Group by (IP, username).
2. Threshold 5 -> 4.
3. Success must match user and IP.

## Test cases

| # | Test case | Expected | v2 actual | Verdict |
|---|---|---|---|---|
| 1 | Brute force 203.0.113.45 / alice | Alert | Alert | True positive |
| 2 | Shared NAT 192.168.1.100 | No alert | No alert | True negative (fixed) |
| 3 | Short attack 203.0.113.99 / carol | Alert | Alert | True positive (recovered) |
| 4 | Slow failures 198.51.100.22 / bob | No alert | No alert | True negative |

## Alerts produced

Total alerts: 2

{'rule': 'v2', 'ip': '203.0.113.45', 'user': 'alice', 'fail_window_start': datetime(2025, 3, 15, 2, 0), 'fail_window_end': datetime(2025, 3, 15, 2, 5), 'num_failures': 6, 'last_failure': datetime(2025, 3, 15, 2, 2, 30), 'success': datetime(2025, 3, 15, 2, 5)}
{'rule': 'v2', 'ip': '203.0.113.99', 'user': 'carol', 'fail_window_start': datetime(2025, 3, 15, 14, 0), 'fail_window_end': datetime(2025, 3, 15, 14, 5), 'num_failures': 4, 'last_failure': datetime(2025, 3, 15, 14, 3), 'success': datetime(2025, 3, 15, 14, 4)}

## Analysis
- True positive retained: alice brute force still detected.
- False positive eliminated: no single user had >= 4 failures on the shared NAT IP.
- Missed case recovered: carol's 4 failures now alert.
- True negative preserved: bob's slow failures still ignored.

## Remaining limitations
- Distributed brute force across many IPs is not covered.
- Threshold 4 is a judgement call; tune per environment.
- Time-of-day context not considered.

## Conclusion
v2 is a clear improvement: detects both credible attacks, avoids the shared-NAT false positive.
