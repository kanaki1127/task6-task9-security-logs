# Task 6 — Decode and Interpret Security Logs

## 1. Log overview

48 authentication events over 2025-03-15. Format: `timestamp, source_ip, username, action`. Actions are `LOGIN_SUCCESS` or `LOGIN_FAILURE`.

## 2. Baseline normal behaviour

- **Users:** alice, bob, carol (occasional dave).
- **Source IPs:** 192.168.1.10-12 (internal).
- **Hours:** 08:00-18:00.
- **Failures:** isolated, followed quickly by success (mistyped password).
- **Success rate:** high during business hours.

## 3. Unusual patterns

### Pattern A — Rapid failures then success (02:00-02:05)
- IP: 203.0.113.45 (external). User: alice. 6 failures in 2.5 min, then success.
- Assessment: strong brute-force indicator. Successful login after failures is concerning.
- Priority: **High.** Review account activity; consider forced password reset.

### Pattern B — Shared IP burst across users (11:00-11:05)
- IP: 192.168.1.100 (internal). Users: alice, bob, carol; dave succeeds.
- Assessment: likely shared NAT; no single account targeted.
- Priority: **Low.** Monitor only.

### Pattern C — Slow failures by one user (10:00-10:11)
- IP: 198.51.100.22 (external). User: bob. 5 failures over 8 min, then success.
- Assessment: likely user error; too slow for typical automated brute force.
- Priority: **Medium-low.** Confirm with user.

### Pattern D — Four failures then success (14:00-14:04)
- IP: 203.0.113.99 (external). User: carol. 4 failures in 3 min, then success.
- Assessment: below v1 threshold but still suspicious; **missed case** for v1.
- Priority: **Medium-high.**

## 4. Investigation priorities

| Priority | Event | Reason |
|---|---|---|
| High | Pattern A (203.0.113.45 / alice) | Rapid brute force + successful login |
| Medium-high | Pattern D (203.0.113.99 / carol) | Rapid failures below v1 threshold |
| Medium-low | Pattern C (198.51.100.22 / bob) | External IP, spaced failures |
| Low | Pattern B (192.168.1.100) | Shared IP, multiple users |

## 5. Justified observations

- External IPs 203.0.113.45 and 203.0.113.99 show rapid failure bursts; strongest signals.
- 192.168.1.100 shows a burst across users — consistent with shared NAT, not a targeted attack.
- v1 correctly alerts on Pattern A, false-positives on Pattern B, misses Pattern D.
- v2 (per-user grouping, threshold 4) detects A and D, avoids B.

## 6. Conclusion

Two credible brute-force indicators (A, D) and one likely benign burst (B). v2 is better suited to this environment.
