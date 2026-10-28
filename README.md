# Task 6 + Task 9 — Security Log Analysis & Detection Rule Testing

Deliverables for:

- **Task 6 — Decode and Interpret Security Logs**
- **Task 9 — Test a Defensive Detection Rule**

## Scenario

A fictional organisation's authentication logs are analysed. A baseline brute-force detection rule is tested against synthetic logs, then improved based on false positives and missed cases.

## Contents

| Path | Purpose |
|---|---|
| `data/synthetic_auth.log` | Sanitised synthetic authentication log |
| `analysis/task6_log_analysis.md` | Task 6: annotated findings and observations |
| `detection/rule_v1.py` | Baseline detection rule |
| `detection/rule_v2_improved.py` | Improved detection rule |
| `detection/test_detection.py` | Test harness |
| `results/v1_test_results.md` | Task 9: v1 test cases and results |
| `results/v2_test_results.md` | Task 9: v2 test cases and results |
| `results/v1_alerts.txt` | v1 alert output |
| `results/v2_alerts.txt` | v2 alert output |

## Run

```bash
cd detection
python test_detection.py
```

This parses `../data/synthetic_auth.log`, runs both rules, prints alerts, and writes `../results/v1_alerts.txt` and `../results/v2_alerts.txt`.

## Test cases

- True positive: brute-force followed by success
- False positive avoided: shared NAT IP with failures across users
- Missed case recovered: 4-failure attack below v1 threshold
- True negative: slow, spaced failures by a legitimate user

All data is synthetic.
