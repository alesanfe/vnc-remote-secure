# Postmortem — <title> (<date>)

> Copy this file to `docs/reports/incident-YYYY-MM-DD.md` for every
> S1/S2 incident. Blameless: describe the system, not the person.

## Summary
Two sentences: what happened, who was affected, for how long.

## Severity
S1–S4 (see `incident-response.md`) + justification.

## Impact
- Users/operators affected:
- Data lost / exposed:
- Duration (detect → mitigate → fully recovered):
- SLO/error-budget consumption:

## Timeline (all times UTC)
| Time | Event |
|------|-------|
| | |

## Detection
How it was noticed (alert, audit check, user report). MTTD.

## Root cause
Technical cause, and the chain of conditions that made it possible.

## Contributing factors
What made it easier to happen or harder to catch (missing alert,
missing test, undocumented step, stale doc).

## What worked
Controls that fired as designed.

## What failed
Controls that did not fire or did not exist.

## Action items
| Action | Owner | Due | Type (fix/alert/test/doc) |
|--------|-------|-----|---------------------------|
| | | | |

Every S1/S2 closes with at least one **regression test** and one
**detection/alert** improvement — code-only fixes are not closure.
