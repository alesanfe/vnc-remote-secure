# Code Review Checklist

Beyond style — Google-style review gate. A review that only checks
formatting is not a review. Comment classes: **blocker** (functional
error, security, data loss, unsustainable design) · **important**
(must fix or justify) · **suggestion** · **question** · **nit**.

## Correctness

- [ ] Solves the actual requirement (issue/ADR/bug), not a different one
- [ ] Error paths handled at the right boundary — fail closed on
      security surfaces, never swallow silently
- [ ] Concurrency: shared state via `shared_state`, not module
      globals; idempotent ops where repeated submission is possible
- [ ] Inputs validated at the trust boundary (pydantic `extra='forbid'`
      / `_read_json_body` limits / path containment)
- [ ] Revertable: can this be rolled back? Does it need a migration?

## Architecture

- [ ] Respects the layers — engine never imports transport/infra;
      `test_import_boundaries.py` still passes
- [ ] New ops registered in `engine/domain/operations.py` (parity
      catalog) — CLI/API can't drift
- [ ] No duplicate logic where a shared helper exists
      (`terminal_spawn`, `stores`, `http_auth`…)
- [ ] Public API surface unchanged or consciously versioned

## Security

- [ ] No secrets/creds in code, logs, or audit details
      (`redaction.py` covers new fields?)
- [ ] New endpoints carry an auth scope and rate limit
- [ ] Audit event emitted for every sensitive action
- [ ] `risk-register.md` rows touched are updated

## Tests & docs

- [ ] New behavior has tests; security behavior has *negative* tests
- [ ] Contract/parity tests updated when routes change
- [ ] `CHANGELOG.md`, `config.schema.json`, `.env.example`,
      `FEATURE_FLAGS.md` updated if applicable
- [ ] Docs updated in the same PR (DoD — REQUIREMENTS.md)

## Operability

- [ ] New failure modes → new alert/metric/runbook note?
- [ ] No unbounded loops, unbounded memory, unbounded request sizes
- [ ] Timeouts on every outbound call (`security/http_client.py`)

## When in doubt

Ask: does this change make the codebase *healthier*? "Not worse" is
the floor; "better" is the goal — but perfect is not the bar for
merging a good improvement.
