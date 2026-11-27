#!/usr/bin/env python3
"""Per-risk coverage floors (QA-002 / TD-13).

Reads a coverage.py XML report and fails when any security-critical
module drops below its declared line-rate floor. The global gate
(--cov-fail-under) catches broad regressions; these per-module floors
protect the paths where a coverage slide is a security risk: auth,
session issuance/verification, signing, and rate limiting.

Thresholds are a RATCHET — set just under the last measured value and
only ever raised, never lowered. The ramp target is 85% overall; each
release should bump floors to (measured - 2%) for covered modules.

Usage: python tools/check_coverage_targets.py coverage.xml
Exit 0 when every floor holds, 1 with a per-module report otherwise.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

# module suffix -> minimum line-rate (0..1). Set ~2 points under the
# last measured value; raise with every release toward 0.85+.
FLOORS = {
    "security/auth_gateway.py": 0.80,
    "security/authentication.py": 0.78,
    "security/ephemeral_sessions.py": 0.78,
    "security/http_auth.py": 0.80,
    "security/mfa.py": 0.85,
    "security/rate_limit.py": 0.90,
    "security/sessions.py": 0.85,
    "security/shared_state.py": 0.80,
    "security/step_up_auth.py": 0.80,
    "security/token_signing.py": 0.85,
    "security/websocket_registry.py": 0.78,
    "security/audit.py": 0.75,
    "security/jobs.py": 0.78,
    "security/secret_rotation.py": 0.78,
    "security/file_permissions.py": 0.85,
    "security/certificates.py": 0.85,
    "core/paths.py": 0.75,
    "core/share_url.py": 0.85,
    "core/logging.py": 0.90,
    "core/processes.py": 0.95,
    "core/deferred_lifecycle.py": 0.95,
    "security/http_client.py": 0.80,
    "core/service_manager.py": 0.60,
    "services/ws_adapter.py": 0.75,
}


def main(xml_path: str) -> int:
    tree = ET.parse(xml_path)
    classes = {
        c.get("filename", "").replace("\\", "/"): float(c.get("line-rate", 0))
        for c in tree.iter("class")
    }
    failures = []
    for suffix, floor in FLOORS.items():
        rate = next((r for f, r in classes.items() if f.endswith(suffix)), None)
        if rate is None:
            failures.append(f"MISSING  {suffix}: not in coverage report")
        elif rate < floor:
            failures.append(f"FAIL     {suffix}: {rate:.1%} < {floor:.0%}")
        else:
            print(f"OK       {suffix}: {rate:.1%} >= {floor:.0%}")
    if failures:
        print("\nCoverage floors violated:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
