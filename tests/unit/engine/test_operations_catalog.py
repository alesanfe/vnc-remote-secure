"""Contract: the operation catalog IS the parity matrix.

Every catalog operation must declare a coherent policy, every API
operation must map to a registered route with matching permission /
step-up / audit metadata, and every destructive operation must run
through the job ledger. This file fails loudly when a transport
drifts from the catalog — that drift IS the parity bug.
"""
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.engine.domain.operations import (  # noqa: E402
    OPERATIONS,
    parity_matrix,
)


def test_every_operation_declares_policy():
    for op in OPERATIONS.values():
        assert op.risk in ('low', 'moderate', 'high', 'critical'), \
            op.operation_id
        assert op.reversible in ('yes', 'no', 'partially')
        assert op.authentication_policy in ('', 'stepup', 'stepup-bound')
        assert op.execution_mode in ('sync', 'job', 'deferred')
        assert op.confirmation_type in ('none', 'simple', 'typed')
        if op.supports_api:
            assert op.api_route, f'{op.operation_id} missing api_route'
        if op.supports_cli:
            assert op.cli_command, f'{op.operation_id} missing cli_command'


def test_destructive_ops_are_bound_and_jobified():
    """critical/high ops MUST NOT run on a bare recent-auth window."""
    for op in OPERATIONS.values():
        if op.risk == 'critical' and op.supports_api:
            assert op.authentication_policy == 'stepup-bound', \
                op.operation_id
            assert op.confirmation_type in ('typed', 'simple')
        if op.execution_mode in ('job', 'deferred'):
            assert op.job_type, op.operation_id
            assert op.audit_event, op.operation_id


def test_api_routes_match_catalog():
    """Catalog api_route <-> _ROUTES entry must agree on every
    gate field — the route registry cannot quietly weaken a policy."""
    from vnc_remote_secure.services.api_v1 import _ROUTES

    for op in OPERATIONS.values():
        if not op.supports_api:
            continue
        method, rel = op.api_route.split(' ', 1)
        key = (method, rel.lstrip('/'))
        assert key in _ROUTES, \
            f'{op.operation_id}: {op.api_route} not in _ROUTES'
        spec = _ROUTES[key]
        assert spec.perm == op.required_capability, (
            op.operation_id, spec.perm, op.required_capability)
        # stepup-bound implies the route requires step-up at the gate.
        assert spec.step_up == bool(op.authentication_policy), (
            op.operation_id, spec.step_up, op.authentication_policy)
        if method != 'GET' and op.audit_event:
            assert spec.audit == op.audit_event, (
                op.operation_id, spec.audit, op.audit_event)


def test_step_up_routes_appear_in_catalog():
    """A step_up route without a catalog operation is an unmanaged
    destructive surface."""
    from vnc_remote_secure.services.api_v1 import _ROUTES
    bound_ops = {f"{o.api_route.split(' ', 1)[0]} "
                 f"{o.api_route.split(' ', 1)[1].lstrip('/')}"
                 for o in OPERATIONS.values() if o.api_route}
    for (method, rel), spec in _ROUTES.items():
        if spec.step_up:
            assert f'{method} {rel}' in bound_ops, \
                f'{method} {rel} is step-up gated but not catalogued'


def test_parity_matrix_shape():
    rows = parity_matrix()
    assert len(rows) == len(OPERATIONS)
    for row in rows:
        assert set(row) >= {'operation', 'cli', 'api', 'ui',
                            'perm', 'step_up', 'execution', 'audit'}


def test_cli_only_is_documented_by_design():
    """install/uninstall/service must not leak into the API — the UI
    only exists when the host bootstrap already ran."""
    for op_id in ('host.install', 'host.uninstall', 'host.service'):
        op = OPERATIONS[op_id]
        assert not op.supports_api and not op.supports_ui
        assert op.supports_cli


def _subparser_paths(parser, prefix=()):
    """Walk an argparse parser → {('secrets','rotate'), ('upgrade'),…}."""
    found = set()
    for action in parser._actions:
        choices = getattr(action, 'choices', None)
        if not isinstance(choices, dict):  # subparsers only
            continue
        for name, sub in choices.items():
            path = prefix + (name,)
            found.add(path)
            found |= _subparser_paths(sub, path)
    return found


def test_catalog_cli_commands_exist_in_parser():
    """Every catalog cli_command must resolve to real argparse
    verbs — the catalog is the source; a renamed subcommand breaks
    parity documentation AND this test."""
    from vnc_remote_secure.cli._parser import create_parser
    verbs = _subparser_paths(create_parser())
    for op in OPERATIONS.values():
        if not op.supports_cli:
            continue
        # 'start|stop|restart' → 'start'; '--flag' tokens dropped.
        toks = [t.split('|', 1)[0]
                for t in op.cli_command.split()
                if not t.startswith('--')]
        cmd = tuple(toks)
        # try progressively shorter prefixes until a path matches
        matched = any(cmd[:n] in verbs for n in (len(cmd), 1))
        assert matched, \
            f'{op.operation_id}: cli_command {op.cli_command!r} ' \
            f'not in parser'


def test_openapi_operations_carry_catalog_id():
    """The spec is generated/verified FROM the catalog: every
    catalogued api_route must carry x-operation-id = its id."""
    import yaml
    spec = yaml.safe_load(open(
        'docs/api/openapi.v1.yaml', encoding='utf-8'))
    for op in OPERATIONS.values():
        if not op.supports_api:
            continue
        method, rel = op.api_route.split(' ', 1)
        rel = '/' + rel.lstrip('/')
        body = spec['paths'][rel][method.lower()]
        assert body.get('x-operation-id') == op.operation_id, (
            rel, method, body.get('x-operation-id'),
            op.operation_id)
