"""Formal jsonschema validation of config.schema.json and the
defaults files — the declarative contract must itself be a valid
JSON Schema document, and every shipped default must satisfy its
declared type."""
import json
import os
import re

import pytest
from jsonschema import Draft202012Validator, validate
from jsonschema.validators import validator_for

pytestmark = pytest.mark.timeout(30)

_SCHEMA_PATH = os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'src',
    'vnc_remote_secure', 'config', 'schema', 'config.schema.json')
_DEFAULTS_DIR = os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'src',
    'vnc_remote_secure', 'config', 'defaults')


@pytest.fixture(scope='module')
def schema():
    with open(_SCHEMA_PATH, encoding='utf-8') as f:
        return json.load(f)


def _coerce_env(value: str, schema_type: str):
    """Env vars are strings — map a declared schema type onto the
    typed value a non-empty string must represent."""
    if schema_type == 'boolean':
        if value.strip().lower() in ('true', 'false'):
            return value.strip().lower() == 'true'
        return value  # leave invalid — the validator rejects it
    if schema_type == 'integer':
        try:
            return int(value.strip())
        except ValueError:
            return value
    return value


def _env_file_vars(path):
    """Minimal .env reader — same quoting rules as config_inspector."""
    out = {}
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, val = line.partition('=')
            key, val = key.strip(), val.strip()
            if val and val[0] in '"\'' and val[-1] == val[0]:
                val = val[1:-1]
            if val.startswith('$('):
                continue  # command substitution — not a literal
            out[key] = val
    return out


def test_schema_document_is_valid_json_schema(schema):
    """The declarative contract must itself satisfy its meta-schema —
    a malformed rule would silently stop protecting anything."""
    cls = validator_for(schema)
    cls.check_schema(schema)


def test_schema_declares_no_unknown_types(schema):
    known = {'string', 'boolean', 'integer', 'number', 'array',
             'object', 'null'}
    for name, prop in schema['properties'].items():
        st = prop.get('type')
        if st is None:
            continue
        for t in ([st] if isinstance(st, str) else st):
            assert t in known, f'{name}: unknown JSON Schema type {t!r}'


def test_schema_defaults_satisfy_own_type(schema):
    """A ``default`` that violates its declared type is a bug that
    shipped — validate every default against its property."""
    for name, prop in schema['properties'].items():
        if 'default' not in prop:
            continue
        validate(instance=prop['default'], schema=prop,
                 cls=Draft202012Validator)


def test_shipped_defaults_files_satisfy_schema(schema):
    """Each var set in config/defaults/*.env must satisfy the declared
    type/pattern/enum of its schema property."""
    files = [os.path.join(_DEFAULTS_DIR, n)
             for n in os.listdir(_DEFAULTS_DIR) if n.endswith('.env')]
    assert files, 'defaults dir missing'
    props = schema['properties']
    for path in files:
        for key, raw in _env_file_vars(path).items():
            prop = props.get(key)
            if prop is None or 'type' not in prop:
                continue
            st = prop['type']
            typed = _coerce_env(raw, st if isinstance(st, str) else 'string')
            try:
                validate(instance=typed, schema=prop,
                         cls=Draft202012Validator)
            except Exception as exc:
                raise AssertionError(
                    f'{os.path.basename(path)}: {key}={raw!r} fails '
                    f'schema {prop}') from exc


def test_schema_only_declares_upper_env_names(schema):
    """Properties are env-var names — keep the contract uniform."""
    bad = [n for n in schema['properties']
           if not re.fullmatch(r'[A-Z][A-Z0-9_]*', n)]
    assert not bad, f'non-env-style names in schema: {bad}'
