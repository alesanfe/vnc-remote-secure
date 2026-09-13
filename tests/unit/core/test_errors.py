"""Tests for centralized error handling."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.errors import (
    ERROR_CODES,
    error_json,
    structured_error,
    generate_request_id,
)


class TestErrorHandling:
    def test_error_json_basic(self):
        body, status = error_json('Something went wrong', 500)
        parsed = json.loads(body)
        assert parsed['error'] is True
        assert parsed['message'] == 'Something went wrong'
        assert status == 500

    def test_error_json_with_code(self):
        body, status = error_json('Not found', 404, code='ERR_NOT_FOUND')
        parsed = json.loads(body)
        assert parsed['code'] == 'ERR_NOT_FOUND'
        assert status == 404

    def test_error_json_with_detail(self):
        body, _ = error_json('Validation failed', 422, detail='Missing field: username')
        parsed = json.loads(body)
        assert parsed['detail'] == 'Missing field: username'

    def test_error_json_with_request_id(self):
        body, _ = error_json('Error', 500, request_id='abc-123')
        parsed = json.loads(body)
        assert parsed['request_id'] == 'abc-123'

    def test_structured_error_uses_registry(self):
        body, status = structured_error('ERR_AUTH_REQUIRED', 'Login required')
        parsed = json.loads(body)
        assert parsed['code'] == 'ERR_AUTH_REQUIRED'
        assert status == 401

    def test_structured_error_unknown_code_defaults_500(self):
        body, status = structured_error('ERR_UNKNOWN', 'Unknown')
        assert status == 500

    def test_error_codes_cover_common_cases(self):
        assert 'ERR_AUTH_REQUIRED' in ERROR_CODES
        assert 'ERR_PERMISSION_DENIED' in ERROR_CODES
        assert 'ERR_RATE_LIMITED' in ERROR_CODES
        assert 'ERR_NOT_FOUND' in ERROR_CODES
        assert 'ERR_INTERNAL' in ERROR_CODES

    def test_generate_request_id_is_unique(self):
        id1 = generate_request_id()
        id2 = generate_request_id()
        assert id1 != id2
        assert len(id1) > 0
