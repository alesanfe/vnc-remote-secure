"""Tests for centralized error handling."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.errors import (
    error_json,
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
