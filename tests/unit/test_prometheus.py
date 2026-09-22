"""Tests for Prometheus metrics export."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.monitoring.prometheus import (
    inc_counter,
    metrics_handler,
    render_metrics,
    set_gauge,
)


class TestPrometheusMetrics:
    def test_render_includes_help_and_type(self):
        output = render_metrics()
        assert '# HELP' in output
        assert '# TYPE' in output

    def test_counter_increment(self):
        inc_counter('vnc_remote_auth_attempts_total', 'result=success')
        output = render_metrics()
        assert 'vnc_remote_auth_attempts_total' in output

    def test_gauge_set(self):
        set_gauge('vnc_remote_posture_score', 85.0)
        output = render_metrics()
        assert 'vnc_remote_posture_score' in output
        assert '85' in output

    def test_metrics_handler_returns_body_and_status(self):
        body, status = metrics_handler()
        assert status == 200
        assert 'vnc_remote_up' in body or 'vnc_remote_process_start_time' in body

    def test_process_start_time_present(self):
        output = render_metrics()
        assert 'vnc_remote_process_start_time' in output


class TestEscaping:
    """Label/metric values with quotes/newlines must not break the
    exposition format or inject lines."""

    def test_quote_and_newline_in_label_escaped(self):
        from vnc_remote_secure.monitoring import prometheus
        # A label value containing " or a newline must not inject
        # lines into the exposition format.
        assert prometheus._format_labels('k="a\nb"') == \
            '{k=\\"a\\nb\\"}'
        assert prometheus._format_labels('a=b\\c') == '{a=b\\\\c}'
        assert prometheus._format_labels('') == ''
