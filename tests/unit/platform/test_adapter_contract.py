"""Platform adapter contract tests.

Both platform adapters must implement the full PlatformAdapter
interface so the common business logic can rely on symmetric
behaviour across Linux and Windows. This test fails when a method
declared in the base class is missing or has an incompatible
signature on either adapter — the "cross-platform" claim then stays
verifiable rather than aspirational.
"""
import inspect
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest

from vnc_remote_secure.platform.base import PlatformAdapter
from vnc_remote_secure.platform.linux.adapter import LinuxAdapter
from vnc_remote_secure.platform.windows.adapter import WindowsAdapter


def _public_methods(cls):
    return {
        name for name, member in inspect.getmembers(cls, inspect.isfunction)
        if not name.startswith('_')
    }


@pytest.mark.parametrize('adapter_cls', [LinuxAdapter, WindowsAdapter])
def test_adapter_implements_base_contract(adapter_cls):
    """Every public method of PlatformAdapter must exist on the
    concrete adapter with a compatible signature."""
    for name in _public_methods(PlatformAdapter):
        assert hasattr(adapter_cls, name), (
            f"{adapter_cls.__name__} is missing {name}()")
        base_sig = inspect.signature(
            getattr(PlatformAdapter, name))
        impl_sig = inspect.signature(
            getattr(adapter_cls, name))
        # Parameter names must match (defaults may differ).
        base_params = [p.name for p in base_sig.parameters.values()
                       if p.name != 'self']
        impl_params = [p.name for p in impl_sig.parameters.values()
                       if p.name != 'self']
        assert base_params == impl_params, (
            f"{adapter_cls.__name__}.{name} signature {impl_params} "
            f"!= base {base_params}")


@pytest.mark.parametrize('adapter_cls', [LinuxAdapter, WindowsAdapter])
def test_adapter_is_platform_adapter_subclass(adapter_cls):
    assert issubclass(adapter_cls, PlatformAdapter)
