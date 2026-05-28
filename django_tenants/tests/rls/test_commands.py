"""Tests that enable_rls / disable_rls exit non-zero when a model fails.

A deploy/migration script must not get a success exit code when one or more
tables were left unprotected (or not disabled). The commands collect failures
and raise ``CommandError`` so the process exits non-zero. Driven by calling the
Command directly with a mocked model list -- no database needed.
"""

import io
import unittest
from unittest import mock

from django.core.management.base import CommandError

from django_tenants.rls.management.commands import disable_rls, enable_rls


class _FakeMeta:
    label = "app.Fake"


class _FailingModel:
    _meta = _FakeMeta()

    @classmethod
    def has_unscoped_rows(cls):
        return False

    @classmethod
    def enable_rls(cls):
        raise RuntimeError("boom-enable")

    @classmethod
    def disable_rls(cls):
        raise RuntimeError("boom-disable")


def _cmd(module):
    return module.Command(stdout=io.StringIO(), stderr=io.StringIO())


class CommandFailureExitTestCase(unittest.TestCase):
    def test_enable_rls_raises_command_error_on_failure(self):
        cmd = _cmd(enable_rls)
        with mock.patch.object(cmd, "_get_models", return_value=[_FailingModel]):
            with self.assertRaises(CommandError):
                cmd.handle(app=None, model=None)

    def test_disable_rls_raises_command_error_on_failure(self):
        cmd = _cmd(disable_rls)
        with mock.patch.object(cmd, "_get_models", return_value=[_FailingModel]):
            with self.assertRaises(CommandError):
                cmd.handle(app=None, model=None)

    def test_enable_rls_no_matching_models_is_success(self):
        # No matching models is a clean no-op (no CommandError, exit 0).
        cmd = _cmd(enable_rls)
        with mock.patch.object(cmd, "_get_models", return_value=[]):
            cmd.handle(app=None, model=None)


if __name__ == "__main__":
    unittest.main()
