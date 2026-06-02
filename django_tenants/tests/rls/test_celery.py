"""Unit tests for ``django_tenants.rls.celery``.

These run without a database and without Celery installed. Celery is an optional
dependency, so ``celery.signals`` is imported lazily inside ``register()``.

The contract under test (DEC-5):

* the task_prerun and task_postrun handlers make every task START from the
  secure default by calling ``clear_current_tenant()`` + ``set_bypass(False)``
  (so a reused worker connection never inherits a prior task's tenant/bypass);
* ``register()`` connects BOTH handlers to ``celery.signals.task_prerun`` /
  ``task_postrun`` (lazy import), and raises ``ImproperlyConfigured`` with a
  clear message when Celery is not importable.

We never import the real Celery: a fake ``celery.signals`` module is injected
into ``sys.modules`` to record ``.connect(...)`` calls, and ``session``'s two
mutators are stubbed so no database is touched.
"""

import sys
import unittest
from unittest import mock

from django.core.exceptions import ImproperlyConfigured

from django_tenants.rls import celery as rls_celery


class _FakeSignal:
    """Records handlers connected to it (mimics a Celery Signal)."""

    def __init__(self, name):
        self.name = name
        self.connected = []

    def connect(self, handler=None, **kwargs):
        # Celery's Signal.connect is usable both as ``sig.connect(fn)`` and as a
        # decorator ``@sig.connect``. Support both call styles.
        if handler is None:
            def _decorator(fn):
                self.connected.append(fn)
                return fn
            return _decorator
        self.connected.append(handler)
        return handler


class _FakeCelerySignals:
    """Stand-in for the ``celery.signals`` module."""

    def __init__(self):
        self.task_prerun = _FakeSignal("task_prerun")
        self.task_postrun = _FakeSignal("task_postrun")


def _inject_fake_celery():
    """Install a fake ``celery`` + ``celery.signals`` into ``sys.modules``.

    Returns the fake signals object so the test can inspect connections.
    """
    fake_signals = _FakeCelerySignals()
    fake_celery = mock.Mock(name="celery")
    fake_celery.signals = fake_signals
    return fake_signals, mock.patch.dict(
        sys.modules,
        {"celery": fake_celery, "celery.signals": fake_signals},
    )


class HandlerBehaviorTestCase(unittest.TestCase):
    """Whatever handlers register() wires up must reset tenant + bypass."""

    def _connected_handlers(self):
        fake_signals, patcher = _inject_fake_celery()
        with patcher:
            rls_celery.register()
        prerun = fake_signals.task_prerun.connected
        postrun = fake_signals.task_postrun.connected
        return prerun, postrun

    def test_register_connects_both_signals(self):
        prerun, postrun = self._connected_handlers()
        self.assertEqual(len(prerun), 1, "exactly one task_prerun handler")
        self.assertEqual(len(postrun), 1, "exactly one task_postrun handler")

    def test_prerun_handler_clears_tenant_and_bypass(self):
        prerun, _ = self._connected_handlers()
        handler = prerun[0]
        with mock.patch.object(rls_celery.session, "clear_current_tenant") as clear, \
                mock.patch.object(rls_celery.session, "set_bypass") as set_bypass:
            # Celery invokes signal handlers with kwargs only.
            handler(sender=None, task_id="t1", task=None, args=(), kwargs={})
        clear.assert_called_once()
        set_bypass.assert_called_once()
        # set_bypass must be turned OFF (secure default).
        self._assert_bypass_off(set_bypass)

    def test_postrun_handler_clears_tenant_and_bypass(self):
        _, postrun = self._connected_handlers()
        handler = postrun[0]
        with mock.patch.object(rls_celery.session, "clear_current_tenant") as clear, \
                mock.patch.object(rls_celery.session, "set_bypass") as set_bypass:
            handler(sender=None, task_id="t1", task=None, args=(), kwargs={},
                    retval=None, state="SUCCESS")
        clear.assert_called_once()
        set_bypass.assert_called_once()
        self._assert_bypass_off(set_bypass)

    def _assert_bypass_off(self, set_bypass):
        # The single set_bypass call must request bypass OFF, whether passed
        # positionally or as the ``value=`` keyword.
        _, kwargs = set_bypass.call_args
        args = set_bypass.call_args.args
        if "value" in kwargs:
            self.assertFalse(kwargs["value"])
        else:
            # value is the second positional arg of session.set_bypass
            # (connection, value, using); a positional False is the bypass flag.
            self.assertIn(False, args)


class RegisterWithoutCeleryTestCase(unittest.TestCase):
    def test_raises_improperly_configured_when_celery_missing(self):
        # Force the lazy ``import celery.signals`` inside register() to fail.
        real_import = __import__

        def _no_celery(name, *args, **kwargs):
            if name == "celery" or name.startswith("celery."):
                raise ImportError("No module named 'celery'")
            return real_import(name, *args, **kwargs)

        # Also ensure no stale celery is cached in sys.modules.
        with mock.patch.dict(sys.modules):
            sys.modules.pop("celery", None)
            sys.modules.pop("celery.signals", None)
            with mock.patch("builtins.__import__", side_effect=_no_celery):
                with self.assertRaises(ImproperlyConfigured):
                    rls_celery.register()


if __name__ == "__main__":
    unittest.main()
