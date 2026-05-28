"""Out-of-request tenant glue for shared-schema RLS mode + Celery.

Celery tasks run outside the request/response cycle, so the RLS middleware
never fires and never sets (or clears) the per-connection tenant session
variable. Worse, Celery workers reuse pooled database connections across tasks,
so the tenant GUC (and the bypass GUC) set by one task can *strand* on the
connection and silently leak into the next task that happens to reuse it. A task
that forgets to scope itself would then run against whatever tenant the previous
task left behind -- a cross-tenant data hazard.

The in-task API
---------------
There is intentionally no implicit "current tenant" for tasks. Each task must
explicitly wrap its database work in the RLS context managers from
:mod:`django_tenants.rls.session`::

    from django_tenants.rls import rls_context, bypass_rls

    @app.task
    def email_tenant_users(tenant_pk):
        with rls_context(tenant_pk):           # scope to one tenant
            for user in User.objects.all():
                ...

    @app.task
    def nightly_rollup():
        with bypass_rls():                     # deliberate cross-tenant work
            Invoice.objects.aggregate(...)

``rls_context`` accepts a tenant instance, a bare pk, or ``None``; see
:mod:`django_tenants.rls.session`. Passing a tenant *pk* (not the instance) to
the task is recommended so the task body re-resolves the tenant under its own
isolation.

What this module ships
----------------------
The signal handlers below make every task START from the secure default --
*no* tenant and bypass OFF -- regardless of what a prior task left on a reused
worker connection. They do NOT pick a tenant for you; a task that omits its own
``rls_context`` / ``bypass_rls`` simply sees no rows. That is the safe failure
mode: a missing scope yields an empty result set, never another tenant's data.

* ``task_prerun``  -> ``clear_current_tenant()`` + ``set_bypass(False)``
* ``task_postrun`` -> ``clear_current_tenant()`` + ``set_bypass(False)``

Wiring it up
------------
Call :func:`register` once at worker startup (e.g. from your Celery app module,
or a ``celeryd_init`` / app-ready hook)::

    from django_tenants.rls.celery import register
    register()

Celery is an optional dependency of django-tenants; :func:`register` imports
``celery.signals`` lazily and raises :class:`~django.core.exceptions.ImproperlyConfigured`
with a clear message if Celery is not installed.
"""

from . import session


def _reset_to_secure_default(**kwargs):
    """Reset the tenant database connection to the secure RLS default.

    Clears the current-tenant session variable and forces bypass OFF on the
    tenant database alias, so a task never inherits a prior task's tenant (or a
    stranded bypass) on a reused worker connection. Used for both the
    ``task_prerun`` and ``task_postrun`` boundaries.

    Accepts and ignores the Celery signal kwargs (``task_id``, ``task``,
    ``sender``, ...).
    """
    session.clear_current_tenant()
    session.set_bypass(value=False)


# Public aliases for the two signal-handler boundaries. They share one
# implementation (reset to the secure default) but are named per the signal
# they handle so they read clearly at the connect site and in tracebacks.
def on_task_prerun(**kwargs):
    """``task_prerun`` handler: start every task with no tenant and bypass off."""
    _reset_to_secure_default(**kwargs)


def on_task_postrun(**kwargs):
    """``task_postrun`` handler: leave the connection at the secure default."""
    _reset_to_secure_default(**kwargs)


def register():
    """Connect the prerun/postrun RLS-reset handlers to Celery's signals.

    Imports ``celery.signals`` lazily (Celery is an optional dependency) and
    raises :class:`~django.core.exceptions.ImproperlyConfigured` with a clear
    message if Celery is not installed.

    Call once at worker startup. The handlers only guarantee that a task never
    inherits a prior task's tenant (or a stranded bypass) on a reused worker
    connection; each task must still wrap its own DB work in
    ``with rls_context(tenant):`` (or ``with bypass_rls():``).
    """
    try:
        from celery import signals
    except ImportError as exc:
        from django.core.exceptions import ImproperlyConfigured

        raise ImproperlyConfigured(
            "django_tenants.rls.celery.register() requires Celery to be "
            "installed, but importing celery.signals failed. Install Celery "
            "(pip install celery) or do not call register()."
        ) from exc

    signals.task_prerun.connect(on_task_prerun, dispatch_uid="django_tenants_rls_task_prerun")
    signals.task_postrun.connect(on_task_postrun, dispatch_uid="django_tenants_rls_task_postrun")
