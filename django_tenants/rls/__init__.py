"""Row-Level Security (RLS) support for django-tenants (shared-schema mode).

This subpackage provides PostgreSQL Row-Level Security as an alternative to the
schema-per-tenant isolation that django-tenants offers by default. Instead of a
separate PostgreSQL schema per tenant, every tenant-scoped row lives in a single
shared schema and is filtered by a database RLS policy keyed on a per-connection
session variable.

Public API
----------
The small, stable surface intended for application code is::

    from django_tenants.rls import (
        TenantRLSModel,        # abstract base model carrying the tenant FK
        TenantPolicy,          # the default tenant-isolation policy
        rls_context,           # context manager / decorator: run as a tenant
        bypass_rls,            # context manager / decorator: bypass RLS
        set_current_tenant,    # set the per-connection tenant session var
        get_current_tenant_id, # read the per-connection tenant session var
    )

Lazy attribute access
----------------------
Importing this package stays cheap and side-effect free. ``conf``, ``session``,
and ``schema`` (the registry-free layers the backend depends on) remain
importable as submodules in the usual way, while every public name above is
resolved lazily via :pep:`562` ``__getattr__`` only on first attribute access.

This deferral is a deliberate hygiene choice rather than a load-order
requirement: ``django_tenants.rls.backend.base`` -- like every Django database
backend -- is imported when Django resolves the ENGINE, which happens *after*
``django.setup()``, and that import transitively loads this ``__init__``. Keeping
the eager import surface to the registry-free helpers means merely importing the
package never drags in :mod:`django_tenants.rls.models` (which defines a
``ForeignKey(settings.TENANT_MODEL)`` at class-body time) or
:mod:`django_tenants.rls.policies`, so this package adds no app-registry coupling
of its own beyond what the parent backend already carries.
"""

# Map each lazily-exported public name to the submodule it lives in. Resolution
# is deferred to __getattr__ so merely importing the package never pulls in the
# model / policy layers, keeping this package free of any app-registry coupling
# of its own beyond what the parent backend already carries.
_LAZY_EXPORTS = {
    "TenantRLSModel": "models",
    "TenantPolicy": "policies",
    "CustomPolicy": "policies",
    "BasePolicy": "policies",
    "PolicyError": "policies",
    "rls_context": "session",
    "bypass_rls": "session",
    "set_current_tenant": "session",
    "clear_current_tenant": "session",
    "get_current_tenant_id": "session",
    "require_current_tenant": "session",
    "NoActiveTenant": "session",
    "set_bypass": "session",
    "get_bypass": "session",
}

__all__ = [
    "TenantRLSModel",
    "TenantPolicy",
    "CustomPolicy",
    "BasePolicy",
    "PolicyError",
    "rls_context",
    "bypass_rls",
    "set_current_tenant",
    "clear_current_tenant",
    "get_current_tenant_id",
    "require_current_tenant",
    "NoActiveTenant",
    "set_bypass",
    "get_bypass",
]


def __getattr__(name):
    """PEP 562 lazy attribute access for the public API.

    Defers importing :mod:`.models` / :mod:`.policies` / :mod:`.session` until a
    public symbol is actually accessed, keeping ``import django_tenants.rls``
    (and, transitively, the database backend's import) free of any
    ``django.db.models`` side effects of its own.
    """
    submodule = _LAZY_EXPORTS.get(name)
    if submodule is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    module = import_module(f".{submodule}", __name__)
    value = getattr(module, name)
    # Cache on the package module so subsequent lookups skip __getattr__.
    globals()[name] = value
    return value


def __dir__():
    return sorted(list(globals().keys()) + __all__)
