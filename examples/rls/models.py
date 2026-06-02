"""Minimal example models for django-tenants shared-schema RLS mode.

In RLS mode there is a single ``public`` schema and tenant isolation is enforced
by PostgreSQL Row-Level Security policies on the ``tenant`` foreign key that
``TenantRLSModel`` provides. Subclass ``TenantRLSModel`` instead of
``models.Model`` for any model whose rows must be isolated per tenant.

This app must be listed in ``SHARED_APPS`` (NOT ``TENANT_APPS``) -- see
``examples/rls/settings_snippet.py`` and ``docs/rls.rst``.
"""

from django.db import models

from django_tenants.rls.models import TenantRLSModel


class Note(TenantRLSModel):
    """A tenant-isolated note.

    ``TenantRLSModel`` adds a ``tenant`` foreign key to ``settings.TENANT_MODEL``
    and an overridden ``save()`` that auto-populates ``tenant`` from the active
    connection's tenant, so existing code that never passes ``tenant`` keeps
    working as a drop-in.

    With no explicit ``Meta.rls_policies`` a default ``TenantPolicy`` is built
    automatically on the ``tenant`` field when RLS is enabled (via
    ``manage.py enable_rls``, the ``post_migrate`` auto-enable hook, or an
    ``EnableRLS`` / ``CreateTenantPolicy`` migration operation).
    """

    text = models.TextField()
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.text

    # The auto-generated policy is named "<db_table>_tenant_isolation"
    # (here "myapp_note_tenant_isolation"). To override it, declare the policy
    # explicitly -- match that default name if you want enable_rls/disable_rls
    # to target the same policy:
    #
    #     from django_tenants.rls.policies import TenantPolicy
    #
    #     class Meta:
    #         rls_policies = [
    #             TenantPolicy(name="myapp_note_tenant_isolation"),
    #         ]
    #
    # ``django_tenants.rls.policies.CustomPolicy(name, expression,
    # check_expression=None)`` is also available for a raw SQL expression --
    # but its SQL is NOT validated, so never build it from untrusted input.
