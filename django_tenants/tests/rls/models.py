"""Test-only tenant-scoped models for the RLS test suite.

These models subclass :class:`django_tenants.rls.models.TenantRLSModel` and are
used by the unit tests (and the optionally-skipped isolation test) to exercise
policy generation, ``save()`` auto-population and the migration operations.

They declare an explicit ``app_label`` of ``rls`` so they register without the
package having to be listed in ``INSTALLED_APPS`` for the non-DB tests. The
suite as a whole never requires these tables to exist unless the Postgres-only
isolation test runs.
"""

from django.db import models

from django_tenants.rls.models import TenantRLSModel
from django_tenants.rls.policies import CustomPolicy, TenantPolicy


class Note(TenantRLSModel):
    """A minimal tenant-scoped model with the default (auto-built) policy."""

    text = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        app_label = "rls"


class NoteWithExplicitPolicy(TenantRLSModel):
    """A tenant-scoped model that overrides the policy list via ``Meta``."""

    text = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        app_label = "rls"
        rls_policies = [
            TenantPolicy(
                name="note_explicit_isolation",
                tenant_field="tenant",
                session_variable="django_tenants.tenant_id",
                bypass_variable="django_tenants.bypass_rls",
                pk_cast="integer",
            )
        ]


class NoteWithCustomPolicy(TenantRLSModel):
    """A tenant-scoped model whose policy is a raw-SQL ``CustomPolicy``."""

    text = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        app_label = "rls"
        rls_policies = [
            CustomPolicy(
                name="note_custom",
                expression="tenant_id IS NOT NULL",
            )
        ]
