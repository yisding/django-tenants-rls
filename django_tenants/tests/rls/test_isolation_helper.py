"""Exercises the public ``RLSIsolationTestCaseMixin`` (Postgres required).

This proves the reusable isolation helper in ``django_tenants.rls.test`` works
against a real ``TenantRLSModel`` (the suite's :class:`~.models.Note`). Like
``test_isolation``, it needs a real, connectable Postgres database and is SKIPPED
cleanly otherwise: the mixin's ``setUpClass`` raises ``unittest.SkipTest`` with a
clear reason when RLS is disabled, the backend is not Postgres, the database is
unreachable, or a non-superuser test role cannot be created.

We deliberately do NOT duplicate ``test_isolation``'s low-level round-trips here;
the point of this module is to demonstrate (and regression-guard) the public
helper's ergonomics: ``rls_model``, ``as_tenant``, ``assertIsolated`` and
``assertInvisibleWithoutTenant``.
"""

from django.test import TransactionTestCase

from django_tenants.rls.test import RLSIsolationTestCaseMixin

from .models import Note


def _note_row(tenant):
    """Extra create() kwargs for ``Note`` beyond the auto-stamped tenant FK."""
    return {"text": "note-for-%s" % tenant.schema_name}


class NoteIsolationHelperTestCase(RLSIsolationTestCaseMixin, TransactionTestCase):
    """Drive the mixin against ``Note`` to prove the helper isolates correctly."""

    rls_model = Note
    # Distinct schema names so we never collide with ``test_isolation``'s tenants
    # if both run in the same process.
    tenant_a_schema = "rls_helper_tenant_a"
    tenant_b_schema = "rls_helper_tenant_b"

    def test_assert_isolated(self):
        self.assertIsolated(Note, self.tenant_a, self.tenant_b, make_row=_note_row)

    def test_assert_invisible_without_tenant(self):
        self.assertInvisibleWithoutTenant(Note, make_row=_note_row)

    def test_as_tenant_scopes_queries(self):
        with self.as_tenant(self.tenant_a):
            Note.objects.create(text="a", tenant=self.tenant_a)
        with self.as_tenant(self.tenant_b):
            Note.objects.create(text="b", tenant=self.tenant_b)

        with self.as_tenant(self.tenant_a):
            self.assertEqual(
                list(Note.objects.values_list("text", flat=True)), ["a"]
            )
        with self.as_tenant(self.tenant_b):
            self.assertEqual(
                list(Note.objects.values_list("text", flat=True)), ["b"]
            )

    def test_default_row_stamps_tenant_without_make_row(self):
        # ``Note.text`` has a blank default, so the mixin's default per-row kwargs
        # (just the tenant FK) are sufficient -- no ``make_row`` needed.
        self.assertIsolated(Note, self.tenant_a, self.tenant_b)
