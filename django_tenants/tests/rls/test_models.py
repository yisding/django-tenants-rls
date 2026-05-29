"""Unit tests for ``django_tenants.rls.models``.

These exercise the ``RLSModelMeta`` policy collection / clearing, the lazy
default-policy build, and ``save()`` auto-population. ``save()`` is tested
without a database: ``django.db.models.Model.save`` is patched to a recorder so
no row is written, and ``connections`` is patched to a stub carrying a fake
tenant. The test models declare an explicit ``app_label`` so importing them does
not require the package to be in ``INSTALLED_APPS``.
"""

import unittest

from django.db import models as dj_models
from django.test.utils import override_settings

from django_tenants.rls import models as rls_models
from django_tenants.rls.policies import BasePolicy, CustomPolicy, TenantPolicy

from .models import Note, NoteWithCustomPolicy, NoteWithExplicitPolicy


class StubTenant:
    def __init__(self, pk):
        self.pk = pk


class StubConnection:
    def __init__(self, tenant, rls_tenant_id=None):
        self.tenant = tenant
        # The GUC source of truth set by rls_context()/set_tenant. Per D3 this is
        # resolved FIRST in save(), before connection.tenant.
        if rls_tenant_id is not None:
            self._rls_tenant_id = rls_tenant_id


class MetaCollectionTestCase(unittest.TestCase):
    def test_meta_rls_policies_removed_from_meta(self):
        # The unknown attribute must not survive on Django's _meta options.
        self.assertFalse(hasattr(NoteWithExplicitPolicy._meta, "rls_policies"))

    def test_explicit_policies_collected(self):
        policies = NoteWithExplicitPolicy.get_rls_policies()
        self.assertEqual(len(policies), 1)
        self.assertIsInstance(policies[0], TenantPolicy)
        self.assertEqual(policies[0].name, "note_explicit_isolation")

    def test_custom_policy_collected(self):
        policies = NoteWithCustomPolicy.get_rls_policies()
        self.assertEqual(len(policies), 1)
        self.assertIsInstance(policies[0], CustomPolicy)

    def test_default_policy_built_lazily(self):
        # Reset the cached sentinel so we observe the lazy build.
        Note._rls_policies = None
        policies = Note.get_rls_policies()
        self.assertEqual(len(policies), 1)
        self.assertIsInstance(policies[0], TenantPolicy)
        self.assertEqual(policies[0].name, "%s_tenant_isolation" % Note._meta.db_table)
        # Cached: a second call returns the same list object.
        self.assertIs(Note.get_rls_policies(), policies)

    def test_default_policy_uses_configured_tenant_field(self):
        Note._rls_policies = None
        policy = Note.get_rls_policies()[0]
        self.assertEqual(policy.tenant_field, "tenant")

    def test_all_policies_are_base_policy(self):
        for model in (Note, NoteWithExplicitPolicy, NoteWithCustomPolicy):
            if model is Note:
                model._rls_policies = None
            for policy in model.get_rls_policies():
                self.assertIsInstance(policy, BasePolicy)

    def test_concrete_subclass_inherits_abstract_meta_rls_policies(self):
        # F20: an abstract parent that declares Meta.rls_policies should pass them
        # down to a concrete child that declares no policies of its own (the child
        # must NOT fall back to the default-policy None sentinel and lose them).
        class AbstractWithPolicies(rls_models.TenantRLSModel):
            text = dj_models.CharField(max_length=10, blank=True, default="")

            class Meta:
                app_label = "rls"
                abstract = True
                rls_policies = [
                    TenantPolicy(
                        name="inherited_iso",
                        tenant_field="tenant",
                        session_variable="django_tenants.tenant_id",
                        bypass_variable="django_tenants.bypass_rls",
                        pk_cast="integer",
                    )
                ]

        class ConcreteChild(AbstractWithPolicies):
            class Meta:
                app_label = "rls"

        policies = ConcreteChild.get_rls_policies()
        self.assertEqual(len(policies), 1)
        self.assertIsInstance(policies[0], TenantPolicy)
        self.assertEqual(policies[0].name, "inherited_iso")
        # The concrete child resolved a non-empty inherited list, not the sentinel.
        self.assertIsNotNone(ConcreteChild._rls_policies)

    def test_direct_concrete_subclass_with_no_policies_uses_default(self):
        # The base TenantRLSModel itself declares no policies (its _rls_policies is
        # the empty []), so a direct concrete subclass with none of its own must
        # still fall back to the default policy -- inheritance only kicks in for a
        # NON-empty base list. (Regression guard for the F20 inheritance rule.)
        Note._rls_policies = None
        policies = Note.get_rls_policies()
        self.assertEqual(len(policies), 1)
        self.assertEqual(policies[0].name, "%s_tenant_isolation" % Note._meta.db_table)

    def test_auto_default_policy_name_within_63_bytes(self):
        # F1/F19/D4: the auto default name "<db_table>_tenant_isolation" must never
        # exceed the 63-byte Postgres identifier limit. For a very long db_table it
        # is deterministically shortened (stable, still valid identifier) so a
        # TenantPolicy can be constructed without tripping the >63-byte check.
        long_table = "a_very_long_application_table_name_that_blows_past_the_limit"
        name = rls_models._default_policy_name(long_table)
        self.assertLessEqual(len(name.encode("utf-8")), 63)
        # Deterministic: same input -> same output across calls.
        self.assertEqual(name, rls_models._default_policy_name(long_table))
        # The result is a valid policy name (passes BasePolicy validation).
        policy = TenantPolicy(
            name=name,
            tenant_field="tenant",
            session_variable="django_tenants.tenant_id",
            bypass_variable="django_tenants.bypass_rls",
            pk_cast="integer",
        )
        self.assertEqual(policy.name, name)

    def test_auto_default_policy_name_short_table_is_natural(self):
        # A short table keeps the readable natural name unchanged.
        self.assertEqual(
            rls_models._default_policy_name("rls_note"),
            "rls_note_tenant_isolation",
        )

    def test_metaclass_robust_to_inherited_meta_rls_policies(self):
        # Regression: hasattr()/delattr() on an INHERITED Meta.rls_policies would
        # raise AttributeError. The metaclass must read/clear via the class's own
        # __dict__, so an inherited rls_policies neither crashes construction nor
        # leaks into Django's Options (which would raise on an unknown attribute).
        class ParentMeta:
            rls_policies = [TenantPolicy(name="parent_iso", pk_cast="integer")]

        class ChildMeta(ParentMeta):
            app_label = "rls"
            abstract = True

        class Child(rls_models.TenantRLSModel):
            Meta = ChildMeta

        # Construction succeeded; the inherited attribute is left on the parent
        # Meta only and Child does not pick up the parent's explicit policies as
        # its own (its own __dict__ had none).
        self.assertTrue(getattr(Child._meta, "abstract", False))


class SaveAutoPopulateTestCase(unittest.TestCase):
    def setUp(self):
        # Patch Model.save so no DB write happens; record the receiver instead.
        self.saved = []
        self._orig_save = dj_models.Model.save

        def fake_save(inst, *args, **kwargs):
            self.saved.append(inst)

        dj_models.Model.save = fake_save

        # Patch the connections registry used inside TenantRLSModel.save.
        from django.db import connections as real_connections
        self._real_connections = real_connections
        self._orig_getitem = type(real_connections).__getitem__

    def tearDown(self):
        dj_models.Model.save = self._orig_save
        type(self._real_connections).__getitem__ = self._orig_getitem

    def _patch_connection(self, tenant, rls_tenant_id=None):
        stub = StubConnection(tenant, rls_tenant_id=rls_tenant_id)
        type(self._real_connections).__getitem__ = lambda self, alias: stub

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_save_autopopulates_tenant_from_connection(self):
        self._patch_connection(StubTenant(pk=42))
        note = Note(text="hello")
        note.save()
        self.assertEqual(note.tenant_id, 42)
        self.assertEqual(self.saved, [note])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_save_resolves_rls_tenant_id_when_conn_tenant_unset(self):
        # F18/D3: the GUC (connection._rls_tenant_id, set by rls_context()) is the
        # source of truth and is resolved FIRST. rls_context()+create() sets the
        # GUC but never sets connection.tenant, so save() must still populate the
        # FK from _rls_tenant_id. A string value is fine (the FK target field
        # coerces it on save).
        self._patch_connection(StubTenant(pk=None), rls_tenant_id="5")
        note = Note(text="hello")
        note.save()
        self.assertEqual(note.tenant_id, "5")
        self.assertEqual(self.saved, [note])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_save_rls_tenant_id_wins_over_stale_connection_tenant(self):
        # The GUC takes precedence over a (possibly stale) connection.tenant.
        self._patch_connection(StubTenant(pk=99), rls_tenant_id="5")
        note = Note(text="hello")
        note.save()
        self.assertEqual(note.tenant_id, "5")

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_save_falls_back_to_connection_tenant_when_no_guc(self):
        # When _rls_tenant_id is unset/empty, fall back to connection.tenant.pk.
        self._patch_connection(StubTenant(pk=42), rls_tenant_id="")
        note = Note(text="hello")
        note.save()
        self.assertEqual(note.tenant_id, 42)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_save_does_not_overwrite_explicit_tenant(self):
        self._patch_connection(StubTenant(pk=42))
        note = Note(text="hello")
        note.tenant_id = 7
        note.save()
        self.assertEqual(note.tenant_id, 7)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_save_no_tenant_on_connection_leaves_unset(self):
        self._patch_connection(StubTenant(pk=None))
        note = Note(text="hello")
        note.save()
        self.assertIsNone(note.tenant_id)

    @override_settings(TENANT_RLS_ENABLED=False)
    def test_save_disabled_does_not_touch_tenant_id(self):
        # When RLS is disabled, save() must not even look at the connection.
        def explode(self, alias):
            raise AssertionError("connection must not be accessed when RLS is off")

        type(self._real_connections).__getitem__ = explode
        note = Note(text="hello")
        note.save()
        self.assertIsNone(note.tenant_id)
        self.assertEqual(self.saved, [note])


class FullCleanAutoPopulateTestCase(unittest.TestCase):
    """full_clean() must stamp the tenant BEFORE validating.

    A model validated before it is saved (e.g. a ModelForm) would otherwise fail
    with "tenant cannot be null", because the save()-time stamp comes too late.
    These tests record into ``Model.full_clean`` (patched) the tenant_id observed
    at validation time, so they assert the stamp already happened by then -- no DB
    write occurs.
    """

    def setUp(self):
        # Patch Model.full_clean so no real validation runs; record the tenant_id
        # the instance has at the moment super().full_clean() would have been
        # called (i.e. AFTER the auto-stamp).
        self.validated = []
        self._orig_full_clean = dj_models.Model.full_clean

        def fake_full_clean(inst, *args, **kwargs):
            self.validated.append((inst, inst.tenant_id))

        dj_models.Model.full_clean = fake_full_clean

        from django.db import connections as real_connections
        self._real_connections = real_connections
        self._orig_getitem = type(real_connections).__getitem__

    def tearDown(self):
        dj_models.Model.full_clean = self._orig_full_clean
        type(self._real_connections).__getitem__ = self._orig_getitem

    def _patch_connection(self, tenant, rls_tenant_id=None):
        stub = StubConnection(tenant, rls_tenant_id=rls_tenant_id)
        type(self._real_connections).__getitem__ = lambda self, alias: stub

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_full_clean_before_save_stamps_tenant(self):
        # The production bug: full_clean() before save() must NOT see a null
        # tenant. The stamp happens early, so by the time validation runs the FK
        # is populated.
        self._patch_connection(StubTenant(pk=42))
        note = Note(text="hello")
        note.full_clean()
        self.assertEqual(note.tenant_id, 42)
        self.assertEqual(self.validated, [(note, 42)])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_full_clean_resolves_rls_tenant_id_when_conn_tenant_unset(self):
        # The GUC source of truth is resolved first here too.
        self._patch_connection(StubTenant(pk=None), rls_tenant_id="5")
        note = Note(text="hello")
        note.full_clean()
        self.assertEqual(note.tenant_id, "5")

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_full_clean_does_not_overwrite_explicit_tenant(self):
        self._patch_connection(StubTenant(pk=42))
        note = Note(text="hello")
        note.tenant_id = 7
        note.full_clean()
        self.assertEqual(note.tenant_id, 7)
        self.assertEqual(self.validated, [(note, 7)])

    @override_settings(TENANT_RLS_ENABLED=False)
    def test_full_clean_disabled_does_not_touch_tenant_id(self):
        # When RLS is disabled, full_clean() must not even look at the connection.
        def explode(self, alias):
            raise AssertionError("connection must not be accessed when RLS is off")

        type(self._real_connections).__getitem__ = explode
        note = Note(text="hello")
        note.full_clean()
        self.assertIsNone(note.tenant_id)
        self.assertEqual(self.validated, [(note, None)])


class BulkCreateAutoPopulateTestCase(unittest.TestCase):
    """bulk_create() bypasses save(), so it must stamp tenant_id itself.

    These tests patch ``Manager.bulk_create`` (the super() the RLS manager
    delegates to) with a recorder, so no DB write happens; the assertion is on the
    tenant_id stamped onto each instance before delegation.
    """

    def setUp(self):
        self.created = []

        # ``bulk_create`` is defined up the Manager MRO (on the queryset-derived
        # base), so shadow it directly on the class TenantRLSManager.super() lands
        # on -- ``models.Manager`` -- and restore by removing the shadow in
        # tearDown (it was an inherited attribute, never in Manager.__dict__).
        self._had_own_bulk_create = "bulk_create" in dj_models.Manager.__dict__
        self._orig_bulk_create = dj_models.Manager.__dict__.get("bulk_create")

        recorder = self

        def fake_bulk_create(manager, objs, *args, **kwargs):
            # Record the list as forwarded (already stamped by the override).
            recorder.created.append(list(objs))
            return objs

        dj_models.Manager.bulk_create = fake_bulk_create

        from django.db import connections as real_connections
        self._real_connections = real_connections
        self._orig_getitem = type(real_connections).__getitem__

    def tearDown(self):
        if self._had_own_bulk_create:
            dj_models.Manager.bulk_create = self._orig_bulk_create
        else:
            del dj_models.Manager.bulk_create
        type(self._real_connections).__getitem__ = self._orig_getitem

    def _patch_connection(self, tenant, rls_tenant_id=None):
        stub = StubConnection(tenant, rls_tenant_id=rls_tenant_id)
        type(self._real_connections).__getitem__ = lambda self, alias: stub

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_bulk_create_stamps_tenant_id_on_each_instance(self):
        self._patch_connection(StubTenant(pk=42))
        notes = [Note(text="a"), Note(text="b")]
        Note.objects.bulk_create(notes)
        self.assertEqual([n.tenant_id for n in notes], [42, 42])
        # The same (stamped) list was forwarded to the underlying bulk_create.
        self.assertEqual(self.created, [notes])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_bulk_create_resolves_rls_tenant_id_when_conn_tenant_unset(self):
        # GUC source of truth wins here too (rls_context() never sets conn.tenant).
        self._patch_connection(StubTenant(pk=None), rls_tenant_id="5")
        notes = [Note(text="a"), Note(text="b")]
        Note.objects.bulk_create(notes)
        self.assertEqual([n.tenant_id for n in notes], ["5", "5"])

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_bulk_create_preserves_explicit_tenant_per_instance(self):
        # An instance that already has a tenant keeps it; only unset ones are
        # stamped from the connection.
        self._patch_connection(StubTenant(pk=42))
        explicit = Note(text="a")
        explicit.tenant_id = 7
        unset = Note(text="b")
        Note.objects.bulk_create([explicit, unset])
        self.assertEqual(explicit.tenant_id, 7)
        self.assertEqual(unset.tenant_id, 42)

    @override_settings(TENANT_RLS_ENABLED=True)
    def test_bulk_create_accepts_arbitrary_iterable(self):
        # objs may be any iterable (a generator); it must be stamped and forwarded
        # as a materialized list without being exhausted before the insert.
        self._patch_connection(StubTenant(pk=42))
        gen = (Note(text=str(i)) for i in range(3))
        Note.objects.bulk_create(gen)
        self.assertEqual(len(self.created), 1)
        self.assertEqual([n.tenant_id for n in self.created[0]], [42, 42, 42])

    @override_settings(TENANT_RLS_ENABLED=False)
    def test_bulk_create_disabled_does_not_touch_tenant_id(self):
        # When RLS is disabled, bulk_create() must not even look at the connection.
        def explode(self, alias):
            raise AssertionError("connection must not be accessed when RLS is off")

        type(self._real_connections).__getitem__ = explode
        notes = [Note(text="a"), Note(text="b")]
        Note.objects.bulk_create(notes)
        self.assertEqual([n.tenant_id for n in notes], [None, None])
        self.assertEqual(self.created, [notes])


class DefaultManagerContractTestCase(unittest.TestCase):
    """The default manager must remain the unchanged, non-filtering contract.

    It is a TenantRLSManager (so bulk_create() auto-stamps), but it must not add
    any tenant filtering -- its base queryset is the stock unfiltered one, because
    the database (RLS) does the filtering.
    """

    def test_default_manager_is_tenant_rls_manager(self):
        self.assertIsInstance(Note.objects, rls_models.TenantRLSManager)
        self.assertIsInstance(Note._default_manager, rls_models.TenantRLSManager)

    def test_manager_does_not_override_get_queryset(self):
        # No tenant-filtering: get_queryset is the stock Manager implementation
        # (the database enforces isolation, not the manager).
        self.assertIs(
            rls_models.TenantRLSManager.get_queryset,
            dj_models.Manager.get_queryset,
        )
