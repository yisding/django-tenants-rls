"""Django migration operations for shared-schema Row Level Security (RLS).

These operations emit pure DDL (``ALTER TABLE ... ENABLE/DISABLE/FORCE ROW LEVEL
SECURITY`` and ``CREATE/DROP POLICY``) against the RLS-aware schema editor. They
make no change to the migration *state* (they do not add/remove model fields),
only to the database, so :meth:`state_forwards` is a no-op for all of them.

Every operation resolves its model via ``from_state.apps.get_model(...)`` -- this
is the correct, registry-backed lookup. (The django-rls ``RLSOperation.get_model``
helper is broken: it calls ``router.db_for_write`` on a list of tables, so it is
deliberately NOT ported here.)

All database methods are guarded by ``hasattr(schema_editor, "<method>")`` so that
running them against a non-RLS schema editor (for example when the project still
uses the stock ``django_tenants.postgresql_backend`` engine) is a safe no-op
rather than an error.
"""

from django.db.migrations.operations.base import Operation

from . import conf


class _RLSOperationBase(Operation):
    """Common behavior for RLS migration operations.

    RLS operations are reversible and reduce to SQL, and they never mutate the
    in-memory model state.
    """

    reversible = True
    reduces_to_sql = True

    def state_forwards(self, app_label, state):
        # RLS operations do not change model state, only the database.
        pass


class EnableRLS(_RLSOperationBase):
    """Enable Row Level Security on a model's table.

    When ``TENANT_RLS_FORCE`` is true the table is additionally switched to
    ``FORCE ROW LEVEL SECURITY`` so the policy applies even to the table owner
    (the role Django connects as); otherwise the owner silently bypasses RLS and
    isolation is an illusion.
    """

    def __init__(self, model_name):
        self.model_name = model_name

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "enable_rls"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.enable_rls(model)
            if conf.force_rls() and hasattr(schema_editor, "force_rls"):
                schema_editor.force_rls(model)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "disable_rls"):
            model = from_state.apps.get_model(app_label, self.model_name)
            # FORCE is a persistent table attribute in Postgres; un-force it
            # before disabling so a later re-enable does not inherit stale FORCE
            # state (mirrors TenantRLSModel.disable_rls()).
            if conf.force_rls() and hasattr(schema_editor, "unforce_rls"):
                schema_editor.unforce_rls(model)
            schema_editor.disable_rls(model)

    def describe(self):
        return "Enable RLS on %s" % self.model_name

    def deconstruct(self):
        return (self.__class__.__name__, [self.model_name], {})


class DisableRLS(_RLSOperationBase):
    """Disable Row Level Security on a model's table.

    The reverse re-enables RLS (and ``FORCE`` when ``TENANT_RLS_FORCE`` is true),
    mirroring :class:`EnableRLS`.
    """

    def __init__(self, model_name):
        self.model_name = model_name

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "disable_rls"):
            model = from_state.apps.get_model(app_label, self.model_name)
            # Un-force before disabling so the persistent FORCE attribute does
            # not survive to a later re-enable (mirrors EnableRLS.database_backwards
            # and TenantRLSModel.disable_rls()).
            if conf.force_rls() and hasattr(schema_editor, "unforce_rls"):
                schema_editor.unforce_rls(model)
            schema_editor.disable_rls(model)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "enable_rls"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.enable_rls(model)
            if conf.force_rls() and hasattr(schema_editor, "force_rls"):
                schema_editor.force_rls(model)

    def describe(self):
        return "Disable RLS on %s" % self.model_name

    def deconstruct(self):
        return (self.__class__.__name__, [self.model_name], {})


class CreateTenantPolicy(_RLSOperationBase):
    """Create the default tenant-isolation policy for a model.

    Convenience wrapper that builds a :class:`~django_tenants.rls.policies.TenantPolicy`
    bound to the model's tenant field and creates it.

    All ``TenantPolicy`` parameters are explicit named arguments rather than
    ``**kwargs``. This is required for the migration writer to round-trip the
    operation: Django's ``OperationWriter`` only serialises kwargs that are
    explicit ``__init__`` parameters (a ``**VAR_KEYWORD`` catch-all is silently
    dropped from the rendered migration), so any value passed through a
    ``**kwargs`` would be lost on replay.

    The ``pk_cast`` is snapshotted at authoring time (when the operation is
    constructed) rather than resolved lazily at apply time. Capturing it makes
    the migration a deterministic, reproducible record of the policy DDL: a later
    change to the tenant model's PK type cannot silently alter the cast baked
    into an already-written migration.

    The policy ``name``, by contrast, is resolved lazily at apply time when it is
    not given explicitly: it defaults to ``"<db_table>_tenant_isolation"`` derived
    from the model's ``_meta.db_table`` (via :func:`~django_tenants.rls.models._default_policy_name`),
    exactly matching the name the models auto-enable path creates. Deriving it
    from ``db_table`` rather than ``model_name`` ensures ``disable_rls`` /
    ``drop_policy`` target the *same* policy that was created, instead of
    orphaning it under a divergent name.
    """

    def __init__(self, model_name, name=None, tenant_field=None,
                 session_variable=None, bypass_variable=None, pk_cast=None,
                 operation=None, permissive=None, roles=None):
        self.model_name = model_name
        # When None, the name is resolved at apply time from the model's db_table
        # (see _resolve_name); we keep None here so deconstruct only emits an
        # explicit name and the default stays in lockstep with the models path.
        self.name = name
        self.tenant_field = tenant_field if tenant_field is not None else conf.tenant_field()
        self.session_variable = session_variable
        self.bypass_variable = bypass_variable
        # Snapshot the cast at authoring time for a reproducible migration.
        self.pk_cast = pk_cast if pk_cast is not None else conf.get_tenant_pk_cast()
        self.operation = operation
        self.permissive = permissive
        self.roles = roles

    def _resolve_name(self, model):
        """Resolve the policy name from the model at apply time.

        When ``self.name`` is explicit, use it verbatim; otherwise default to
        ``"<db_table>_tenant_isolation"`` derived from ``model._meta.db_table``,
        matching the models auto-enable path so enable/disable target the same
        policy.
        """
        if self.name is not None:
            return self.name
        # Imported lazily to keep the migration module import-light and to avoid
        # importing the models module (which touches the app registry) at the
        # top of this migration-operations module.
        from .models import _default_policy_name

        return _default_policy_name(model._meta.db_table)

    def _policy(self, model):
        # Imported lazily to keep the migration module import-light.
        from .policies import TenantPolicy

        kwargs = {
            "name": self._resolve_name(model),
            "tenant_field": self.tenant_field,
            "session_variable": self.session_variable,
            "bypass_variable": self.bypass_variable,
            "pk_cast": self.pk_cast,
        }
        # Only forward the optional BasePolicy kwargs when explicitly set so the
        # policy's own defaults apply otherwise.
        if self.operation is not None:
            kwargs["operation"] = self.operation
        if self.permissive is not None:
            kwargs["permissive"] = self.permissive
        if self.roles is not None:
            kwargs["roles"] = self.roles
        return TenantPolicy(**kwargs)

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "create_policy"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.create_policy(model, self._policy(model))

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "drop_policy"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.drop_policy(model, self._resolve_name(model))

    def describe(self):
        return "Create tenant RLS policy on %s" % self.model_name

    def deconstruct(self):
        # Emit only non-None / non-default values so makemigrations stays stable,
        # but always include the snapshotted pk_cast so the migration is a
        # deterministic record of the policy DDL. Every key here is an explicit
        # __init__ parameter, so OperationWriter round-trips all of them.
        #
        # name is emitted ONLY when it was set explicitly; when left to default
        # it stays None so it is resolved from the model's db_table at apply time
        # (keeping the default in lockstep with the models auto-enable path).
        kwargs = {
            "tenant_field": self.tenant_field,
            "pk_cast": self.pk_cast,
        }
        if self.name is not None:
            kwargs["name"] = self.name
        if self.session_variable is not None:
            kwargs["session_variable"] = self.session_variable
        if self.bypass_variable is not None:
            kwargs["bypass_variable"] = self.bypass_variable
        if self.operation is not None:
            kwargs["operation"] = self.operation
        if self.permissive is not None:
            kwargs["permissive"] = self.permissive
        if self.roles is not None:
            kwargs["roles"] = self.roles
        return (self.__class__.__name__, [self.model_name], kwargs)


class CreatePolicy(_RLSOperationBase):
    """Create an arbitrary :class:`~django_tenants.rls.policies.BasePolicy` instance."""

    def __init__(self, model_name, policy):
        self.model_name = model_name
        self.policy = policy

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "create_policy"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.create_policy(model, self.policy)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "drop_policy"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.drop_policy(model, self.policy.name)

    def describe(self):
        return "Create RLS policy %s on %s" % (self.policy.name, self.model_name)

    def deconstruct(self):
        return (self.__class__.__name__, [self.model_name, self.policy], {})


class DropPolicy(_RLSOperationBase):
    """Drop a named policy from a model's table.

    Irreversible: the original policy definition is not retained, so it cannot be
    recreated by the reverse migration.
    """

    reversible = False

    def __init__(self, model_name, policy_name):
        self.model_name = model_name
        self.policy_name = policy_name

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if hasattr(schema_editor, "drop_policy"):
            model = from_state.apps.get_model(app_label, self.model_name)
            schema_editor.drop_policy(model, self.policy_name)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        raise NotImplementedError("DropPolicy is irreversible: the original policy "
                                  "definition is not retained.")

    def describe(self):
        return "Drop RLS policy %s on %s" % (self.policy_name, self.model_name)

    def deconstruct(self):
        return (self.__class__.__name__, [self.model_name, self.policy_name], {})
