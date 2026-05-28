"""Schema-editor mixin that emits Row Level Security DDL.

``RLSSchemaEditorMixin`` is mixed into the parent backend's schema editor
(see ``django_tenants.rls.backend.base``). It knows how to enable/disable/force
RLS on a table and how to create/drop/alter row-security policies.

All identifiers (table, policy and role names) are validated against the strict
regexes defined in :mod:`django_tenants.rls.policies` AND quoted via
``self.quote_name(...)`` before they are embedded into DDL, so they can never be
an injection vector. Session-variable *values* are never embedded here -- they
travel as bound parameters in the policy expressions produced by the policy
objects (see :mod:`django_tenants.rls.policies`).

The SQL templates were ported and cleaned from django-rls
(``backends/postgresql/base.py``); the ``ModelPolicy.get_compiled_sql`` /
``%%%%``-escaping hack was intentionally dropped and the USING / WITH CHECK
clauses are built by joining non-empty parts so no dangling keyword is ever
emitted.
"""

from .policies import FIELD_NAME_PATTERN, ROLE_NAME_PATTERN, PolicyError


class RLSSchemaEditorMixin:
    """Adds RLS DDL helpers to a Django PostgreSQL schema editor.

    Every method is a thin wrapper that formats a validated, identifier-quoted
    SQL string and runs it through ``self.execute(...)`` (provided by the schema
    editor this mixin is combined with).
    """

    sql_enable_rls = "ALTER TABLE %(table)s ENABLE ROW LEVEL SECURITY"
    sql_disable_rls = "ALTER TABLE %(table)s DISABLE ROW LEVEL SECURITY"
    sql_force_rls = "ALTER TABLE %(table)s FORCE ROW LEVEL SECURITY"
    sql_no_force_rls = "ALTER TABLE %(table)s NO FORCE ROW LEVEL SECURITY"

    # The USING / WITH CHECK clauses are pre-rendered (or empty) and slotted in
    # so an empty clause never leaves a dangling keyword behind.
    sql_create_policy = (
        "CREATE POLICY %(name)s ON %(table)s "
        "AS %(permissive)s FOR %(operation)s TO %(roles)s %(using_clause)s %(check_clause)s"
    )
    sql_drop_policy = "DROP POLICY IF EXISTS %(name)s ON %(table)s"
    sql_alter_policy = "ALTER POLICY %(name)s ON %(table)s %(using_clause)s %(check_clause)s"

    def enable_rls(self, model):
        """Enable row level security on the table backing ``model``."""
        sql = self.sql_enable_rls % {"table": self.quote_name(model._meta.db_table)}
        self.execute(sql)

    def disable_rls(self, model):
        """Disable row level security on the table backing ``model``."""
        sql = self.sql_disable_rls % {"table": self.quote_name(model._meta.db_table)}
        self.execute(sql)

    def force_rls(self, model):
        """Force RLS so the policy applies even to the table owner role.

        Without ``FORCE``, a superuser/owner connection silently bypasses the
        policy and isolation becomes an illusion.
        """
        sql = self.sql_force_rls % {"table": self.quote_name(model._meta.db_table)}
        self.execute(sql)

    def unforce_rls(self, model):
        """Undo :meth:`force_rls` (used by the disable path)."""
        sql = self.sql_no_force_rls % {"table": self.quote_name(model._meta.db_table)}
        self.execute(sql)

    def create_policy(self, model, policy):
        """Create the row-security ``policy`` on the table backing ``model``."""
        table = self.quote_name(model._meta.db_table)
        name = self.quote_name(policy.name)
        permissive = "PERMISSIVE" if getattr(policy, "permissive", True) else "RESTRICTIVE"
        operation = policy.operation
        roles = self._render_roles(policy.roles)

        using = policy.get_using_expression()
        check = policy.get_check_expression()
        using_clause = "USING ({})".format(using) if using else ""
        check_clause = "WITH CHECK ({})".format(check) if check else ""

        if not using_clause and not check_clause:
            raise PolicyError(
                "Policy {!r} has neither a USING nor a WITH CHECK expression; "
                "CREATE POLICY would be invalid SQL.".format(policy.name)
            )

        sql = self.sql_create_policy % {
            "name": name,
            "table": table,
            "permissive": permissive,
            "operation": operation,
            "roles": roles,
            "using_clause": using_clause,
            "check_clause": check_clause,
        }
        self.execute(sql)

    def drop_policy(self, model, policy_name):
        """Drop the policy named ``policy_name`` from ``model``'s table.

        ``policy_name`` is validated against ``FIELD_NAME_PATTERN`` and then
        quoted, so it is safe to embed into the DDL.
        """
        if not FIELD_NAME_PATTERN.match(policy_name):
            raise PolicyError("Invalid policy name: {!r}".format(policy_name))
        table = self.quote_name(model._meta.db_table)
        name = self.quote_name(policy_name)
        sql = self.sql_drop_policy % {"name": name, "table": table}
        self.execute(sql)

    def alter_policy(self, model, policy):
        """Alter the USING / WITH CHECK expressions of an existing ``policy``."""
        table = self.quote_name(model._meta.db_table)
        name = self.quote_name(policy.name)

        using = policy.get_using_expression()
        check = policy.get_check_expression()
        using_clause = "USING ({})".format(using) if using else ""
        check_clause = "WITH CHECK ({})".format(check) if check else ""

        if not using_clause and not check_clause:
            raise PolicyError(
                "Policy {!r} has neither a USING nor a WITH CHECK expression; "
                "ALTER POLICY would be invalid SQL.".format(policy.name)
            )

        sql = self.sql_alter_policy % {
            "name": name,
            "table": table,
            "using_clause": using_clause,
            "check_clause": check_clause,
        }
        self.execute(sql)

    def _render_roles(self, roles):
        """Render the policy ``roles`` into a safe ``TO`` clause target.

        ``public``/``PUBLIC`` is the special keyword (every role) and is emitted
        verbatim. Any other role name is validated against ``ROLE_NAME_PATTERN``
        and quoted; a list of roles is validated + quoted member-by-member and
        comma-joined. This blocks role-name injection.
        """
        if isinstance(roles, str):
            if roles in ("public", "PUBLIC"):
                return "public"
            return self._quote_role(roles)
        return ", ".join(self._quote_role(role) for role in roles)

    def _quote_role(self, role):
        """Validate a single role name and return it quoted (or ``public``)."""
        if role in ("public", "PUBLIC"):
            return "public"
        if not ROLE_NAME_PATTERN.match(role):
            raise PolicyError("Invalid role name: {!r}".format(role))
        return self.quote_name(role)
