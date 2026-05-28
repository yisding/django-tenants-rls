"""
Row-level-security (RLS) policy definitions for django-tenants shared-schema mode.

A *policy* is a small, declarative description of a Postgres ``CREATE POLICY``
statement. Policies do not touch the database themselves; they only render the
SQL expression that goes into the ``USING`` / ``WITH CHECK`` clauses. The schema
editor (see ``django_tenants.rls.schema``) consumes these objects and emits the
DDL with every identifier quoted.

Three public policy types are provided:

* ``BasePolicy``   -- abstract base, validation + serialization helpers.
* ``TenantPolicy`` -- the secure-by-default tenant-isolation policy. Rows are
  invisible unless the tenant session variable matches the row's tenant FK, or
  the bypass session variable is set to ``on``.
* ``CustomPolicy`` -- escape hatch for a raw SQL expression supplied by the
  caller (NOT validated beyond non-emptiness -- see the class docstring).

Security note: identifiers (policy names, tenant field names, role names) are
validated against strict regexes because they are embedded directly into DDL and
cannot be passed as bound parameters. Session-variable *values* are always passed
as bound parameters elsewhere; session-variable *names* appear inside the policy
expression and so are validated here too. This regex validation is the primary
SQL-injection defense for these strings and is non-negotiable.
"""

import re
from abc import ABC, abstractmethod

from . import conf


class PolicyError(Exception):
    """Raised when a policy is constructed or validated with invalid input."""


# Identifiers (policy names, field names) must be plain SQL identifiers.
FIELD_NAME_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

# Database role names are validated the same way; the literal PUBLIC keyword is
# handled separately and allowed verbatim.
ROLE_NAME_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

# The allowed Postgres cast suffixes for the tenant PK comparison.
ALLOWED_PK_CASTS = frozenset({"integer", "bigint", "uuid", "text"})


def _q(name):
    """Return ``name`` as a single-quoted SQL string literal for DDL embedding."""
    return conf._quote_literal(name)


class BasePolicy(ABC):
    """
    Abstract base class for RLS policies.

    Subclasses must implement :meth:`get_sql_expression`. The base class handles
    validation of the policy name, operation and roles, and provides the
    ``USING`` / ``WITH CHECK`` expression resolution plus migration serialization.
    """

    ALL = "ALL"
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"

    OPERATIONS = (ALL, SELECT, INSERT, UPDATE, DELETE)

    # Operations for which a WITH CHECK clause is meaningful (write paths).
    _CHECK_OPERATIONS = (ALL, INSERT, UPDATE)

    def __init__(self, name, operation=ALL, permissive=True, roles="public", **kwargs):
        self.name = name
        self.operation = operation
        self.permissive = permissive
        self.roles = roles
        self.extra_kwargs = kwargs
        self.validate()

    def validate(self):
        """Validate name, operation and roles. Raises :class:`PolicyError`."""
        if not isinstance(self.name, str) or not FIELD_NAME_PATTERN.match(self.name):
            raise PolicyError(
                "Invalid policy name %r: must match %s"
                % (self.name, FIELD_NAME_PATTERN.pattern)
            )

        # A Postgres identifier is limited to 63 bytes; longer names are
        # silently truncated by the server, which would make policy
        # creation/drop target a different name than intended.
        if len(self.name.encode("utf-8")) > 63:
            raise PolicyError(
                "Invalid policy name %r: exceeds the Postgres identifier limit "
                "of 63 bytes (got %d bytes)"
                % (self.name, len(self.name.encode("utf-8")))
            )

        if self.operation not in self.OPERATIONS:
            raise PolicyError(
                "Invalid operation %r: must be one of %s"
                % (self.operation, ", ".join(self.OPERATIONS))
            )

        # An empty roles container would render an invalid ``TO`` clause (Postgres
        # rejects ``... TO  USING (...)``). The valid default is the string
        # ``"public"``; an empty list/tuple is a misconfiguration.
        if not isinstance(self.roles, str) and len(self.roles) == 0:
            raise PolicyError(
                "roles must be non-empty or the string \"public\"."
            )

        for role in self._iter_roles():
            if role in ("public", "PUBLIC"):
                continue
            if not isinstance(role, str) or not ROLE_NAME_PATTERN.match(role):
                raise PolicyError(
                    "Invalid role name %r: must match %s or be 'public'"
                    % (role, ROLE_NAME_PATTERN.pattern)
                )

    def _iter_roles(self):
        """Yield each configured role as a string (accepts a str or a list)."""
        roles = self.roles
        if isinstance(roles, str):
            yield roles
        else:
            for role in roles:
                yield role

    def validate_field_name(self, field_name):
        """Validate a field/identifier name. Raises :class:`PolicyError`."""
        if not isinstance(field_name, str) or not FIELD_NAME_PATTERN.match(field_name):
            raise PolicyError(
                "Invalid field name %r: must match %s"
                % (field_name, FIELD_NAME_PATTERN.pattern)
            )

    def validate_session_variable(self, name):
        """Validate a GUC session-variable name. Raises :class:`PolicyError`."""
        if not isinstance(name, str) or not conf.SESSION_VAR_NAME_PATTERN.match(name):
            raise PolicyError(
                "Invalid session variable name %r: must match %s"
                % (name, conf.SESSION_VAR_NAME_PATTERN.pattern)
            )

    @abstractmethod
    def get_sql_expression(self):
        """Return the core SQL boolean expression for this policy."""
        raise NotImplementedError

    def get_using_expression(self):
        """Return the ``USING`` clause expression, or None for no clause."""
        return self.get_sql_expression()

    def get_check_expression(self):
        """
        Return the ``WITH CHECK`` clause expression, or None for no clause.

        Defaults to the core expression for write operations (ALL/INSERT/UPDATE)
        and None for read-only operations (SELECT/DELETE), since a WITH CHECK
        clause is only meaningful on writes.
        """
        if self.operation in self._CHECK_OPERATIONS:
            return self.get_sql_expression()
        return None

    def deconstruct(self):
        """
        Return ``(path, args, kwargs)`` for Django migration serialization.

        Subclasses must override to provide their own import path and the kwargs
        needed to faithfully reconstruct the policy inside a migration file.
        """
        raise NotImplementedError(
            "%s must implement deconstruct() for migration serialization"
            % self.__class__.__name__
        )

    def __eq__(self, other):
        if not isinstance(other, BasePolicy):
            return NotImplemented
        return self.deconstruct() == other.deconstruct()

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)


class TenantPolicy(BasePolicy):
    """
    The core secure-by-default tenant-isolation policy.

    The rendered SQL compares the row's tenant FK column against the tenant
    session variable, OR allows everything when the bypass session variable is
    ``on``. Each ``current_setting()`` call is wrapped in a scalar sub-SELECT so
    Postgres evaluates it once per statement as an InitPlan, not once per row
    (a major win on large shared tables)::

        (tenant_id = (SELECT NULLIF(current_setting('django_tenants.tenant_id', true), '')::integer)
         OR (SELECT current_setting('django_tenants.bypass_rls', true)) = 'on')

    With no tenant set (the session variable is empty/unset), ``NULLIF('', '')``
    yields ``NULL`` and the comparison is ``NULL`` (not true), so no rows are
    visible -- secure by default. The same expression is used for both ``USING``
    and ``WITH CHECK`` so writes get the same isolation (defense in depth).

    All defaults are read from ``django_tenants.rls.conf`` so the policy reflects
    the configured tenant field, session-variable names and PK cast.

    .. warning::

       A single policy must be **PERMISSIVE** (the default ``permissive=True``) to
       grant any visibility. Postgres AND-combines RESTRICTIVE policies with the
       permissive ones, so a table whose *only* policy is RESTRICTIVE
       (``permissive=False``) returns **zero rows for everyone** -- including the
       correct tenant, and even under ``bypass_rls()`` -- because there is no
       permissive policy to grant access. RESTRICTIVE is only meaningful when
       combined with a separate permissive policy (e.g. to add an extra
       AND-constraint on top of the default tenant isolation). Do not set
       ``permissive=False`` on a model's sole policy.
    """

    def __init__(self, name, tenant_field=None, session_variable=None,
                 bypass_variable=None, pk_cast=None, **kwargs):
        if tenant_field is None:
            tenant_field = conf.tenant_field()
        if session_variable is None:
            session_variable = conf.session_variable()
        if bypass_variable is None:
            bypass_variable = conf.bypass_variable()
        if pk_cast is None:
            pk_cast = conf.get_tenant_pk_cast()

        self.tenant_field = tenant_field
        self.session_variable = session_variable
        self.bypass_variable = bypass_variable
        self.pk_cast = pk_cast

        super().__init__(name, **kwargs)

    def validate(self):
        super().validate()
        self.validate_field_name(self.tenant_field)
        self.validate_session_variable(self.session_variable)
        self.validate_session_variable(self.bypass_variable)
        if self.pk_cast not in ALLOWED_PK_CASTS:
            raise PolicyError(
                "Invalid pk_cast %r: must be one of %s"
                % (self.pk_cast, ", ".join(sorted(ALLOWED_PK_CASTS)))
            )

    def get_sql_expression(self):
        # Each current_setting() is wrapped in a scalar sub-SELECT so Postgres
        # evaluates it once per statement (an InitPlan) rather than once per row.
        # On large shared tables this is a major performance win; the semantics
        # are identical to the bare calls.
        return (
            "(%s_id = (SELECT NULLIF(current_setting(%s, true), '')::%s)"
            " OR (SELECT current_setting(%s, true)) = 'on')"
            % (
                self.tenant_field,
                _q(self.session_variable),
                self.pk_cast,
                _q(self.bypass_variable),
            )
        )

    def deconstruct(self):
        kwargs = {
            "name": self.name,
            "tenant_field": self.tenant_field,
            "session_variable": self.session_variable,
            "bypass_variable": self.bypass_variable,
            "pk_cast": self.pk_cast,
        }
        if self.operation != self.ALL:
            kwargs["operation"] = self.operation
        if self.permissive is not True:
            kwargs["permissive"] = self.permissive
        if self.roles != "public":
            kwargs["roles"] = self.roles
        return ("django_tenants.rls.policies.TenantPolicy", [], kwargs)


class CustomPolicy(BasePolicy):
    """
    A policy with a caller-supplied raw SQL expression.

    WARNING: ``expression`` (and ``check_expression``) are raw SQL and are NOT
    validated beyond being non-empty. The caller is FULLY responsible for the
    safety of these strings. Never build them from untrusted input -- doing so is
    a SQL-injection vector. Prefer :class:`TenantPolicy` whenever possible.
    """

    def __init__(self, name, expression, check_expression=None, **kwargs):
        self.expression = expression
        self.check_expression = check_expression
        super().__init__(name, **kwargs)

    def validate(self):
        super().validate()
        if not isinstance(self.expression, str) or not self.expression.strip():
            raise PolicyError(
                "CustomPolicy %r requires a non-empty expression" % self.name
            )
        if self.check_expression is not None and (
            not isinstance(self.check_expression, str)
            or not self.check_expression.strip()
        ):
            raise PolicyError(
                "CustomPolicy %r check_expression must be a non-empty string or None"
                % self.name
            )

    def get_sql_expression(self):
        return self.expression

    def get_check_expression(self):
        if self.operation not in self._CHECK_OPERATIONS:
            return None
        return self.check_expression or self.expression

    def deconstruct(self):
        kwargs = {
            "name": self.name,
            "expression": self.expression,
        }
        if self.check_expression is not None:
            kwargs["check_expression"] = self.check_expression
        if self.operation != self.ALL:
            kwargs["operation"] = self.operation
        if self.permissive is not True:
            kwargs["permissive"] = self.permissive
        if self.roles != "public":
            kwargs["roles"] = self.roles
        return ("django_tenants.rls.policies.CustomPolicy", [], kwargs)
