.. _rls-migration:

=========================================================================
Migrating an Existing django-tenants Deployment to Shared-Schema RLS Mode
=========================================================================

This guide is the migration journey for an engineering team already running a
populated, schema-per-tenant django-tenants deployment in production that wants
to move some or all apps to the opt-in shared-schema Row-Level-Security (RLS)
mode. It is task- and safety-oriented (wrong steps cause data loss or
cross-tenant leakage), walking from assessment through backfill, cutover,
validation, decommission, and rollback. It cross-references the RLS reference
doc :doc:`rls` for API and DDL detail via ``:ref:`` rather than duplicating it,
so this document stays focused on the sequence and the pitfalls of converting
live data.

.. contents::
   :local:
   :depth: 2


Overview: why (and when not) to migrate
========================================

This guide walks an **existing, populated** schema-per-tenant django-tenants
deployment through migrating some or all of its apps to the opt-in shared-schema
**Row-Level Security (RLS)** mode. Before planning any of the mechanical steps in
the sections that follow, decide whether you should migrate at all. This section
frames that decision; for the underlying API and reference detail it links to the
companion document :doc:`rls` rather than restating it.

What shared-schema RLS mode is
------------------------------

In the classic model, django-tenants gives every tenant its **own PostgreSQL
schema** and routes each request by switching the connection's ``search_path``.
Shared-schema RLS mode replaces that with a fundamentally different isolation
model: **all tenants share the single** ``public`` **schema**, every isolated
table carries a ``tenant`` **foreign key** to ``settings.TENANT_MODEL``, and
isolation is enforced by a **PostgreSQL Row-Level Security policy** keyed on that
column. The active tenant is communicated to the database not through
``search_path`` but through a **per-connection session variable** (a Postgres
GUC, ``django_tenants.tenant_id`` by default) that the policy reads on every
query. This is the "Shared Approach (option 3)" from the
:doc:`introduction <index>`. The full mechanics are documented under
:ref:`rls-mechanism`; this guide does not duplicate them.

Why migrate
-----------

Migrating to RLS mode is worth considering when the per-schema model has become a
liability rather than a benefit. The reference doc's *When to use RLS mode*
section (see :doc:`rls`) calls out the same three drivers:

* **Very large tenant counts.** With thousands of schemas, per-tenant
  ``migrate``, ``backup``, and DDL operations become slow and operationally
  heavy. A single shared schema means one migration run and one logical backup
  covers every tenant.
* **Cross-tenant analytics.** Aggregate or reporting queries that span many
  tenants are awkward and expensive across many schemas; in shared-schema mode
  they are ordinary queries over one set of tables (run under
  ``bypass_rls()`` when you deliberately need to
  see all tenants).
* **Database-enforced isolation.** The policy is applied by PostgreSQL itself,
  not by application ``WHERE`` clauses, and it does so without per-schema
  overhead. With no active tenant the policy is **secure-by-default**: zero rows
  are returned (see :ref:`rls-mechanism`).

Trade-offs
----------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Aspect
     - What changes with RLS mode
   * - Per-cursor cost
     - The RLS backend issues exactly **one extra** ``set_config`` **round-trip
       per database cursor** to (re)assert the tenant and bypass session
       variables. This is security-load-bearing, not incidental: it is what
       re-establishes isolation across pooled or reused connections and across
       transaction rollback. See the *Performance note* in :doc:`rls`. (When
       ``TENANT_RLS_ENABLED`` is ``False`` the backend emits nothing extra.)
   * - Database role
     - RLS requires a **least-privilege** ``NOSUPERUSER NOBYPASSRLS`` role.
       PostgreSQL silently bypasses *every* RLS policy for a superuser or a
       ``BYPASSRLS`` role -- even with ``FORCE ROW LEVEL SECURITY`` -- so a
       bypassing role means *no isolation at all*. The :ref:`W003 check
       <rls-system-checks>` enforces this at startup. See
       :ref:`rls-database-role`.
   * - Physical separation
     - Schema-per-tenant keeps **strong physical separation**: each tenant's
       tables, indexes, and data are in a distinct schema you can dump, restore,
       or drop in isolation. RLS gives logical isolation within one shared set of
       tables; you trade physical separation for operational simplicity at scale.

When **not** to migrate
-----------------------

Do not migrate an app to RLS mode if any of the following is true:

* **You rely on physical schema separation** -- for compliance, per-tenant
  encryption-at-rest boundaries, or simply the assurance that one tenant's data
  is in a physically distinct schema.
* **You depend on per-tenant restore or drop.** Restoring a single tenant from
  backup, or hard-dropping one tenant's schema, is trivial with
  schema-per-tenant and has no clean equivalent in a shared table.
* **Your database connection is a superuser-only role you cannot change.**
  PostgreSQL bypasses RLS for superuser/``BYPASSRLS`` roles, so RLS cannot
  isolate anything over such a connection. The :ref:`W003 check
  <rls-system-checks>` will block startup unless you set
  ``TENANT_RLS_ALLOW_BYPASS_ROLE = True``, which only silences the warning -- it
  does not make isolation work. If you cannot provision a ``NOSUPERUSER
  NOBYPASSRLS`` role, do not migrate.

The hybrid option is first-class
--------------------------------

Migration is **not** all-or-nothing. RLS mode and schema-per-tenant coexist in
the same project on a **per-app** basis. Apps that stay in ``TENANT_APPS`` remain
schema-per-tenant; apps you move to ``SHARED_APPS`` become RLS-isolated. You can
migrate the apps that benefit most (high tenant-count, analytics-heavy) while
leaving apps that need physical separation exactly where they are. Choosing the
right list per app is the single most important placement decision -- see
:ref:`shared-apps-vs-tenant-apps`.

.. important::

   RLS mode is **opt-in and off by default**: ``TENANT_RLS_ENABLED`` defaults to
   ``False``. Installing the ``django_tenants.rls`` package alone changes
   nothing. With the flag unset (or ``False``) the RLS backend is
   behaviourally identical to the standard
   ``django_tenants.postgresql_backend`` backend -- no session variable is set,
   no policy SQL is emitted, and the tenant model is never imported at connection
   time. This means you can install the package and adopt the new ENGINE on a
   running deployment **without changing any behavior**, then perform the
   migration deliberately, one app at a time, in the controlled steps described
   in the sections that follow.

.. warning::

   The most dangerous part of this migration is enabling RLS on a table that
   still has rows with a ``NULL`` ``tenant_id``: a ``NULL`` never matches the
   policy, so those rows become invisible to **every** tenant. The non-negotiable
   safe ordering -- add the FK as ``null=True``, **backfill every row**,
   ``AlterField`` to ``null=False``, and only **then** enable RLS -- is covered in
   :ref:`rls-upgrade-existing` and detailed throughout this guide. Set
   ``TENANT_RLS_AUTO_ENABLE = False`` for the duration of the upgrade so RLS is
   never switched on before the backfill completes.


Mental model: what changes and what stays the same
===================================================

Before touching settings or writing a migration, get the two isolation models
clear in your head. Almost every later step is an application of the contrast
below, and most migration mistakes come from carrying a schema-per-tenant
assumption into RLS mode (or vice versa).

The two isolation mechanisms side by side
-----------------------------------------

**Schema-per-tenant (what you run today).** Each tenant owns its own PostgreSQL
schema. Every request, ``TenantMainMiddleware`` resolves the tenant from the
host and the backend switches the connection's ``search_path`` to that tenant's
schema. Your tables are physically *duplicated* once per schema, and isolation
is a property of the namespace: a query simply cannot see another schema's
``myapp_invoice`` because that table is not on the ``search_path``. There is no
``tenant_id`` column; the schema name *is* the tenant.

**Shared-schema RLS (where you are going).** There is exactly one schema --
``public`` -- and one physical copy of each table. Every isolated row carries a
``tenant_id`` foreign key to your ``TENANT_MODEL``. Isolation is enforced by a
**PERMISSIVE** PostgreSQL Row-Level-Security policy whose ``USING`` (reads) and
``WITH CHECK`` (writes) expression compares the row's ``tenant_id`` to a session
variable (a GUC), *or* admits everything when an explicit bypass GUC is ``on``.
The policy is built automatically for every ``TenantRLSModel`` by
``TenantPolicy.get_sql_expression()`` and reads, in full::

    (tenant_id = (SELECT NULLIF(current_setting('django_tenants.tenant_id', true), '')::integer)
     OR (SELECT current_setting('django_tenants.bypass_rls', true)) = 'on')

This is the exact expression ``TenantPolicy`` renders, not a simplification:
each ``current_setting()`` is wrapped in a scalar sub-SELECT so PostgreSQL
evaluates it once per statement (an InitPlan) instead of once per row. The cast
(here ``::integer``) is chosen from your tenant primary-key type. The
step-by-step request flow, the exact GUC names, and the secure-by-default
reasoning are documented once in :ref:`rls-mechanism`; this guide does not
reproduce them.

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Concern
     - Schema-per-tenant
     - Shared-schema RLS
   * - Schemas
     - One per tenant
     - One (``public``) for everyone
   * - Tables
     - Duplicated per schema
     - One physical copy
   * - Tenant marker on a row
     - Implicit (the schema)
     - Explicit ``tenant_id`` FK column
   * - How a request scopes data
     - ``search_path`` switched to ``<schema>``
     - Tenant pk written to a session GUC on every cursor
   * - Who enforces isolation
     - Namespace (table not visible)
     - PostgreSQL evaluates the RLS policy
   * - "Show me everything" escape hatch
     - Activate the ``public`` schema
     - ``bypass_rls()`` (sets the bypass GUC ``on``)

How the active tenant reaches PostgreSQL
----------------------------------------

In schema-per-tenant mode the backend pushes the active tenant into the
``search_path``. In RLS mode it pushes the active tenant into a session GUC
instead -- and it does so on **every cursor**, not once per request.

The RLS backend keeps the source of truth in Python state on the connection:
``_rls_tenant_id`` (the active tenant's primary key, coerced to text) and
``_rls_bypass`` (a boolean, default ``False``). On each ``_cursor()`` call the
backend re-issues a single SQL statement that re-asserts **both** GUCs in one
round-trip -- a ``SELECT set_config(...), set_config(...)`` that sets the tenant
variable *and* the bypass variable -- with both values derived from that Python
state (``django_tenants/rls/backend/base.py``, ``_rls_session_params()`` /
``_cursor()``). This re-assertion is what makes isolation correct under two
conditions that would otherwise be dangerous:

* **Pooled / persistent / reused connections.** A connection handed back to your
  worker never inherits a stale GUC from a prior request -- the very next cursor
  re-asserts the current Python state. (This matters for ``CONN_MAX_AGE`` and
  external poolers; see the connection-pooler notes later in this guide.)
* **After a transaction rollback.** A rolled-back transaction discards the
  ``set_config`` it ran, but the *next* cursor sets it again from the Python
  flags, so the session never silently loses its tenant scoping.

Deriving the bypass value from the flag (rather than hard-coding ``off``) is
deliberate: a query inside a ``bypass_rls()`` block opens its own cursor, so if
the cursor forced bypass ``off`` it would defeat the block. The flag keeps it
``on`` for the duration of the block and snaps it back to ``off`` the instant the
block exits.

Secure by default
-----------------

With **no active tenant**, ``_rls_tenant_id`` is the empty string ``''``, so the
GUC is empty, ``NULLIF('', '')`` is ``NULL``, the comparison is ``NULL`` (not
true), and the policy returns **zero rows** -- ``'' => NULLIF('','') => NULL =>
no rows``. Forgetting to set a tenant fails *closed* (you see nothing), never
*open* (cross-tenant leak). The only two ways to see rows are to set a real
tenant pk in the GUC, or to open a ``bypass_rls()`` block. This secure-by-default
property is the single biggest safety difference from schema-per-tenant, where a
missing/incorrect ``search_path`` typically lands you on ``public`` rather than
on nothing.

.. note::

   Secure-by-default is only real if the connecting database role cannot bypass
   RLS. PostgreSQL **ignores all policies** for a ``SUPERUSER`` or ``BYPASSRLS``
   role, even with ``FORCE ROW LEVEL SECURITY``. The app must connect as a
   ``NOSUPERUSER NOBYPASSRLS`` role; system check ``W003`` blocks startup
   otherwise. See :ref:`rls-database-role`.

What stays identical
--------------------

RLS mode is an *additive* backend, not a rewrite. The following carry over
unchanged from your current deployment (see the :ref:`rls-mechanism` intro,
"RLS mode reuses the rest of django-tenants unchanged"):

* **Your tenant and domain models.** ``TenantMixin`` and ``DomainMixin``, and the
  ``TENANT_MODEL`` / ``TENANT_DOMAIN_MODEL`` settings pointing at them, are
  untouched.
* **Host resolution.** ``TenantMainMiddleware`` resolves ``request.tenant`` from
  the host exactly as before. RLS only changes what happens *after* resolution
  (a GUC is written instead of a ``search_path`` switch).
* **Migration routing.** ``TenantSyncRouter`` still decides where models migrate.
  Because RLS pins ``connection.schema_name`` to ``public`` (below), the router
  routes RLS apps to the shared/``public`` migrate.
* **The underlying driver.** The RLS backend subclasses the standard
  django-tenants backend, so ``ORIGINAL_BACKEND`` and the rest of the
  ``DATABASES`` plumbing behave as today. With ``TENANT_RLS_ENABLED`` unset/
  ``False`` the RLS backend is byte-for-byte identical to the standard backend.

.. _migration-key-invariant:

The key invariant: ``schema_name`` stays ``public``
----------------------------------------------------

In schema-per-tenant mode, activating tenant ``acme`` sets
``connection.schema_name == "acme"``. **In RLS mode this is no longer true.**
``set_tenant()`` (``django_tenants/rls/backend/base.py``) remembers the tenant's
pk in ``_rls_tenant_id``, resets ``_rls_bypass`` to ``False`` (every tenant
activation starts from the secure, non-bypass state), and then *pins the schema
back to* ``public``::

    public = get_public_schema_name()
    self.schema_name = public
    self.set_settings_schema(public)
    self.search_path_set_schemas = None

So the invariant to internalise is:

.. important::

   In RLS mode, ``connection.schema_name`` is **always** ``public`` for every
   tenant operation. The active tenant lives in the session GUC, **not** in the
   schema name. Any code or assertion you have that reads
   ``connection.schema_name`` (or ``tenant.schema_name``) to discover "which
   tenant am I in?" must be revisited -- it will now report ``public`` regardless
   of the active tenant.

This invariant is *why* ``TenantSyncRouter`` keeps working: it keys off
``connection.schema_name``, which RLS keeps at ``public``, so your RLS apps
migrate into the shared schema. Audit any custom routers, signal handlers, or
logging that branch on ``schema_name`` before you flip ``TENANT_RLS_ENABLED``
on.


Prerequisites and the least-privilege database role
====================================================

Before you move a single row, three things must be true: you are on a
PostgreSQL that supports row-level security, your application is wired to the
RLS backend, and -- the one mistake that silently destroys isolation -- your
application connects as a role that **cannot** bypass RLS. Get the role wrong
and every other step in this guide is theatre: the policies exist, the tables
report as protected, every query succeeds, and there is *zero* tenant
isolation.

PostgreSQL and the RLS backend
------------------------------

RLS mode requires PostgreSQL (row-level security has shipped since 9.5; any
currently supported version is fine). The classic schema-per-tenant backend you
are migrating *from* is already PostgreSQL-only, so this is not a new
constraint.

Point the database ``ENGINE`` at the RLS backend. It subclasses the stock
django-tenants backend, so when ``TENANT_RLS_ENABLED`` is ``False`` it behaves
identically to what you run today -- you can switch the ``ENGINE`` ahead of
time with no behavioural change:

.. code-block:: python

    DATABASES = {
        'default': {
            'ENGINE': 'django_tenants.rls.backend',
            # ORIGINAL_BACKEND defaults to 'django.db.backends.postgresql'.
            # Override ONLY if you run a custom psycopg backend; the RLS
            # backend handles both psycopg2 and psycopg3 transparently.
            # 'ORIGINAL_BACKEND': 'django.db.backends.postgresql',
            'NAME': 'myproject',
            'USER': 'app_rls',         # see "The mandatory non-bypassing role"
            'PASSWORD': 'change-me',   # supply via env/secret in production
            'HOST': 'localhost',
            'PORT': '5432',
        }
    }

You do not pick psycopg2 vs psycopg3 here -- ``ORIGINAL_BACKEND`` stays
``django.db.backends.postgresql`` and the backend supports either driver.

The mandatory non-bypassing role
--------------------------------

.. danger::

   **The application MUST connect as a** ``NOSUPERUSER NOBYPASSRLS`` **role.**

   PostgreSQL bypasses *all* row-security policies for a superuser or for any
   role carrying the ``BYPASSRLS`` attribute -- **even when the table has**
   ``FORCE ROW LEVEL SECURITY``. The tables still report as protected and every
   query succeeds, so the misconfiguration is invisible: it **fails open and
   silently**. The stock ``postgres`` superuser (and the ``POSTGRES_USER`` of
   most Docker images) bypasses RLS, which is exactly how an otherwise-correct
   setup leaks across tenants. This is non-negotiable.

Create a dedicated least-privilege role for the application and keep your
superuser strictly for migrations and admin tasks. The full recipe and the
rationale live in :ref:`rls-database-role`; the essentials are:

.. code-block:: sql

    CREATE ROLE app_rls LOGIN PASSWORD '…' NOSUPERUSER NOBYPASSRLS;
    GRANT USAGE ON SCHEMA public TO app_rls;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_rls;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_rls;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_rls;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT USAGE, SELECT ON SEQUENCES TO app_rls;

Then point ``DATABASES['default']['USER']`` for **tenant traffic** at that role
(``app_rls`` above) -- **not** at ``postgres`` or any other superuser.

Migrations and other ``manage.py`` work need a more privileged role than
``app_rls`` (creating tables and running ``ENABLE`` / ``FORCE ROW LEVEL
SECURITY`` requires *owning* the table). Use a role that **owns** the tenant
tables and can run DDL but is **not** a superuser and does **not** carry
``BYPASSRLS`` -- such a role can migrate *and* passes the W003 check below. Do
**not** run checked commands (``migrate`` runs the system checks) as a
superuser: with ``TENANT_RLS_ENABLED`` on, W003 is an Error and will fail the
command. If your only migration role is a superuser, run those commands with a
migration-only settings module that sets ``TENANT_RLS_ALLOW_BYPASS_ROLE = True``
(and never serve tenant traffic with that settings/role).

.. note::

   This is a change from how many schema-per-tenant deployments run today, where
   the app often connects as a single privileged (often superuser) role. In RLS
   mode a superuser/BYPASSRLS role bypasses every policy, and W003 blocks checked
   commands run as one. Provisioning a non-superuser ``app_rls`` for tenant
   traffic, plus a non-superuser owner role (or the opt-out settings) for
   migrations, is a prerequisite -- not optional hardening.

The W003 safety net blocks startup
-----------------------------------

Once ``TENANT_RLS_ENABLED`` is ``True``, the :ref:`W003 system check
<rls-system-checks>` connects at startup, reads ``current_user``'s ``rolsuper``
and ``rolbypassrls`` from ``pg_roles``, and raises an **Error** (not a soft
warning) if the connected role is a superuser or carries ``BYPASSRLS``. Because
an ``Error`` blocks ``check`` and ``migrate``, a bypassing role stops you before
you can serve traffic against unenforced policies. The check is best-effort: if
the database is unreachable or is not PostgreSQL it cannot inspect the role and
stays silent rather than raising a false alarm.

.. warning::

   ``TENANT_RLS_ALLOW_BYPASS_ROLE = True`` (default ``False``) downgrades W003
   to *no finding*, disabling this safety net. Set it only for a deliberate,
   well-understood case -- for example a migration-only connection that never
   serves tenant traffic. With it on, isolation depends entirely on you never
   pointing tenant requests at the bypassing role. See :ref:`bypass-leak-note`.

Connection poolers
------------------

Persistent connections (``CONN_MAX_AGE``) are safe with the RLS backend: it
re-asserts the tenant and bypass session variables on **every cursor** from the
connection's Python state, so a connection reused by a later request -- or after
a transaction rollback -- always reflects the *current* tenant rather than a
leftover from a previous one.

**External connection poolers (PgBouncer, RDS Proxy, pgcat) must run in session
pooling mode.** The tenant GUC is set at SESSION scope as a statement *separate*
from the query it protects; under transaction- or statement-pooling those two
statements can be routed to different server backends, which strands the tenant
context (queries return zero rows) or -- worst case -- runs your query on a
backend still carrying another client's tenant. This is a hard requirement, not
a tuning knob; see :ref:`rls-migration-poolers` for the mechanism and the only
transaction-pooling-safe alternative.


.. _rls-migration-assessment:

Assessment: inventory your apps, models, and data
==================================================

Before you change a single setting, take stock of what you have. RLS mode
collapses every per-tenant schema into one shared ``public`` schema, so the
migration is not just "flip a flag" -- it physically merges data that was
previously kept apart by ``search_path``. The decisions you make here (which
apps move, which primary keys survive, how rows are re-keyed) are hard to
reverse once data has been copied into ``public``. Treat this section as a
checklist you complete *and write down* before touching code.

.. note::

   This section produces an inventory and a plan. The actual settings changes,
   backfill, and enable steps come in later sections; here you are only
   gathering facts and classifying.

Step 1 -- Classify every app: tenant-isolated, shared, or RLS
-------------------------------------------------------------

List your current ``SHARED_APPS`` and ``TENANT_APPS`` and put every app into
one of three buckets:

* **Stays shared (no change).** Apps already in ``SHARED_APPS`` -- the
  ``django_tenants`` machinery, the ``TENANT_MODEL`` app, the domain model app,
  global lookup/reference data, and anything genuinely cross-tenant. These keep
  living in ``public`` exactly as before.
* **Becomes an RLS app (the migration targets).** Apps currently in
  ``TENANT_APPS`` whose per-tenant rows you want to keep isolated, but now via
  RLS policies in a single schema instead of separate schemas. **These move
  from** ``TENANT_APPS`` **to** ``SHARED_APPS``.
* **Stays schema-per-tenant (optional, mixed mode).** Apps you are not ready to
  migrate yet can remain in ``TENANT_APPS``. You do not have to convert
  everything at once.

.. warning::

   An RLS-isolated app **must** end up in ``SHARED_APPS``, never
   ``TENANT_APPS``. In RLS mode there is exactly one schema (``public``); an app
   left in ``TENANT_APPS`` would only have its tables created in per-tenant
   schemas that RLS mode never uses, and would be missing from ``public``. See
   :ref:`SHARED_APPS vs TENANT_APPS <shared-apps-vs-tenant-apps>` for the full
   rationale and the router behaviour behind it.

Record, for each app you intend to convert, the list of models it contains and
which of them hold per-tenant data. Every per-tenant model in a converted app
will gain a ``tenant`` foreign key and an RLS policy; pure lookup tables inside
the same app that are genuinely global are a design decision you must make
explicitly (see *Step 3* below).

Step 2 -- Confirm each tenant primary-key type is castable (avoid E002)
-----------------------------------------------------------------------

The RLS policy works by comparing each row's ``tenant_id`` against a session
variable, casting that variable's text value to the tenant model's primary-key
SQL type. Only a known, correct cast is supported. ``get_tenant_pk_cast()`` maps
the tenant model's PK ``internal_type`` like this:

* **Integer family** -> ``integer`` (``AutoField`` / ``SmallAutoField`` /
  ``IntegerField`` / ``SmallIntegerField`` / ``PositiveIntegerField`` /
  ``PositiveSmallIntegerField``) or ``bigint`` (``BigAutoField`` /
  ``BigIntegerField`` / ``PositiveBigIntegerField``).
* **UUID** -> ``uuid`` (``UUIDField``).
* **Text-like** -> ``text`` (``CharField`` / ``SlugField`` / ``TextField``).

Any other PK internal type raises ``django.core.exceptions.ImproperlyConfigured``
rather than silently falling back to ``text`` -- a text cast on an integer
column would miscompare and break every RLS-policed query. This is surfaced at
startup as system check **E002** (``check_tenant_pk_cast``), which fires only
when RLS is enabled.

Inventory item: find your tenant model (``settings.TENANT_MODEL``) and confirm
its primary key is in one of the three supported families above. You can check
this without enabling RLS:

.. code-block:: pycon

    >>> from django_tenants.utils import get_tenant_model
    >>> pk = get_tenant_model()._meta.pk
    >>> pk.get_internal_type()
    'BigAutoField'

If that prints anything outside the supported set, you must change the tenant
model's PK type (or supply a matching ``TenantPolicy(pk_cast=...)`` per model)
*before* enabling RLS, or startup will be blocked by E002. The full type table
lives at :ref:`Supported tenant primary-key types <rls-pk-types>`, and the
check is documented at :ref:`rls-system-checks`.

.. note::

   It is the **tenant model's** PK type that drives the cast, not each
   per-tenant model's PK. The ``tenant_id`` column added to every RLS model is a
   foreign key to the tenant model, so it inherits the tenant PK type.

Step 3 -- Map cross-schema dependencies and shared lookups
----------------------------------------------------------

In schema-per-tenant mode, a foreign key from a ``TENANT_APP`` model could only
ever point at another row in the *same* tenant schema (or at a ``public`` row
for a ``SHARED_APP`` model). Collapsing to a single schema changes which foreign
keys are legal and which are now needed. Walk every model you plan to convert
and classify each foreign key:

* **FK to another model in the same converted app** -- both tables end up in
  ``public``, so the FK is fine; just be aware of the id-collision problem in
  Step 4, because the referenced ids are being merged too.
* **FK to a model that stays in** ``SHARED_APPS`` (a genuine global lookup) --
  this becomes a normal ``public``-to-``public`` FK and is straightforward.
* **A lookup table that was duplicated per tenant** -- if every tenant schema
  held its own copy of the same reference data, decide whether it becomes a
  single shared table (one ``public`` row referenced by all tenants) or an
  RLS-isolated table (per-tenant rows, kept apart by policy). A single shared
  table changes which FKs are legal: rows from all tenants will now reference
  the same lookup rows, so the data must actually be identical across tenants,
  or you must keep it isolated.

Write down, per converted model, the target of every FK and whether that target
is shared or RLS-isolated. A mis-classified lookup is a silent correctness bug:
either two tenants share a row that should have been private, or you fail to
merge rows that should have been one.

Step 4 -- Find primary-key collisions across tenant schemas
-----------------------------------------------------------

This is the highest-risk item in the inventory. In schema-per-tenant mode each
schema has its **own** sequences, so ``tenant1.blog_note`` and
``tenant2.blog_note`` can both legitimately contain a row with ``id = 1``. When
you copy every tenant's rows into one ``public.blog_note``, those ids collide.

For each table you plan to migrate, quantify the overlap *before* you design the
backfill. A quick way to find collisions for a table across all tenant schemas:

.. code-block:: sql

    -- Run as a bypass/superuser-equivalent role, BEFORE RLS is enabled.
    -- Adjust schema names to your real tenants and table to your real table.
    SELECT id, count(*) AS schemas_with_this_id
    FROM (
        SELECT id FROM tenant1.blog_note
        UNION ALL
        SELECT id FROM tenant2.blog_note
        -- ... UNION ALL one SELECT per tenant schema ...
    ) all_ids
    GROUP BY id
    HAVING count(*) > 1;

If that returns any rows, you cannot copy both tenants' rows into ``public``
while preserving ``id`` -- you need one of two strategies (chosen per table):

* **Re-key (re-sequence).** Let ``public`` assign fresh ids and drop the
  original ``id`` from the copy. Only safe if **nothing references that id**.
* **Preserve id (de-dup / partition by tenant).** Keep the original ``id`` so
  cross-table FKs survive (see Step 5). This only works if the
  ``(tenant_id, id)`` pairs are unique -- which they are, since each id is
  scoped to its tenant -- but the table's own primary key is still just ``id``,
  so genuine ``id`` collisions across tenants force a re-key for the colliding
  rows.

See the :ref:`backfill recipe <rls-backfill-recipe>` for the actual copy loop
and where ``ON CONFLICT`` / de-duplication goes; this section is about
*discovering* the collisions so you can choose a strategy.

Step 5 -- Decide: preserve ids (keep FKs) vs re-sequence (rewrite FKs)
----------------------------------------------------------------------

The id strategy from Step 4 has a direct consequence for foreign keys:

* **Preserving the original** ``id`` **keeps cross-table FKs intact.** If
  ``blog_comment.note_id`` points at ``blog_note.id``, and you copy both tables
  preserving their ids, the FK still resolves with no rewrite. This is the
  cheapest path and the default recommendation -- copy the original ``id``
  whenever nothing forces a re-key.
* **Re-sequencing requires updating every referencing row.** If you let
  ``public`` assign new ids (because of collisions, or because you drop ``id``),
  every table that referenced the old id must be rewritten to the new id. That
  means building and carrying an old-id -> new-id mapping per tenant per table
  through the entire backfill, and applying it to all referencing columns in the
  same transaction. This is error-prone; prefer preserving ids unless collisions
  make it impossible.

For UUID primary keys, collisions are effectively impossible, so preserving the
``id`` is almost always available -- just make sure the ``tenant_id`` column
type matches the tenant PK type. See the UUID note in the
:ref:`backfill recipe <rls-backfill-recipe>`.

Produce, per converted app, a small table: each model, its id strategy
(preserve vs re-key), and -- if re-keying -- the list of referencing columns
that must be rewritten.

Step 6 -- Quantify data volume and downtime tolerance
-----------------------------------------------------

The size of the merge drives *how* you migrate. Gather row counts per tenant per
table:

.. code-block:: sql

    -- Per-tenant row count for one table; repeat per schema/table or script it.
    SELECT 'tenant1' AS schema, count(*) FROM tenant1.blog_note
    UNION ALL
    SELECT 'tenant2', count(*) FROM tenant2.blog_note;

Use the totals to decide:

* **Batching.** Large tables should be copied in batches (by id range or by
  tenant) rather than one giant transaction, to bound lock duration and WAL
  growth.
* **Per-app, incremental migration.** You do not have to convert every app in
  one window. Migrating one app at a time (it moves to ``SHARED_APPS``, gets
  backfilled, then has RLS enabled) keeps each change small and reversible while
  the rest of the deployment stays schema-per-tenant.
* **Downtime tolerance.** A maintenance window lets you backfill and enable in
  one pass; a low-downtime requirement pushes you toward per-app batches and
  careful sequencing. Either way, the upgrade ordering is non-negotiable: add
  the tenant FK as ``null=True``, backfill every row, ``AlterField`` to
  ``null=False``, and only *then* enable RLS -- enabling RLS while NULL
  ``tenant_id`` rows remain makes those rows invisible to every tenant. See
  :ref:`Upgrading an existing populated table <rls-upgrade-existing>`.

Step 7 -- Pick a low-risk first app to migrate
----------------------------------------------

Do not make your largest, most FK-entangled app the first one you convert.
Choose a first app that:

* has **few or no inbound foreign keys** from other apps (so a re-key, if
  needed, stays local),
* has **modest data volume per tenant** (so the backfill is quick to run and
  quick to verify),
* is **not on the critical write path** (so a mistake is recoverable), and
* ideally uses a primary-key type you have already confirmed castable (Step 2).

Migrating this app end-to-end -- move to ``SHARED_APPS``, backfill, verify zero
NULL ``tenant_id`` rows, enable RLS, validate isolation -- proves out the whole
process on a small surface before you commit your high-value apps. The output of
this assessment (the app/model classification, the PK confirmation, the
FK/collision map, the id strategy, and the volume estimates) is the input to the
backfill and enable steps that follow.


.. _rls-migration-strategy:

Migration strategy: big-bang, incremental, or permanent hybrid
==============================================================

Before you touch a single model, decide *which shape* your migration takes.
The mechanics of converting one app are the same in every case (and are spelled
out step-by-step in :ref:`rls-upgrade-existing`); what differs is how many apps
you convert at once, how long you run a mixed deployment, and how you validate
isolation before you trust it. This section is the decision matrix. Pick a
strategy that matches your downtime tolerance and risk appetite, then follow the
canonical step list in :doc:`rls` to execute it.

.. important::

   **You migrate one APP (table) at a time, not one tenant at a time.** This is
   the single most common mental-model error. In schema-per-tenant, each tenant
   owns a private copy of every table in its own schema, so "do one tenant"
   feels natural. Under RLS there is exactly **one** shared table in ``public``
   that holds *all* tenants' rows, distinguished only by the ``tenant_id``
   column and the row-level policy. There is no per-tenant table to flip. When
   you convert an app you copy **every** tenant's rows for that app's tables
   into ``public`` in one backfill. The unit of migration is the
   **app/table**; the backfill iterates over tenants only to gather their rows.

The three rollout shapes
------------------------

Big-bang
~~~~~~~~

Convert **all** RLS-bound apps in a single maintenance window: move every app
from ``TENANT_APPS`` to ``SHARED_APPS``, run the staged column changes, backfill
every table, enable RLS, and cut the read path over -- all at once.

* **Pros:** simplest mental model; the deployment is never in a mixed state for
  long; one window, one rollback plan, one validation pass.
* **Cons:** highest blast radius. Every app's backfill must succeed in the same
  window, and a mistake (an un-backfilled table, a wrong-tenant stamp, a
  bypass-capable DB role) leaks or hides data across your *entire* product at
  once. The window is as long as your largest table's backfill.
* **Choose it when** your dataset is small enough to backfill and verify inside
  an acceptable downtime window, and you can afford a full-stack rollback if
  validation fails.

Per-app incremental (temporary hybrid)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Move **one app at a time** from ``TENANT_APPS`` to ``SHARED_APPS``. While app A
is being converted to RLS, apps B and C remain schema-per-tenant. The
deployment is a **hybrid for the duration of the rollout** and converges on
all-RLS (or your chosen permanent mix) when the last app lands.

* **Pros:** smallest blast radius per change; each app gets its own backfill,
  its own isolation validation, and its own rollback. You learn on a low-risk
  app before touching the crown-jewels app.
* **Cons:** longer overall calendar; you operate and reason about a mixed
  deployment for weeks. The hybrid is supported (see below), but every engineer
  must know which apps are which.
* **Choose it when** you have a large or business-critical dataset, low downtime
  tolerance, and want to validate isolation on real production data one app at a
  time.

This is the **recommended default** for an existing, populated deployment.

Permanent hybrid
~~~~~~~~~~~~~~~~~

A hybrid does not have to be a transition state -- you may **deliberately keep
some apps schema-per-tenant forever** and only convert others to RLS. Mixing
isolation models per app is explicitly supported. See
:ref:`shared-apps-vs-tenant-apps` for the rules.

.. note::

   **Every RLS app MUST be in** ``SHARED_APPS``. Schema-per-tenant apps stay in
   ``TENANT_APPS``; RLS-isolated-in-``public`` apps move to ``SHARED_APPS``. An
   app cannot be RLS-isolated while still living in ``TENANT_APPS``. Keeping an
   app schema-per-tenant must be a *deliberate* choice, not an accident of a
   half-finished migration.

* **Choose it when** some apps genuinely benefit from hard schema isolation
  (e.g. compliance boundaries, per-tenant extensions, wildly different row
  volumes) while others are better served by the single shared table that RLS
  gives you.

Recommended phased rollout (validate before cutover)
----------------------------------------------------

Whichever shape you pick, run each app through the same phased sequence. The
guiding principle is **validate before cutover**: get the data into ``public``
and prove isolation works *before* you make ``public`` the source of truth.

.. important::

   **Set** ``TENANT_RLS_AUTO_ENABLE = False`` **for the entire upgrade.** The
   default is ``True`` (see ``DEFAULTS`` in
   ``django_tenants.rls.conf``), which wires up a ``post_migrate`` hook that
   enables RLS in the *same* ``migrate`` run that creates or alters the table.
   That default is safe **only for greenfield/empty tables**. On an existing
   populated table it would enable RLS *before* you have backfilled, hiding
   every un-backfilled (NULL ``tenant_id``) row from every tenant. The
   auto-enable hook does defensively SKIP any table that still has NULL tenant
   rows and logs a loud warning, and ``manage.py enable_rls`` warns but
   *proceeds* -- so do not rely on those guards. Turn auto-enable off and enable
   RLS explicitly, after the backfill, on your schedule.

   .. code-block:: python

       # settings.py -- for the duration of the upgrade
       TENANT_RLS_ENABLED = True
       TENANT_RLS_AUTO_ENABLE = False          # enable RLS by hand, after backfill
       DATABASES = {
           "default": {
               "ENGINE": "django_tenants.rls.backend",
               # ... your existing connection settings ...
           }
       }

The phased sequence, per app:

#. **Add the FK as** ``null=True``. Make the model subclass
   ``django_tenants.rls.models.TenantRLSModel`` (or add an explicit
   nullable ``tenant`` FK) and migrate. Existing rows get
   ``tenant_id IS NULL``; the schema applies with no forced default. Never add
   the column as ``null=False`` in one step and never accept a one-off default
   -- that stamps every historical row into a single tenant.

#. **Backfill** ``tenant_id`` **on every row, then verify counts.** Copy each
   tenant's rows for this app's tables into ``public`` with the owning tenant pk
   attached. Run the backfill under
   ``django_tenants.rls.session.bypass_rls()`` (or before RLS is enabled at
   all) so the writes themselves are not filtered. Then prove the copy is
   complete and exact: the count of ``tenant_id IS NULL`` rows must be **zero**,
   and the per-tenant row counts in ``public`` must match the per-tenant schema
   counts they came from.

   .. code-block:: pycon

       >>> from blog.models import Note
       >>> Note.objects.filter(tenant__isnull=True).count()
       0   # MUST be zero before you tighten or enable RLS

#. **Tighten to** ``null=False`` with an ``AlterField`` migration -- only once
   the NULL count is zero.

#. **Enable RLS**, then **validate isolation**. Run ``manage.py enable_rls
   --app <app>`` (or the ``EnableRLS`` migration operation). Then, connecting as
   your **application** role (a ``NOSUPERUSER NOBYPASSRLS`` role -- a
   superuser/BYPASSRLS role bypasses RLS even with FORCE; check W003 enforces
   this, see :ref:`rls-database-role`), prove isolation holds:

   .. code-block:: pycon

       >>> from django_tenants.rls.session import rls_context
       >>> from blog.models import Note
       >>> # With no active tenant, secure-by-default => zero rows
       >>> Note.objects.count()
       0
       >>> with rls_context(tenant_a):
       ...     a_count = Note.objects.count()        # only tenant A's rows
       >>> with rls_context(tenant_b):
       ...     b_count = Note.objects.count()        # only tenant B's rows
       >>> # a_count + b_count (+ ...) must equal the total under bypass_rls()

   Confirm each tenant sees exactly the rows it owned in its old schema, sees
   none of any other tenant's, and that a write under one tenant cannot land
   under another (the policy's ``WITH CHECK`` rejects wrong-tenant writes).

#. **Cut the read path over**, then **decommission the old schemas**. Only after
   isolation validates do you point reads at ``public`` and retire the now-stale
   per-tenant copies of this app's tables.

The exact migration ops, the backfill recipe, and why each step is ordered the
way it is live in :ref:`rls-upgrade-existing` (and its sub-sections
:ref:`rls-backfill-recipe`, :ref:`rls-null-rows`, :ref:`rls-step-6-enable`).
This guide tells you *which* strategy to run and *when* to validate; that
reference holds the canonical, copy-pasteable step list.

The shadow / validate window
----------------------------

The phased sequence above has a natural safety gap you should exploit
deliberately: between **backfill** (step 2) and **cutover** (step 5), the data
exists in *both* places. Old per-tenant schemas still serve production reads;
the freshly backfilled ``public`` table is a shadow copy. Use that window to
build confidence without risking the live read path.

#. **Backfill into** ``public`` while the app keeps serving from the per-tenant
   schemas. Production is unaffected; ``public`` is a shadow.
#. **Verify counts** -- per-tenant row counts in ``public`` match the source
   schemas, and zero NULL ``tenant_id`` rows.
#. **Enable RLS and validate isolation under the application role** -- run the
   ``rls_context``/``bypass_rls`` checks above as the ``NOSUPERUSER NOBYPASSRLS``
   app role, not as a superuser, so you are testing the same enforcement
   production will use.
#. **Only then cut the read path over** to ``public``.
#. **Decommission** the old per-tenant copies once you have soaked on the new
   path and are satisfied.

.. tip::

   **Re-run isolation validation through your connection pooler, not just a
   direct connection** -- it is the configuration production runs. The RLS
   backend re-asserts the tenant/bypass GUCs on *every* cursor, which keeps
   isolation correct across reused connections **only under session pooling**.
   If your pooler is in transaction/statement mode, this is exactly where the
   isolation breaks (see :ref:`rls-migration-poolers`): add a CI test that runs
   the two-tenant isolation check *through* the pooler in its production mode and
   asserts the result -- under transaction pooling you should observe stranded
   context (zero rows) or a leak, which is your signal to switch to session
   pooling.

.. danger::

   If validation fails after you have enabled RLS, do **not** "fix" it by
   merely setting ``TENANT_RLS_ENABLED = False``. Disabling RLS is two-part:
   flip ``TENANT_RLS_ENABLED = False`` **and** run ``manage.py disable_rls``
   (or the ``DisableRLS`` op). Flipping only the flag while FORCE plus the
   policy remain in place locks a ``NOBYPASSRLS`` app role out of **every** row.
   See :ref:`rls-rollback`.


.. _rls-migration-step-1:

Step 1 -- Configuration cutover
===============================

This step makes the **non-data** configuration changes that put your project
into RLS mode: registering the RLS app, turning the feature on (but *not*
auto-enabling it yet), switching the database ``ENGINE``, and -- the single
highest-impact edit -- moving every RLS-isolated app from ``TENANT_APPS`` to
``SHARED_APPS``. No data is touched here; the table changes (tenant FK,
backfill) and the actual ``ENABLE ROW LEVEL SECURITY`` come in later steps.

A complete, copy-paste version of every change below lives in
``examples/rls/settings_snippet.py``. Use it as the diff target for your own
``settings.py``.

.. note::

   Nothing in this step enables RLS on any populated table. With
   ``TENANT_RLS_AUTO_ENABLE = False`` (set below) it is safe to deploy these
   configuration changes ahead of the data migration -- the RLS backend behaves
   identically to the stock backend until policies actually exist on a table.

Register ``django_tenants.rls`` in ``SHARED_APPS``
--------------------------------------------------

Add ``django_tenants.rls`` to ``SHARED_APPS``. It must be a *shared* app
because in RLS mode everything lives in the ``public`` schema. Adding it
registers the RLS :ref:`system checks <rls-system-checks>` and, when
``TENANT_RLS_AUTO_ENABLE`` is on, a ``post_migrate`` hook that enables RLS
automatically after migrations.

.. code-block:: python

    SHARED_APPS = (
        'django_tenants',            # mandatory
        'django_tenants.rls',        # registers RLS checks + post_migrate auto-enable
        'customers',                 # the app holding your TENANT_MODEL
        # ... your RLS-isolated data apps move here too (see "Move each app" below) ...
    )

The ``post_migrate`` hook is only wired up when **both** ``TENANT_RLS_ENABLED``
and ``TENANT_RLS_AUTO_ENABLE`` are true; otherwise registering the app is a
no-op beyond the system checks. Because the next sub-step sets
``TENANT_RLS_AUTO_ENABLE = False`` for an upgrade, the hook stays disconnected
until you deliberately re-enable it -- exactly what you want while populated
tables still need their ``tenant_id`` backfilled.

Turn RLS on, but keep auto-enable OFF for the upgrade
-----------------------------------------------------

Set the RLS feature flags. Every value may be given as an individual top-level
setting **or** inside an optional ``DJANGO_TENANTS_RLS`` dict (the individual
top-level setting wins, then the dict, then the hardcoded default).

For an upgrade of an existing, populated deployment, the two settings that
matter here are:

.. code-block:: python

    # Individual top-level form:
    TENANT_RLS_ENABLED = True

    # CRITICAL during an upgrade: do NOT auto-enable RLS on migrate. Populated
    # tables must have tenant_id backfilled FIRST; auto-enabling now risks
    # making un-backfilled rows invisible to every tenant.
    TENANT_RLS_AUTO_ENABLE = False

or, equivalently, the grouped dict form:

.. code-block:: python

    DJANGO_TENANTS_RLS = {
        "TENANT_RLS_ENABLED": True,
        "TENANT_RLS_AUTO_ENABLE": False,
    }

.. warning::

   **Leave** ``TENANT_RLS_AUTO_ENABLE = False`` **for the entire duration of the
   upgrade.** The default is ``True`` (greenfield-friendly), which runs the
   ``post_migrate`` hook in the *same* ``migrate`` that creates or alters the
   table. On an existing table that still has rows without a ``tenant_id`` that
   would attempt to enable RLS too early. The hook does defensively *skip* any
   table that still has ``NULL`` tenant rows (with a loud warning), but you
   should not rely on that safety net during a planned migration -- keep
   auto-enable off and enable RLS explicitly after the backfill (see the data
   steps and :ref:`rls-step-6-enable`).

The remaining RLS settings keep their defaults during the cutover and are
documented in the *RLS settings reference* section of :doc:`rls`; you do not
need to change them in this step.

Switch the database ENGINE to the RLS backend
---------------------------------------------

Point the tenant database at ``django_tenants.rls.backend``. It *subclasses*
the standard django-tenants backend and is byte-for-byte identical in behaviour
until a policy exists on a table, so the usual ``ORIGINAL_BACKEND`` setting
still applies and defaults to ``django.db.backends.postgresql`` exactly as
before -- leave it unchanged unless you already override it with a custom
psycopg backend.

.. code-block:: python

    DATABASES = {
        'default': {
            'ENGINE': 'django_tenants.rls.backend',
            # ORIGINAL_BACKEND unchanged; defaults to django.db.backends.postgresql.
            # 'ORIGINAL_BACKEND': 'django.db.backends.postgresql',
            'NAME': 'myproject',
            # ... HOST / USER / PASSWORD / PORT as usual ...
        }
    }

    DATABASE_ROUTERS = (
        'django_tenants.routers.TenantSyncRouter',
    )

With the RLS backend in place, the wrapper re-asserts the tenant session
variable on **every** cursor, so isolation is applied without any extra request
plumbing. (The DB-role requirement -- a ``NOSUPERUSER NOBYPASSRLS`` role,
enforced by the W003 check -- is part of the database-preparation step and is
covered there; see :ref:`rls-database-role`.)

Move each RLS-isolated app from ``TENANT_APPS`` to ``SHARED_APPS``
------------------------------------------------------------------

This is the highest-impact edit in the whole cutover.

.. danger::

   **Every app you are isolating with RLS MUST be listed in** ``SHARED_APPS``\ **,
   NOT** ``TENANT_APPS``\ **.**

   In RLS mode there is exactly one schema (``public``). ``TenantSyncRouter``
   reads ``connection.schema_name`` to decide where a migration applies; with
   the RLS backend the ``search_path`` stays ``public`` for all tenant
   operations, so ``allow_migrate`` decides purely on ``SHARED_APPS``
   membership. If an RLS app is left in ``TENANT_APPS``, the router will only
   ever let its tables be created inside per-tenant schemas -- which RLS mode
   never creates or uses -- so its tables will be **missing from** ``public``
   and the app will break.

For each app you are converting from schema-per-tenant to RLS, move its entry
out of ``TENANT_APPS`` and into ``SHARED_APPS``, following the standard
procedure for moving apps between the two app lists. The rationale and the
``allow_migrate`` mechanics are documented in
:ref:`shared-apps-vs-tenant-apps`; do not skip the relocation of existing
per-tenant *data* into ``public`` described there and in the data steps of this
guide.

.. code-block:: python

    TENANT_APPS = (
        # 'myapp',  <-- REMOVE from here ...
    )

    SHARED_APPS = (
        'django_tenants',
        'django_tenants.rls',
        'customers',
        'myapp',          # <-- ... and ADD here. RLS apps live in public.
    )

The ``TENANT_MODEL`` app (e.g. ``customers``) and ``django_tenants.rls`` itself
also belong in ``SHARED_APPS``.

.. note::

   In a full RLS-only cutover every isolated app moves out, so ``TENANT_APPS``
   ends up empty (``TENANT_APPS = ()``). ``django_tenants`` allows this **only
   when** ``TENANT_RLS_ENABLED = True`` -- core ``DjangoTenantsConfig.ready()``
   otherwise raises ``ImproperlyConfigured("TENANT_APPS is empty")``. So set the
   RLS feature flag (previous sub-step) *before* you empty ``TENANT_APPS``. If you
   are on an older django-tenants that predates this allowance, keep one harmless
   entry in ``TENANT_APPS`` (e.g. ``'django.contrib.contenttypes'``).

**Hybrid deployments are chosen per database connection, not per app on one
connection.** The RLS backend pins ``search_path`` to ``public`` for every
tenant, so a connection using it cannot also serve schema-per-tenant
``TENANT_APPS`` (their per-tenant-schema tables are no longer on the search
path). A true hybrid therefore keeps the schema-per-tenant apps on a **separate**
``DATABASES`` alias using the stock ``django_tenants.postgresql_backend``, routed
via a database router; every RLS-isolated app goes in ``SHARED_APPS`` on the
RLS-backend connection. See :ref:`shared-apps-vs-tenant-apps` and the matching
``Hybrid deployments`` discussion in :ref:`the RLS reference <rls-mechanism>`.

Disable per-tenant schema creation on your ``TenantMixin`` (RLS-only)
---------------------------------------------------------------------

``TenantMixin.auto_create_schema`` defaults to ``True``, which makes
``TenantMixin.save()`` create a new PostgreSQL schema for each tenant.

* **RLS-only deployment** (no schema-per-tenant apps on any connection): there is
  only ``public``, so per-tenant schemas would be empty and pointless. Set
  ``auto_create_schema = False`` (and ``auto_drop_schema = False``) on your
  ``TenantMixin`` subclass so no per-tenant schemas are created or dropped going
  forward:

  .. code-block:: python

      from django_tenants.models import TenantMixin

      class Client(TenantMixin):
          # ... your fields ...
          auto_create_schema = False   # RLS-only: keep a single public schema
          auto_drop_schema = False

* **Hybrid deployment** (some apps remain schema-per-tenant on a separate
  connection): **keep ``auto_create_schema = True``.** New tenants still need
  their schema created on the schema-per-tenant connection, or those apps break /
  route to missing tables. The (otherwise-unused) per-tenant schema on the RLS
  side is harmless.

This affects only *future* tenant creation. Any per-tenant schemas that already
exist from your schema-per-tenant deployment are addressed in the data-migration
steps; for an RLS-only cutover this setting just stops new empty ones appearing.

Middleware: keep ``TenantMainMiddleware``; ``TenantRLSMiddleware`` is optional
------------------------------------------------------------------------------

Keep ``TenantMainMiddleware`` exactly as in schema-per-tenant mode -- it still
resolves ``request.tenant`` from the request:

.. code-block:: python

    MIDDLEWARE = (
        'django_tenants.middleware.main.TenantMainMiddleware',
        # 'django_tenants.rls.middleware.TenantRLSMiddleware',  # OPTIONAL fallback
        # ... your other middleware ...
    )

With the RLS backend (above) the tenant session variable is set on every
cursor, so ``TenantRLSMiddleware`` is **not required**. It is only the fallback
enforcer for setups that keep the stock backend instead of switching the
``ENGINE``. It is harmless to leave installed; if you do, place it *after*
``TenantMainMiddleware``.

Run ``manage.py check --deploy`` and clear W001 before proceeding
-----------------------------------------------------------------

Once the settings above are in place, confirm that an *enforcer* is configured.
The :ref:`W001 check <rls-system-checks>` fires when ``TENANT_RLS_ENABLED`` is
``True`` but neither the RLS backend ``ENGINE`` nor ``TenantRLSMiddleware`` is
configured -- meaning policies would be created on tables but the tenant
session variable would never be set, so every query would evaluate against an
unset variable and silently return nothing.

.. danger::

   **You must pass** ``--deploy``\ **.** ``W001`` and ``W003`` are registered as
   *deployment* checks, so a plain ``manage.py check`` (without ``--deploy``)
   **never runs them** -- it will report "no issues" even when the RLS backend is
   not wired at all, giving you false confidence that isolation is on when it is
   not. Always verify with:

.. code-block:: console

    $ python manage.py check --deploy --database default

A clean run (no ``W001``) confirms the backend is wired correctly. If W001
still appears, you either did not switch ``DATABASES[alias]['ENGINE']`` to
``'django_tenants.rls.backend'`` or you intended the stock-backend fallback and
forgot to add ``TenantRLSMiddleware``. Resolve it before moving on to the
data-migration steps.

.. note::

   The same ``--deploy`` run also surfaces the W003 role check (an **error** that
   blocks startup) if your configured DB role can bypass RLS -- it, too, is a
   deployment check and is invisible to a plain ``manage.py check``. W003 belongs
   to database preparation rather than the settings cutover; see
   :ref:`rls-database-role` and :ref:`rls-system-checks`.

.. tip::

   The most reliable gate is ``manage.py rls_doctor``: it re-runs W001/W003/E001
   regardless of ``--deploy`` (so it cannot be masked by the deploy-check split)
   *and* reports per-model readiness. Prefer it as your verification command.


.. _rls-migration-step-2:

Step 2 -- Model changes and the staged nullable-FK migration
============================================================

In this step you convert your isolated models to the RLS base class and stage
the schema change. The conversion itself is one line per model; the *migration*
is the dangerous part. On a populated production table the schema change **must**
be split into a precise sequence. Collapsing it into one step either fails the
deploy or silently stamps your entire history into a single tenant. Read this
section in full before you run ``makemigrations``.

Subclass ``TenantRLSModel``
---------------------------

Change each isolated model to subclass
``django_tenants.rls.models.TenantRLSModel`` instead of ``django.db.models.Model``:

.. code-block:: python

    from django.db import models
    from django_tenants.rls.models import TenantRLSModel

    class Note(TenantRLSModel):
        text = models.TextField()
        # No explicit Meta.rls_policies -> a default TenantPolicy is built
        # automatically on the `tenant` field at enable time.

The abstract base contributes two things to every subclass:

* **A ``tenant`` foreign key** to ``settings.TENANT_MODEL``
  (``on_delete=CASCADE``, ``db_index=True``, ``related_name="+"``). This is the
  column the RLS policy filters on.
* **An overridden ``save()``** that auto-populates ``tenant_id`` from the active
  connection when it is unset, so existing application code that never passed a
  tenant keeps working as a drop-in. The resolution order is the GUC first
  (``connection._rls_tenant_id``, the session variable the RLS backend pushes --
  this is what ``rls_context()`` sets) and then the bound ``connection.tenant.pk``
  as a fallback. An explicitly-set tenant is never overwritten, and when RLS is
  disabled this is a no-op (behaviour identical to a plain model).

Because the FK attribute name ``tenant`` is hard-coded on the base, it matches
the default ``TENANT_RLS_TENANT_FIELD = "tenant"``. The default policy is built
lazily and named ``"<db_table>_tenant_isolation"``.

.. note::

   **Custom tenant field name.** If you set ``TENANT_RLS_TENANT_FIELD`` to
   something other than ``"tenant"``, the base FK alone will not satisfy it: you
   must define your own ``ForeignKey`` with that name **and** declare a matching
   ``TenantPolicy(tenant_field=...)`` in ``Meta.rls_policies`` so the generated
   policy SQL references the column that actually exists.

.. _rls-migration-existing-tenant-col:

Your model already has a ``tenant`` / ``tenant_id`` column
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some schema-per-tenant apps **denormalize** the owning tenant into a plain column
(e.g. ``tenant_id = models.IntegerField(...)``) so background/async code that has
lost the schema context can still recover it. The base ``tenant`` FK maps to the
column ``tenant_id`` (Django derives ``<field>_id``), so subclassing
``TenantRLSModel`` on such a model is a **column-name collision**, not merely a
type mismatch -- Django raises ``models.E006`` at check/``makemigrations`` time::

    yourapp.YourModel.tenant_id: (models.E006) The field 'tenant_id' clashes with
    the field 'tenant' from model 'yourapp.yourmodel'.

This blocks the migration before any SQL runs. ``rls_doctor`` is no help here: it
keys on a field literally named ``tenant`` (``conf.tenant_field()``), so a model
whose only tenant column is a bare ``tenant_id`` is reported as *missing the FK*
(``generate_migration`` with a staged ``AddField``), which would then try to add
an already-existing ``tenant_id`` column. Resolve it one of two ways:

* **Rename/drop the legacy column first.** Rename the existing ``tenant_id`` out
  of the way (or drop it once nothing reads it), *then* add the real ``tenant`` FK
  and backfill it (Step 3). If the legacy integer already holds the numeric
  ``Tenant`` primary key for every row, it is a convenient in-row backfill source
  (see :ref:`the in-row backfill note <rls-backfill-inrow>`) -- but only if it is
  reliably the **pk** and not, say, a schema-name string; verify before trusting
  it.
* **Use a different FK attribute name.** Set ``TENANT_RLS_TENANT_FIELD`` to a
  non-colliding name, add a ``ForeignKey`` with that name, and a matching
  ``TenantPolicy(tenant_field=...)`` (as in the custom-field note above).

.. _rls-migration-w002:

Confirm the W002 system check is clear
--------------------------------------

A ``TenantRLSModel`` subclass that has no field named ``TENANT_RLS_TENANT_FIELD``
triggers system check **W002** (``django_tenants_rls.W002``): the generated
policy filters on ``<tenant_field>_id``, and a missing column would make every
query against the table error. The check only runs when RLS is enabled.

After subclassing (and after writing the migration below) confirm it is clear:

.. code-block:: console

    $ python manage.py check

A clean run means each ``TenantRLSModel`` resolves its tenant field. If W002
fires, you either forgot the FK or set a custom ``TENANT_RLS_TENANT_FIELD``
without defining the matching FK (see the note above). See
:ref:`rls-system-checks` for the full check reference.

.. danger::

   **Never add the tenant FK as ``null=False`` in one step on a populated
   table.** Both shortcuts that ``makemigrations`` will offer you are wrong on
   existing data:

   * Adding a ``NOT NULL`` column to a table that already has rows **fails
     outright** under ``migrate --noinput`` -- there is no value for the existing
     rows.
   * Accepting the one-off default that ``makemigrations`` prompts for stamps
     **every historical row into a single tenant**, silently cross-contaminating
     all of your data into one tenant -- the exact opposite of isolation.

   Use the staged ordering below instead. See :ref:`rls-null-rows` for why a
   single NULL-or-wrong tenant value is catastrophic once RLS is on.

.. _rls-migration-staged-order:

The non-negotiable staged ordering (populated tables)
-----------------------------------------------------

For any table that **already contains rows** the schema change must be staged in
exactly this order. This is the same four-step path described in
:ref:`rls-upgrade-existing`; the steps are summarised here so you can see where
they sit in the migration journey:

#. **AddField the tenant FK as ``null=True``.** The column applies to existing
   rows without a forced default; every existing row gets ``tenant_id IS NULL``.
#. **Backfill ``tenant_id`` on every row** with its real owning tenant, run under
   ``bypass_rls()`` or before RLS is enabled at all (see
   :ref:`rls-backfill-recipe`).
#. **AlterField to ``null=False``** -- only after verifying zero
   ``tenant_id IS NULL`` rows remain.
#. **Then, and only then, enable RLS** (:ref:`rls-migration-step-4-enable` /
   :ref:`rls-step-6-enable`).

Enabling RLS while any ``NULL`` ``tenant_id`` rows remain makes those rows
invisible to **every** tenant, because ``NULL = <pk>`` is never true. The
``post_migrate`` auto-enable hook skips tables that still have NULL rows (with a
loud warning) and ``manage.py enable_rls`` warns but proceeds -- neither is a
safety net you should rely on. Set ``TENANT_RLS_AUTO_ENABLE = False`` for the
duration of the upgrade so RLS is never switched on inside the same ``migrate``
run that creates the column. See :ref:`rls-null-rows`.

.. note::

   **Greenfield / empty tables can skip staging.** If the table has no rows yet,
   the ``tenant`` FK is just a normal column and a single ordinary migration
   (``makemigrations`` then ``migrate_schemas --shared``) is fine. This guide
   assumes an existing, populated deployment, so it uses the staged path
   throughout.

Migration shapes
----------------

Subclassing ``TenantRLSModel`` will make ``makemigrations`` want to add the FK
as ``null=False`` in a single operation. **Do not accept that.** Author the two
schema migrations explicitly (with the backfill data migration in between).

**(1) AddField the FK as** ``null=True`` -- the column existing rows will start
NULL in:

.. code-block:: python

    # 0002_add_tenant_fk.py -- add the column as NULLable first
    from django.conf import settings
    from django.db import migrations, models
    import django.db.models.deletion


    class Migration(migrations.Migration):
        dependencies = [("blog", "0001_initial")]
        operations = [
            migrations.AddField(
                model_name="note",
                name="tenant",
                # Mirror TenantRLSModel's tenant FK exactly except for null=True
                # here (db_index=True, related_name="+"), so makemigrations does
                # not detect drift and the index exists during the backfill.
                field=models.ForeignKey(
                    null=True,
                    db_index=True,
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="+",
                    to=settings.TENANT_MODEL,
                ),
            ),
        ]

Then run the backfill (see :ref:`rls-backfill-recipe` and
:ref:`rls-migration-step-3-backfill`) as a separate data migration or one-off
script, and verify it is complete:

.. code-block:: sql

    -- must return 0 before you tighten the column
    SELECT count(*) FROM blog_note WHERE tenant_id IS NULL;

**(3) AlterField to** ``null=False`` -- run only after the count above is zero:

.. code-block:: python

    # 0004_tenant_not_null.py -- after the backfill data migration
    from django.conf import settings
    from django.db import migrations, models
    import django.db.models.deletion


    class Migration(migrations.Migration):
        dependencies = [("blog", "0003_backfill_tenant")]
        operations = [
            migrations.AlterField(
                model_name="note",
                name="tenant",
                # Same options as TenantRLSModel's field, now with null=False.
                field=models.ForeignKey(
                    db_index=True,
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="+",
                    to=settings.TENANT_MODEL,
                ),
            ),
        ]

With the column populated and tightened to ``NOT NULL``, the table is ready for
RLS to be enabled -- proceed to enabling RLS (:ref:`rls-migration-step-4-enable`
/ :ref:`rls-step-6-enable`) only at that point, and keep
``TENANT_RLS_AUTO_ENABLE = False`` until you do.


.. _rls-migration-step-3-backfill:

Step 3 -- Backfilling tenant_id from per-tenant schemas
=======================================================

This is the heart of the migration. After Step 2 your shared ``public``
tables exist with a **nullable** ``tenant`` FK (``tenant_id``) column, but
every historical row still lives in its per-tenant schema
(``tenant1.blog_note``, ``tenant2.blog_note``, ...) and ``public.blog_note``
is empty. This step copies each row into ``public`` with its owning tenant's
primary key stamped into ``tenant_id``.

.. danger::

   Do this **with RLS still disabled** (or strictly under ``bypass_rls()``),
   **before** the ``AlterField`` to ``null=False``, and **before** enabling
   RLS. The ordering is non-negotiable (:ref:`rls-upgrade-existing`): a single
   row left with a NULL ``tenant_id`` becomes invisible to *every* tenant once
   the policy is on (``NULL = <pk>`` is ``NULL``, never true -- see
   :ref:`rls-null-rows`). Keep ``TENANT_RLS_AUTO_ENABLE = False`` for the
   duration of the upgrade so a stray ``migrate`` cannot turn RLS on
   underneath a half-finished backfill.

There is no generic backfill command
-------------------------------------

django-tenants deliberately ships **no** management command for this. The
candidate column list, the per-table type coercions, and the conflict handling
are too project-specific to automate safely. Treat the backfill as an
explicit, reviewed **data migration** (a ``RunPython`` operation) or a one-off
script run against production with your app settings loaded. Review it the way
you would review a destructive SQL change, because that is what it is.

The copy-pasteable starting point is the recipe in the reference doc,
:ref:`rls-backfill-recipe`. This section does **not** re-print it; instead it
expands on the hard parts the reference only flags in passing: id collisions,
sequences, batching, restartability, and verification.

The shape of the backfill
--------------------------

For each table being migrated, the pattern is always the same three moving
parts:

#. Loop over every tenant except ``public``:
   ``TenantModel.objects.exclude(schema_name=get_public_schema_name())``.
#. For each tenant, ``INSERT ... SELECT`` the rows out of that tenant's schema
   (``"<schema>".<table>``) into the shared ``public.<table>``, stamping
   ``tenant.pk`` into the ``tenant_id`` column.
#. Run the entire loop inside ``bypass_rls()`` so the writes (and any
   verification reads) are not themselves filtered by a policy.

The reference recipe (:ref:`rls-backfill-recipe`) shows the exact
``INSERT INTO public.blog_note (<cols>, tenant_id) SELECT <cols>, %s FROM
"<schema>".blog_note`` form, the explicit ``COLUMNS`` list, the ``bypass_rls()``
wrapper, and the closing ``count(*) WHERE tenant_id IS NULL`` assertion. Start
from that and adapt the column list per table.

Why ``bypass_rls()`` is mandatory here
--------------------------------------

If RLS is already enabled when you run the backfill (or you forget the
wrapper), the policy filters your reads and the ``WITH CHECK`` clause can reject
your writes, so the copy silently does nothing or errors. ``bypass_rls()``
flips the ``django_tenants.bypass_rls`` session variable on enter and restores
the previous value on exit, even on exception (``django_tenants/rls/session.py``,
``bypass_rls.__enter__`` / ``__exit__``). The policy ORs the bypass clause in
explicitly, so it works **even for the table-owner role under FORCE ROW LEVEL
SECURITY**.

.. warning::

   ``bypass_rls()`` is a tenant-isolation hole for the duration of the block --
   it makes *all* tenants' rows visible and writable. Keep the block as narrow
   as the backfill itself, and never leave a connection in the bypass state.
   See :ref:`bypass-leak-note` for the per-cursor re-assertion that keeps this
   safe across pooled/reused connections.

If you would rather avoid the bypass entirely, run the backfill while RLS is
still fully disabled (``TENANT_RLS_ENABLED = False`` and no
policies applied yet). With no policy on the table there is nothing to filter,
and the ``bypass_rls()`` wrapper is then a harmless no-op you can keep for
defence in depth.

The tenant pk type must match the ``tenant_id`` column type
-----------------------------------------------------------

The recipe passes ``tenant.pk`` as a bound ``%s`` parameter. The driver adapts
whatever Python type that is -- ``int``, ``uuid.UUID``, or ``str`` -- so the same
recipe works for integer, bigint, UUID, and text-like tenant keys without code
changes. A ``uuid.UUID`` str()-ifies to its canonical hyphenated form, which
casts cleanly into a ``uuid`` column and into the ``::uuid`` cast in the
policy (this is exactly what ``_coerce_tenant_id`` in
``django_tenants/rls/session.py`` relies on at runtime).

What you **must** get right is that the ``tenant_id`` column you created in
Step 2 has the **same type** as the tenant model's primary key. An integer
``tenant_id`` cannot receive a UUID pk. Only the integer family, UUID, and
text-like (``CharField`` / ``SlugField`` / ``TextField``) pk types are
supported by the policy cast; anything else raises ``ImproperlyConfigured``
(system check ``E002``). See :ref:`rls-pk-types`.

Primary-key / id collisions across schemas
-------------------------------------------

In schema-per-tenant, every tenant schema has its **own** sequence, so
``tenant1.blog_note`` and ``tenant2.blog_note`` both very likely contain a row
with ``id = 1``. When you merge them into one ``public.blog_note``, those ids
collide.

You have to choose, per table, between two strategies:

**A. Preserve the original id (default).**
   Keep ``id`` in the ``COLUMNS`` list and copy it verbatim. This is correct
   and necessary when **other tables' foreign keys reference this id** -- copying
   the original id keeps every cross-table FK pointing at the right row. This
   only works if ids do **not** collide across tenants for this table (e.g. the
   table already uses a globally-unique key such as a UUID, or you have verified
   ranges do not overlap).

**B. Re-key on insert.**
   If ids *do* collide and you must keep the rows distinct, you cannot copy the
   raw id. Either:

   - Drop ``id`` from ``COLUMNS`` and let ``public`` assign fresh ids from its
     own sequence -- **only safe if nothing references the old id** -- or
   - Insert with a deterministic remapping and then **update every referencing
     row** to the new id before continuing. Maintain an explicit
     ``(tenant_pk, old_id) -> new_id`` map and apply it to child tables in FK
     dependency order.

.. warning::

   Re-keying without fixing referencing rows will silently break foreign keys
   and orphan child data. If a table is referenced by others, prefer
   strategy A; reach for B only when collisions force it, and migrate parent
   tables before their children so the FK updates have a valid target.

For idempotency / accidental double-runs you can add an ``ON CONFLICT`` clause,
for example ``ON CONFLICT (id) DO NOTHING`` when preserving ids, so re-running
the migration does not raise on rows already copied. Use ``DO NOTHING`` (not
``DO UPDATE``) unless you have a specific reason to overwrite.

Resetting sequences after preserving ids
-----------------------------------------

If you used strategy A (copied the original ``id``), the ``public`` table now
contains rows whose ids the ``public`` sequence has never handed out. The next
``INSERT`` from your application will try to reuse a low id and collide. After
the backfill, fast-forward the sequence past the current maximum:

.. code-block:: python

    # Run once per table, inside the same bypass_rls() block, AFTER the copy.
    with connection.cursor() as cur:
        cur.execute(
            "SELECT setval("
            "  pg_get_serial_sequence('public.blog_note', 'id'),"
            "  COALESCE((SELECT MAX(id) FROM public.blog_note), 1),"
            "  true"
            ")"
        )

``pg_get_serial_sequence`` finds the sequence backing the column regardless of
its generated name. ``COALESCE(..., 1)`` keeps it correct on an empty table, and
the trailing ``true`` marks the value as "already used" so the next id is
``MAX(id) + 1``. Skip this step entirely for tables migrated with strategy B
(fresh ids), and for UUID / non-sequence primary keys.

Batching huge tables
--------------------

The recipe's single ``INSERT ... SELECT`` per tenant is fine for small and
medium tables, but on a large table it produces one enormous transaction that
holds locks and bloats WAL. For big tables, copy in id-ordered batches so each
statement commits a bounded chunk:

.. code-block:: python

    BATCH = 50_000
    with bypass_rls():
        for tenant in TenantModel.objects.exclude(schema_name=public):
            last_id = 0
            while True:
                with connection.cursor() as cur:
                    # Copy one bounded, id-ordered chunk of THIS tenant's rows.
                    cur.execute(
                        'INSERT INTO public.blog_note (%s, tenant_id) '
                        'SELECT %s, %%s FROM "%s".blog_note '
                        'WHERE id > %%s ORDER BY id LIMIT %%s '
                        'ON CONFLICT (id) DO NOTHING'
                        % (col_sql, col_sql, tenant.schema_name),
                        [tenant.pk, last_id, BATCH],
                    )
                    # Advance the cursor to the largest SOURCE id in this chunk,
                    # so the next iteration starts after it. Driving by the source
                    # id (not rowcount) keeps the loop correct even when
                    # ON CONFLICT skips already-copied rows.
                    cur.execute(
                        'SELECT max(id) FROM ('
                        '  SELECT id FROM "%s".blog_note '
                        '  WHERE id > %%s ORDER BY id LIMIT %%s'
                        ') AS chunk'
                        % tenant.schema_name,
                        [last_id, BATCH],
                    )
                    row = cur.fetchone()
                if row is None or row[0] is None:
                    break
                last_id = row[0]

Key properties of a batched backfill:

* **Bounded transactions / lock time.** Each batch is its own statement;
  commit between batches (or run the script with autocommit) so locks and WAL
  do not accumulate.
* **Restartable.** Driving the loop by ``id > last_id`` plus
  ``ON CONFLICT (id) DO NOTHING`` makes the copy idempotent: if the script dies
  partway, re-running it skips rows already present and continues. Persist
  ``last_id`` (or simply rely on ``ON CONFLICT``) so a restart never duplicates
  or skips.
* **Per-tenant isolation of failures.** Wrapping each *tenant* in its own
  transaction lets you retry one tenant without redoing the others.

Adjust ``BATCH`` to your row size and lock tolerance; tune the cursor-advance
query to match your table's key. The exact mechanics are project-specific --
the point is bounded, ordered, resumable chunks.

.. _rls-backfill-inrow:

In-row / denormalized tenant source (no cross-schema copy)
----------------------------------------------------------

The recipe above copies rows *across schemas*. If a table is **already in the
shared schema** and merely needs its new ``tenant_id`` populated -- the common
case when a model denormalized the owning tenant into a legacy column (see
:ref:`your model already has a tenant_id column
<rls-migration-existing-tenant-col>`) -- there is
no cross-schema loop at all. The backfill is a same-table ``UPDATE`` from the
legacy column:

.. code-block:: python

    with bypass_rls(), connection.cursor() as cur:
        # ONLY valid if the legacy column holds the numeric Tenant pk for every
        # row. If it holds a schema-name STRING instead, join to the tenant
        # registry: SET tenant_id = (SELECT id FROM customers_tenant t
        #   WHERE t.schema_name = myapp_event.legacy_schema_name)
        cur.execute(
            "UPDATE myapp_event "
            "SET tenant_id = legacy_tenant_id "
            "WHERE tenant_id IS NULL AND legacy_tenant_id IS NOT NULL"
        )

.. warning::

   **The zero-NULL gate still applies.** A denormalized column is often
   incomplete -- e.g. a "warn and skip when no tenant is set" emit path leaves
   some rows with a NULL legacy value. Those rows will still be NULL after the
   ``UPDATE`` and will fail the verification below (correctly). Handle them
   explicitly (a cross-schema fallback, or delete/repair) before tightening to
   ``null=False``. Never assume the legacy column is complete.

Verification -- the hard gate before tightening the schema
-----------------------------------------------------------

The backfill is **not done** until every row carries a tenant. Assert it
explicitly, inside the bypass block, for **each** migrated table:

.. code-block:: python

    with connection.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.blog_note WHERE tenant_id IS NULL")
        nulls = cur.fetchone()[0]
        assert nulls == 0, "backfill incomplete: %d NULL tenant_id rows remain" % nulls

This count **must be 0** before you proceed. This is the same NULL-row condition
the framework's own safeguards check: ``TenantRLSModel.has_unscoped_rows()``
(``django_tenants/rls/models.py``) runs a ``SELECT EXISTS(SELECT 1 FROM <table>
WHERE <tenant>_id IS NULL)``, and the ``post_migrate`` auto-enable hook uses it
to **skip** (with a loud warning) any table that still has unscoped rows;
``manage.py enable_rls`` warns but proceeds. Do not rely on those warnings as
your gate -- make the assertion fail your migration instead.

You **must also** cross-check the copied counts against the sources -- this is
**not optional whenever you batched the backfill**. A batch that breaks
mid-tenant leaves the zero-NULL check passing (every *copied* row has a non-NULL
``tenant_id``; the un-copied rows are simply absent, not NULL), so only the
per-tenant source-vs-destination count catches the silently-dropped rows:

.. code-block:: python

    with bypass_rls(), connection.cursor() as cur:
        for tenant in TenantModel.objects.exclude(schema_name=public):
            cur.execute('SELECT count(*) FROM "%s".blog_note' % tenant.schema_name)
            src = cur.fetchone()[0]
            cur.execute(
                "SELECT count(*) FROM public.blog_note WHERE tenant_id = %s",
                [tenant.pk],
            )
            dst = cur.fetchone()[0]
            assert src == dst, (
                "tenant %s: source=%d copied=%d" % (tenant.schema_name, src, dst)
            )

Only once **both** checks pass for **all** migrated tables should you move on to
tightening ``tenant_id`` to ``null=False`` (the ``AlterField`` migration) and
then enabling RLS. Those are the subjects of the next step; the framework's
enable path is documented at :ref:`rls-step-6-enable`.


.. _rls-migration-step-4-enable:

Step 4 -- Enabling RLS: auto, command, or migration operations
==============================================================

By the end of :ref:`Step 3 <rls-migration-step-3-backfill>` every row in the
table carries a real ``tenant_id``. This step turns RLS *on*: it locks the
column down to ``NOT NULL``, enables row-level security, and creates the
isolation policy. Up to now the table has behaved exactly like an ordinary
table; from here on PostgreSQL enforces tenant isolation in the kernel.

Order matters and is non-negotiable. Enabling RLS *before* every row is
backfilled makes the un-backfilled rows invisible to every tenant, because a
``NULL`` ``tenant_id`` never matches the policy. The full reasoning lives in
:ref:`rls-null-rows`; this step assumes the backfill is complete and verified.

.. _rls-migration-tighten-not-null:

First: verify zero NULL rows, then tighten to ``NOT NULL``
----------------------------------------------------------

Do **not** add ``null=False`` and enable RLS in one motion. Confirm the backfill
left no gaps, then tighten the column in its own ``AlterField`` migration:

.. code-block:: pycon

    >>> from blog.models import Note
    >>> Note.objects.filter(tenant__isnull=True).count()
    0

Only when that count is ``0`` for every migrated model, add the
``AlterField``. The field passed to ``AlterField`` must match the ``tenant``
field that ``TenantRLSModel`` actually declares (it sets ``on_delete=CASCADE``,
``db_index=True`` and ``related_name="+"``) -- otherwise ``makemigrations`` will
detect drift and generate a follow-up migration:

.. code-block:: python

    from django.db import migrations, models
    import django.db.models.deletion
    from django.conf import settings

    class Migration(migrations.Migration):
        dependencies = [
            ("blog", "0003_backfill_note_tenant"),
        ]
        operations = [
            migrations.AlterField(
                model_name="note",
                name="tenant",
                field=models.ForeignKey(
                    null=False,
                    on_delete=django.db.models.deletion.CASCADE,
                    db_index=True,
                    related_name="+",
                    to=settings.TENANT_MODEL,
                ),
            ),
        ]

The ``NOT NULL`` constraint is a database-level guard: once it is in place,
PostgreSQL itself rejects any future insert that would create an un-scoped row,
so the "invisible row" failure mode cannot recur. Enable RLS *after* this
``AlterField``, never before.

.. warning::

   ``AlterField`` to ``NOT NULL`` takes a table-level lock and (on older
   PostgreSQL) a full table scan to validate existing rows. Treat it as a
   scheduled, locking DDL -- see :ref:`the lock/downtime profile
   <rls-migration-enable-locks>` below.

Three ways to enable -- and which to use for an upgrade
-------------------------------------------------------

There are three ways to enable RLS, documented in full at
:ref:`rls-step-6-enable`. For an upgrade of an existing populated deployment,
**Option A is the wrong choice** and Options B or C are correct. Each is
summarised here with the upgrade-specific guidance.

Option A -- automatic via ``post_migrate`` (greenfield only)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When ``TENANT_RLS_AUTO_ENABLE`` is ``True`` (the default) and
``TENANT_RLS_ENABLED`` is ``True``, the ``django_tenants.rls`` app connects a
``post_migrate`` handler that enables RLS and creates the policy for every
concrete ``TenantRLSModel`` subclass in the migrated app -- **inside the same**
``migrate`` **that created or altered the table.**

For a brand-new empty table that is exactly right. For an *upgrade* it is a
trap: the auto-enable would fire in the same ``migrate`` that adds the column,
turning RLS on before you have backfilled and hiding every un-backfilled row.

.. important::

   For an upgrade, set ``TENANT_RLS_AUTO_ENABLE = False`` for the entire
   migration journey (add column -> backfill -> ``NOT NULL`` -> enable). Enable
   RLS yourself with Option B or C *after* the backfill, then re-enable
   auto-enable later if you want new greenfield tables to pick it up
   automatically.

   .. code-block:: python

       # settings.py -- during the upgrade
       DJANGO_TENANTS_RLS = {
           "TENANT_RLS_ENABLED": True,
           "TENANT_RLS_AUTO_ENABLE": False,
       }

Option B -- ``manage.py enable_rls`` (recommended for upgrades)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run the bundled command after the backfill and ``NOT NULL`` migrations are
applied:

.. code-block:: console

    $ python manage.py enable_rls                 # all TenantRLSModel subclasses
    $ python manage.py enable_rls --app blog      # limit to one app label
    $ python manage.py enable_rls --model note    # limit to one model

The ``--app`` and ``--model`` filters let you migrate one app (or one model) at
a time -- useful for a staged rollout where only some apps move to shared-schema
RLS. (If ``TENANT_RLS_ENABLED`` is ``False`` the command warns and enables RLS
anyway, since you invoked it deliberately.)

.. danger::

   ``manage.py enable_rls`` **warns but proceeds** if a table still has
   ``tenant_id IS NULL`` rows. It prints a prominent warning naming the model
   and the fact that those rows will become invisible to all tenants, then
   enables RLS anyway -- because you invoked it deliberately. The command does
   **not** stop you from hiding data; it is your responsibility to confirm the
   :ref:`backfill <rls-migration-step-3-backfill>` is complete first. This is
   the key difference from the auto-enable hook, which *skips* such tables.

Option C -- explicit migration operations (reproducible, versioned)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For reproducible, versioned RLS state -- so a fresh ``migrate`` of the codebase
reconstructs the exact same database state -- add the operations from
``django_tenants.rls.operations`` to a migration that depends on the ``NOT
NULL`` ``AlterField``:

.. code-block:: python

    from django.db import migrations
    from django_tenants.rls.operations import EnableRLS, CreateTenantPolicy

    class Migration(migrations.Migration):
        dependencies = [
            ("blog", "0004_note_tenant_not_null"),
        ]
        operations = [
            EnableRLS("note"),
            CreateTenantPolicy("note"),
        ]

* ``EnableRLS("note")`` runs ``ENABLE ROW LEVEL SECURITY`` and, when
  ``TENANT_RLS_FORCE`` is on (the default), ``FORCE ROW LEVEL SECURITY``. It is
  **reversible**: reversing this migration (e.g. ``migrate blog 0004``) runs
  ``EnableRLS``'s backward step, which un-forces first (so the persistent
  ``FORCE`` attribute does not survive to a later re-enable) and then disables
  RLS.
* ``CreateTenantPolicy("note")`` builds and creates the tenant-isolation
  policy. With ``name`` left at its default, the policy name resolves at apply
  time to ``"<db_table>_tenant_isolation"`` -- the *same* name the auto path and
  ``manage.py enable_rls`` create, so reversing the migration / ``DropPolicy``
  later targets the identical policy. Its full signature
  (``name``, ``tenant_field``, ``session_variable``, ``bypass_variable``,
  ``pk_cast``, ``operation``, ``permissive``, ``roles``) and round-trip
  behaviour are documented at :ref:`rls-step-6-enable`.

Each operation is a no-op against a non-RLS schema editor (every database step
is guarded by ``hasattr``), so a migration containing them still runs cleanly
under the stock django-tenants backend.

Because Option C is versioned, it is the best fit when your team requires every
environment to be reconstructable from migrations alone. Option B is simplest
for a one-time, hands-on production cutover. Both are correct for an upgrade;
Option A is not.

.. _rls-migration-null-safeguards:

NULL-row safeguards (and why they are not a substitute for backfilling)
-----------------------------------------------------------------------

The three paths handle a still-NULL table differently. Know which you are
relying on:

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Path
     - Behaviour when ``tenant_id IS NULL`` rows remain
   * - Option A (auto ``post_migrate``)
     - **Skips** the table. The hook calls ``model.has_unscoped_rows()`` and,
       if any NULL rows exist, logs a loud warning and does **not** enable RLS
       on that model -- enabling would hide those rows.
   * - Option B (``enable_rls``)
     - **Warns but proceeds.** Prints a prominent warning naming the model,
       then enables RLS anyway.
   * - Option C (migration op)
     - **No NULL check.** The operation runs the DDL unconditionally; you are
       expected to have ordered the migration after the backfill and
       ``NOT NULL``.

The auto-enable hook also never silently swallows an *enable failure*. If
enabling a model raises, the hook logs the full traceback via
``logger.exception`` and flags that table's isolation state as
**INDETERMINATE**, but it does not crash ``migrate`` -- so a clean
``migrate`` exit does **not** prove RLS is on. See :ref:`rls-null-rows` for the
underlying detail.

.. caution::

   These safeguards reduce blast radius; they do not replace the backfill. The
   only safe state to enable RLS in is "zero NULL ``tenant_id`` rows, column is
   ``NOT NULL``." Reach that state first (Steps 2--3 and the ``AlterField``
   above), *then* enable.

``FORCE ROW LEVEL SECURITY`` and ``WITH CHECK`` -- why isolation is real
------------------------------------------------------------------------

``TENANT_RLS_FORCE`` defaults to ``True``, so enabling RLS (by any path) also
issues ``ALTER TABLE ... FORCE ROW LEVEL SECURITY``. This is
security-critical: without ``FORCE``, the table-owner role -- the role your
application connects as -- silently bypasses the policy, and isolation is an
illusion. ``FORCE`` makes the policy apply to the owner too. The rationale is
covered in :ref:`rls-mechanism`.

The created policy also carries a ``WITH CHECK`` clause, which rejects writes
that would create or move a row into the wrong tenant -- not just filters reads.
A ``CREATE POLICY`` that had neither a ``USING`` nor a ``WITH CHECK`` expression
would be invalid SQL and is refused outright by the schema editor.

.. danger::

   ``FORCE`` does **not** stop a PostgreSQL ``SUPERUSER`` or ``BYPASSRLS`` role
   -- those roles bypass *all* RLS, policy and ``FORCE`` notwithstanding. Your
   app must connect as a ``NOSUPERUSER NOBYPASSRLS`` role; the W003 system check
   is an **error** that blocks ``check`` and ``migrate`` otherwise (opt out only
   via ``TENANT_RLS_ALLOW_BYPASS_ROLE = True``). See :ref:`rls-database-role`.

.. _rls-migration-enable-locks:

Lock and downtime profile of the enable DDL
-------------------------------------------

Enabling RLS issues real DDL that takes **table-level locks**. Schedule it like
any locking migration:

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Statement
     - Lock / cost
   * - ``ALTER TABLE ... ENABLE ROW LEVEL SECURITY``
     - Table-level lock. Schedule it.
   * - ``ALTER TABLE ... FORCE ROW LEVEL SECURITY``
     - Table-level lock. Schedule it.
   * - The ``NOT NULL`` ``AlterField`` (prerequisite, above)
     - Table-level lock; may scan the table to validate. Schedule it.
   * - ``CREATE POLICY ...``
     - Cheap -- metadata only, no table scan.

In practice the ``NOT NULL`` ``ALTER`` and the ``ENABLE`` / ``FORCE`` statements
are the ones to plan a maintenance window (or low-traffic deploy) around;
``CREATE POLICY`` is effectively free.

Confirm the result -- do not trust ``migrate`` exit 0
-----------------------------------------------------

Because the auto-enable hook logs failures rather than raising, and because
``enable_rls`` proceeds past NULL-row warnings, a ``migrate`` that exits ``0``
is **not** proof that RLS is on and correct. Verify explicitly:

.. code-block:: console

    $ python manage.py check --database default

(Use the alias matching ``TENANT_DB_ALIAS`` if it is not ``default``.) Then
review the application logs for any ``RLS auto-enable SKIPPED`` /
``RLS auto-enable FAILED`` / ``INDETERMINATE`` messages. Only once
``check`` passes clean and the logs are quiet should you consider the table's
isolation enabled.

With RLS enabled and verified, proceed to
:ref:`Step 6 <rls-migration-validate>` to prove isolation end-to-end before
sending production traffic.


.. _rls-migration-null-trap:

The NULL ``tenant_id`` trap (invisible, not lost)
=================================================

.. danger::

   **Enabling RLS on a table that still has any ``tenant_id IS NULL`` row makes
   those rows invisible to every tenant.** This is the single most likely
   data-disappearance incident during a migration. The rows are *not* deleted --
   but to your application they have vanished.

Why a NULL row matches no tenant
--------------------------------

The tenant policy compares each row's ``tenant_id`` against the active tenant
session variable. When ``tenant_id`` is ``NULL`` that comparison is
``NULL = <pk>``, which evaluates to ``NULL`` -- never ``true``. And because an
active tenant is never ``NULL`` (a request always runs under a concrete tenant
pk, set via ``rls_context()``), a NULL-tenant row can satisfy *no* tenant's
policy, no matter which tenant is active. It is filtered out of every query.

Invisible, not deleted
----------------------

The rows are still on disk. They reappear, unchanged, under ``bypass_rls()`` or
after you run ``manage.py disable_rls``. Nothing was destroyed -- the policy is
simply hiding them. But for ordinary tenant-scoped application traffic they have
effectively disappeared, and they stay gone until you backfill ``tenant_id``
(under bypass) so each row re-matches a real tenant.

The rule: zero NULL rows before you enable
------------------------------------------

This is exactly why the staged upgrade ordering is **strict and
non-negotiable**: complete the backfill so that *no* ``tenant_id IS NULL`` rows
remain, and only then enable RLS. See :ref:`rls-upgrade-existing` for the full
ordering and :ref:`rls-backfill-recipe` for the backfill itself.

Built-in protections
--------------------

The package tries hard to stop you from hiding data by accident:

* The ``post_migrate`` auto-enable hook **skips** any model whose table still
  has NULL ``tenant_id`` rows and logs a loud warning instead of enabling RLS on
  it. (It calls ``has_unscoped_rows()`` per model and ``continue``\ s.)
* ``manage.py enable_rls`` prints a prominent warning naming the affected model,
  then **proceeds anyway** -- because you invoked it deliberately. Do not ignore
  that warning.

Both checks call the same internal helper,
``TenantRLSModel.has_unscoped_rows()``, which runs a cheap
``SELECT EXISTS(SELECT 1 FROM <table> WHERE <tenant>_id IS NULL)`` on the tenant
DB alias.

Detection recipe
----------------

Before enabling RLS, count the un-backfilled rows for every model you are
migrating. From a Django shell (no active tenant needed -- RLS is not on yet):

.. code-block:: pycon

   >>> from myapp.models import Invoice
   >>> Invoice.objects.filter(tenant__isnull=True).count()
   0   # must be 0 before you enable RLS

Or directly in SQL against the tenant database:

.. code-block:: sql

   SELECT count(*) FROM myapp_invoice WHERE tenant_id IS NULL;
   -- must return 0 before enabling RLS

A non-zero count means you are not ready: finish the backfill first. For the
mechanics of *why* this happens and how the protections behave, defer to the
full explanation in :ref:`rls-null-rows`; this alert is just the count query and
the pointer.


.. _rls-migration-step-5-code:

Step 5 -- Application, script, and admin code changes
=====================================================

Once a model inherits from ``django_tenants.rls.models.TenantRLSModel`` and RLS
is enforced on its table (Steps 3--4 and :ref:`rls-step-6-enable`), the database
itself filters every query by the active tenant. This step tells you precisely
which code keeps working untouched and which code must take explicit action.

The short version: **ordinary request-cycle ORM code needs no changes.** The
code that needs attention is the code that runs *without* an HTTP request to
establish the tenant -- management commands, Celery tasks, data migrations -- and
the code that deliberately reaches across tenants -- the admin and aggregation.

Querysets are unchanged -- do not add a ``tenant=`` filter
----------------------------------------------------------

Under RLS the tenant filter lives in the **database policy**, not in your
Python. A request whose middleware has activated tenant ``5`` will see only
tenant ``5``'s rows for *every* query against an RLS table, with no ORM change:

.. code-block:: python

    # In a normal request (tenant already activated by the middleware):
    Note.objects.all()                      # returns ONLY this tenant's rows
    Note.objects.filter(archived=False)     # still scoped by the policy
    note.save()                             # tenant_id auto-filled (see below)

This is why the package **intentionally does not replace the default manager**.
``TenantRLSModel`` adds the ``tenant`` FK and a ``save()`` override, but
``objects`` remains a plain ``models.Manager``. There is no implicit
``.filter(tenant=...)`` to remove or reason about: isolation is enforced one
layer down, by PostgreSQL, on every connection. Adding a redundant ``tenant=``
filter is harmless but unnecessary, and it gives a false impression that the
ORM is what protects you -- it is not. See :ref:`rls-mechanism`.

.. important::

   "Secure by default" cuts both ways. If **no** tenant is active on the
   connection, the policy matches **zero rows** -- queries silently return
   empty results and inserts are rejected. Request-cycle code is fine because
   the middleware always activates a tenant. Request-less code (the next two
   subsections) must activate one explicitly, or it will appear to "see
   nothing."

Cross-tenant and request-less code: ``tenant_context`` / ``schema_context``
---------------------------------------------------------------------------

The existing ``django_tenants.utils.tenant_context`` and ``schema_context``
context managers still activate a tenant outside a request. Internally they call
``connection.set_tenant()``, which the RLS backend turns into the per-connection
tenant GUC (and pins the schema to ``public``, since RLS mode keeps all data in
one schema):

.. code-block:: python

    from django_tenants.utils import tenant_context, schema_context

    with tenant_context(tenant):     # activates `tenant` (a Tenant INSTANCE)
        Note.objects.all()           # sees only `tenant`'s rows

.. danger::

   **Under RLS, ``schema_context(<schema_name string>)`` silently returns zero
   rows.** ``schema_context`` is given only a *name*, so it activates a synthetic
   ``FakeTenant`` that has **no primary key** -- and the RLS GUC is the tenant
   **pk**. A pk-less tenant sets the GUC to the empty sentinel, so the policy
   matches *nothing*: reads return nothing and writes fail the ``WITH CHECK``.
   This is fail-closed (no data leak) but it is a silent correctness bug, and it
   is exactly the pattern schema-per-tenant background code tends to use
   (``with schema_context(snapshot_schema_name):``).

   Only ``tenant_context(<Tenant instance>)`` and ``rls_context(<instance or
   pk>)`` activate a *real* tenant under RLS. If your code is holding a
   ``schema_name`` string, resolve it to a ``Tenant`` (or its pk) first:
   ``tenant = Tenant.objects.get(schema_name=name)`` then
   ``with rls_context(tenant): ...``.

On exit, both managers **restore the previously active tenant** (or revert to
the public/no-tenant state if none was active) -- and they restore it from the
*target alias's* connection, which matters when ``TENANT_DB_ALIAS`` is not
``default``. Nesting is therefore correct.

These remain general-purpose and backend-agnostic. When you are writing new RLS
scripting code, prefer ``rls_context`` below -- it is the RLS-native entry point,
accepts a bare pk, and reads more clearly as "run as this tenant."

Scripts, management commands, Celery: ``rls_context(tenant_or_pk)``
-------------------------------------------------------------------

``django_tenants.rls.session.rls_context`` runs a block **as** a specific tenant
without an HTTP request. It accepts either a tenant **instance** or a bare
**pk**, remembers the previously active tenant on enter, applies the new one,
and restores the previous value on exit (an empty value restores the
"no tenant" sentinel), so nesting is correct.

.. code-block:: python

    from django_tenants.rls import rls_context   # convenience re-export

    # In a management command, cron job, or Celery task:
    with rls_context(tenant):          # an instance ...
        Note.objects.create(text="hi") # tenant auto-set; only this tenant visible

    with rls_context(tenant_pk):       # ... or a bare pk
        count = Note.objects.count()

Because it subclasses ``contextlib.ContextDecorator``, it also works as a
**decorator** -- convenient for a whole Celery task that always runs as one
tenant:

.. code-block:: python

    from celery import shared_task
    from django_tenants.rls import rls_context

    @shared_task
    def rebuild_index(tenant_pk):
        # Resolve the tenant from the pk the task was queued with, then
        # run the whole body scoped to it.
        with rls_context(tenant_pk):
            for note in Note.objects.all():
                ...

.. warning::

   A Celery task receives **no request**, so nothing activates a tenant for it.
   A task that queries an RLS model **without** an ``rls_context`` (or
   ``bypass_rls``) block runs with no active tenant and will see **zero rows** --
   a silent correctness bug, not an error. Pass the tenant pk into the task
   payload and wrap the body in ``rls_context``.

See :ref:`bypass-leak-note` for how bypass state interacts with tenant
(re)activation inside these blocks.

Admin, cross-tenant aggregation, data migrations: ``bypass_rls()``
------------------------------------------------------------------

When privileged code genuinely needs to see or write rows across **all**
tenants -- the Django admin, a cross-tenant report, a data migration --
use ``django_tenants.rls.session.bypass_rls``. It sets the bypass GUC to
``on``, which the policy explicitly ``OR``\ s in, so it works **even under**
``FORCE ROW LEVEL SECURITY`` and even for the table-owner role:

.. code-block:: python

    from django_tenants.rls import bypass_rls   # convenience re-export

    with bypass_rls():
        Note.objects.all()        # sees ALL tenants' rows; writes unrestricted

.. warning::

   ``bypass_rls()`` removes tenant isolation for the duration of the block. It
   is the single most dangerous primitive in RLS mode -- a too-wide block is
   exactly how cross-tenant leakage happens. Keep the block **as small as
   possible** and scope it to the precise queryset that needs cross-tenant
   visibility. In the admin, scope it to the specific views/querysets, not the
   whole ``ModelAdmin``.

For the full admin and cross-tenant patterns (and the rationale behind the
bypass design), see the "Admin and cross-tenant access" and
"bulk_create and other save()-bypassing paths" sections in :doc:`rls`.

.. _rls-migration-bypass-innermost:

Open ``bypass_rls()`` at the innermost scope
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Bypass is bound to the connection and is **reset to ``off`` on every tenant
(re)activation that goes through the backend's ``set_tenant()``** -- that is, on
every request and on any ``tenant_context`` / ``schema_context`` /
``tenant.activate()``. This is deliberate (every request starts secure). Note
that ``rls_context()`` does **not** go through ``set_tenant()`` -- it sets only
the tenant GUC and leaves the bypass flag untouched -- so a ``bypass_rls()``
block is **preserved** across a ``rls_context()`` nested inside it, but is reset
by a ``tenant_context`` / ``schema_context`` nested inside it.

.. code-block:: python

    # CAREFUL -- a nested tenant_context/schema_context resets bypass to off:
    with bypass_rls():
        with tenant_context(other_tenant):  # <-- set_tenant() resets bypass OFF
            Note.objects.all()              # NOT a bypass; scoped to other_tenant

    # ROBUST -- activate first, then open bypass at the innermost scope:
    with tenant_context(other_tenant):
        with bypass_rls():                  # opened AFTER any activation
            Note.objects.all()              # sees ALL tenants' rows

As a rule, open ``bypass_rls()`` **after** any tenant activation so the block is
not silently cancelled by a nested ``set_tenant()``. See :ref:`bypass-leak-note`
for why this reset exists and what stops a leaked bypass from crossing requests.

``save()`` auto-fills ``tenant_id``; bulk paths do not
------------------------------------------------------

``TenantRLSModel.save()`` auto-populates the tenant FK from the **active
connection** when it is unset, so existing code that creates objects without
ever mentioning a tenant keeps working as a drop-in. The GUC (the value set by
the request, ``rls_context``, or ``tenant_context``) is the **source of truth**;
``save()`` resolves it in this order:

#. the connection's tenant GUC (``connection._rls_tenant_id``), if a non-empty
   string;
#. otherwise the bound ``connection.tenant.pk``, if a tenant object is attached.

An explicitly-set ``tenant`` is never overwritten, and when RLS is disabled the
override is a no-op.

**Operations that bypass** ``save()`` get **no** auto-population. This includes
``QuerySet.bulk_create()``, ``QuerySet.bulk_update()``, and raw SQL inserts. You
**must pass the tenant explicitly** on these paths:

.. code-block:: python

    from django_tenants.rls import rls_context

    with rls_context(tenant):
        Note.objects.bulk_create([
            Note(text="a", tenant=tenant),   # explicit -- bulk_create skips save()
            Note(text="b", tenant=tenant),
        ])

.. note::

   The policy's ``WITH CHECK`` clause is your safety net here: an ``INSERT``
   whose ``tenant_id`` does not match the active tenant GUC is **rejected by
   PostgreSQL**, even though no Python exception fired beforehand. A
   ``bulk_create`` of rows with a missing or wrong ``tenant_id`` will error at
   the database rather than silently writing cross-tenant rows. This is defense
   in depth -- but rely on it as a backstop, not as your primary mechanism: set
   the tenant explicitly on every bulk path. See
   :ref:`bypass-leak-note` for the related bypass caveat.

Migration audit checklist
-------------------------

When converting an app to RLS, grep for and review each of these patterns:

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Pattern in your code
     - Action under RLS
   * - Plain queryset in a request (``Model.objects...``)
     - No change. The policy filters it.
   * - Management command / cron / script touching RLS models
     - Wrap in ``rls_context(tenant_or_pk)`` (or ``bypass_rls()`` if genuinely
       cross-tenant). Without it: zero rows.
   * - Celery task touching RLS models
     - Pass the tenant pk in the payload; wrap the body in ``rls_context``
       (or decorate it).
   * - ``obj.save()`` / ``Model.objects.create()``
     - No change. ``tenant_id`` is auto-filled from the active tenant.
   * - ``bulk_create`` / ``bulk_update`` / raw inserts
     - Set ``tenant=`` explicitly on every object. ``WITH CHECK`` rejects
       mismatches at the DB.
   * - Admin / cross-tenant reports / data migrations
     - Wrap the narrowest possible block in ``bypass_rls()``, opened **after**
       any tenant activation.

API quick reference
-------------------

Convenience imports from the package root::

    from django_tenants.rls import rls_context, bypass_rls

Lower-level, per-connection helpers in ``django_tenants.rls.session`` when you
need finer control::

    from django_tenants.rls.session import (
        set_current_tenant,     # set the tenant GUC on a connection
        clear_current_tenant,   # set it to the '' (no-tenant) sentinel
        get_current_tenant_id,  # read it back (None if unset/empty)
        set_bypass,             # set the bypass GUC ('on'/'off')
        get_bypass,             # read the bypass GUC
    )

For the full API and reference detail, see :doc:`rls`.


.. _rls-migration-validate:

Step 6 -- Validate isolation before trusting it
================================================

A successful ``migrate`` proves only that the tenant column, the policies and
``FORCE ROW LEVEL SECURITY`` were *created*. It does **not** prove that the
database is actually *enforcing* them for your application connection. The most
dangerous RLS failure mode is *fail-open*: the tables look protected, every
query succeeds, and yet there is no isolation at all (see :ref:`rls-mechanism`
and the danger admonition in :ref:`rls-database-role`). This step is the
runnable proof-of-isolation procedure that the reference doc deliberately leaves
to you. **Do not enable RLS in production on the strength of a green migrate --
run these tests first.**

.. danger::

   **Never run the isolation tests as a superuser.** PostgreSQL bypasses *all*
   row-security policies for a ``SUPERUSER`` or ``BYPASSRLS`` role, even with
   ``FORCE ROW LEVEL SECURITY`` (:ref:`rls-mechanism`). If you connect as
   ``postgres`` (or any role carrying ``BYPASSRLS``) you will see every tenant's
   rows and conclude -- wrongly -- that isolation is broken, or worse, you will
   "fix" a policy that was always correct. Every query below must be issued as
   the dedicated ``NOSUPERUSER NOBYPASSRLS`` application role configured in
   :ref:`rls-database-role`.

Confirm the safety nets with ``manage.py check``
------------------------------------------------

Run the system checks against the tenant database alias. The catalog of these
checks lives in :ref:`rls-system-checks`; here we use two of them as gates.
Pass the alias that ``get_tenant_database_alias()`` resolves to -- usually
``default``:

.. code-block:: console

   $ python manage.py check --database default

* **W003 must NOT fire.** ``W003`` is reported as an **Error** (not a warning):
  it reads ``current_user``'s ``rolsuper`` / ``rolbypassrls`` from ``pg_roles``
  and fails if either is set. Because it is an error it *blocks* ``check`` (and
  therefore ``migrate``) from exiting cleanly. If you see::

     ERROR: django_tenants_rls.W003: TENANT_RLS_ENABLED is True but the database
     role 'postgres' is a superuser, so PostgreSQL bypasses ALL row-security
     policies: tenant isolation is NOT enforced for this connection (even with
     FORCE ROW LEVEL SECURITY).

  then your application connects as a bypassing role and **nothing you test
  below means anything**. Fix the ``DATABASES`` credentials to use the
  least-privilege role from :ref:`rls-database-role` before continuing. (The
  opt-out ``TENANT_RLS_ALLOW_BYPASS_ROLE = True`` exists only for deployments
  whose isolation is guaranteed by another mechanism; setting it disables this
  guard, so do not use it to make the error go away.)

* **W001 must NOT fire.** ``W001`` warns that ``TENANT_RLS_ENABLED`` is ``True``
  but nothing will actually *apply* the policies -- i.e. neither the
  ``django_tenants.rls.backend`` ``ENGINE`` nor ``TenantRLSMiddleware`` is wired
  up. With no enforcer, the tenant session variable is never set, so every query
  evaluates the policy against an unset variable and silently returns nothing.
  A clean run (no ``W001``) proves an enforcer is in place.

A ``check`` that prints no ``W001`` and no ``W003`` is the green light for the
behavioural tests below. A green ``check`` alone is **not** proof of isolation
-- it only proves the safety nets are armed.

The single GUC behind every test
---------------------------------

The policy expression generated for each table is the same string for both the
``USING`` clause (which rows are *visible*) and the ``WITH CHECK`` clause (which
rows may be *written*)::

   (tenant_id = NULLIF(current_setting('django_tenants.tenant_id', true), '')::<cast>
    OR current_setting('django_tenants.bypass_rls', true) = 'on')

Two consequences drive the tests:

* When the tenant GUC is the **empty string**, ``NULLIF(..., '')`` is ``NULL``,
  the equality is ``NULL`` (never true), and -- unless bypass is ``on`` -- the
  table returns **zero rows**. This is the secure-by-default behaviour: the RLS
  backend re-asserts ``django_tenants.tenant_id`` as ``''`` on every cursor when
  no tenant is active.
* ``WITH CHECK`` uses the identical expression, so a write whose ``tenant_id``
  does not equal the active tenant is rejected by PostgreSQL.

In application code you drive the GUC with the context managers from
``django_tenants.rls.session`` -- ``rls_context(tenant_or_pk)`` and
``bypass_rls()``. The examples use those so the test exercises exactly what
production does.

Positive test: each tenant sees only its own rows
--------------------------------------------------

Pick two real tenants whose data you backfilled in
:ref:`rls-backfill-recipe`. Open a Django shell **with the application role**
(``python manage.py shell``) and assert visibility:

.. code-block:: python

   from django_tenants.rls.session import rls_context
   from myapp.models import Note            # a TenantRLSModel

   with rls_context(tenant_a):
       a_ids = set(Note.objects.values_list("pk", flat=True))

   with rls_context(tenant_b):
       b_ids = set(Note.objects.values_list("pk", flat=True))

   # Inside A's context you see only A's rows; same for B; no overlap.
   assert a_ids and b_ids
   assert a_ids.isdisjoint(b_ids)

If ``a_ids`` and ``b_ids`` overlap (or are equal), you are almost certainly
connected as a bypassing role -- go back to the ``check`` step and re-verify
``W003``.

Secure-by-default test: no tenant => zero rows
----------------------------------------------

With no active tenant, the table must return nothing. This is the property that
makes a forgotten ``rls_context`` *safe* rather than a leak.

.. code-block:: python

   from myapp.models import Note

   # No rls_context: the connection's tenant GUC is the empty-string sentinel.
   assert Note.objects.count() == 0

A non-zero count here means either the GUC is being left set from a previous
operation, or -- again -- you are a bypassing role. It must be exactly ``0``.

``WITH CHECK`` test: wrong-tenant writes are rejected
-----------------------------------------------------

Isolation is not only about reads. Attempt to *stamp* a row with the wrong
tenant while a different tenant is active. PostgreSQL must refuse it at the
database level, regardless of what Python believes:

.. code-block:: python

   from django.db import DatabaseError
   from django_tenants.rls.session import rls_context
   from myapp.models import Note

   try:
       with rls_context(tenant_a):
           # Pass an explicit tenant: save() only auto-stamps tenant_id when it
           # is unset, so an explicitly-set wrong tenant is sent to the database
           # as-is and the policy's WITH CHECK clause must reject it.
           Note.objects.create(text="leak", tenant=tenant_b)
   except DatabaseError as exc:
       print("rejected by WITH CHECK:", exc)   # expected path
   else:
       raise SystemExit("WITH CHECK did NOT reject a cross-tenant write!")

The same check applies to ``UPDATE`` -- attempting to move a row to another
tenant while that other tenant is not the active one is rejected identically.
This is defense in depth: the database is the source of truth even if
application code is buggy.

Bypass test: privileged code sees everything, and the counts reconcile
-----------------------------------------------------------------------

``bypass_rls()`` turns on the bypass GUC, which the policy explicitly ``OR``\ s
in, so it works even for the table owner under ``FORCE``. Use it to confirm the
*global* row count matches what you backfilled:

.. code-block:: python

   from django.db.models import Count
   from django_tenants.rls.session import rls_context, bypass_rls
   from myapp.models import Note

   with bypass_rls():
       total = Note.objects.count()
       per_tenant_public = dict(
           Note.objects.values_list("tenant_id").annotate(n=Count("pk"))
       )

   # The bypass total must equal the sum of every tenant's rows.
   assert total == sum(per_tenant_public.values())

   # And the secure default must still hold for each individual tenant.
   recomputed = 0
   for tenant in (tenant_a, tenant_b):   # ... all tenants
       with rls_context(tenant):
           recomputed += Note.objects.count()
   assert recomputed == total            # no orphaned / NULL-tenant rows

If ``recomputed`` is *less* than ``total``, some rows have a ``tenant_id`` that
matches no active tenant -- typically rows still carrying ``NULL`` (which never
matches, see :ref:`rls-null-rows`) or a stale tenant id. Those rows are
invisible to every tenant and must be repaired before you trust isolation.

Reconcile against the originating schemas before decommission
-------------------------------------------------------------

The previous tests prove the shared ``public`` table is internally consistent.
Before you decommission the per-tenant schemas, prove that the migrated data is
*complete* -- that each tenant's per-tenant count under RLS equals the row count
in its original schema-per-tenant table.

.. code-block:: python

   from django_tenants.utils import schema_context
   from django_tenants.rls.session import rls_context
   from myapp.models import Note

   for tenant in Tenant.objects.exclude(schema_name="public"):
       with schema_context(tenant.schema_name):       # classic, per-schema table
           legacy = Note.objects.count()
       with rls_context(tenant):                       # shared public table, RLS
           migrated = Note.objects.count()
       assert legacy == migrated, (
           f"{tenant.schema_name}: legacy={legacy} migrated={migrated}"
       )

Run this for every tenant and every migrated model. Only when all counts
reconcile -- *and* the tests above pass -- do you have proof of isolation strong
enough to proceed toward decommissioning the old schemas. If anything fails, do
**not** continue; revisit the backfill and, if necessary, roll back per
:ref:`rls-rollback`.

.. note::

   The RLS backend re-asserts both the tenant and bypass GUCs from the
   connection's Python state on *every* cursor it opens, so these results are
   stable across reused connections and across transaction rollback **under
   session pooling**. Run the tests through your pooler in its production mode
   and as the same ``NOSUPERUSER`` role. If that mode is transaction/statement
   pooling, expect these checks to FAIL (stranded context or a leak) -- that is
   the documented incompatibility, not a test bug; switch the pooler to session
   mode (see :ref:`rls-migration-poolers`).


.. _rls-migration-decommission:

Step 7 -- Decommissioning the old per-tenant schemas
====================================================

Once isolation is validated (Step 6) and the per-tenant row counts have been
reconciled against ``public``, the old per-tenant PostgreSQL schemas are dead
weight: nothing in RLS mode reads from them. This step retires them safely.

.. danger::

   **Dropping a schema is destructive and irreversible.** ``DROP SCHEMA ...
   CASCADE`` deletes every table, index, sequence, and row in that schema in one
   statement, with no undo. Do not run any drop until all of the following are
   true:

   - Isolation has been validated end to end (see :ref:`rls-step-6-enable` and
     your :ref:`Step 6 verification <rls-migration-validate>`).
   - Every per-tenant table's row count has been reconciled against the
     corresponding ``public`` table, so you have proven no rows were lost or
     left behind during the backfill.
   - A **fresh, restorable backup** of the database has been taken and
     test-restored.

   If any of these is in doubt, stop. The per-tenant schemas are your last
   physical copy of the pre-migration data; once dropped, the only remaining
   copy is in ``public``.

Why the schemas are now safe to remove
--------------------------------------

In RLS mode there is exactly one schema, ``public``. The RLS backend pins the
connection's schema back to ``public`` on every tenant activation -- in
``set_tenant`` (``django_tenants/rls/backend/base.py``) it sets
``self.schema_name = public``, calls ``self.set_settings_schema(public)``, and
sets ``self.search_path_set_schemas = None``, so
``connection.schema_name == get_public_schema_name()`` for all tenant
operations and isolation is enforced by the policies, not the ``search_path``.
The per-tenant schemas are therefore **never on the search path at runtime**
once an app is migrated to RLS; they are unreferenced and can be removed without
affecting live serving.

Precondition: stop creating and auto-dropping schemas
-----------------------------------------------------

Before you drop anything, make sure no new per-tenant schemas can appear and
that deleting a tenant row will not try to drop a schema (which, mis-pointed,
could target ``public``). If you have not already done so as part of
:ref:`shared-apps-vs-tenant-apps`, set both flags on your ``TenantMixin``
subclass:

.. code-block:: python

    from django_tenants.models import TenantMixin

    class Client(TenantMixin):
        # ... your fields ...
        auto_create_schema = False   # RLS mode: keep a single public schema
        auto_drop_schema = False     # deleting a tenant must not drop a schema

With ``auto_create_schema = False``, creating a new tenant no longer runs
``TenantMixin.save()``'s schema-creation path (which is gated on
``is_new and self.auto_create_schema``), so no fresh empty per-tenant schema is
ever created. With ``auto_drop_schema = False``, deleting a tenant row does not
attempt to drop a schema as a side effect: ``TenantMixin.delete()`` only issues
``DROP SCHEMA ... CASCADE`` when ``auto_drop_schema`` (or an explicit
``force_drop``) is set. Both flags are described in
:ref:`shared-apps-vs-tenant-apps`.

.. important::

   The tenant and domain rows, and your ``TENANT_MODEL`` itself, **stay**. You
   are removing only the per-tenant *schemas* -- not the tenant records. Routing
   and host resolution (``TenantMainMiddleware``, the domain table) are
   completely unchanged: the middleware still looks up the tenant by host and
   activates it; the RLS backend then scopes queries to that tenant inside
   ``public``. Do not delete tenant rows as part of decommissioning.

Soak first, then drop
---------------------

Serve production traffic entirely from ``public`` for a deliberate **soak
period** (days to weeks, sized to your traffic and confidence) before dropping
any schema. During the soak the per-tenant schemas remain on disk, untouched,
as a physical fallback: if Step 6 validation surfaces a problem, you can
investigate against the original per-tenant data instead of a backup.

Stage the drop behind a feature flag / soak window so the decision to retire the
schemas is reversible up to the moment you run ``DROP SCHEMA``. Recommended
sequencing:

#. Cut traffic over to RLS-on-``public`` (Steps 1--6 complete,
   ``TENANT_RLS_ENABLED = True``, RLS enabled on the tables).
#. Leave the per-tenant schemas in place and **observe** for the full soak
   window -- error rates, row counts, customer reports.
#. Only after the soak window passes cleanly, take a final backup and drop the
   obsolete schemas.

Because the schemas are unused at runtime, a problem found during the soak lets
you fall back: if you must temporarily return to schema-per-tenant for an app,
follow :ref:`rls-rollback` (RLS rollback is a two-part operation -- the flag
*and* ``disable_rls`` -- and the per-tenant data is still present in its schema
to fall back to).

Dropping the obsolete schemas
-----------------------------

After the soak window, identify the per-tenant schemas. They are named after
each tenant's ``schema_name`` and exclude ``public`` (and any other system
schema you keep). List them first:

.. code-block:: sql

    -- Inspect before you destroy. Adjust the exclusion list to your setup.
    SELECT nspname AS schema_name
    FROM pg_namespace
    WHERE nspname NOT IN ('public', 'pg_catalog', 'information_schema')
      AND nspname NOT LIKE 'pg_%'
    ORDER BY nspname;

Cross-check that list against your tenant rows so you only drop schemas you
recognise:

.. code-block:: console

    $ python manage.py shell -c "from myproject.customers.models import Client; print([t.schema_name for t in Client.objects.all()])"

Then drop each obsolete per-tenant schema. ``CASCADE`` is required because the
schema still contains the old tenant tables:

.. code-block:: sql

    -- Run per schema, after backup + soak. IRREVERSIBLE.
    DROP SCHEMA "tenant_acme" CASCADE;
    DROP SCHEMA "tenant_globex" CASCADE;
    -- ... one per retired tenant ...

.. warning::

   Never script a blanket "drop everything that is not ``public``". Always drop
   from an explicit, reviewed list of schema names, and never include
   ``public`` -- ``public`` holds your live RLS data. Drop a small batch first,
   verify the application is still healthy, then proceed with the rest.

Hybrid deployments: drop only the migrated apps' schemas
--------------------------------------------------------

If you run a permanent **hybrid** (some apps RLS-isolated in ``public``, others
still schema-per-tenant in ``TENANT_APPS`` -- see
:ref:`shared-apps-vs-tenant-apps`), do **not** drop the per-tenant schemas
wholesale. Apps that remain in ``TENANT_APPS`` still live in, and are migrated
into, each per-tenant schema; their tables and rows are active.

In a hybrid you therefore retire only the tables for the apps you actually
migrated to RLS, leaving the rest of each schema intact. Drop the specific
migrated tables rather than the whole schema:

.. code-block:: sql

    -- Hybrid: remove ONLY the tables of apps you migrated to RLS.
    -- The schema itself and the still-tenant-scoped apps' tables remain.
    DROP TABLE IF EXISTS "tenant_acme"."myrlsapp_invoice" CASCADE;
    DROP TABLE IF EXISTS "tenant_acme"."myrlsapp_lineitem" CASCADE;
    -- ... repeat per migrated table, per schema ...

Use a full ``DROP SCHEMA ... CASCADE`` only when **every** app for that tenant
has moved to RLS and the schema holds nothing but obsolete copies.

After decommissioning
---------------------

When the schemas are gone, nothing else changes: ``TENANT_MODEL``, the tenant
and domain rows, routing, and the RLS backend all continue to operate against
``public``. If you set ``TENANT_RLS_AUTO_ENABLE = False`` during the upgrade
(see :ref:`rls-upgrade-existing`), decide separately whether to re-enable it for
future tables -- that is independent of dropping the old schemas.


.. _rls-migration-rollback:

Rolling back: the two-part disable and the flag-only lockout
============================================================

Migrations go wrong, requirements change, and "we shipped RLS and now we regret
it" is a real state to plan for. This section covers how to reverse course
safely, whether you are mid-upgrade or already live on RLS. The single most
dangerous mistake here is assuming that flipping ``TENANT_RLS_ENABLED = False``
is a rollback. It is not -- on its own it locks you out of your own data.

For the full reference treatment of the two-part disable and the lockout
mechanics, see :ref:`rls-rollback`. This section does not duplicate that; it
adds the revert paths specific to an *in-flight* upgrade of an existing,
populated deployment.

Disabling RLS is a two-part operation
-------------------------------------

Turning RLS off requires changing **two independent things** -- one in your
settings, one in the database:

#. **The setting.** Set ``TENANT_RLS_ENABLED = False``. This makes the RLS
   backend stop setting the tenant session variable on each cursor and puts the
   subpackage inert.
#. **The database state.** Run ``manage.py disable_rls`` (or apply a
   ``DisableRLS`` + ``DropPolicy`` migration), which drops the policies on the
   table, un-forces RLS, and runs ``DISABLE ROW LEVEL SECURITY``.

.. code-block:: console

   # Part 2, for every TenantRLSModel:
   $ python manage.py disable_rls

   # Or scope it to one app / one model (both flags are accepted):
   $ python manage.py disable_rls --app billing
   $ python manage.py disable_rls --app billing --model invoice

Doing only part one is the foot-gun described below.

.. danger::

   **Flipping only the setting is not a rollback -- it is a lockout.**

   If you set ``TENANT_RLS_ENABLED = False`` but leave ``FORCE ROW LEVEL
   SECURITY`` and the policies in place on the table, the backend no longer sets
   the tenant session variable. The policy then compares ``tenant_id`` against
   the empty string, ``NULLIF('', '')`` evaluates to ``NULL``, and your
   ``NOSUPERUSER NOBYPASSRLS`` application role sees **zero rows on every query,
   on every table**. You have not relaxed enforcement; you have made all of your
   data invisible to the application.

   The cure is to also complete part two: run ``disable_rls`` (or apply the
   ``DisableRLS`` operation). Until both parts are done, the rollback is not
   real. See :ref:`rls-rollback`.

Your data is retained
---------------------

Disabling RLS **only removes the database-level enforcement**. It does not touch
your rows, and it does not drop the ``tenant_id`` column or the ``tenant`` FK --
both stay on the model and on the table. This is deliberate: a rollback should
not be destructive, and you will want the column intact if you later re-enable.

If you genuinely want to remove the ``tenant`` FK and column afterward, that is
a **separate, ordinary schema migration that you write yourself** (a normal
``RemoveField``). It is not part of disabling RLS, and you should only do it once
you are certain you are not re-enabling.

Why ``DisableRLS`` un-forces, and why ``DropPolicy`` is one-way
---------------------------------------------------------------

Two details of the migration operations matter when you reverse course:

- **``DisableRLS`` un-forces before it disables.** ``FORCE ROW LEVEL SECURITY``
  is a persistent table attribute. If it survived a disable/re-enable cycle, a
  later ``EnableRLS`` would silently inherit stale ``FORCE`` even if you had
  since set ``TENANT_RLS_FORCE = False``. To prevent that, ``DisableRLS`` (and
  the model's ``disable_rls()`` classmethod) un-forces the table -- when
  ``TENANT_RLS_FORCE`` is on -- before it disables RLS, so a clean re-enable
  starts from a clean state. Its reverse re-enables RLS and re-applies ``FORCE``
  when ``TENANT_RLS_FORCE`` is true, mirroring ``EnableRLS``.

- **``DropPolicy`` is irreversible.** The operation does **not** retain the
  original policy definition, so its reverse cannot recreate it
  (``DropPolicy.reversible = False``; running ``migrate`` backwards over it
  raises ``NotImplementedError``). To restore a dropped policy you re-create it
  forward with ``CreateTenantPolicy`` (or ``manage.py enable_rls``), not by
  reversing the drop.

Mid-migration revert
--------------------

Where you can safely retreat to depends on how far the upgrade got. Map your
situation to one of these:

**You backfilled, but have not cut reads over to the shared schema yet.**
   Your old per-tenant schemas are still authoritative and untouched. The
   shared-schema table now carries a populated ``tenant_id`` column, but nothing
   is reading from it under RLS. The safe move is simply to **keep serving from
   the per-tenant schemas** -- stop the upgrade, leave the backfilled column in
   place (it is harmless), and resume later. Do not enable RLS. If you had set
   ``TENANT_RLS_AUTO_ENABLE = False`` for the upgrade (as recommended in
   :ref:`rls-upgrade-existing`), there is no auto-enable hook to undo.

**You already enabled RLS and something is wrong.**
   For example, a bad backfill left NULL ``tenant_id`` rows invisible (see
   :ref:`rls-null-rows`). Restore full visibility immediately by completing the
   two-part disable:

   .. code-block:: console

      $ python manage.py disable_rls

   and set ``TENANT_RLS_ENABLED = False`` in settings. With enforcement removed,
   your ``NOSUPERUSER NOBYPASSRLS`` role can see every row again, including the
   NULL-``tenant_id`` rows that were hidden, so you can inspect and fix the
   backfill at leisure. The data was never deleted -- only filtered. When the
   backfill is correct and ``tenant_id`` is non-NULL on every row, re-enable
   (next section).

.. warning::

   When reverting, change **both** parts together, and prefer disabling the
   database state (``disable_rls``) *before or together with* clearing the
   setting. The reverse ordering -- clearing the setting while ``FORCE`` and the
   policies remain -- is exactly the flag-only lockout above.

Re-enabling after a revert
--------------------------

The path back on is the inverse of the disable, and because the ``tenant_id``
column and data were retained, there is nothing to backfill again:

#. Set ``TENANT_RLS_ENABLED = True`` (and ensure your app still connects as a
   ``NOSUPERUSER NOBYPASSRLS`` role -- see :ref:`rls-database-role`).
#. Re-create the enforcement:

   .. code-block:: console

      $ python manage.py enable_rls

   or apply ``EnableRLS`` + ``CreateTenantPolicy`` operations in a migration.

Because ``DisableRLS`` left the table un-forced and ``DropPolicy`` discarded the
old policy, the re-enable builds ``FORCE`` and the policy fresh from your current
settings -- so the state it produces reflects ``TENANT_RLS_FORCE`` as it stands
now, not whatever it was before the rollback.


.. _rls-migration-third-party:

Third-party packages and plugins under RLS
==========================================

Most of the migration above is about *your* models. The subtler risk is the
**rest of your stack**: a package that works perfectly under schema-per-tenant
can quietly misbehave -- or silently lose isolation -- once RLS mode is on,
because classic django-tenants gave it isolation "for free" through two
primitives RLS removes: a distinct ``connection.schema_name`` per tenant, and a
per-schema *copy* of every ``TENANT_APPS`` table reached via ``search_path``.
Under RLS there is one ``public`` schema, ``connection.schema_name`` is pinned to
the literal ``"public"`` for every tenant, and isolation is carried only by the
tenant session GUC plus a policy on tables that have a ``tenant_id`` column.
Anything that previously rode on schema-per-tenant must now be re-derived from
tenant *identity* (``connection.tenant``), not from ``connection.schema_name``.

Three failure classes follow; walk your dependency list against them.

The three failure classes
-------------------------

#. **Unpolicied third-party models share data across tenants (silent, worst
   case).** RLS applies only to tables with a ``tenant_id`` column and a policy
   -- i.e. ``TenantRLSModel`` subclasses (or tables you policy by hand). A
   third-party model you cannot edit lands in the single ``public`` table with
   **no** ``tenant_id`` and **no** policy; queries succeed and the rows are
   shared by every tenant. The drift check :ref:`W004 <rls-system-checks>` only
   inspects ``TenantRLSModel`` subclasses, so it will **not** catch these.
#. **Anything keyed on ``connection.schema_name`` collapses (silent).** Cache
   key prefixes, per-tenant file/media paths, lock names, log tags -- if built
   from ``connection.schema_name`` they now resolve to ``"public"`` for every
   tenant, so all tenants share one namespace. These live *outside* Postgres, so
   RLS gives **zero** protection and no check fires.
#. **Out-of-request code starts with no tenant (loud, fail-closed).** Celery
   tasks, Channels consumers, management commands, signal handlers, **and
   in-process background work -- ``ThreadPoolExecutor``, ``loop.run_in_executor``,
   ``asyncio.to_thread``, raw threads, and shielded/detached coroutines** -- run
   without ``TenantMainMiddleware``, so the tenant GUC is at its empty sentinel:
   policied reads return **zero rows** and policied writes are rejected by
   ``WITH CHECK`` until the code sets the tenant with ``with rls_context(tenant):``.
   Connections are **thread-local**, so a pooled worker thread gets a *fresh*
   connection at the empty sentinel -- capture the tenant pk on the submitting
   thread, pass it into the worker, and open ``with rls_context(tenant_pk):`` at
   the **start** of the worker. This is the direct replacement for code that
   previously snapshotted ``schema_name`` and re-entered ``schema_context()`` in a
   thread (which, as the warning above explains, now degrades to zero rows).

The one rule
------------

   **Every tenant-scoped model -- including third-party ones -- must carry a
   ``tenant_id`` column and an RLS policy, and every cache / storage / lock key
   must derive from the tenant identity, not from ``connection.schema_name``.
   Anything else is shared across all tenants.**

What the library ships to help
------------------------------

Three failure-class-2 problems have first-party fixes (see
:ref:`rls-cache-storage-celery` for usage):

* ``django_tenants.rls.cache.make_key`` / ``reverse_key`` -- drop-in
  ``KEY_FUNCTION`` / ``REVERSE_KEY_FUNCTION`` keyed on the real tenant.
* ``django_tenants.rls.storage.RLSTenantFileSystemStorage`` (+ an
  ``S3Boto3Storage`` recipe in that module) -- per-tenant media keyed on the
  real tenant.
* ``django_tenants.rls.celery.register()`` -- ``task_prerun`` / ``task_postrun``
  handlers so a worker never inherits a prior task's tenant or bypass.

Everything else here is **yours to change in your own code** -- the library
cannot policy a model it does not define or re-key a function it does not own.

Compatibility at a glance
-------------------------

.. list-table::
   :header-rows: 1
   :widths: 28 20 52

   * - Package / category
     - Under RLS
     - What to do
   * - Token auth (``rest_framework.authtoken``)
     - Breaks (silent)
     - Third-party ``Token`` has no ``tenant_id``/policy → one shared token
       table. Policy it by hand, or use a first-party token model.
   * - JWT blacklist (``simplejwt`` ``token_blacklist``)
     - Breaks (silent)
     - ``OutstandingToken`` / ``BlacklistedToken`` shared across tenants. Policy
       them, or accept a documented *global* blacklist.
   * - Vendored / private auth backends
     - Review required
     - Tenant-scoped models you cannot edit are unpolicied → shared. Inventory
       its models; policy each per-tenant table.
   * - Cache key isolation (e.g. django-redis)
     - Breaks (silent)
     - If keyed on ``schema_name`` it collapses. Switch ``KEY_FUNCTION`` to
       ``django_tenants.rls.cache.make_key``.
   * - Per-tenant file storage (e.g. django-storages)
     - Breaks (silent)
     - If the prefix is from ``schema_name`` all tenants share it. Use
       ``RLSTenantFileSystemStorage`` / the S3 recipe.
   * - ASGI / WebSockets (Channels)
     - Needs adaptation
     - No middleware runs; wrap each DB block in ``rls_context(tenant)``. Mostly
       fails closed; a reused connection can leak.
   * - Bulk admin import (e.g. django-import-export)
     - Needs adaptation
     - ``use_bulk=True`` skips ``save()`` → ``tenant_id`` NULL → rejected; a
       resource on a non-policied model exports all tenants.
   * - Redis locks (e.g. python-redis-lock)
     - Pre-existing
     - Lock names were never schema-scoped; RLS neither causes nor fixes this.
       Prefix names with the tenant if collisions matter.
   * - Admin confirmation (e.g. django-admin-confirm)
     - Fixed via cache
     - Stashes in-flight edits in the shared cache; fixed once ``KEY_FUNCTION``
       is tenant-aware.
   * - DRF, django-filter, drf-spectacular, CORS, WhiteNoise, health-check, field
       helpers
     - Unaffected
     - No tenancy primitive in their path; they inherit isolation from the models
       they touch.

Per-package notes
-----------------

Token authentication (DRF ``authtoken``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``rest_framework.authtoken.Token`` cannot inherit ``TenantRLSModel``, so under
RLS there is one shared ``public.authtoken_token`` with no policy and
``TokenAuthentication`` looks tokens up by key alone -- **a token minted for
tenant A authenticates as tenant B**. The same applies to every tenant-resident
third-party table you cannot edit (``django.contrib.auth``,
``django.contrib.sessions``, vendored auth packages, …).

.. important::

   **The tool only emits the policy, not the column.** ``rls_doctor`` and
   ``--generate`` ignore non-``TenantRLSModel`` tables, and
   ``django_tenants.rls.scaffold.third_party_policy_sql`` **assumes the table
   already has a ``<tenant_field>_id`` column.** None of authtoken / auth /
   sessions do. You must run the **full ordered sequence yourself** -- add the
   column, backfill it, tighten it, scope its UNIQUEs, *then* apply the policy:

.. code-block:: sql

   -- (1) Add the tenant column NULLABLE (match the type to your tenant PK:
   --     bigint for BigAutoField, integer for AutoField, uuid/text as needed).
   ALTER TABLE authtoken_token ADD COLUMN tenant_id bigint NULL
       REFERENCES customers_tenant(id) ON DELETE CASCADE;

   -- (2) Backfill every row under bypass_rls() (no policy exists yet, but make
   --     it a habit), then make it NOT NULL once zero rows are NULL.
   --     UPDATE authtoken_token SET tenant_id = <resolve owner> WHERE tenant_id IS NULL;
   ALTER TABLE authtoken_token ALTER COLUMN tenant_id SET NOT NULL;

   -- (3) Tenant-scope any global UNIQUE so it is not a covert channel. The token
   --     PK is `key`; replace the implicit global uniqueness with (tenant_id, key).
   ALTER TABLE authtoken_token ADD CONSTRAINT authtoken_token_key_per_tenant
       UNIQUE (tenant_id, key);   -- and drop the old global UNIQUE on key if present

   -- (4) Now the policy (byte-identical to TenantPolicy; ::bigint for BigAutoField).
   ALTER TABLE authtoken_token ENABLE ROW LEVEL SECURITY;
   ALTER TABLE authtoken_token FORCE ROW LEVEL SECURITY;
   CREATE POLICY authtoken_token_tenant_isolation ON authtoken_token
     USING (tenant_id = (SELECT NULLIF(current_setting('django_tenants.tenant_id', true), '')::bigint)
            OR (SELECT current_setting('django_tenants.bypass_rls', true)) = 'on')
     WITH CHECK (tenant_id = (SELECT NULLIF(current_setting('django_tenants.tenant_id', true), '')::bigint)
            OR (SELECT current_setting('django_tenants.bypass_rls', true)) = 'on');

.. note::

   The ``::bigint`` cast above matches a ``BigAutoField`` tenant PK (Django's
   default since 3.2). Match it to **your** tenant PK type -- ``::integer`` for an
   ``AutoField``, ``::uuid`` for a ``UUIDField``, ``::text`` for a text key --
   exactly as ``TenantPolicy`` does via ``conf.get_tenant_pk_cast()``. The
   ``tenant_id`` column you add (step 1) must be the same type as the tenant PK.
   ``third_party_policy_sql(table, pk_cast=...)`` will emit step (4) for you with
   the right cast, but it does **not** emit steps (1)-(3).

Populate ``tenant_id`` on token creation (override the creation path or a
``BEFORE INSERT`` trigger defaulting to the GUC), or -- cleaner long term -- use a
first-party token model that subclasses ``TenantRLSModel`` with a custom DRF auth
class. Backfill before enabling RLS (see :ref:`rls-backfill-recipe`); NULL
``tenant_id`` rows are invisible to everyone. **Verify:** mint a token under
tenant A, switch to tenant B, assert it does not authenticate and that
``Token.objects.count()`` with no tenant active is ``0``.

JWT (``simplejwt``) and the user model
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Stateless JWTs need no table, and the normal request path works (the middleware
sets the GUC before the view runs). Two caveats: (1) the optional
``token_blacklist`` app's ``OutstandingToken`` / ``BlacklistedToken`` are
third-party and unpolicied → a token blacklisted in one tenant is treated as
blacklisted everywhere and listings leak; policy them as above or accept a
documented *global* blacklist. (2) **Check where ``AUTH_USER_MODEL`` lives.** If
the user app is in ``SHARED_APPS`` (the usual case) lookups were always global --
fine, but your auth class must enforce the per-tenant membership check against a
policied table. If the user app was in ``TENANT_APPS`` and ``User`` is not
policied, ``auth_user`` is now one shared table and a JWT/`get_user()` can
authenticate **any** tenant's user by id -- a cross-tenant auth hole. Token
rotation / ``flushexpiredtokens`` run out-of-request: wrap per-tenant sweeps in
``with rls_context(tenant):`` (or a global sweep in ``with bypass_rls():``).

Vendored / private auth backends
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A private auth package you cannot modify is the highest-uncertainty item: if it
defines tenant-scoped models that were in ``TENANT_APPS``, they are now one
shared table with no policy -- and because it is auth, that can let one tenant
act as another. Inventory its models (see the checklist below), determine which
hold per-tenant data, and for each one you cannot edit, add ``tenant_id`` + a
policy via your own DDL migration and backfill before enabling RLS. If its models
were intentionally global (already in ``SHARED_APPS``), there is no regression.

Cache (e.g. django-redis)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you isolated the cache by wiring ``KEY_FUNCTION`` to
``django_tenants.cache.make_key`` (which prefixes with ``connection.schema_name``),
every tenant's keyspace collapses to ``public:`` under RLS -- sessions, cached
querysets, rate-limit counters and cache-based locks leak. Postgres RLS does not
reach Redis. Switch ``KEY_FUNCTION`` / ``REVERSE_KEY_FUNCTION`` to
``django_tenants.rls.cache.make_key`` / ``reverse_key`` (same key shape, sourced
from the real tenant), then **flush / namespace-bump Redis** so stale
``public:``-prefixed entries written during the broken window are not served.
Ensure out-of-request code sets the tenant before any cache access, or the key
falls back to the public prefix.

.. note::

   **If you never set ``KEY_FUNCTION`` at all**, your cache was already a single
   shared keyspace across tenants -- a pre-existing condition that RLS neither
   causes nor fixes (Postgres RLS does not reach Redis). ``rls_doctor`` reports
   the cache as ``ok`` in this case because there is no schema-name
   ``KEY_FUNCTION`` to flag, which is *literally* true but easy to misread as "the
   cache is tenant-safe." It is not: adopting RLS is the moment to add
   ``KEY_FUNCTION = "django_tenants.rls.cache.make_key"`` (and the matching
   ``REVERSE_KEY_FUNCTION``) so cached values are actually per-tenant.

File / media storage (e.g. django-storages S3)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Per-tenant media isolation comes from prefixing the storage key by the tenant. If
that prefix derives from ``connection.schema_name`` (the standard
``parse_tenant_config_path`` pattern), it collapses to one prefix and all tenants
read/write the same objects -- with no DB protection. Use
``django_tenants.rls.storage.RLSTenantFileSystemStorage`` for local media, and for
S3 override ``location`` to prepend ``current_tenant_schema()`` (recipe in that
module's docstring) instead of ``connection.schema_name``. Code touching storage
outside a request (thumbnailing tasks, commands) must establish tenant context
first. Audit any objects written under the collapsed prefix during testing.

Channels / ASGI
~~~~~~~~~~~~~~~

``TenantMainMiddleware`` is WSGI-only; a WebSocket consumer's DB access runs with
no tenant set, so wrap **every** ``database_sync_to_async`` block in
``with rls_context(tenant):`` (resolve the tenant *object* in your scope
middleware -- ``schema_context`` resolves to a pk-less ``FakeTenant`` and yields
zero rows). Re-activate after ``aclose_old_connections``/reconnect. This mostly
fails closed (zero rows); a long-lived consumer reusing a connection whose tenant
was left set is the narrow leak case. Channel-layer group names are not policied
-- tenant-namespace them yourself, as in classic mode.

Bulk admin import/export (e.g. django-import-export)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Export of a ``TenantRLSModel`` is *safer* than before (no tenant → zero rows).
Row-by-row import works (``save()`` auto-stamps ``tenant_id``). But ``use_bulk =
True`` calls ``bulk_create`` / ``bulk_update``, which skip ``save()`` → the
WITH CHECK policy rejects the INSERT (loud). Set ``use_bulk = False``, or stamp
``instance.tenant_id`` in ``before_save_instance``. And only register resources
for ``TenantRLSModel`` models: a resource on an unpolicied model exports every
tenant's rows. Commands/Celery runs need ``with rls_context(tenant):``.

Redis locks and admin confirmation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``python-redis-lock`` lock names were never schema-namespaced (Redis is one store
in classic mode too), so RLS introduces no new regression -- but if a lock name
is built only from a session/user id with no tenant component, that is a
pre-existing cross-tenant collision; prefix it with the tenant. ``django-admin-confirm``
stashes in-flight confirmation state in the shared cache with no tenant component;
it is fixed automatically once your cache ``KEY_FUNCTION`` is tenant-aware (above).

Adopter checklist (grep your own codebase)
------------------------------------------

Every item above depends on *your* settings and code. Concretely:

.. code-block:: console

   # Cache / storage / lock keys keyed on schema_name (failure class 2):
   grep -rn "KEY_FUNCTION\|REVERSE_KEY_FUNCTION" <settings>     # -> rls.cache.make_key?
   grep -rn "STORAGES\|DEFAULT_FILE_STORAGE\|STATICFILES_STORAGE" <settings>
   grep -rn "connection.schema_name\|parse_tenant_config_path" <app>  # cache/lock/path/group names

   # Third-party / non-policied tenant models (failure class 1):
   grep -rn "rest_framework.authtoken" <settings>              # in TENANT_APPS?
   grep -rn "AUTH_USER_MODEL" <settings>                       # SHARED_APPS (safe) vs TENANT_APPS (danger)
   python manage.py shell -c "from django.apps import apps; [print(m._meta.label, m._meta.db_table) for m in apps.get_models()]"
   # then in psql, for each suspect per-tenant table:
   #   SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname IN (...);
   #   SELECT * FROM pg_policies WHERE tablename IN (...);   -- empty policy set on a per-tenant table = the bug

   # Out-of-request execution (failure class 3) -- incl. in-process threads:
   grep -rn "call_command\|database_sync_to_async\|@shared_task\|@app.task\|post_save\|pre_save" <app>
   grep -rnE "ThreadPoolExecutor|run_in_executor|asyncio.to_thread|\.submit\(|threading.Thread" <app>
   grep -rn "schema_context\|optional_schema_context" <app>   # string-based -> degrades to zero rows under RLS

   # Confirm the runtime role cannot bypass RLS (W001/W003 are DEPLOY checks):
   python manage.py check --deploy --database default         # W001/W003 must NOT fire
   python manage.py rls_doctor                                # authoritative gate (not masked by --deploy)

After fixing, run ``manage.py verify_rls`` in CI (it fails non-zero if any
``TenantRLSModel`` table is missing RLS/FORCE/a policy), and re-run a two-tenant
isolation check for tokens, cached values, files, and any policied third-party
table.


.. _rls-migration-performance:

Performance and operations after cutover
========================================

Cutting over from schema-per-tenant to shared-schema RLS changes your
operational profile in three ways: every cursor now does one extra round-trip,
the formerly-tiny per-schema tables become one large shared table, and tenant
isolation now depends on session state surviving connection reuse. Plan for the
steady state below before you cut over, not after.

.. note::

   In :ref:`disabled mode <rls-mechanism>` (``TENANT_RLS_ENABLED = False``) the
   RLS backend is **byte-for-byte identical to the stock django-tenants
   backend** -- ``_cursor`` returns the parent cursor unchanged and emits no
   ``set_config``. There is zero added overhead, which is what makes a staged
   rollout (deploy the backend disabled, flip the flag later) safe to measure
   against your existing baseline.

The per-cursor GUC round-trip
-----------------------------

When RLS is enabled the backend issues exactly **one extra round-trip per
database cursor**: a single combined ``set_config`` statement that re-asserts
both the tenant variable and the bypass variable from the connection's Python
state. The statement is

.. code-block:: sql

   SELECT set_config(%s, %s, false), set_config(%s, %s, false)

with the four bound parameters being the tenant GUC name, the active tenant pk,
the bypass GUC name, and ``'on'``/``'off'`` -- all passed as parameters, never
interpolated. This is not optional bookkeeping: it is **security-load-bearing**.
It is what re-establishes isolation on every cursor, so a rolled-back
transaction or a pooled connection cannot inherit a stale tenant or a leaked
``bypass=on``. It is emitted **only when** ``TENANT_RLS_ENABLED`` is ``True``;
when disabled the backend emits nothing extra.

For the full rationale see the Performance note under :ref:`rls-mechanism` in
the reference doc. Budget one round-trip per cursor (not per request and not per
query plan): for typical request/response workloads this is in the noise next to
the query it precedes, but very chatty code paths that open many short-lived
cursors will see it accumulate. Measure against your disabled-mode baseline.

Index ``tenant_id`` on the now-shared tables
--------------------------------------------

Under schema-per-tenant a query touched one small table per schema. Under RLS
every tenant's rows live in **one shared table**, and every policy-filtered
query carries an implicit ``tenant_id = current_tenant`` predicate. Indexing for
that predicate is now a first-order performance concern.

``TenantRLSModel`` defines its ``tenant`` foreign key with ``db_index=True`` by
default, so a standalone index on ``tenant_id`` already exists:

.. code-block:: python

   class TenantRLSModel(models.Model, metaclass=RLSModelMeta):
       tenant = models.ForeignKey(
           settings.TENANT_MODEL,
           on_delete=models.CASCADE,
           db_index=True,
           related_name="+",
       )

That single-column index covers the bare tenant scope. It does **not** cover
your tenant-scoped lookups and sorts. Any composite index you add for a query
that runs within a tenant should **lead with** ``tenant_id``, because the RLS
predicate is always present:

.. code-block:: python

   class Invoice(TenantRLSModel):
       status = models.CharField(max_length=16)
       created_at = models.DateTimeField()

       class Meta:
           indexes = [
               # tenant_id first: every query is already filtered by tenant,
               # so a tenant-leading composite serves "this tenant's invoices
               # by status / recency" without scanning other tenants' rows.
               models.Index(fields=["tenant", "status"]),
               models.Index(fields=["tenant", "-created_at"]),
           ]

Audit the per-schema indexes you relied on before the cutover and re-express
each one as a tenant-leading composite. Unique constraints in particular almost
always need ``tenant_id`` added as the leading column, since a value that was
unique within a schema is no longer unique within the shared table.

.. warning::

   **Uniqueness enforced in Python is invisible to the tooling.** The ``W005``
   check and ``rls_doctor`` only see uniqueness *declared on the model*
   (``unique=True``, ``Meta.unique_together``, ``Meta.constraints``). A rule
   enforced in ``Model.clean()`` / ``validate_unique()`` / ``save()`` via a
   ``.filter(...).exists()`` lookup is **not** flagged -- and under RLS that
   lookup now runs *with* the tenant predicate, so it silently becomes
   tenant-scoped: it can no longer see another tenant's colliding row, so a
   previously-global guarantee quietly narrows (and the cross-tenant existence it
   used to detect is now invisible). Grep your models for ``.exists()`` /
   ``.filter(`` inside ``save``/``clean`` and either add a real
   ``UniqueConstraint(fields=["tenant", ...])`` (so the DB enforces it and W005
   can see it) or run the lookup under ``bypass_rls()`` if a global check is
   genuinely intended.

.. _rls-migration-poolers:

Connection poolers
------------------

Per-cursor re-assertion makes RLS correct across pooled and persistent
connections *as long as the pooler keeps a client on one server backend for the
work that needs it*. The backend derives both GUCs from the connection's Python
source-of-truth (``_rls_tenant_id`` and ``_rls_bypass``) on every cursor, so a
connection reused by a different request -- or after a transaction rollback --
carries the correct tenant and a bypass that has snapped back to ``off`` (see
:ref:`bypass-leak-note`).

.. important::

   **An external server-side pooler MUST run in session pooling mode.** The
   tenant GUC is set at **SESSION scope** (the ``false`` third argument to
   ``set_config(...)`` -- see ``SET_RLS_SESSION_SQL`` in the backend and
   ``SET_CONFIG_SQL`` in ``django_tenants/rls/session.py``) and, under Django's
   default autocommit, the per-cursor ``set_config`` and the query it protects
   are **two separate statements in two separate transactions**.

   * **Session pooling** -- a client holds one server backend for its whole
     session, so the ``set_config`` and the following query always run on the
     same backend. Correct, and it mirrors how the parent backend's persistent
     ``search_path`` works. **Use this.**
   * **Transaction / statement pooling** -- the pooler may hand the
     ``set_config`` and the query to *different* server backends. The query then
     runs either on a backend whose tenant GUC was never set (secure-default
     **zero rows** -- a silent availability bug that only appears under
     production concurrency) or, worst case, on one still holding a **previous
     client's** tenant GUC (**cross-tenant read**). Per-cursor re-assertion does
     **not** rescue this: it pins the GUC on the backend that ran ``set_config``,
     not on the one that runs the query. **Unsupported.**

   The only transaction-pooling-safe configuration is to make the ``set_config``
   and the query share one transaction -- e.g. ``ATOMIC_REQUESTS = True`` (or an
   explicit ``transaction.atomic()`` around all tenant work) so both land on the
   same backend. The default autocommit design does not do this, so treat
   transaction/statement pooling as unsupported unless you have wrapped every
   tenant query in a transaction *and* validated isolation through the pooler.

.. note::

   **RDS Proxy / connection multiplexing.** A SESSION-scope ``set_config`` on
   every cursor **pins** the proxied connection -- the proxy can no longer
   multiplex it -- which collapses the benefit RDS Proxy exists to provide.
   Prefer plain session pooling and size the pool accordingly; do not try to
   move the tenant into a proxy ``init`` query.

.. note::

   **Server-side cursors.** ``QuerySet.iterator()`` and other named/server-side
   cursors FETCH across multiple round-trips; under transaction pooling those
   fetches can land on a backend that never had the GUC set and silently return
   nothing. If you use them, set ``DISABLE_SERVER_SIDE_CURSORS = True`` or route
   those reads through a session-pooled connection.

Stock-backend fallback: keep ``TenantRLSMiddleware``
----------------------------------------------------

If your deployment keeps the stock ``django_tenants.postgresql_backend`` ENGINE
and uses ``TenantRLSMiddleware`` for isolation (rather than the RLS backend),
the **middleware -- not a backend cursor -- is what forces bypass off at request
start**:

.. code-block:: python

   def process_request(self, request):
       if not conf.rls_enabled():
           return
       # FORCE bypass off at request start so a leaked bypass=on from a prior
       # request's interrupted bypass_rls() block cannot carry over on a pooled
       # connection.
       session.set_bypass(connection=None, value=False)
       ...

Under that deployment there is no per-cursor re-assertion to fall back on, so
**do not remove this middleware** and do not let it drift out of ``MIDDLEWARE``
(it must sit *after* ``TenantMainMiddleware``). Removing it reopens the
bypass-leak gap on pooled/persistent connections described in
:ref:`bypass-leak-note`. On the RLS backend the middleware is redundant but
harmless, so it is safe to leave installed in either deployment.

.. warning::

   The fallback middleware sets the tenant GUC **once per request**, with no
   per-cursor re-assertion behind it. It therefore depends on every query in the
   request reaching the *same* server backend, so the stock-backend + middleware
   deployment requires **session pooling** even more strictly than the RLS
   backend does (see :ref:`rls-migration-poolers`): under transaction/statement
   pooling the tenant is stranded mid-request. The RLS backend (per-cursor
   re-assertion) is the more robust choice and is recommended.

Planner, statistics, and autovacuum
------------------------------------

This is the operational change most teams underestimate. Before the cutover each
tenant's rows lived in its own schema's table -- many small tables, each with its
own statistics and its own autovacuum cadence. After the cutover **one shared
table holds every tenant's rows**, so it is far larger and its access patterns
differ from any single pre-cutover table.

Expect, and monitor for, the following after cutover:

* **Autovacuum thresholds.** Postgres scales the autovacuum/analyze trigger off
  table size (``autovacuum_vacuum_scale_factor``). A much larger shared table
  triggers vacuum/analyze less frequently in relative terms, so dead tuples and
  stale stats can accumulate longer. For hot shared tables consider lowering the
  scale factor (or raising the threshold floor) per-table via
  ``ALTER TABLE ... SET (autovacuum_vacuum_scale_factor = ...)``.
* **Planner statistics and plans.** Statistics are now aggregated across all
  tenants. The planner's row estimates for a single-tenant query depend on the
  selectivity of ``tenant_id`` and how skewed your tenant sizes are; a plan that
  was trivial against a one-tenant table may now choose a sequential scan or a
  different join order. After a representative load settles, run ``ANALYZE`` and
  re-check ``EXPLAIN (ANALYZE, BUFFERS)`` on your hottest tenant-scoped queries.
  Consider raising the per-column statistics target on ``tenant_id`` and on the
  leading columns of your composite indexes if estimates are off.
* **Bloat and index maintenance.** A single large, write-heavy shared table
  bloats and fragments its indexes differently from many small ones. Fold it
  into your existing bloat monitoring.

There is no setting in django-tenants that tunes any of this -- it is ordinary
Postgres operations on what is now an ordinary (large) shared table. Treat the
cutover as the introduction of a new high-traffic table and watch it for a few
days under real load before considering the migration complete.


.. _rls-migration-troubleshooting:

Troubleshooting and the "all queries return zero rows" checklist
================================================================

This section is symptom-driven. Find the symptom you are seeing, then follow the
arrow to its cause and fix. Most migration-day surprises reduce to one of a
handful of root causes, and the single most common one -- *every query suddenly
returns nothing* -- has its own checklist below. For the underlying mechanics
behind these symptoms, see :ref:`rls-mechanism`; for the full catalogue of
startup diagnostics, see :ref:`rls-system-checks`.

.. _rls-migration-zero-rows:

"All my queries return 0 rows"
------------------------------

This is the secure-by-default behaviour failing *safe*: when the policy cannot
prove a row belongs to the active tenant, it hides the row. Work down this list
in order; each item is a distinct root cause.

#. **No active tenant (the session variable is empty).**
   The tenant policy compares ``tenant_id`` against the session GUC via
   ``NULLIF(current_setting(...), '')``. With no tenant set the GUC is the empty
   string, ``NULLIF('', '')`` is ``NULL``, the comparison is ``NULL`` (not
   true), and **no rows are visible** -- by design. This is the intended
   secure-by-default state, not a bug: a request that never activated a tenant,
   a management command, a Celery task, or a shell session that forgot to enter
   a context will all see zero rows.

   *Fix:* activate a tenant before querying. In a request this is the tenant
   middleware; everywhere else use a context manager:

   .. code-block:: python

       from django_tenants.rls.session import rls_context

       with rls_context(tenant):          # tenant instance or bare pk
           Note.objects.count()           # now scoped to that tenant

   Confirm what Postgres actually sees on the connection you are querying:

   .. code-block:: python

       from django.db import connections
       from django_tenants.rls import conf
       from django_tenants.utils import get_tenant_database_alias

       conn = connections[get_tenant_database_alias()]
       with conn.cursor() as cur:
           cur.execute("SELECT current_setting(%s, true)", [conf.session_variable()])
           print(repr(cur.fetchone()[0]))   # '' or None => no tenant => zero rows

#. **The flag is on but the policies were never created (or were torn down).**
   ``TENANT_RLS_ENABLED = True`` only changes Python behaviour (the backend sets
   the GUC, ``save()`` auto-populates ``tenant_id``). It does **not** create or
   drop policies by itself. If ``FORCE ROW LEVEL SECURITY`` plus a policy are on
   the table but the table or rows are out of sync with what you think you
   enabled -- or, conversely, if you flipped the flag off without running
   ``disable_rls`` -- you get a teardown mismatch. The classic case: the flag is
   ``False`` while ``FORCE`` and the policy remain, which locks out a
   ``NOBYPASSRLS`` role and returns zero rows. Disabling RLS is **two-part**:
   ``TENANT_RLS_ENABLED = False`` **and** ``manage.py disable_rls`` (or the
   ``DisableRLS`` operation). Inspect the live state:

   .. code-block:: sql

       -- Is the table forced + does it have a policy?
       SELECT relname, relrowsecurity, relforcerowsecurity
         FROM pg_class WHERE relname = 'myapp_note';
       SELECT polname, polpermissive, polcmd
         FROM pg_policy WHERE polrelid = 'myapp_note'::regclass;

   *Fix:* bring the flag and the DDL into agreement -- enable both, or disable
   both. See :ref:`rls-step-6-enable` and :ref:`rls-rollback`.

#. **The model's only policy is RESTRICTIVE.**
   A single policy must be **PERMISSIVE** to grant any visibility. PostgreSQL
   AND-combines RESTRICTIVE policies on top of the permissive ones, so a table
   whose *sole* policy is RESTRICTIVE (``permissive=False``) returns **zero rows
   for everyone** -- the correct tenant included, and **even under**
   ``bypass_rls()``, because there is no permissive policy to grant access in the
   first place. ``RESTRICTIVE`` is only meaningful as an *additional*
   AND-constraint layered on top of the default permissive tenant policy.

   *Fix:* never set ``permissive=False`` on a model's only policy. Verify with
   the ``polpermissive`` column above (it is ``t`` for permissive). The
   auto-built ``TenantPolicy`` is permissive by default; this only bites if you
   hand-wrote one.

#. **W001 -- RLS is on but nothing sets the GUC.**
   If ``TENANT_RLS_ENABLED = True`` but the tenant database ``ENGINE`` is not the
   RLS backend **and** ``TenantRLSMiddleware`` is not installed, the policies
   exist but the tenant session variable is **never set** on any connection. Every
   query then evaluates against an unset variable and silently returns nothing --
   exactly item 1, but caused by configuration rather than a missing context. The
   :ref:`W001 check <rls-system-checks>` warns about precisely this.

   *Fix:* point the tenant alias at the RLS backend (keeping your
   ``ORIGINAL_BACKEND``), or install the fallback middleware:

   .. code-block:: python

       DATABASES = {
           "default": {
               "ENGINE": "django_tenants.rls.backend",
               "ORIGINAL_BACKEND": "django.db.backends.postgresql",
               # ... name / user / password / host ...
           }
       }

.. _rls-migration-isolation-off:

Rows are visible from ``postgres`` but isolation "doesn't work"
---------------------------------------------------------------

**Symptom:** queries return rows, often *every* tenant's rows, and the tenant
session variable seems to be ignored.

**Cause:** you are connected as a **superuser or a ``BYPASSRLS`` role**.
PostgreSQL bypasses *all* row-security policies for such a role even with
``FORCE ROW LEVEL SECURITY`` set -- the tables look protected and the policies
exist, yet there is zero isolation. This is the single most dangerous
misconfiguration, which is why the :ref:`W003 check <rls-system-checks>` reports
it as an **Error** that blocks startup (see :ref:`rls-database-role`). The
default ``postgres`` role and most Docker ``POSTGRES_USER`` roles bypass RLS.

**Fix:** connect django-tenants as a dedicated ``NOSUPERUSER NOBYPASSRLS`` role
and reconnect:

.. code-block:: sql

    CREATE ROLE app_rls LOGIN PASSWORD '...' NOSUPERUSER NOBYPASSRLS;
    GRANT USAGE ON SCHEMA public TO app_rls;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_rls;

Keep a separate superuser only for migrations and admin tasks. If you must run
as a bypassing role *and* isolation is guaranteed by another mechanism, the
documented opt-out is ``TENANT_RLS_ALLOW_BYPASS_ROLE = True`` -- this disables
the safety net, so use it knowingly.

.. _rls-migration-missing-rows:

Some specific rows are missing (not all)
----------------------------------------

**Symptom:** most rows are visible under the correct tenant, but a known subset
has vanished from every tenant.

**Cause:** those rows have ``tenant_id IS NULL``. ``NULL = <active tenant>`` is
``NULL`` (not true), so a NULL-tenant row is invisible to *every* tenant no
matter which is active. The rows are **invisible, not lost** -- they are still on
disk and reappear under ``bypass_rls()`` or after ``disable_rls``. This almost
always means RLS was enabled before the backfill finished. See
:ref:`rls-null-rows`.

**Fix:** backfill the orphaned rows **under bypass** (the policy hides them, so
you cannot fix them with normal queries), assigning each to its rightful tenant:

.. code-block:: python

    from django_tenants.rls.session import bypass_rls

    with bypass_rls():
        Note.objects.filter(tenant__isnull=True).update(tenant=correct_tenant)

For the bulk backfill procedure on a populated table, see
:ref:`rls-backfill-recipe`. To avoid this entirely, follow the strict upgrade
ordering and finish the backfill *before* enabling RLS (see
:ref:`rls-upgrade-existing`).

.. _rls-migration-startup-blocked:

Startup is blocked or ``migrate`` fails
---------------------------------------

System checks run before ``runserver`` and most ``manage.py`` commands, so an
``Error``-level check halts startup. Three RLS checks raise errors:

* **W003 (Error) -- bypassing role.** The connecting role is a superuser or has
  ``BYPASSRLS``. *Fix:* reconnect as a ``NOSUPERUSER NOBYPASSRLS`` role (see
  above), or, knowingly, set ``TENANT_RLS_ALLOW_BYPASS_ROLE = True``.

* **E001 -- bad GUC variable name.** ``TENANT_RLS_SESSION_VARIABLE`` or
  ``TENANT_RLS_BYPASS_VARIABLE`` is malformed. These names are embedded into
  policy DDL (they cannot be bound parameters), so they must match
  ``<class>.<name>`` -- letters, digits and underscores, exactly one dot, e.g.
  the defaults ``django_tenants.tenant_id`` and ``django_tenants.bypass_rls``.
  *Fix:* correct the name to that format.

* **E002 -- unsupported tenant PK cast.** The tenant model's primary key is not a
  type the policy can cast the GUC text to. Supported PK types are the integer
  family, ``UUID``, and text-like fields (``CharField`` / ``SlugField`` /
  ``TextField``); anything else raises ``ImproperlyConfigured``. *Fix:* use a
  supported PK type on the tenant model, or set a matching
  ``TenantPolicy(pk_cast=...)`` on each model's tenant policy. See
  :ref:`rls-pk-types`.

See :ref:`rls-system-checks` for each check's full text and ID.

.. _rls-migration-missing-column:

A policy references a missing column / every query on a table errors
--------------------------------------------------------------------

**Symptom:** every query against one table raises a database error about a
non-existent column.

**Cause:** **W002** -- a ``TenantRLSModel`` subclass is missing the configured
tenant field. The default policy filters on ``<tenant_field>_id`` (the
``TENANT_RLS_TENANT_FIELD``, default ``tenant``). If that field is absent, the
generated policy SQL references a column that does not exist and the table errors
on every query. The :ref:`W002 check <rls-system-checks>` warns at startup.

**Fix:** add a ``ForeignKey`` named ``tenant`` to ``settings.TENANT_MODEL`` on
the model, or set ``TENANT_RLS_TENANT_FIELD`` to the correct field name and use a
matching ``TenantPolicy(tenant_field=...)``.

.. _rls-migration-multidb:

Multi-DB: ``TENANT_DB_ALIAS`` is not ``default``
------------------------------------------------

**Symptom:** you set the tenant on one connection but query another, and the
results are wrong or empty; or context managers seem to restore the wrong tenant.

**Cause:** the session GUC is per-connection, and the helpers default to the
tenant alias, not necessarily ``default``. ``rls_context`` / ``bypass_rls``
resolve the connection via the tenant database alias when ``using`` is ``None``,
and ``tenant_context`` / ``schema_context`` snapshot and restore
``connection.tenant`` from the **target alias** connection (the ``database=``
kwarg, defaulting to ``get_tenant_database_alias()``). If you set the GUC on one
alias and run your query on another, the query's connection has no tenant set.

**Fix:** set the tenant and run the query on the **same alias**. Pass the alias
explicitly when it is not the tenant alias:

.. code-block:: python

    from django_tenants.rls.session import rls_context

    with rls_context(tenant, using="reporting"):
        Note.objects.using("reporting").count()

.. _rls-migration-bulk-create:

``bulk_create`` wrote rows that vanished
----------------------------------------

**Symptom:** ``bulk_create`` (or ``bulk_update`` / raw insert) reported success,
but the rows are not visible afterwards -- or the insert was rejected.

**Cause:** these paths bypass ``TenantRLSModel.save()``, so ``tenant_id`` is
**not** auto-populated. The rows are written with a NULL or wrong ``tenant_id``
(making them invisible, per the NULL-rows symptom above), and the policy's
``WITH CHECK`` clause **rejects** any insert whose ``tenant_id`` does not match
the active tenant -- defense in depth at the database level. See
:ref:`rls-null-rows`.

**Fix:** set the tenant explicitly on every object and run inside
``rls_context``:

.. code-block:: python

    from django_tenants.rls.session import rls_context

    with rls_context(tenant):
        Note.objects.bulk_create([
            Note(text="a", tenant=tenant),
            Note(text="b", tenant=tenant),
        ])

.. _rls-migration-nested-bypass:

``bypass_rls`` had no effect inside a nested ``tenant_context``
---------------------------------------------------------------

**Symptom:** you opened ``bypass_rls()`` and then activated (or re-activated) a
tenant inside it, and bypass appeared to silently turn off.

**Cause:** every tenant (re)activation -- including ``set_tenant`` driven by
``tenant_context`` and the per-request middleware -- resets the connection to a
secure-by-default, **bypass-off** state. This is deliberate: it guarantees no
stale bypass value can survive from a prior request on a pooled connection. The
consequence is that opening ``bypass_rls()`` *outside* a subsequent tenant
activation is clobbered when that activation happens.

**Fix:** open ``bypass_rls()`` at the **innermost** scope, after any tenant
activation:

.. code-block:: python

    from django_tenants.utils import tenant_context
    from django_tenants.rls.session import bypass_rls

    with tenant_context(tenant):       # activation resets bypass to off
        with bypass_rls():             # open bypass last -> it sticks
            Note.objects.all()         # cross-tenant visibility here

See :ref:`bypass-leak-note` for the full reasoning.


FAQ
===

Short answers to the questions migrating teams ask most. Each links to the
section or reference that covers it in depth.

Can I migrate one tenant at a time?
-----------------------------------

No. In schema-per-tenant every tenant has its own physical table
(``tenant1.blog_note``, ``tenant2.blog_note``, ...). Under RLS all tenants share
**one** table in ``public`` (``public.blog_note``), isolated by a row-level
policy. There is no per-tenant cutover; the unit of migration is one
**app/table** at a time. For each table you convert, you copy **every** tenant's
rows out of its per-tenant schema into the single shared ``public`` table,
stamping each row's owning ``tenant_id``. See :ref:`rls-backfill-recipe` for the
backfill shape, and :ref:`rls-upgrade-existing` for the full per-table ordering.

Do I keep my Domain/Tenant models and ``TenantMainMiddleware``?
---------------------------------------------------------------

Yes. RLS changes only how *tenant-scoped row data* is isolated, not how tenants
are identified. Your tenant and domain models, the ``TENANT_MODEL`` /
``TENANT_DOMAIN_MODEL`` settings, host-based resolution, and
``TenantMainMiddleware`` routing are all unchanged. ``TenantMainMiddleware``
still resolves ``request.tenant``; the RLS layer simply reads that active tenant
to set the row-security session variable.

Can RLS and schema-per-tenant coexist?
--------------------------------------

Yes -- this is a supported **per-app hybrid**. Some apps stay schema-per-tenant
(in ``TENANT_APPS``) while others become RLS-isolated-in-public. The one rule:
**each RLS app must be in** ``SHARED_APPS`` (its tables live in ``public``), and
making an app RLS must be a deliberate choice. See
:ref:`shared-apps-vs-tenant-apps`.

Is ``FORCE`` required?
----------------------

With the default setup -- where the table owner is the role Django connects as
-- **yes**. ``TENANT_RLS_FORCE = True`` (the default) applies the policy even to
the table's owner; without ``FORCE`` the owner is exempt from its own policies
and isolation becomes an illusion for the owning connection.

.. danger::

   ``FORCE`` does **not** override a superuser or ``BYPASSRLS`` role. PostgreSQL
   *always* ignores every row-security policy for those roles, and this fails
   *open* and *silently*. Your application **must** connect as a
   ``NOSUPERUSER NOBYPASSRLS`` role. System check **W003** turns this into a
   startup ERROR by default. See :ref:`rls-database-role` and
   :ref:`rls-mechanism`.

What about django-admin?
------------------------

The admin and any other genuinely cross-tenant code (aggregation, one-off
scripts) needs to see rows across tenants. Wrap exactly those views or querysets
in ``bypass_rls()``, scoped as tightly as possible:

.. code-block:: python

    from django_tenants.rls.session import bypass_rls

    with bypass_rls():
        Note.objects.all()      # sees ALL tenants' rows; writes unrestricted

Keep the block as small as possible -- ``bypass_rls()`` removes isolation for its
duration. See :ref:`bypass-leak-note`.

Do I need ``TenantRLSMiddleware``?
----------------------------------

Only on the **stock-backend fallback** (you kept the standard
``django_tenants.postgresql_backend`` ENGINE and want RLS isolation). With the
recommended RLS backend (``ENGINE = 'django_tenants.rls.backend'``) it is
**optional**: the backend re-asserts the tenant and bypass session variables on
every cursor, so the middleware is redundant. It is harmless if left installed,
so you can keep it during a backend switch. See :ref:`bypass-leak-note`.

Is the ``tenant_id`` column kept if I disable RLS?
--------------------------------------------------

Yes. Disabling RLS only removes the database-level enforcement (``DISABLE ROW
LEVEL SECURITY`` plus dropping the policies); it **retains your data and the**
``tenant_id`` **column**, and the ``tenant`` FK stays on the model and table.
Removing the FK entirely is a separate, ordinary schema migration you write
afterwards.

.. danger::

   Disabling is a **two-part** operation: set ``TENANT_RLS_ENABLED = False``
   **and** run ``manage.py disable_rls`` (or a ``DisableRLS`` + ``DropPolicy``
   migration). Flipping only the flag while ``FORCE`` and the policies remain
   locks a ``NOSUPERUSER NOBYPASSRLS`` role out of its own data (zero rows on
   every query). See :ref:`rls-rollback`.

What tenant primary-key types are supported?
--------------------------------------------

The policy casts the session variable to the tenant PK's SQL type, so only PK
types with a known, correct cast are supported:

* **Integer family** -- cast to ``integer`` or ``bigint``.
* **UUID** (``UUIDField``) -- cast to ``uuid``.
* **Text-like** (``CharField`` / ``SlugField`` / ``TextField``) -- cast to
  ``text``.

Any other PK type raises ``ImproperlyConfigured`` (surfaced by system check
**E002**) rather than silently miscasting. See :ref:`rls-pk-types`.
