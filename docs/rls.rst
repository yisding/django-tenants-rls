===========================================
Row-Level Security (shared-schema RLS mode)
===========================================

django-tenants normally isolates tenants with one **PostgreSQL schema per
tenant**. The optional ``django_tenants.rls`` subpackage adds an alternative,
**shared-schema** isolation model: every tenant's data lives in a *single*
``public`` schema and isolation is enforced by `PostgreSQL Row-Level Security
<https://www.postgresql.org/docs/current/ddl-rowsecurity.html>`_ policies on a
``tenant`` foreign key.

This guide is a complete drop-in walkthrough. RLS mode reuses the rest of
django-tenants unchanged: the same ``TenantMixin`` / ``DomainMixin`` tenant and
domain models, the same ``TENANT_MODEL`` / ``TENANT_DOMAIN_MODEL`` settings, the
same ``TenantMainMiddleware`` request flow, and the same
``TenantSyncRouter``. The RLS database backend subclasses the standard
django-tenants backend, so the ``search_path`` still resolves to ``public``.

.. important::

   RLS mode is **opt-in** and **off by default**. With ``TENANT_RLS_ENABLED``
   unset (or ``False``) the RLS backend behaves byte-for-byte like the standard
   ``django_tenants.postgresql_backend`` backend: no session variable is set, no
   policy SQL is emitted, and the tenant model is never imported at
   connection time. You can install the package without changing any behavior.

.. warning::

   **Schema-per-tenant and shared-schema RLS are two different isolation
   models.** Choose one per app. The single most important migration rule is
   that RLS-isolated apps go in ``SHARED_APPS``, **not** ``TENANT_APPS`` (see
   :ref:`SHARED_APPS vs TENANT_APPS <shared-apps-vs-tenant-apps>` below). Getting
   this wrong leaves your tables un-created in ``public`` and the app will break.


When to use RLS mode
====================

Shared-schema RLS is the "Shared Approach" (option 3) from the
:doc:`introduction <index>`: a single shared database **and** a single shared
schema, with a tenant foreign key on every isolated table. Consider it when:

* You have a very large number of tenants and per-tenant schemas become
  expensive to migrate or back up.
* You need cross-tenant analytics that are awkward across many schemas.
* You want database-enforced isolation (the policy is applied by PostgreSQL,
  not by your application code) without per-schema overhead.

Schema-per-tenant remains the default and is the right choice for strong
physical separation. RLS mode and schema-per-tenant mode can coexist in one
project, but the choice is made **per database connection** -- a connection
running the RLS backend serves only the shared ``public`` schema and cannot also
serve schema-per-tenant ``TENANT_APPS`` (see `Hybrid deployments`_).


.. _rls-mechanism:

How RLS mode works
==================

1. ``TenantMainMiddleware`` resolves ``request.tenant`` from the host name
   exactly as it always does.
2. The RLS database backend remembers that tenant's primary key and, on **every
   cursor**, issues ``SELECT set_config('django_tenants.tenant_id', '<pk>',
   false)`` on the connection (SESSION scope), after the parent backend has set
   ``search_path`` to ``public``.
3. Each RLS-isolated table has a PostgreSQL policy whose ``USING`` /
   ``WITH CHECK`` expression compares the row's ``tenant_id`` against that
   session variable:

   .. code-block:: sql

       (tenant_id = NULLIF(current_setting('django_tenants.tenant_id', true), '')::integer
        OR current_setting('django_tenants.bypass_rls', true) = 'on')

4. The database transparently filters every ``SELECT`` and validates every
   ``INSERT`` / ``UPDATE`` to the active tenant. No application query needs to
   add a ``tenant=`` filter.

**Secure by default.** With no tenant set the session variable is the empty
string, ``NULLIF('', '')`` is ``NULL``, the comparison is ``NULL`` (not true),
and **no rows are visible**. The only escape hatches are (a) setting the tenant
session variable to a real primary key, or (b) setting the bypass variable to
the literal string ``on`` (see `Admin and cross-tenant access (bypass_rls)`_).

**FORCE ROW LEVEL SECURITY.** When ``TENANT_RLS_FORCE`` is ``True`` (the
default) the policy is applied even to the role that **owns** the table -- which
is normally the role Django connects as. Without ``FORCE``, the table owner is
exempt from its own policies, so isolation would be an illusion for the owning
connection. The bypass variable still works for the owner because the policy
explicitly ``OR``\ s it in.

.. danger::

   **The connecting role must not be a superuser and must not have BYPASSRLS.**
   PostgreSQL **always** ignores every row-security policy for a superuser or a
   role carrying the ``BYPASSRLS`` attribute -- ``FORCE ROW LEVEL SECURITY`` does
   **not** change this; ``FORCE`` only affects the (non-superuser) table owner.
   This is the most dangerous RLS misconfiguration because it fails *open* and
   *silently*: ``relrowsecurity`` is true, the policies exist, every query
   succeeds, and yet **there is no tenant isolation at all**. It is very easy to
   hit -- the default Postgres superuser (the ``postgres`` role, or a Docker
   image's ``POSTGRES_USER``) bypasses RLS.

   See the :ref:`Database role <rls-database-role>` section below for the
   least-privilege ``CREATE ROLE`` recipe and the matching ``DATABASES``
   configuration.

   The :ref:`W003 system check <rls-system-checks>` inspects the connecting role
   at startup. As of this release **W003 is an ERROR, not a warning**: by default
   a bypassing role blocks ``check`` (and therefore ``migrate``) from succeeding.
   You can opt out with ``TENANT_RLS_ALLOW_BYPASS_ROLE = True``, but doing so
   disables the only automatic guard against a silently-open deployment -- see
   :ref:`Database role <rls-database-role>`.


.. _rls-database-role:

Database role
-------------

The role your application connects as **must** be created
``NOSUPERUSER NOBYPASSRLS``. Connect your application as a dedicated,
least-privilege role and keep the superuser only for migrations and admin
tasks:

.. code-block:: sql

    CREATE ROLE app_rls LOGIN PASSWORD '…' NOSUPERUSER NOBYPASSRLS;
    GRANT USAGE ON SCHEMA public TO app_rls;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_rls;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_rls;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_rls;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT USAGE, SELECT ON SEQUENCES TO app_rls;

Point ``DATABASES['default']['USER']`` at that role (``app_rls`` above), **not**
at ``postgres`` or any other superuser. The ``examples/rls/settings_snippet.py``
file uses ``app_rls`` for exactly this reason.

The :ref:`W003 system check <rls-system-checks>` connects at startup and, if the
role is a superuser or carries ``BYPASSRLS``, raises an **Error** that blocks
``check``/``migrate``. If the database is unreachable or is not PostgreSQL the
check cannot inspect the role, so it stays silent (it can neither confirm nor
block).

.. warning::

   ``TENANT_RLS_ALLOW_BYPASS_ROLE`` (default ``False``) downgrades W003 back to
   *no finding* so a bypassing role no longer blocks startup. Set it **only** if
   you have a deliberate reason to run as a bypassing role (for example a
   migration-only connection that never serves tenant traffic). It turns off the
   single automatic safety net against the silent, fail-open misconfiguration
   described in the danger note above; isolation then depends entirely on you
   never pointing tenant traffic at that role.


Step 1 -- Install and add to SHARED_APPS
========================================

``django_tenants.rls`` ships inside the ``django-tenants`` package; there is
nothing extra to install. Add it to ``SHARED_APPS`` (it must be a *shared* app
because, in RLS mode, everything lives in ``public``):

.. code-block:: python

    SHARED_APPS = (
        'django_tenants',            # mandatory
        'django_tenants.rls',        # enables RLS system checks + auto-enable
        'customers',                 # the app holding your TENANT_MODEL
        # ... your RLS-isolated data apps go here too (see Step 4) ...
    )

Adding the app registers the RLS :ref:`system checks <rls-system-checks>` and,
when ``TENANT_RLS_AUTO_ENABLE`` is on, a ``post_migrate`` hook that enables RLS
automatically after migrations.

.. important::

   **Disable per-tenant schema creation.** ``TenantMixin.auto_create_schema``
   defaults to ``True``, which makes ``TenantMixin.save()`` create a new
   PostgreSQL schema named after each tenant's ``schema_name``. In RLS mode there
   is exactly one schema (``public``), so those per-tenant schemas would be empty
   and pointless. Set ``auto_create_schema = False`` (and, optionally,
   ``auto_drop_schema = False``) on your ``TenantMixin`` subclass so no per-tenant
   schemas are ever created:

   .. code-block:: python

       from django_tenants.models import TenantMixin

       class Client(TenantMixin):
           # ... your fields ...
           auto_create_schema = False   # RLS mode: keep a single public schema
           auto_drop_schema = False


Step 2 -- Enable RLS
====================

Turn the feature on. Each setting may be given as an individual top-level
setting **or** inside an optional ``DJANGO_TENANTS_RLS`` dict. The resolution
order is: individual top-level setting > ``DJANGO_TENANTS_RLS[name]`` >
hardcoded default.

.. code-block:: python

    # Either an individual setting ...
    TENANT_RLS_ENABLED = True

    # ... or the grouped dict form:
    DJANGO_TENANTS_RLS = {
        "TENANT_RLS_ENABLED": True,
    }

See `RLS settings reference`_ for the full list.


Step 3 -- Switch the database ENGINE
====================================

Point the tenant database at the RLS backend. It subclasses the standard
django-tenants backend, so the usual ``ORIGINAL_BACKEND`` setting still applies
(it defaults to ``django.db.backends.postgresql`` exactly as before).

.. code-block:: python

    DATABASES = {
        'default': {
            'ENGINE': 'django_tenants.rls.backend',
            # ORIGINAL_BACKEND defaults to django.db.backends.postgresql;
            # override only if you use a custom psycopg backend.
            # 'ORIGINAL_BACKEND': 'django.db.backends.postgresql',
            'NAME': 'myproject',
            # ... HOST / USER / PASSWORD / PORT as usual ...
        }
    }

    DATABASE_ROUTERS = (
        'django_tenants.routers.TenantSyncRouter',
    )

    MIDDLEWARE = (
        'django_tenants.middleware.main.TenantMainMiddleware',
        # ... your other middleware ...
    )

.. note::

   With the RLS backend in place, the backend sets the tenant session variable
   on every cursor, so you do **not** need any extra middleware. The optional
   ``TenantRLSMiddleware`` (`Optional fallback middleware`_) is only for setups
   that keep the stock backend.


.. _shared-apps-vs-tenant-apps:

Step 4 -- SHARED_APPS vs TENANT_APPS
====================================

This is the most important migration instruction in RLS mode.

In schema-per-tenant mode, tenant data apps go in ``TENANT_APPS`` and are
migrated into each tenant schema. **In RLS mode there is exactly one schema
(**\ ``public``\ **).** Therefore:

.. warning::

   **RLS-isolated apps MUST be listed in** ``SHARED_APPS``\ **, NOT**
   ``TENANT_APPS``\ **.**

   If an RLS app is left in ``TENANT_APPS``, ``TenantSyncRouter.allow_migrate``
   will only let its tables be created inside per-tenant schemas -- which RLS
   mode never creates or uses -- so the tables will be **missing from**
   ``public`` and the app will break.

Why this works
--------------

``TenantSyncRouter`` reads ``connection.schema_name`` to decide where a
migration applies. With the RLS backend the ``search_path`` stays ``public``,
so ``connection.schema_name == get_public_schema_name()`` for all tenant
operations, and ``allow_migrate`` returns based on membership in ``SHARED_APPS``.
Putting RLS apps in ``SHARED_APPS`` makes ``migrate_schemas --shared`` (the
public/shared migrate) create their tables in ``public``. **No per-tenant
migrate pass is needed** for RLS apps.

The tenant model's app (the ``TENANT_MODEL`` app) and ``django_tenants.rls``
itself also belong in ``SHARED_APPS``.

Moving an app from TENANT_APPS to SHARED_APPS
---------------------------------------------

If you are converting an existing schema-per-tenant app to RLS, move it from
``TENANT_APPS`` to ``SHARED_APPS`` following the standard procedure for moving
apps between the two (see the :doc:`install <install>` guide's warning on
*Moving apps between SHARED_APPS and TENANT_APPS*), then migrate any per-tenant
data into ``public`` with a ``tenant`` foreign key populated for every row.

Hybrid deployments
------------------

The isolation model is chosen **per database connection, not per app on a single
connection.** The RLS backend pins ``search_path`` to ``public`` for every tenant
(that is how shared-schema isolation works), so a connection that uses
``django_tenants.rls.backend`` **cannot** also serve schema-per-tenant
``TENANT_APPS``: those tables live in per-tenant schemas that are no longer on the
search path, and queries against them will fail. Do not expect ``TENANT_APPS`` to
remain schema-isolated on a connection running the RLS backend.

A hybrid is therefore possible, but at the connection/database level:

* Put every RLS-isolated app in ``SHARED_APPS`` on the RLS-backend connection
  (the single most important rule -- see
  :ref:`SHARED_APPS vs TENANT_APPS <shared-apps-vs-tenant-apps>`); and
* if you still need schema-per-tenant apps, route them to a **separate**
  ``DATABASES`` alias that uses the standard ``django_tenants.postgresql_backend``
  (via a database router), where ``TENANT_APPS`` keep working as before.

During the migration itself ``TENANT_APPS`` is expected to be non-empty
transiently as you move apps to ``SHARED_APPS``; just do not point production
tenant traffic for those apps at the RLS-backend connection until they have moved.


Step 5 -- Make models inherit TenantRLSModel
============================================

Change your isolated models to subclass
``django_tenants.rls.models.TenantRLSModel`` instead of ``models.Model``. The
base class adds a ``tenant`` foreign key to ``settings.TENANT_MODEL`` and an
overridden ``save()`` that auto-populates the tenant from the active connection.

.. code-block:: python

    from django.db import models
    from django_tenants.rls.models import TenantRLSModel

    class Note(TenantRLSModel):
        text = models.TextField()

        # No explicit Meta.rls_policies -> a default TenantPolicy is built
        # automatically on the `tenant` field at enable time.

For a **brand-new (empty) table** the new ``tenant`` FK is a normal column, so
this is a normal schema migration:

.. code-block:: bash

    python manage.py makemigrations
    python manage.py migrate_schemas --shared

.. danger::

   **Do NOT do this on an EXISTING, already-populated table.** It is tempting to
   add the ``tenant`` FK as ``null=False`` in one step and let
   ``makemigrations`` prompt you for a one-off default. **Both halves of that are
   wrong on populated data:**

   * Adding a ``NOT NULL`` column to a table that already has rows fails outright
     under ``migrate --noinput`` (there is no value for the existing rows).
   * Supplying a one-off default stamps **every existing row into a single
     tenant**, silently cross-contaminating all of your historical data into one
     tenant -- the exact opposite of isolation.

   Use the staged path in :ref:`Upgrading an existing populated table
   <rls-upgrade-existing>` instead: add the FK as ``null=True`` **first**,
   backfill the real ``tenant_id`` per row, *then* tighten to ``null=False``, and
   only then enable RLS.

.. note::

   **tenant field coupling.** The abstract base hard-codes the FK attribute
   name ``tenant``, which matches the default ``TENANT_RLS_TENANT_FIELD``. If you
   need a different field name, set ``TENANT_RLS_TENANT_FIELD`` **and** define
   your own FK with that name plus a matching
   ``TenantPolicy(tenant_field=...)``.


.. _rls-upgrade-existing:

Upgrading an existing populated table
-------------------------------------

If the table **already contains rows** (you are converting an established app to
RLS, or moving an app from ``TENANT_APPS`` to ``SHARED_APPS``), the order of
operations matters for both correctness and safety. Never add the tenant FK as
non-nullable in a single step, and never accept a one-off default -- see the
danger note above.

Stage the change across these steps, in this exact order:

#. **Add the FK as nullable.** Define the ``tenant`` FK with ``null=True`` (or
   subclass ``TenantRLSModel`` and add an explicit
   ``AlterField``/``AddField`` making the column nullable) and migrate. Existing
   rows now have ``tenant_id IS NULL``; new schema applies without a forced
   default.

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
                   field=models.ForeignKey(
                       null=True,
                       on_delete=django.db.models.deletion.CASCADE,
                       to=settings.TENANT_MODEL,
                   ),
               ),
           ]

#. **Backfill ``tenant_id`` for every row.** Stamp each existing row with its
   real owning tenant. For a deployment migrating *out of* schema-per-tenant
   this means copying each per-tenant schema's rows into ``public`` with the
   tenant pk attached -- see :ref:`Backfilling tenant_id
   <rls-backfill-recipe>` for a copy-pasteable recipe. Run the backfill under
   ``bypass_rls()`` (or before RLS is enabled at all) so the writes are not
   themselves filtered.

#. **Tighten to ``null=False``.** Only once **every** row has a non-NULL
   ``tenant_id`` (verify with a count of ``tenant_id IS NULL`` rows -- it must be
   zero), add an ``AlterField`` making the column ``null=False``:

   .. code-block:: python

       # 0004_tenant_not_null.py -- after the backfill data migration
       operations = [
           migrations.AlterField(
               model_name="note",
               name="tenant",
               field=models.ForeignKey(
                   on_delete=django.db.models.deletion.CASCADE,
                   to=settings.TENANT_MODEL,
               ),
           ),
       ]

#. **Then, and only then, enable RLS** (see :ref:`Step 6
   <rls-step-6-enable>`). Enabling RLS before the backfill completes makes the
   un-backfilled ``NULL`` rows invisible to every tenant (see :ref:`NULL
   tenant_id rows <rls-null-rows>`).

.. warning::

   With the recommended defaults (``TENANT_RLS_AUTO_ENABLE = True``) the
   ``post_migrate`` auto-enable hook fires in the **same** ``migrate`` run that
   creates or alters the table. For an existing populated table that would
   enable RLS *before* you have backfilled. Set
   ``TENANT_RLS_AUTO_ENABLE = False`` for the upgrade and enable RLS explicitly
   after the backfill -- see :ref:`Step 6 <rls-step-6-enable>` and :ref:`NULL
   tenant_id rows <rls-null-rows>`.

Customising policies
--------------------

To override the auto-generated policy, set ``Meta.rls_policies`` to a list of
policy objects from ``django_tenants.rls.policies``:

.. code-block:: python

    from django_tenants.rls.models import TenantRLSModel
    from django_tenants.rls.policies import TenantPolicy

    class Note(TenantRLSModel):
        text = models.TextField()

        class Meta:
            rls_policies = [
                # Pass pk_cast (and the session/bypass variable names) explicitly
                # so the policy never has to import the tenant model at class /
                # import time to resolve its defaults. Use 'integer' for an
                # AutoField PK, 'bigint' for a BigAutoField PK, or 'uuid' for a
                # UUIDField PK.
                #
                # If you omit name=, the default policy name is
                # "<db_table>_tenant_isolation" (e.g. "blog_note_tenant_isolation"
                # for app "blog", model "Note"). Passing name= explicitly here
                # means you must use the SAME name with disable_rls / DropPolicy.
                TenantPolicy(name="blog_note_tenant_isolation", pk_cast="integer"),
            ]

``CustomPolicy(name, expression, check_expression=None)`` is also available for
a raw SQL expression.

.. note::

   **Policy names are limited to 63 bytes** (a PostgreSQL identifier maximum).
   ``BasePolicy.validate()`` raises ``PolicyError`` for a longer name. The
   auto-generated default name ``"<db_table>_tenant_isolation"`` is
   automatically shortened (a readable ``db_table`` prefix plus a short stable
   hash) when the full string would exceed 63 bytes, so long table names are
   handled for you; only explicit ``name=`` values are your responsibility.

.. note::

   When you declare ``Meta.rls_policies`` explicitly, the ``TenantPolicy`` is
   constructed at class-definition (import) time. Passing ``pk_cast`` (and, if
   you have customised them, ``session_variable`` / ``bypass_variable``)
   explicitly avoids resolving those defaults -- which would import the tenant
   model -- during your app's models import. The auto-generated default policy
   (no explicit ``Meta.rls_policies``) is instead built lazily at enable time and
   has no such constraint.

.. warning::

   ``CustomPolicy`` expressions are raw SQL and are **NOT** validated beyond
   being non-empty. The caller is fully responsible for their safety -- never
   build a ``CustomPolicy`` expression from untrusted input. Prefer
   ``TenantPolicy`` whenever possible.


.. _rls-backfill-recipe:

Backfilling tenant_id (migrating from schema-per-tenant)
========================================================

If you are converting an **existing schema-per-tenant deployment** to RLS, your
historical rows currently live in per-tenant schemas (``tenant1.blog_note``,
``tenant2.blog_note``, ...) and the new ``public.blog_note`` table is empty. You
must copy every row into ``public`` with its owning tenant's primary key stamped
into ``tenant_id``. There is **no generic management command for this** -- the
right candidate columns, type coercions, and conflict handling are too
project-specific to ship safely -- so do it as an explicit, reviewed data
migration or one-off script.

The shape of the backfill is: loop over every tenant, point ``search_path`` at
that tenant's schema, and ``INSERT`` its rows into the shared ``public`` table
with the tenant pk added. Run the whole thing under ``bypass_rls()`` (or before
RLS is enabled at all) so the writes are not themselves filtered:

.. code-block:: python

    # A data migration step, or a one-off script run with the app settings.
    from django.db import connection
    from django_tenants.rls.session import bypass_rls
    from django_tenants.utils import get_tenant_model, get_public_schema_name

    TenantModel = get_tenant_model()
    public = get_public_schema_name()

    # List the real data columns of the table (everything EXCEPT the new
    # tenant_id, which we supply per-tenant). Keep this list explicit so you
    # never copy a column that does not exist in both schemas.
    COLUMNS = ["id", "text", "created_at"]
    col_sql = ", ".join('"%s"' % c for c in COLUMNS)

    with bypass_rls():
        with connection.cursor() as cur:
            for tenant in TenantModel.objects.exclude(schema_name=public):
                # Stamp THIS tenant's pk into tenant_id for every row copied
                # out of THIS tenant's schema.
                # Quote the schema identifier via the connection's quoting
                # helper rather than hand-wrapping it in double quotes -- schema
                # names permit characters that would otherwise let a stray quote
                # break out of the identifier.
                schema = connection.ops.quote_name(tenant.schema_name)
                cur.execute(
                    'INSERT INTO public.blog_note (%s, tenant_id) '
                    'SELECT %s, %%s FROM %s.blog_note'
                    % (col_sql, col_sql, schema),
                    [tenant.pk],
                )

            # Verify: there must be NO un-stamped rows before you tighten the
            # column to NOT NULL or enable RLS.
            cur.execute("SELECT count(*) FROM public.blog_note WHERE tenant_id IS NULL")
            assert cur.fetchone()[0] == 0, "backfill incomplete: NULL tenant_id rows remain"

Notes and cautions:

* Adjust ``COLUMNS`` to your real schema, and add ``ON CONFLICT`` /
  de-duplication if the source schemas can contain colliding primary keys.
  Copying the original ``id`` preserves cross-table foreign keys; drop it (and
  let ``public`` re-sequence) only if nothing references it.
* If the tenant pk type is not an integer (for example ``UUID``), the ``%s``
  placeholder still works -- the driver adapts it -- but make sure the
  ``tenant_id`` column type matches the tenant pk type (see :ref:`Supported
  tenant primary-key types <rls-pk-types>`).
* Run this **after** the FK column exists as ``null=True`` and **before** the
  ``AlterField`` to ``null=False`` and before enabling RLS -- see
  :ref:`Upgrading an existing populated table <rls-upgrade-existing>`.
* After the counts verify, ``SET NOT NULL`` on the column (via the
  ``AlterField`` migration) and *then* enable RLS.


.. _rls-null-rows:

What happens to NULL tenant_id rows once RLS is on
==================================================

Once RLS is enabled, the policy compares ``tenant_id`` to the active tenant
session variable. A row whose ``tenant_id`` **is NULL** can never satisfy that
comparison: ``NULL = <anything>`` is ``NULL`` (not true), so the row is
**invisible to every tenant** -- and, because the active tenant is never NULL,
invisible no matter which tenant is active.

The rows are **invisible, not lost.** They are still on disk and become visible
again under ``bypass_rls()`` or after you ``disable_rls``. But to your
application they have effectively vanished. This is precisely why the
:ref:`upgrade ordering <rls-upgrade-existing>` is strict: **finish the backfill
(no NULL ``tenant_id`` rows remain) before enabling RLS.** If you enable RLS on a
table that still has un-backfilled NULL rows, those rows silently disappear from
every tenant's view until you backfill them (under bypass) and they re-match a
tenant.

To protect you from doing this accidentally:

* The ``post_migrate`` auto-enable handler **skips** any model whose table still
  has NULL ``tenant_id`` rows and logs a loud warning instead of enabling RLS on
  it.
* ``manage.py enable_rls`` still proceeds (you invoked it deliberately) but
  prints a prominent warning naming the affected model so you know those rows are
  about to become invisible.


.. _rls-step-6-enable:

Step 6 -- Enable RLS on the database
====================================

The migration that creates your tables does *not* by itself turn on RLS or
create the policies. There are three ways to do that; pick one.

.. important::

   **Greenfield (empty tables) vs. existing populated tables.** Auto-enable
   (Option A) is safe and recommended for **new, empty** tables. For a table
   that **already has rows** you must backfill ``tenant_id`` *before* RLS is
   enabled, so set ``TENANT_RLS_AUTO_ENABLE = False`` and enable RLS explicitly
   (Option B or C) **after** the backfill. See :ref:`Upgrading an existing
   populated table <rls-upgrade-existing>` and :ref:`NULL tenant_id rows
   <rls-null-rows>`.

Option A -- automatic, via post_migrate
---------------------------------------

When ``TENANT_RLS_AUTO_ENABLE`` is ``True`` (the default) and
``TENANT_RLS_ENABLED`` is ``True``, the ``django_tenants.rls`` app connects a
``post_migrate`` handler that enables RLS and creates policies for every
concrete ``TenantRLSModel`` subclass in the migrated app. For greenfield
projects this means you simply run your normal migrate and RLS is on.

**This hook runs inside the same** ``migrate`` **that created or altered the
table.** That is exactly what you want for a brand-new empty table, but it is
*not* what you want for an existing populated table: it would enable RLS before
you have backfilled ``tenant_id``, making every un-backfilled row invisible (see
:ref:`NULL tenant_id rows <rls-null-rows>`). For upgrades of existing data set
``TENANT_RLS_AUTO_ENABLE = False`` and use Option B or C after backfilling.

Two safeguards apply to the auto-enable hook:

* **It skips tables with NULL ``tenant_id`` rows.** Before enabling RLS on a
  model the handler checks for un-backfilled rows; if any exist it logs a loud
  warning and **does not** enable RLS on that model (enabling would hide those
  rows).
* **Failures are logged, never swallowed silently.** A failure enabling a given
  model does not crash ``migrate``, but the full traceback is logged via
  ``logger.exception`` and the log makes clear that the isolation state of that
  model is **indeterminate** -- do not assume RLS is on just because ``migrate``
  exited 0. Check the log, or run ``manage.py check --database default``.

Option B -- the management command
----------------------------------

Run the bundled command at any time (for example after a deploy, **after**
backfilling an existing table):

.. code-block:: bash

    python manage.py enable_rls
    python manage.py enable_rls --app blog          # limit to one app label
    python manage.py enable_rls --model note         # limit to one model

If a model's table still has rows with ``tenant_id IS NULL``, the command prints
a prominent warning naming that model (those rows will become invisible to every
tenant once RLS is on -- see :ref:`NULL tenant_id rows <rls-null-rows>`) but
still proceeds, because you invoked it deliberately. Backfill first if that is
not what you intend.

The inverse command tears policies down again (see :ref:`Rolling back / disabling
RLS <rls-rollback>` for the full picture -- flipping the setting alone is not
enough):

.. code-block:: bash

    python manage.py disable_rls

Option C -- explicit migration operations
-----------------------------------------

For reproducible, versioned RLS state, add the operations from
``django_tenants.rls.operations`` to a migration:

.. code-block:: python

    from django.db import migrations
    from django_tenants.rls.operations import EnableRLS, CreateTenantPolicy

    class Migration(migrations.Migration):
        dependencies = [
            ("blog", "0001_initial"),
        ]
        operations = [
            EnableRLS("note"),
            CreateTenantPolicy("note"),
        ]

The available operations are:

* ``EnableRLS(model_name)`` -- ``ENABLE ROW LEVEL SECURITY`` (and
  ``FORCE ROW LEVEL SECURITY`` when ``TENANT_RLS_FORCE`` is on). Reversible to
  ``DisableRLS``.
* ``DisableRLS(model_name)`` -- the inverse.
* ``CreateTenantPolicy(model_name, name=None, tenant_field=None,
  session_variable=None, bypass_variable=None, pk_cast=None, operation=None,
  permissive=None, roles=None)`` -- build and create a ``TenantPolicy`` for the
  model's tenant field. When ``name`` is left ``None`` the policy name defaults
  to ``"<db_table>_tenant_isolation"``, **resolved from the model's**
  ``_meta.db_table`` **at apply time** -- the *same* name the models auto path
  and ``manage.py enable_rls`` create. This means ``DisableRLS`` /
  ``DropPolicy`` target the identical policy, so disable/teardown actually
  removes the policy created by enable. (Earlier versions derived the default
  from ``model_name``, which could orphan the policy.) Every policy argument is
  an explicit keyword (not ``**kwargs``) so the operation round-trips faithfully
  through ``makemigrations``; ``deconstruct`` only emits ``name`` when you set it
  explicitly. The ``pk_cast`` is snapshotted when the operation is written, so
  the migration records the exact cast and stays reproducible even if the tenant
  model's PK type changes later.
* ``CreatePolicy(model_name, policy)`` -- create an arbitrary ``BasePolicy``
  instance.
* ``DropPolicy(model_name, policy_name)`` -- drop a policy by name (irreversible).

Each operation is a no-op against a non-RLS schema editor (guarded by
``hasattr``), so a migration containing them still runs cleanly under the stock
backend.

.. note::

   The default policy is built lazily at enable time (inside
   ``get_rls_policies()``), not at model-definition time, so settings such as
   the session-variable names and the PK cast are read after the app registry
   and settings are fully loaded.


.. _rls-rollback:

Rolling back / disabling RLS
============================

Disabling RLS is a **two-part** operation, and getting only one part done is a
foot-gun:

#. Set ``TENANT_RLS_ENABLED = False`` (so the backend stops setting the tenant
   session variable and the subpackage goes inert), **and**
#. Tear the database state down with ``manage.py disable_rls`` (or a
   ``DisableRLS`` + ``DropPolicy`` migration operation), which runs
   ``DISABLE ROW LEVEL SECURITY`` and drops the policies.

.. danger::

   **Flipping only the setting is not a rollback.** If you set
   ``TENANT_RLS_ENABLED = False`` but leave ``FORCE ROW LEVEL SECURITY`` and the
   policies in place on the table, the backend no longer sets the tenant session
   variable -- so the policy's comparison is against the empty string,
   ``NULLIF('', '')`` is ``NULL``, and a ``NOSUPERUSER NOBYPASSRLS`` application
   role sees **zero rows** on every query. You have locked yourself out of your
   own data. Always run ``disable_rls`` (or the ``DisableRLS`` op) as well.

Disabling RLS **retains your data and the ``tenant_id`` column** -- it only
removes the database-level enforcement. The ``tenant`` FK stays on the model and
on the table; if you want to remove it entirely, that is a separate, ordinary
schema migration you write afterwards. To turn RLS back on again, re-enable the
setting and run ``enable_rls`` (or the ``EnableRLS`` + ``CreateTenantPolicy``
ops).


Admin and cross-tenant access (bypass_rls)
==========================================

Privileged work -- the Django admin, data migrations, cross-tenant aggregation,
or one-off scripts -- needs to see or write rows across tenants. Use the
``bypass_rls`` context manager. It sets the bypass session variable to ``on``,
which the policy explicitly ``OR``\ s in, so it works even under
``FORCE ROW LEVEL SECURITY``:

.. code-block:: python

    from django_tenants.rls.session import bypass_rls

    with bypass_rls():
        Note.objects.all()      # sees ALL tenants' rows; writes unrestricted

The previous bypass value is always restored on exit (even on exception), so
nesting is correct.

.. _bypass-leak-note:

.. note::

   Bypass is bound to the connection and is reset to ``off`` whenever a tenant is
   (re)activated -- that is, on every request and on any explicit
   ``tenant_context`` / ``schema_context`` / ``tenant.activate()``. This is
   deliberate: every request starts from the secure, isolated default. The
   practical consequence is that ``bypass_rls()`` must wrap the *innermost*
   scope -- open it after any tenant activation, and do not expect it to survive
   across a ``tenant_context`` block nested inside it.

   **What prevents a leaked bypass from carrying across requests** depends on
   which deployment you run:

   * **With the RLS backend** (``ENGINE = 'django_tenants.rls.backend'``, the
     recommended setup): the backend re-asserts the bypass value on **every
     cursor** and resets it to ``off`` whenever the tenant is set, so a bypass
     left ``on`` cannot survive into the next request on a pooled or persistent
     connection.
   * **On the stock-backend fallback** (you kept the standard backend and only
     installed ``TenantRLSMiddleware``): the middleware forces bypass **off** at
     the start of every request (and clears it again on response/exception). This
     is what closes the gap where a prior request's ``bypass_rls()`` ``__exit__``
     might not have run on a persistent connection.

   In both cases the guarantee is the same in practice -- no bypass leaks across
   requests -- but it is provided by different layers, so do not remove the
   fallback middleware on a stock-backend deployment.

To operate as a *specific* tenant from a script or a management command (without
an HTTP request to set ``request.tenant``), use ``rls_context``:

.. code-block:: python

    from django_tenants.rls.session import rls_context

    with rls_context(tenant):           # accepts a tenant instance or a bare pk
        Note.objects.create(text="...")   # tenant auto-set; only this tenant visible

Both context managers are also usable as decorators (they subclass
``ContextDecorator``) and both restore the *previous* value rather than
unconditionally clearing it. For convenience they are re-exported from the
package root::

    from django_tenants.rls import bypass_rls, rls_context

Lower-level helpers (``set_current_tenant``, ``clear_current_tenant``,
``get_current_tenant_id``, ``set_bypass``, ``get_bypass``) live in
``django_tenants.rls.session`` if you need finer control.

.. warning::

   ``bypass_rls()`` removes tenant isolation for the duration of the block. Use
   it deliberately and keep the block as small as possible. Use it **only** for
   work that genuinely needs to see or write across tenants.

.. important::

   **A normal, per-tenant Django admin needs NO bypass.** When the admin is
   served through ``TenantMainMiddleware`` (or the RLS backend / fallback
   middleware) the active tenant is already set on the connection, so RLS scopes
   every admin queryset to that tenant automatically -- exactly like the rest of
   your app. **Do not** wrap a tenant-scoped admin's ``ModelAdmin`` /
   ``get_queryset`` in ``bypass_rls()``: that would disable isolation and expose
   every tenant's rows in the admin. Reach for ``bypass_rls()`` only in a
   *deliberately* cross-tenant admin (a superuser/staff "all tenants" console),
   and even then scope it to the specific views or querysets that need it.


bulk_create and other save()-bypassing paths
=============================================

``TenantRLSModel.save()`` auto-populates ``tenant_id`` from the active
connection's tenant when it is unset. **Operations that bypass** ``save()`` --
notably ``QuerySet.bulk_create()``, ``bulk_update()`` and raw inserts -- do
**not** get this auto-population, so you must set the tenant explicitly:

.. code-block:: python

    from django_tenants.rls.session import rls_context

    with rls_context(tenant):
        Note.objects.bulk_create([
            Note(text="a", tenant=tenant),
            Note(text="b", tenant=tenant),
        ])

The policy's ``WITH CHECK`` clause still protects you at the database level: an
``INSERT`` whose ``tenant_id`` does not match the active tenant session variable
is **rejected** by PostgreSQL, even though no exception was raised in Python
before the query. This is defense in depth -- the database is the source of
truth for isolation.


.. _rls-constraints:

Database constraints and covert channels
=========================================

RLS policies filter the **rows a query reads and writes**, but PostgreSQL applies
``UNIQUE``, primary-key and foreign-key **constraint checks with row security
bypassed**. A constraint check therefore sees *every* tenant's rows, even though
your queries never can. This is documented behaviour (constraint enforcement is a
privileged internal operation), and it opens a *covert channel*: an attacker can
probe for the **existence** of another tenant's value without ever being able to
read it.

.. danger::

   **A global ``UNIQUE`` constraint leaks cross-tenant existence.** Suppose
   ``email`` is declared ``unique=True``. Tenant A inserts ``alice@example.com``.
   Tenant B then tries to insert the *same* address and gets an
   ``IntegrityError`` -- even though tenant B can never *see* tenant A's row. The
   error itself confirms that some other tenant already owns that email. The
   ``UNIQUE`` index spans the whole shared table, so it silently makes a global
   namespace out of what should be a per-tenant one.

   The fix is to make every uniqueness **tenant-scoped** -- include the tenant
   column in the constraint so the namespace is per-tenant:

   .. code-block:: python

       from django.db import models
       from django_tenants.rls.models import TenantRLSModel

       class Contact(TenantRLSModel):
           # WRONG under RLS: a single global namespace; leaks existence.
           # email = models.EmailField(unique=True)

           # RIGHT: drop the field-level unique= and scope it to the tenant.
           email = models.EmailField()

           class Meta:
               constraints = [
                   models.UniqueConstraint(
                       fields=["tenant", "email"],
                       name="contact_unique_email_per_tenant",
                   ),
               ]

   The same applies to ``Meta.unique_together`` and to any
   ``UniqueConstraint`` -- every uniqueness must list the tenant field. The
   :ref:`W005 system check <rls-system-checks>` flags any ``unique=True`` field,
   ``unique_together``, or ``UniqueConstraint`` on a ``TenantRLSModel`` whose
   field set does **not** include the tenant field.

.. warning::

   **The primary key and cross-model foreign keys are existence-probe surfaces
   too.** The global ``id`` PK is, by definition, unique across the whole shared
   table, so an ``INSERT`` that collides with another tenant's ``id`` raises an
   ``IntegrityError`` that confirms that ``id`` is taken somewhere. Prefer a
   non-guessable surrogate key (``BigAutoField`` is hard to enumerate; ``UUIDField``
   removes the channel entirely) and never let a client choose the ``id``.

   Likewise, a ``ForeignKey`` from one ``TenantRLSModel`` to **another**
   ``TenantRLSModel`` is checked with RLS bypassed: PostgreSQL validates that the
   referenced row exists across *all* tenants, so a foreign-key violation (or its
   absence) reveals whether a given pk exists in the referenced table for *some*
   tenant. Application code should always validate that a referenced object is
   visible **under the current tenant** before saving, rather than relying on the
   FK check, and should avoid surfacing the raw database error to the client.


Optional fallback middleware
============================

If you cannot switch the database ``ENGINE`` to ``django_tenants.rls.backend``
(for example a constrained deployment that must keep the stock backend), you can
still get RLS isolation by installing the fallback middleware. It sets the
tenant session variable from ``request.tenant`` after ``TenantMainMiddleware``
resolves it, **forces bypass off** at the start of each request (so a bypass
left ``on`` by a prior request's ``bypass_rls()`` cannot leak onto a persistent
connection), and clears both the tenant and bypass on response/exception:

.. code-block:: python

    MIDDLEWARE = (
        'django_tenants.middleware.main.TenantMainMiddleware',
        'django_tenants.rls.middleware.TenantRLSMiddleware',   # AFTER TenantMainMiddleware
        # ...
    )

When the RLS backend *is* in use this middleware is redundant (the backend's
``_cursor`` already sets the variable on every cursor and re-asserts bypass per
cursor) but harmless, so it can be left installed. On a stock-backend
deployment, however, this middleware is what provides the cross-request bypass
reset described under :ref:`bypass_rls <bypass-leak-note>` -- do not remove it.


.. _rls-cache-storage-celery:

Tenant-aware cache, file storage, and Celery
============================================

Schema-per-tenant django-tenants ships helpers that key the cache and the file
storage on ``connection.schema_name``. **Under RLS those helpers collapse all
tenants together.** The RLS backend keeps the ``search_path`` on ``public`` for
*every* tenant, so ``connection.schema_name`` is pinned to ``"public"`` and is no
longer the active tenant. Anything keyed on it -- cache keys, on-disk media
paths, Celery routing -- silently shares state across tenants.

The real active tenant is still available as ``connection.tenant`` (the RLS
backend sets it from ``request.tenant`` / ``rls_context`` just like the stock
backend). The RLS subpackage exposes
``django_tenants.rls.session.current_tenant_schema(using=None)``, which returns
``connection.tenant.schema_name`` (falling back to the public schema name when no
tenant is active). All of the helpers below derive their per-tenant key/path from
*that* function, **not** from ``connection.schema_name``.

Cache (django-redis)
--------------------

``django_tenants.rls.cache`` provides drop-in replacements for the
``django_tenants.cache`` key functions that source the tenant from the real
tenant rather than ``connection.schema_name``. The key *shape* is identical
(``"<schema>:<prefix>:<version>:<key>"``), so it is a straight swap:

.. code-block:: python

    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": "redis://127.0.0.1:6379/1",
            "KEY_FUNCTION": "django_tenants.rls.cache.make_key",
            "REVERSE_KEY_FUNCTION": "django_tenants.rls.cache.reverse_key",
        }
    }

Without this, two tenants computing the same logical key under RLS would read and
write the **same** Redis entry (both keyed on ``public:``), leaking cached data
across tenants.

File storage
------------

``django_tenants.rls.storage.RLSTenantFileSystemStorage`` mirrors
``TenantFileSystemStorage`` but builds the per-tenant media path/URL segment from
``current_tenant_schema()`` instead of ``connection.schema_name``:

.. code-block:: python

    # settings.py (Django >= 4.2 STORAGES form)
    STORAGES = {
        "default": {
            "BACKEND": "django_tenants.rls.storage.RLSTenantFileSystemStorage",
        },
        "staticfiles": {
            "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
        },
    }

The module also exposes ``rls_parse_tenant_config_path(config_path)`` (the
RLS-aware analogue of ``django_tenants.utils.parse_tenant_config_path``) and an
``RLSTenantStorageMixin`` you can mix into any ``Storage`` subclass.

If you store media in S3 via **django-storages**, the subpackage deliberately
does *not* import ``S3Boto3Storage`` (it is an optional dependency). Apply the
same override yourself by prepending ``current_tenant_schema()`` to the storage
``location``:

.. code-block:: python

    from storages.backends.s3boto3 import S3Boto3Storage
    from django_tenants.rls.session import current_tenant_schema

    class RLSTenantS3Storage(S3Boto3Storage):
        @property
        def location(self):
            base = super().location or ""
            return "/".join(s for s in (current_tenant_schema(), base.strip("/")) if s)

Celery (out-of-request tasks)
-----------------------------

A Celery worker runs **outside** the request cycle, so nothing sets (or clears)
the tenant GUC for it. Two failure modes follow: a task can run with **no**
tenant set (RLS makes every row invisible), or -- worse, on a reused worker
connection -- it can **inherit the previous task's tenant** and read/write the
wrong tenant's data.

The rule is therefore: **every task must wrap its own database work in a tenant
context**, exactly as a script would:

.. code-block:: python

    from django_tenants.rls.session import rls_context, bypass_rls

    @app.task
    def rebuild_report(tenant_id):
        with rls_context(tenant_id):       # accepts a tenant instance or a bare pk
            ...                            # all DB work scoped to this tenant
        # for deliberate cross-tenant work use bypass_rls() instead

To guarantee a task can never *silently inherit* a prior task's tenant on a
pooled worker connection, register the shipped signal handlers, which reset the
connection to the secure default (no tenant, bypass off) before and after every
task:

.. code-block:: python

    # In your Celery app setup (e.g. celery.py), after the app is created:
    from django_tenants.rls.celery import register

    register()   # connects task_prerun / task_postrun handlers

``register()`` lazily imports ``celery.signals`` and raises
``ImproperlyConfigured`` if Celery is not installed. The handlers only enforce
the secure *default* (they call ``clear_current_tenant()`` and
``set_bypass(False)``); they do **not** activate a tenant for you. Each task is
still responsible for its own ``rls_context(tenant)`` (or ``bypass_rls()``)
block -- the handlers simply ensure that a task that forgets to do so sees *no*
rows rather than the wrong tenant's rows.


.. _rls-system-checks:

System checks
=============

With ``django_tenants.rls`` installed and ``TENANT_RLS_ENABLED`` on, Django's
``check`` framework reports common misconfigurations:

* **W001** -- ``TENANT_RLS_ENABLED`` is ``True`` but the database ``ENGINE`` is
  not ``django_tenants.rls.backend`` and ``TenantRLSMiddleware`` is not
  installed, so RLS isolation will not be applied.
* **W002** -- a ``TenantRLSModel`` subclass has no field named
  ``TENANT_RLS_TENANT_FIELD``.
* **W003 (now an Error)** -- the database role on the tenant alias is a
  superuser or has the ``BYPASSRLS`` attribute, so PostgreSQL bypasses every
  policy and there is **no isolation** (see the :ref:`danger note above
  <rls-mechanism>` and :ref:`Database role <rls-database-role>`). As of this
  release this is reported as an **Error** (it keeps the ``W003`` id for
  continuity) and therefore **blocks** ``check`` and ``migrate``. To opt out
  deliberately, set ``TENANT_RLS_ALLOW_BYPASS_ROLE = True`` -- the check then
  emits *nothing* (see the warning under :ref:`Database role
  <rls-database-role>` about disabling this safety net). This check connects to
  the database; if the database is not reachable or is not PostgreSQL during
  ``check`` it cannot inspect the role and stays silent (it can neither confirm
  nor block). It runs with the ``database`` tag (e.g. during ``migrate`` or
  ``manage.py check --database default``).
* **W004** -- *RLS-live drift.* For each concrete ``TenantRLSModel`` the check
  introspects the database (on the tenant alias) and warns when the table's
  protections do not actually match the configuration: RLS is **not enabled**
  (``pg_class.relrowsecurity`` is false), RLS is **not forced** while
  ``TENANT_RLS_FORCE`` is on (``relforcerowsecurity`` is false), there is **no
  policy** on the table (no ``pg_policies`` row), or the tenant column
  (``<tenant_field>_id``) is **nullable** (so NULL-tenant rows could exist).
  This catches the gap where ``migrate`` exited 0 but a model's
  :ref:`auto-enable hook failed <rls-step-6-enable>`, or where someone disabled a
  policy out of band. It runs with the ``database`` tag and is **best-effort**:
  any database error (not reachable, not PostgreSQL, table not created yet)
  yields no findings rather than a false alarm.
* **W005** -- *unique-without-tenant.* A model-level check (no database access)
  that flags any ``unique=True`` field, ``Meta.unique_together`` set, or
  ``Meta.constraints`` ``UniqueConstraint`` on a ``TenantRLSModel`` whose field
  set does **not** include the tenant field. PostgreSQL evaluates ``UNIQUE``
  checks with row security bypassed, so a global uniqueness leaks cross-tenant
  existence (see :ref:`Database constraints and covert channels
  <rls-constraints>`). The hint is to scope the constraint to the tenant, e.g.
  ``UniqueConstraint(fields=["tenant", ...])``.
* **E001** -- the session/bypass variable name is not a valid PostgreSQL GUC
  variable name (it must be of the form ``<class>.<name>``).
* **E002** -- the tenant model's primary-key type cannot be mapped to a
  PostgreSQL cast for the policy (``conf.get_tenant_pk_cast()`` raised
  ``ImproperlyConfigured``). See :ref:`Supported tenant primary-key types
  <rls-pk-types>`. The hint names the unmappable internal field type.

Checks only fire when RLS is enabled, so disabled installs see nothing.

For CI, the bundled ``verify_rls`` management command runs the same per-model
introspection as **W004** against a live database and exits non-zero if *any*
model's table has a gap (RLS off, not forced, no policy, or a nullable tenant
column), printing ``OK`` / ``PROBLEM`` per model with specifics:

.. code-block:: bash

    python manage.py verify_rls                 # uses the tenant database alias
    python manage.py verify_rls --database default

Unlike the best-effort W004 check (which stays silent when it cannot introspect),
``verify_rls`` is meant to **fail the build**, so wire it into your deploy/CI
pipeline after migrations to catch RLS-live drift before it reaches production.


.. _rls-pk-types:

Supported tenant primary-key types
----------------------------------

The policy casts the session variable to the tenant primary key's SQL type, so
only PK types with a known, correct cast are supported:

* **Integer family** -- ``AutoField`` / ``SmallAutoField`` /
  ``IntegerField`` / ``SmallIntegerField`` / ``PositiveIntegerField`` /
  ``PositiveSmallIntegerField`` cast to ``integer``; ``BigAutoField`` /
  ``BigIntegerField`` / ``PositiveBigIntegerField`` cast to ``bigint``.
* **UUID** -- ``UUIDField`` casts to ``uuid``.
* **Text-like** -- ``CharField`` / ``SlugField`` / ``TextField`` cast to
  ``text``.

Any other PK type raises ``django.core.exceptions.ImproperlyConfigured`` (named
in system check **E002**), naming the unmapped internal field type and the
tenant model. The cast is deliberately **not** allowed to silently fall back to
``text`` -- doing so would miscast an integer column and break every query, so
the misconfiguration is surfaced loudly instead.


.. _rls-checks-deploy:

Running the checks under ``manage.py check --deploy``
-----------------------------------------------------

The production-relevant RLS checks are tagged ``deploy=True``, so they also run
under Django's deployment check::

    python manage.py check --deploy --database default

``--deploy`` turns on the deployment-only check set (it normally also surfaces
Django's own production warnings). The RLS checks that run under it are the ones
that catch a *fail-open* or drifted deployment: **W001** (RLS enabled but no
enforcer wired up), **W003** (the connecting role bypasses RLS -- an Error),
**W004** (RLS not actually live on a tenant table), **W005** (a ``UNIQUE``
constraint that omits the tenant), and **E002** (an uncastable tenant PK type).
Wiring ``check --deploy`` into CI means these run automatically on every deploy,
not only when someone passes ``--database``. The model-level checks (W002, W005,
E001) need no database; W003/W004 connect on the tenant alias and stay
best-effort (silent) when the database is unreachable or is not PostgreSQL (see
:ref:`rls-system-checks`).


.. _rls-migration-assistant:

Migration assistant (``rls_doctor``)
====================================

Adopting shared-schema RLS on an **existing, populated** django-tenants
deployment is a multi-step migration (configuration cutover, moving apps to
``SHARED_APPS``, adding the staged tenant FK, backfilling, tightening to
``NOT NULL``, enabling RLS + policies, third-party model policies, fixing
tenant-omitting ``UNIQUE`` constraints, and decommissioning old schemas -- the
full sequence is in :doc:`rls_migration`). The bundled ``rls_doctor`` management
command is a **readiness assistant** for that journey: it *scans* your project
and database, *auto-applies* only the one provably-safe step, *generates*
migration/SQL scaffolds for the steps that need a migration, and *advises* (but
never runs) the dangerous, app-specific steps.

``rls_doctor`` does **not** reimplement any RLS primitive. It composes the
existing :ref:`system checks <rls-system-checks>`, the per-model live
introspection behind **W004**, ``TenantRLSModel.has_unscoped_rows()``, and
``model.enable_rls()`` -- so what it reports and what it fixes are exactly what
the rest of the subpackage already enforces.

What it scans and classifies
----------------------------

The command runs ``django_tenants.rls.doctor.scan()``, which collects two kinds
of finding:

* **Settings findings.** It re-runs the configuration checks (the ENGINE/W001
  enforcer wiring, the role/W003 bypass check, the GUC-name/E001 check, and the
  PK-cast/E002 check) and adds two lightweight introspections: a **cache**
  finding when a ``CACHES[*]["KEY_FUNCTION"]`` still resolves to the
  ``schema_name``-based ``django_tenants.cache.make_key`` (it advises switching
  to ``django_tenants.rls.cache.make_key``), and a **storage** finding when the
  default storage is the schema-based ``TenantFileSystemStorage`` (it advises
  ``RLSTenantFileSystemStorage``). See
  :ref:`rls-cache-storage-celery` for why those helpers collapse all tenants
  together under RLS.
* **Model findings.** For every concrete ``TenantRLSModel`` it assigns one
  **classification**:

  .. list-table::
     :header-rows: 1
     :widths: 22 78

     * - Classification
       - Meaning (and the migration step it maps to)
     * - ``done``
       - RLS is fully live for this table (the W004 live-introspection is
         clean): RLS enabled, forced when ``TENANT_RLS_FORCE`` is on, a policy
         present, and the tenant column ``NOT NULL``. Nothing to do.
     * - ``auto_fixable``
       - The table has the tenant column, it is ``NOT NULL``, and there are
         **no** un-scoped (``NULL`` ``tenant_id``) rows -- but RLS / FORCE / the
         policy are not on yet. This is the **one safe step**: ``--fix`` will
         call ``model.enable_rls()`` (migration **Step 6**).
     * - ``generate_migration``
       - A migration/scaffold is needed: the tenant FK is missing, the tenant
         column is still nullable, or a ``UNIQUE`` constraint omits the tenant
         (migration **Steps 3 / 5 / 8**). ``--generate`` writes a scaffold.
     * - ``manual``
       - Needs human action that must **not** be auto-run: the table still has
         un-scoped (``NULL`` ``tenant_id``) rows that require an app-specific
         backfill (migration **Step 4**), or app-side cache/storage code must be
         re-pointed.
     * - ``blocked``
       - The connecting role bypasses RLS (**W003**), so enforcement would be
         theatre. Surfaced loudly, and ``--fix`` refuses to run.

  ``scan()`` is **best-effort** on database access: a model whose table is
  missing, or an unreachable database, degrades to a finding rather than raising.

The scan result is the single source of truth for the report, the ``--fix``
decision, the admin dashboard, and the ``--format json`` output. A small helper
``django_tenants.rls.doctor.classify_model(model, connection, *, force)`` returns
``(classification, problems)`` and is reused by the command and the admin view.

The default report
------------------

With no flags the command prints a readable report grouped by classification.
Each non-``done`` item names its problem, the remedy, and the migration step to
read (``see docs/rls_migration.rst step N``)::

    python manage.py rls_doctor
    python manage.py rls_doctor --database default   # default is the tenant alias

**Exit code (CI-usable).** A scan-only run exits ``0`` only when there are
**zero** non-``done`` model items **and** no error-level settings findings;
otherwise it exits ``1``. That makes ``rls_doctor`` safe to gate a pipeline on.

``--fix``: apply only the safe slice
------------------------------------

``--fix`` re-applies the single provably-safe step and nothing else. It enables
RLS (via ``model.enable_rls()``) **only** for models classified
``auto_fixable``, then re-scans and re-reports using the same exit-code rule::

    python manage.py rls_doctor --fix

It deliberately **refuses** (prints a clear message and exits non-zero, applying
nothing) in two cases:

* **The role bypasses RLS** -- ``scan()["blocked"]`` is ``True`` (the W003
  Error). Enabling RLS while the role bypasses it would create policies that do
  nothing; fix the role first (see :ref:`rls-database-role`).
* **A target model still has un-scoped rows** -- ``model.has_unscoped_rows()``
  is ``True``. Enabling RLS now would make those ``NULL`` ``tenant_id`` rows
  invisible to every tenant (see :ref:`rls-null-rows`). Backfill first (migration
  **Step 4**).

``--fix`` **never** runs a backfill, a ``SET NOT NULL``, a ``DROP SCHEMA``, or
any DDL beyond that safe enable path. The dangerous steps stay yours to run
deliberately.

.. note::

   ``ALTER TABLE ... ENABLE ROW LEVEL SECURITY`` requires the connecting role to
   **own** the table -- which is the expected setup, since the application role
   owns its tenant tables so ``FORCE ROW LEVEL SECURITY`` polices it. If you have
   instead granted the app role only DML (no ownership), ``--fix`` cannot enable
   RLS for you (Postgres returns ``must be owner of table``); it reports the
   failure and leaves the scan red. Run ``enable_rls`` (or the generated
   ``EnableRLS`` migration) as the table owner / a migration role instead.

``--generate``: write migration / SQL scaffolds
-----------------------------------------------

``--generate`` writes scaffold files for every ``generate_migration`` item and
prints each path. It writes into a scratch directory (default
``./rls_migrations_scaffold/``) -- **never** into a real ``migrations/``
directory -- and it never applies anything::

    python manage.py rls_doctor --generate
    python manage.py rls_doctor --generate ./my_scaffolds/

The generators live in ``django_tenants.rls.scaffold`` and all return strings
(they write nothing themselves):

* ``staged_fk_migration(model)`` -- a migration that adds the tenant FK as
  ``null=True``, a commented ``RunPython`` backfill **stub**, and a clearly
  delimited ``AlterField`` to ``null=False`` gated by a TODO to run only **after**
  the backfill (migration **Steps 3 / 5**).
* ``enable_rls_migration(model)`` -- a migration using
  ``operations.EnableRLS`` + ``operations.CreateTenantPolicy`` (migration
  **Step 6**).
* ``third_party_policy_sql(table, *, pk_cast="integer")`` -- raw
  ``ENABLE``/``FORCE``/``CREATE POLICY`` DDL for a table you cannot subclass
  (for example ``authtoken_token``). Its ``USING`` / ``WITH CHECK`` is built from
  ``policies.TenantPolicy`` so it is byte-identical to the framework policy
  (migration **Step 7**).
* ``unique_constraint_migration(model, fields)`` -- an ``AddConstraint`` of a
  tenant-scoped ``UniqueConstraint([tenant_field, *fields])`` plus a
  ``RemoveConstraint`` of the old one (migration **Step 8**).

Each generated migration is valid Python you review and drop into the right
app's ``migrations/`` directory yourself; the backfill stub is intentionally a
TODO, because the correct backfill is app-specific (see
:ref:`rls-backfill-recipe`).

``--format json``: machine-readable output
------------------------------------------

For tooling, ``--format json`` dumps the full ``scan()`` dict (settings, models,
summary, ``blocked``) so a pipeline can parse it instead of scraping the report::

    python manage.py rls_doctor --format json

Using it in CI
--------------

``rls_doctor`` complements the existing CI guards rather than replacing them. A
robust pipeline runs all three after migrations:

#. ``manage.py check --deploy --database default`` -- the deploy-tagged checks
   (W001/W003/W004/W005/E002; see :ref:`rls-checks-deploy`) fail the build on a
   mis-wired or fail-open configuration.
#. ``manage.py rls_doctor`` -- exits non-zero while any model is not yet
   ``done`` (or any settings finding is error-level), so a half-finished
   migration cannot pass unnoticed.
#. ``manage.py verify_rls`` -- the live per-model W004 introspection that is
   *meant* to fail the build on RLS-live drift (see :ref:`rls-system-checks`).

The optional read-only admin dashboard
---------------------------------------

For a browser view of the same readiness data, the subpackage ships an
**optional, read-only** admin dashboard. It is not auto-registered; wire it in
explicitly (for example from your project's admin setup)::

    from django_tenants.rls.admin import register_rls_admin

    register_rls_admin()        # defaults to django.contrib.admin.site

This adds a single guarded page (``rls_readiness_view``) -- staff-only, behind
``admin_site.admin_view`` and ``never_cache`` -- that calls the same
``doctor.scan()`` and renders a summary, the per-model classification table, the
settings findings, copy-paste ``manage.py`` commands, and links back to this
guide and :doc:`rls_migration`.

.. important::

   **The dashboard is read-only by design: there is never an "apply", "migrate",
   or "fix" button, and the view has no POST handling.** It may *display* the
   generated plan, but it executes nothing. The rationale is the same
   least-privilege principle the rest of RLS mode depends on: your application
   role is ``NOSUPERUSER NOBYPASSRLS`` and must not run DDL (enabling RLS,
   altering columns, dropping schemas) from a web request. Run ``rls_doctor``
   (and migrations) from a deliberate, privileged context on the command line;
   use the dashboard only to *observe* readiness.


RLS settings reference
======================

All settings may be given individually at the top level **or** as keys inside a
``DJANGO_TENANTS_RLS`` dict (individual top-level setting wins; then the dict;
then the default).

.. attribute:: TENANT_RLS_ENABLED

    :Default: ``False``

    Master switch. When ``False`` the RLS backend behaves exactly like the
    standard django-tenants backend and nothing in this subpackage changes any
    runtime behavior.

.. attribute:: TENANT_RLS_SESSION_VARIABLE

    :Default: ``'django_tenants.tenant_id'``

    The PostgreSQL GUC session variable that carries the active tenant primary
    key. Must be of the form ``<class>.<name>``.

.. attribute:: TENANT_RLS_BYPASS_VARIABLE

    :Default: ``'django_tenants.bypass_rls'``

    The GUC session variable that, when set to the literal ``'on'``, disables
    isolation (used by ``bypass_rls``). Must be of the form ``<class>.<name>``.

.. attribute:: TENANT_RLS_TENANT_FIELD

    :Default: ``'tenant'``

    The name of the tenant foreign key field on isolated models. The abstract
    ``TenantRLSModel`` base hard-codes a field named ``tenant``; override this
    setting only if you define your own FK with a different name.

.. attribute:: TENANT_RLS_FORCE

    :Default: ``True``

    When ``True``, ``FORCE ROW LEVEL SECURITY`` is applied so policies also
    apply to the table owner Django connects as. Strongly recommended -- without
    it an owner/superuser connection silently bypasses RLS.

.. attribute:: TENANT_RLS_AUTO_ENABLE

    :Default: ``True``

    When ``True`` (and ``TENANT_RLS_ENABLED`` is ``True``), RLS and policies are
    enabled automatically via a ``post_migrate`` hook for the migrated app's
    ``TenantRLSModel`` subclasses. Safe for greenfield (empty) tables; set it to
    ``False`` when upgrading an existing populated table and enable RLS
    explicitly after backfilling (see :ref:`Upgrading an existing populated
    table <rls-upgrade-existing>`).

.. attribute:: TENANT_RLS_ALLOW_BYPASS_ROLE

    :Default: ``False``

    When ``False`` (the default), the :ref:`W003 system check
    <rls-system-checks>` raises an **Error** if the connecting role is a
    superuser or has ``BYPASSRLS`` -- blocking ``check`` / ``migrate`` -- because
    such a role silently disables all isolation. Set it to ``True`` to opt out
    deliberately (W003 then emits nothing). **This disables the only automatic
    guard against a fail-open deployment**; set it only for a connection you know
    never serves tenant traffic (see :ref:`Database role <rls-database-role>`).


Performance note
================

When RLS is enabled the backend issues exactly **one extra round-trip per
database cursor**: a single combined ``set_config`` call that (re)asserts the
tenant session variable and the bypass variable. This is security-load-bearing
-- it is what re-establishes isolation per cursor (so a rolled-back transaction
or a pooled connection cannot inherit a stale tenant/bypass) -- and it is the
deliberate cost of database-enforced isolation. When ``TENANT_RLS_ENABLED`` is
``False`` the backend emits **nothing** extra and behaves byte-for-byte like the
stock django-tenants backend.

**Policy evaluation (InitPlan).** The ``TenantPolicy`` expression wraps each
``current_setting()`` call in a scalar sub-SELECT::

    (tenant_id = (SELECT NULLIF(current_setting('django_tenants.tenant_id', true), '')::integer)
     OR (SELECT current_setting('django_tenants.bypass_rls', true)) = 'on')

The sub-SELECT lets PostgreSQL evaluate the session variables **once per
statement** (as an *InitPlan*) instead of once per row. On large shared tables a
bare ``current_setting()`` in the policy would be re-evaluated for every scanned
row, which is a significant, easy-to-miss cost; the InitPlan form removes it.

**Index the tenant column.** Because every policed query is effectively filtered
by ``tenant_id``, add an index that leads with it. A composite index that starts
with ``tenant_id`` and continues with your common filter/order columns lets a
single index serve both the policy and the query:

.. code-block:: python

    class Note(TenantRLSModel):
        text = models.TextField()
        created_at = models.DateTimeField(auto_now_add=True)

        class Meta:
            indexes = [
                models.Index(fields=["tenant", "created_at"]),
            ]

.. note::

   The policy is ``tenant_id = ... OR bypass = 'on'``. That ``OR`` bypass
   disjunct can stop the planner from choosing a pure ``tenant_id`` index scan on
   an **unfiltered** scan such as ``.all()`` or ``.count()`` (the planner must
   account for the bypass branch). Queries that add their own selective
   ``WHERE``/``ORDER BY`` still use the composite index normally; this only
   affects whole-table scans, where a sequential scan is often the right plan
   anyway.


Example project
===============

A minimal, self-contained example lives in the repository at ``examples/rls/``:

* ``examples/rls/models.py`` -- a ``Note(TenantRLSModel)`` model.
* ``examples/rls/settings_snippet.py`` -- the settings changes (``SHARED_APPS``,
  ``ENGINE``, ``DJANGO_TENANTS_RLS``, ``MIDDLEWARE``, ``DATABASE_ROUTERS``).
