"""AppConfig for the django-tenants RLS subpackage.

Add ``django_tenants.rls`` (or ``django_tenants.rls.apps.DjangoTenantsRLSConfig``)
to ``SHARED_APPS``/``INSTALLED_APPS`` to enable the system checks and, when
configured, automatic RLS enablement after migrations.

.. note::
   With the recommended defaults (``TENANT_RLS_AUTO_ENABLE=True``) the
   post-migrate hook runs in the *same* ``migrate`` that creates or alters the
   table, which is safe only for greenfield/empty tables. When UPGRADING an
   EXISTING populated table, set ``TENANT_RLS_AUTO_ENABLE=False`` and enable RLS
   explicitly *after* backfilling ``tenant_id`` for every row (see
   ``docs/rls.rst``). The auto-enable handler defensively SKIPS any table that
   still has un-backfilled ``NULL`` tenant rows.
"""

import logging

from django.apps import AppConfig

logger = logging.getLogger("django_tenants.rls")


class DjangoTenantsRLSConfig(AppConfig):
    name = "django_tenants.rls"
    label = "django_tenants_rls"
    verbose_name = "Django Tenants RLS"

    def ready(self):
        # Importing the checks module registers the @register'd system checks.
        from . import checks  # noqa: F401
        from . import conf

        # Only wire up the post_migrate auto-enable hook when both RLS itself and
        # the auto-enable behaviour are turned on. When RLS is disabled this is a
        # complete no-op so there is zero behaviour change.
        if conf.auto_enable() and conf.rls_enabled():
            from django.db.models.signals import post_migrate

            post_migrate.connect(
                self._enable_rls_post_migrate,
                dispatch_uid="django_tenants_rls.post_migrate",
            )

    @staticmethod
    def _enable_rls_post_migrate(sender, **kwargs):
        """Best-effort: enable RLS for the migrated app's TenantRLSModel subclasses.

        ``sender`` is the ``AppConfig`` of the app whose migrations just ran. We
        only touch models that belong to that app so the handler does not redo
        work for every installed app on every migrate.

        Two safety behaviours apply per model:

        * If the table still has rows with a ``NULL`` tenant id
          (``model.has_unscoped_rows()``), enabling RLS is SKIPPED with a loud
          warning. Enabling now would make those un-backfilled rows invisible to
          every tenant (``NULL`` never matches the policy). Backfill ``tenant_id``
          first, then run ``manage.py enable_rls``.
        * A failure to enable RLS for a model is logged with a full traceback
          (``logger.exception``) and the isolation state of that table is flagged
          as indeterminate, but the exception is swallowed so auto-enable never
          makes ``migrate`` fail.
        """
        from django.apps import apps as django_apps

        from .models import TenantRLSModel

        sender_label = getattr(sender, "label", None)
        sender_name = getattr(sender, "name", None)

        for model in django_apps.get_models():
            if not issubclass(model, TenantRLSModel):
                continue
            if getattr(model._meta, "abstract", False):
                continue
            if sender is not None and model._meta.app_label not in (
                sender_label,
                sender_name,
            ):
                continue
            if model.has_unscoped_rows():
                logger.warning(
                    "RLS auto-enable SKIPPED for %s: the table has rows with a "
                    "NULL tenant id. Enabling RLS now would make those "
                    "un-backfilled rows invisible to EVERY tenant. Backfill "
                    "tenant_id for all existing rows, then run "
                    "'manage.py enable_rls' (or enable explicitly). See "
                    "docs/rls.rst for the safe upgrade path.",
                    model._meta.label,
                )
                continue
            try:
                model.enable_rls()
            except Exception:  # best-effort, never fatal
                logger.exception(
                    "RLS auto-enable FAILED for %s: tenant isolation state for "
                    "this table is INDETERMINATE. Re-run 'manage.py enable_rls' "
                    "after resolving the error before relying on isolation.",
                    model._meta.label,
                )
