"""Management command to enable RLS and policies on TenantRLSModel subclasses."""

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Enable RLS + policies for all TenantRLSModel subclasses."

    def add_arguments(self, parser):
        parser.add_argument(
            "--app",
            type=str,
            default=None,
            help="Only enable RLS for models in the given app label.",
        )
        parser.add_argument(
            "--model",
            type=str,
            default=None,
            help="Only enable RLS for the given model name (case-insensitive).",
        )

    def handle(self, *args, **options):
        from django_tenants.rls.conf import rls_enabled

        if not rls_enabled():
            self.stdout.write(self.style.WARNING(
                "TENANT_RLS_ENABLED is False; enabling RLS anyway as requested."
            ))

        models = self._get_models(options.get("app"), options.get("model"))

        if not models:
            self.stdout.write(self.style.WARNING(
                "No TenantRLSModel subclasses matched the given filters."
            ))
            return

        for model in models:
            try:
                if model.has_unscoped_rows():
                    self.stdout.write(self.style.WARNING(
                        "WARNING: %s has rows with a NULL tenant_id. Once RLS is "
                        "enabled these rows will become INVISIBLE to ALL tenants "
                        "(they are not deleted; visible only under bypass or after "
                        "disabling RLS). Backfill tenant_id for every row before "
                        "enabling to avoid hiding data. Proceeding anyway as "
                        "explicitly requested." % model._meta.label
                    ))
                model.enable_rls()
                self.stdout.write(self.style.SUCCESS(
                    "Enabled RLS for %s" % model._meta.label
                ))
            except Exception as e:
                self.stderr.write(self.style.ERROR(
                    "Failed to enable RLS for %s: %s" % (model._meta.label, e)
                ))

    def _get_models(self, app_label, model_name):
        from django.apps import apps
        from django_tenants.rls.models import TenantRLSModel

        out = []
        for m in apps.get_models():
            if not issubclass(m, TenantRLSModel) or m._meta.abstract:
                continue
            if app_label and m._meta.app_label != app_label:
                continue
            if model_name and m._meta.model_name != model_name.lower():
                continue
            out.append(m)
        return out
