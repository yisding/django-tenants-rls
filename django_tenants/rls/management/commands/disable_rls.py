"""Management command to disable RLS and policies on TenantRLSModel subclasses."""

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Disable RLS + policies for all TenantRLSModel subclasses."

    def add_arguments(self, parser):
        parser.add_argument(
            "--app",
            type=str,
            default=None,
            help="Only disable RLS for models in the given app label.",
        )
        parser.add_argument(
            "--model",
            type=str,
            default=None,
            help="Only disable RLS for the given model name (case-insensitive).",
        )

    def handle(self, *args, **options):
        models = self._get_models(options.get("app"), options.get("model"))

        if not models:
            self.stdout.write(self.style.WARNING(
                "No TenantRLSModel subclasses matched the given filters."
            ))
            return

        for model in models:
            try:
                model.disable_rls()
                self.stdout.write(self.style.SUCCESS(
                    "Disabled RLS for %s" % model._meta.label
                ))
            except Exception as e:
                self.stderr.write(self.style.ERROR(
                    "Failed to disable RLS for %s: %s" % (model._meta.label, e)
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
