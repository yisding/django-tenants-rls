"""Read-only RLS readiness dashboard for the Django admin.

This module exposes a single, *strictly read-only* admin page that renders the
output of :func:`django_tenants.rls.doctor.scan` -- the same scan used by the
``rls_doctor`` management command. It is the in-browser counterpart to that
command: it shows which tenant tables are already protected, which are safely
auto-fixable, which need a migration/scaffold, which need manual work, and
whether the connecting role bypasses RLS (the "blocked" case).

Why there is deliberately NO apply/fix/migrate button (and no POST handling):

* The whole point of shared-schema RLS is that the *application* database role
  is ``NOSUPERUSER NOBYPASSRLS`` and therefore CANNOT (and must not be able to)
  run the privileged DDL that enabling RLS, altering columns, or dropping
  schemas requires. Wiring an "apply" button into the admin would invite
  running that DDL as whatever role the web process uses, which is exactly the
  privilege the RLS design refuses to grant.
* Several migration steps (the cross-schema backfill, ``SET NOT NULL``,
  ``DROP SCHEMA``) are destructive and app-specific; they must be reviewed and
  run deliberately via migrations / ``manage.py``, never triggered by a click.

So this view only ever *reads*: it scans and displays. It may show the
copy-paste ``manage.py`` commands a human should run, but it never executes
anything. ``register_rls_admin`` is OPTIONAL and not auto-wired (see its
docstring); a project opts in explicitly from its own admin/urls bootstrap.
"""

from django.template.response import TemplateResponse
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache


# Permission an admin user must hold (in addition to ``is_staff``) to view the
# readiness dashboard. ``view_tenant`` is the standard auto-generated view
# permission on the tenant model's app; requiring a model-level permission keeps
# the page off-limits to staff who cannot otherwise inspect tenants. Projects
# that want a different gate can wrap their own view around ``doctor.scan``.
RLS_READINESS_PERMISSION = "django_tenants.view_tenant"

# Template rendered by the view. Shipped as package data (see pyproject.toml).
RLS_READINESS_TEMPLATE = "django_tenants_rls/rls_readiness.html"


def _user_may_view(request):
    """Return True if ``request.user`` may see the readiness dashboard.

    Gate: active staff member who additionally holds
    :data:`RLS_READINESS_PERMISSION`. Superusers pass the permission check
    implicitly (``User.has_perm`` returns True for active superusers).
    """
    user = getattr(request, "user", None)
    if user is None or not user.is_active or not user.is_staff:
        return False
    return user.has_perm(RLS_READINESS_PERMISSION)


def rls_readiness_view(request, admin_site=None):
    """Render the read-only RLS readiness dashboard.

    Guarded for staff + :data:`RLS_READINESS_PERMISSION`. Calls
    :func:`django_tenants.rls.doctor.scan` (best-effort; it degrades DB problems
    to findings rather than raising) and renders the result. This view has NO
    POST branch and performs NO mutation: it is safe to expose to anyone allowed
    to inspect tenant configuration.

    ``admin_site`` is the :class:`~django.contrib.admin.AdminSite` the page is
    hosted on; it is used only for the admin chrome (``each_context``) so the
    template inherits the site header/branding. It is injected by
    :func:`register_rls_admin`.
    """
    # Lazy imports so this module is import-light and never touches the app
    # registry / DB at import time (mirrors conf.py / doctor.py conventions).
    from django.contrib import admin as django_admin
    from django.core.exceptions import PermissionDenied

    from django_tenants.rls import doctor

    if not _user_may_view(request):
        # Match the admin's own behaviour for an authenticated-but-unauthorised
        # staff user: a 403 rather than a login redirect.
        raise PermissionDenied(
            "You do not have permission to view the RLS readiness dashboard."
        )

    site = admin_site or django_admin.site

    # Allow ?database=<alias> as a read-only knob; default is the tenant alias
    # (doctor.scan resolves that itself when database is None).
    database = request.GET.get("database") or None

    # Best-effort: doctor.scan never raises on DB access, but guard defensively
    # so a misconfigured project still gets a rendered page (read-only) rather
    # than a 500.
    scan_error = None
    try:
        report = doctor.scan(database=database)
    except Exception as exc:  # pragma: no cover - defensive only
        report = None
        scan_error = str(exc)

    context = {
        **site.each_context(request),
        "title": _("RLS readiness"),
        "report": report,
        "scan_error": scan_error,
        # Copy-paste commands the human should run (the page DISPLAYS them; it
        # never runs them). Kept here, not in the template, so the alias flows
        # through consistently.
        "commands": _manage_commands(report),
        "docs_step_url": (
            "https://django-tenants.readthedocs.io/en/latest/rls_migration.html"
        ),
        "docs_assistant_url": (
            "https://django-tenants.readthedocs.io/en/latest/rls.html"
            "#rls-migration-assistant"
        ),
    }
    return TemplateResponse(request, RLS_READINESS_TEMPLATE, context)


def _manage_commands(report):
    """Build the list of copy-paste ``manage.py`` commands to DISPLAY.

    Read-only: returns strings for the operator to run in a shell themselves.
    """
    database = (report or {}).get("database")
    db_flag = " --database %s" % database if database else ""
    summary = (report or {}).get("summary") or {}
    blocked = bool((report or {}).get("blocked"))

    commands = [
        ("Re-run the scan as a CI gate (exit 1 if not all done)",
         "python manage.py rls_doctor%s" % db_flag),
        ("Machine-readable scan output",
         "python manage.py rls_doctor --format json%s" % db_flag),
    ]
    if summary.get("auto_fixable") and not blocked:
        commands.append((
            "Auto-enable RLS on already-backfilled tables (safe slice only)",
            "python manage.py rls_doctor --fix%s" % db_flag,
        ))
    if summary.get("generate_migration"):
        commands.append((
            "Generate migration/SQL scaffolds for tables that need one",
            "python manage.py rls_doctor --generate%s" % db_flag,
        ))
    commands.append((
        "Verify RLS is live everywhere (deploy gate)",
        "python manage.py verify_rls%s" % db_flag,
    ))
    commands.append((
        "Run production-relevant RLS system checks",
        "python manage.py check --deploy",
    ))
    return commands


def register_rls_admin(admin_site=None):
    """Wire the read-only readiness dashboard into an admin site (OPTIONAL).

    This is **not** auto-run anywhere -- a project opts in explicitly, typically
    from its admin bootstrap (e.g. an ``AppConfig.ready`` or the project's
    ``urls.py``)::

        from django_tenants.rls.admin import register_rls_admin
        register_rls_admin()  # uses django.contrib.admin.site

    It adds a single GET URL, ``rls-readiness/`` under the admin namespace,
    served through ``admin_site.admin_view`` (so the admin's login/auth wrapper
    and ``never_cache`` apply) and named ``rls_readiness``. The page is
    read-only; see the module docstring for why there is intentionally no apply
    action.

    Returns the resolved admin site so callers can chain or assert on it.
    """
    from django.contrib import admin as django_admin
    from django.urls import path

    site = admin_site or django_admin.site

    # Bind the resolved site into the view so the page renders with this site's
    # chrome and so multiple admin sites can each host their own copy.
    @never_cache
    def _view(request):
        return rls_readiness_view(request, admin_site=site)

    _view.__name__ = "rls_readiness_view"

    original_get_urls = site.get_urls

    def get_urls():
        extra = [
            path(
                "rls-readiness/",
                site.admin_view(_view),
                name="rls_readiness",
            ),
        ]
        # Our extra URL goes first so it is matched before the catch-all admin
        # app-index patterns.
        return extra + original_get_urls()

    site.get_urls = get_urls
    return site
