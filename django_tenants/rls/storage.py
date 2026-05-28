"""
RLS-aware per-tenant file storage for shared-schema RLS mode.

Why this exists
---------------
The bundled :class:`django_tenants.files.storage.TenantFileSystemStorage`
derives each tenant's media sub-path from ``connection.schema_name`` (via
:func:`django_tenants.utils.parse_tenant_config_path`). That is correct under
the default schema-per-tenant backend, where ``connection.schema_name`` is the
active tenant's schema.

Under shared-schema RLS it is **not**: the RLS backend keeps every connection
pinned to the ``public`` schema and isolates tenants with a row-level-security
policy instead of a ``search_path`` switch. So ``connection.schema_name`` is
``"public"`` for *every* tenant, and storage keyed on it would write/read all
tenants' files into a single shared ``public/`` directory -- a cross-tenant
file leak.

The real active tenant is still available under RLS via
:func:`django_tenants.rls.session.current_tenant_schema` (which reads
``connection.tenant.schema_name``). This module mirrors
``TenantFileSystemStorage`` but sources the per-tenant path/url segment from
that helper instead of ``connection.schema_name``.

Usage
-----
Point ``DEFAULT_FILE_STORAGE`` / ``STORAGES["default"]`` at
:class:`RLSTenantFileSystemStorage`::

    STORAGES = {
        "default": {
            "BACKEND": "django_tenants.rls.storage.RLSTenantFileSystemStorage",
        },
        ...
    }

As with the bundled storage, ``MULTITENANT_RELATIVE_MEDIA_ROOT`` controls where
the tenant segment lands (it may contain a ``%s`` placeholder; otherwise the
tenant schema name is appended). The only behavioural change is that the
segment comes from the *real* tenant rather than the pinned ``public`` schema.

django-storages / S3 recipe
---------------------------
``django-storages`` is an optional dependency, so it is deliberately **not**
imported here. To get the same RLS-correct, per-tenant prefixing on an
``S3Boto3Storage`` subclass, override ``location`` to prepend the real tenant
schema (do **not** rely on ``connection.schema_name``)::

    from storages.backends.s3boto3 import S3Boto3Storage

    from django_tenants.rls.session import current_tenant_schema


    class RLSTenantS3Boto3Storage(S3Boto3Storage):
        \"\"\"S3 storage that prefixes every key with the real RLS tenant.\"\"\"

        @property
        def location(self):
            # The configured base location (settings.AWS_LOCATION etc.) with the
            # active tenant's schema name prepended. Under RLS this is the real
            # tenant, NOT connection.schema_name (which is pinned to 'public').
            base = super().location
            tenant = current_tenant_schema()
            return "/".join(s.strip("/") for s in [tenant, base] if s)

Keying the S3 ``location`` on ``current_tenant_schema()`` keeps every tenant's
objects under their own prefix exactly as the filesystem variant below keeps
them under their own directory.
"""

import os

from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.utils.functional import cached_property

from .session import current_tenant_schema


def rls_parse_tenant_config_path(config_path):
    """
    RLS-aware variant of :func:`django_tenants.utils.parse_tenant_config_path`.

    Identical behaviour, except the inserted/appended segment is the *real*
    active tenant schema from :func:`current_tenant_schema` rather than
    ``connection.schema_name`` (which is pinned to ``public`` under RLS).

    If ``config_path`` contains ``%s`` the tenant schema name is inserted there;
    otherwise it is appended to the end of the path.

    :param config_path: A configuration path string that optionally contains
        ``%s`` to indicate where the tenant schema name should be inserted.

    :return: The formatted string containing the (real) tenant schema name.
    """
    schema_name = current_tenant_schema()
    try:
        # Insert schema name
        return config_path % schema_name
    except (TypeError, ValueError):
        # No %s in string; append schema name at the end
        return os.path.join(config_path, schema_name)


class RLSTenantStorageMixin:
    """
    Mixin that makes a Django storage backend per-tenant *under RLS*.

    It mirrors :class:`django_tenants.files.storage.TenantFileSystemStorage`
    but every place the bundled storage calls
    :func:`django_tenants.utils.parse_tenant_config_path` (which keys on
    ``connection.schema_name``) this mixin instead calls
    :func:`rls_parse_tenant_config_path` (which keys on the real tenant via
    :func:`current_tenant_schema`). It never reads ``connection.schema_name``.

    Mix it in *before* the concrete storage class so its ``location`` /
    ``base_url`` properties win, e.g.
    ``class MyStorage(RLSTenantStorageMixin, FileSystemStorage)``.
    """

    def _clear_cached_properties(self, setting, **kwargs):
        """Reset setting based property values."""
        super()._clear_cached_properties(settings, **kwargs)

        if setting == 'MULTITENANT_RELATIVE_MEDIA_ROOT':
            self.__dict__.pop('relative_media_root', None)

    @cached_property
    def relative_media_root(self):
        try:
            return os.path.join(settings.MEDIA_ROOT, settings.MULTITENANT_RELATIVE_MEDIA_ROOT)
        except AttributeError:
            # MULTITENANT_RELATIVE_MEDIA_ROOT is an optional setting, use the default value if none provided
            return settings.MEDIA_ROOT

    @cached_property
    def relative_media_url(self):
        try:
            multitenant_relative_url = settings.MULTITENANT_RELATIVE_MEDIA_ROOT
        except AttributeError:
            # MULTITENANT_RELATIVE_MEDIA_ROOT is an optional setting. Use the default of just appending
            # the tenant schema_name to STATIC_ROOT if no configuration value is provided
            multitenant_relative_url = "%s"

        multitenant_relative_url = "/".join(s.strip("/") for s in [settings.MEDIA_URL, multitenant_relative_url]) + "/"

        if not multitenant_relative_url.startswith("/"):
            multitenant_relative_url = "/" + multitenant_relative_url

        return multitenant_relative_url

    @property  # Not cached like in parent class
    def base_location(self):
        return self._value_or_setting(self._location, rls_parse_tenant_config_path(self.relative_media_root))

    @property  # Not cached like in parent class
    def location(self):
        return os.path.abspath(self.base_location)

    @property
    def base_url(self):
        relative_tenant_media_url = rls_parse_tenant_config_path(self.relative_media_url)

        if self._base_url is None:
            return relative_tenant_media_url

        relative_tenant_media_url = "/" + "/".join(s.strip("/") for s in [self._base_url, relative_tenant_media_url]) + "/"

        return relative_tenant_media_url


class RLSTenantFileSystemStorage(RLSTenantStorageMixin, FileSystemStorage):
    """
    RLS-correct counterpart to
    :class:`django_tenants.files.storage.TenantFileSystemStorage`.

    Stores each tenant's media under a per-tenant sub-directory derived from the
    *real* active tenant (:func:`current_tenant_schema`) rather than
    ``connection.schema_name``, which the RLS backend pins to ``public`` for
    every tenant.
    """

    def listdir(self, path):
        """
        More forgiving wrapper for parent class implementation that does not insist on
        each tenant having its own static files dir.
        """
        try:
            return super().listdir(path)
        except FileNotFoundError:
            # Having static files for each tenant is optional - ignore.
            return [], []
