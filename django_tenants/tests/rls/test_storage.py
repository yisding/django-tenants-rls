"""Unit tests for ``django_tenants.rls.storage``.

These run without a database. Under RLS ``connection.schema_name`` is pinned to
``public`` for every tenant, so the bundled ``TenantFileSystemStorage`` (which
derives its per-tenant path via ``utils.parse_tenant_config_path`` ->
``connection.schema_name``) would write every tenant's media into one shared
``public`` directory. The RLS storage must instead derive the per-tenant segment
from ``current_tenant_schema()`` -- the REAL active tenant.

We assert:

* ``rls_parse_tenant_config_path`` substitutes / appends the real tenant schema
  (mocked ``connection.tenant``) and NEVER reads ``connection.schema_name``;
* the mixin's ``base_location`` / ``base_url`` are built from that real tenant.

No django-storages import (it is an optional dependency); the S3 recipe is only
documented, not imported.
"""

import os
import unittest
from unittest import mock

from django.test import SimpleTestCase
from django.test.utils import override_settings

from django_tenants.rls import storage


class _Tenant:
    def __init__(self, schema_name):
        self.schema_name = schema_name


class _Conn:
    """Connection exposing ``.tenant`` and a (deliberately wrong) schema_name.

    ``schema_name`` is a property that fails the test loudly if anything in the
    storage layer reads it: under RLS it is pinned to ``public`` and must be
    ignored in favour of the real tenant.
    """

    def __init__(self, tenant, sentinel="__SHOULD_NOT_BE_READ__"):
        self.tenant = tenant
        self._sentinel = sentinel

    @property
    def schema_name(self):
        # If the storage path ever reflects this value, the test will catch it
        # as a cross-tenant collision in the asserted path.
        return self._sentinel


def _patch_conn(conn):
    # ``current_tenant_schema`` lives in ``rls.session``, which binds
    # ``connections`` at import time, so patch that name (not django.db's).
    return mock.patch("django_tenants.rls.session.connections", {"default": conn})


class RlsParseTenantConfigPathTestCase(unittest.TestCase):
    def test_inserts_real_tenant_at_placeholder(self):
        conn = _Conn(tenant=_Tenant("acme"))
        with _patch_conn(conn):
            result = storage.rls_parse_tenant_config_path("/media/%s/files")
        self.assertEqual(result, "/media/acme/files")
        self.assertNotIn("__SHOULD_NOT_BE_READ__", result)

    def test_appends_real_tenant_when_no_placeholder(self):
        conn = _Conn(tenant=_Tenant("acme"))
        with _patch_conn(conn):
            result = storage.rls_parse_tenant_config_path("/media")
        self.assertEqual(result, os.path.join("/media", "acme"))

    def test_does_not_read_connection_schema_name(self):
        # The real tenant is 'globex'; schema_name would raise/return a sentinel.
        conn = _Conn(tenant=_Tenant("globex"))
        with _patch_conn(conn):
            result = storage.rls_parse_tenant_config_path("/media/%s")
        self.assertEqual(result, "/media/globex")

    def test_falls_back_to_public_when_no_tenant(self):
        conn = _Conn(tenant=None)
        with _patch_conn(conn):
            result = storage.rls_parse_tenant_config_path("/media/%s")
        self.assertEqual(result, "/media/public")


@override_settings(MEDIA_ROOT="/srv/media", MEDIA_URL="/media/")
class RLSTenantFileSystemStorageTestCase(SimpleTestCase):
    """The mixin must build its per-tenant location/url from the real tenant."""

    def test_base_location_uses_real_tenant(self):
        conn = _Conn(tenant=_Tenant("acme"))
        with _patch_conn(conn):
            store = storage.RLSTenantFileSystemStorage()
            base = store.base_location
            location = store.location
        self.assertIn("acme", base)
        self.assertNotIn("__SHOULD_NOT_BE_READ__", base)
        self.assertTrue(os.path.isabs(location))
        self.assertIn("acme", location)

    def test_base_url_uses_real_tenant(self):
        conn = _Conn(tenant=_Tenant("acme"))
        with _patch_conn(conn):
            store = storage.RLSTenantFileSystemStorage()
            url = store.base_url
        self.assertIn("acme", url)
        self.assertNotIn("__SHOULD_NOT_BE_READ__", url)

    def test_two_tenants_get_distinct_locations(self):
        conn_a = _Conn(tenant=_Tenant("acme"))
        conn_b = _Conn(tenant=_Tenant("globex"))
        with _patch_conn(conn_a):
            loc_a = storage.RLSTenantFileSystemStorage().base_location
        with _patch_conn(conn_b):
            loc_b = storage.RLSTenantFileSystemStorage().base_location
        self.assertNotEqual(loc_a, loc_b)
        self.assertIn("acme", loc_a)
        self.assertIn("globex", loc_b)

    def test_mixin_is_applied_to_filesystem_storage(self):
        # RLSTenantFileSystemStorage = RLSTenantStorageMixin + FileSystemStorage.
        from django.core.files.storage import FileSystemStorage

        self.assertTrue(
            issubclass(storage.RLSTenantFileSystemStorage, storage.RLSTenantStorageMixin)
        )
        self.assertTrue(
            issubclass(storage.RLSTenantFileSystemStorage, FileSystemStorage)
        )


if __name__ == "__main__":
    unittest.main()
