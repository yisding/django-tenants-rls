"""Unit tests for ``django_tenants.rls.cache``.

These run without a database. The RLS cache key functions must key on the REAL
active tenant (``connection.tenant.schema_name``) rather than
``connection.schema_name``, because under RLS the latter is pinned to ``public``
for every tenant -- so the bundled ``django_tenants.cache`` would silently share
one cache namespace across all tenants. We assert the key is built from
``current_tenant_schema()`` (mocked tenant), falls back to the public schema name
when there is no real tenant (None / FakeTenant pinned to public), and that the
key shape is the same drop-in shape as ``django_tenants.cache`` so ``reverse_key``
round-trips.
"""

import unittest
from unittest import mock

from django_tenants.postgresql_backend.base import FakeTenant
from django_tenants.rls import cache


class _Conn:
    """A minimal connection exposing ``.tenant`` (and a pinned schema_name)."""

    def __init__(self, tenant, schema_name="public"):
        self.tenant = tenant
        # Under RLS this is pinned to 'public' for ALL tenants; the cache key
        # functions must NOT read it. We set a deliberately-wrong value so any
        # accidental use would show up as a cross-tenant collision in the key.
        self.schema_name = schema_name


class _Tenant:
    def __init__(self, schema_name):
        self.schema_name = schema_name


def _patch_conn(conn):
    """Patch ``connections[<alias>]`` as seen by the rls.cache module.

    ``current_tenant_schema`` lives in ``rls.session`` and resolves the tenant
    alias via ``connections[alias]``. ``session`` binds ``connections`` at import
    time (``from django.db import connections``), so we patch that name rather
    than ``django.db.connections``. A dict keyed on the default alias is enough
    for these no-DB tests.
    """
    return mock.patch("django_tenants.rls.session.connections", {"default": conn})


class MakeKeyTestCase(unittest.TestCase):
    def test_keys_on_real_tenant_schema_not_pinned_schema_name(self):
        # The real tenant is 'acme'; connection.schema_name is the RLS-pinned
        # 'public'. The key must reflect 'acme', proving it ignores schema_name.
        conn = _Conn(tenant=_Tenant("acme"), schema_name="public")
        with _patch_conn(conn):
            key = cache.make_key("widget", "prefix", 1)
        self.assertEqual(key, "acme:prefix:1:widget")
        self.assertTrue(key.startswith("acme:"))

    def test_two_tenants_produce_distinct_namespaces(self):
        conn_a = _Conn(tenant=_Tenant("acme"))
        conn_b = _Conn(tenant=_Tenant("globex"))
        with _patch_conn(conn_a):
            key_a = cache.make_key("k", "p", 2)
        with _patch_conn(conn_b):
            key_b = cache.make_key("k", "p", 2)
        self.assertNotEqual(key_a, key_b)
        self.assertEqual(key_a, "acme:p:2:k")
        self.assertEqual(key_b, "globex:p:2:k")

    def test_falls_back_to_public_when_tenant_is_none(self):
        conn = _Conn(tenant=None, schema_name="public")
        with _patch_conn(conn):
            key = cache.make_key("k", "p", 1)
        self.assertEqual(key, "public:p:1:k")

    def test_falls_back_to_public_for_fake_tenant_pinned_to_public(self):
        # The RLS backend wraps the pinned schema in a FakeTenant("public").
        conn = _Conn(tenant=FakeTenant(schema_name="public"))
        with _patch_conn(conn):
            key = cache.make_key("k", "p", 1)
        self.assertEqual(key, "public:p:1:k")

    def test_key_shape_matches_bundled_cache(self):
        # Drop-in replacement: same 'schema:prefix:version:key' shape, so it can
        # swap straight into KEY_FUNCTION without changing the stored layout.
        conn = _Conn(tenant=_Tenant("acme"))
        with _patch_conn(conn):
            key = cache.make_key("the:key", "pfx", 9)
        self.assertEqual(key, "acme:pfx:9:the:key")


class ReverseKeyTestCase(unittest.TestCase):
    def test_strips_first_segment(self):
        self.assertEqual(cache.reverse_key("acme:prefix:1:widget"), "widget")

    def test_preserves_colons_in_original_key(self):
        # The original user key may itself contain colons; only the first three
        # segments (schema, prefix, version) are stripped.
        self.assertEqual(cache.reverse_key("acme:pfx:9:the:key"), "the:key")

    def test_round_trips_with_make_key(self):
        conn = _Conn(tenant=_Tenant("acme"))
        with _patch_conn(conn):
            built = cache.make_key("user:42:profile", "p", 3)
        self.assertEqual(cache.reverse_key(built), "user:42:profile")


if __name__ == "__main__":
    unittest.main()
