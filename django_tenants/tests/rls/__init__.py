"""Test suite for the django-tenants shared-schema Row Level Security mode.

The non-DB tests in this package never touch a live database: schema-editor,
session and backend behaviour is exercised through small recording fakes so the
suite passes with no Postgres available. The single end-to-end isolation test in
``test_isolation`` is skipped unless a Postgres database is configured.
"""
