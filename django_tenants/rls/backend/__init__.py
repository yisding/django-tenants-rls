"""RLS database backend package.

Django resolves a database ENGINE by importing ``<engine>.base`` and reading
its ``DatabaseWrapper``. This package therefore only needs to exist; the wrapper
lives in :mod:`django_tenants.rls.backend.base`. Set
``DATABASES[...]['ENGINE'] = 'django_tenants.rls.backend'`` to use it.

For convenience the wrapper is also re-exported here so
``from django_tenants.rls.backend import DatabaseWrapper`` works directly. Like
every Django database backend, this package is imported when Django resolves the
ENGINE -- after ``django.setup()`` -- so it adds no new app-registry coupling
beyond the parent django-tenants backend (which already imports ``ContentType``
at module load). For hygiene, ``base`` keeps to the registry-free
``conf``/``session``/``schema`` layers and introduces no dependency on
:mod:`django_tenants.rls.models` of its own.
"""

from django_tenants.rls.backend.base import DatabaseWrapper

__all__ = ["DatabaseWrapper"]
