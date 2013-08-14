from distutils.core import setup

from access_tokens import __version__


version_str = ".".join(str(n) for n in __version__)


setup(
    name = "django-access-tokens",
    version = version_str,
    license = "BSD",
    description = "A Django app for for generating secure scoped access tokens.",
    author = "Dave Hall",
    author_email = "dave@etianen.com",
    url = "http://github.com/mohawkhq/django-access-tokens",
    packages = [
        "access_tokens",
    ],
    classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Framework :: Django",
    ],
)
