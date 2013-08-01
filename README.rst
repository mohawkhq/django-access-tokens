django-access-tokens
====================

**django-access-tokens** is a Django app for generating secure scoped access tokens.


Features
--------

- Generate secure access tokens that grant permissions at the level of model instances,
  models, apps, or globally.
- Expire access tokens after a given age.
- Generate more compact access tokens by including ``'django.contrib.auth'``
  and ``'django.contrib.contenttypes'`` in your project.


Installation
------------

1. Checkout the latest django-access-tokens release and copy or symlink the
   ``access_tokens`` directory into your ``PYTHONPATH``.  If using pip, run 
   ``pip install django-access-tokens``.
2. Add ``'access_tokens'`` to your ``INSTALLED_APPS`` setting.
3. Optionally, ad ``'django.contrib.auth'`` and ``'django.contrib.contenttypes'`` for more
   compact access tokens.


Generating tokens
-----------------

Tokens can be generated as follows:

``tokens.generate(scope=(), key=None, salt=None)``

Some examples of token generation:

::
    
    from access_tokens import scope, tokens

    # Generate an access token granting change permission on a given model instance.
    change_instance_token = tokens.generate(
        scope.access_obj(your_instance, "your_app.change_your_model"),
    )

    # Generate an access token granting add permission on a given model.
    change_model_token = tokens.generate(
        scope.access_model(YourModel, "your_app.add_your_model"),
    )

    # Generate an access token for a custom 'publish' permission on a given app.
    publish_app_token = tokens.generate(
        scope.access_app("your_app", "publish"),
    )

    # Generate an access token for a custom 'moderate' permission globally.
    publish_app_token = tokens.generate(
        scope.access_all("moderate"),
    )

    # Generate a complex token that grants a number of permissions.
    kitchen_sink_token = tokens.generate(
        scope.access_obj(your_instance, "read", "write") +
        scope.access_all("publish", "moderate")
    )

Some things to bear in mind when generating tokens:

- You can combine multiple ``scope.access_*`` invocations using the addition ``+`` operator.
- Permissions are specified as strings, and you can name as many permissions as you want
  in a given ``scope.access_*`` invocation.
- Permission names don't have to match permissions defined by ``'django.contrib.auth'``. If they
  do match, then the generated access token will be smaller.
- If you don't name any permissions in a ``scope.access_*`` call, then the returned scope is effectively
  worthless, as it grants no permissions.


Validating tokens
-----------------

Tokens can be validated as follows:

``tokens.validate(token, scope=(), key=None, salt=None, max_age=None)``

Some examples of token validation:

::
    
    from access_tokens import scope, tokens

    # See if the given token grants 'publish' permission on the given app.
    tokens.validate(
        some_token,
        scope.access_app("your_app", "publish"),
    )

    # Test the above token again, but only allow tokens generated in the last five minutes.
    tokens.validate(
        some_token,
        scope.access_app("your_app", "publish"),
        max_age = 60 * 5,
    )


Some things to bear in mind when validating tokens:

- A token is considered valid if it grants a superset of the permissions specified in
  the comparison scope.
- Tokens, by default, never expire, but you can force an expiry by passing a ``max_age`` argument
  to ``tokens.validate``.
- Token validation should only raise an exception if the code used to generate it was faulty.
  A bad signature on an access token, or an expired ``max_age``, will not raise an exception, but
  will instead simply fail validation and return ``False``.


Security
--------

django-access-tokens generates access tokens by serializing a representation of the granted permissions
and then signing it using ``django.core.signing``. As such, it uses the latest cryptographic techniques
developed by the core Django team, and will stay up-to-date as you upgrade Django.

In order for django-access-tokens to work, it is important that you keep the secret key used
to generate the tokens a secret. By default, tokens are generated using ``settings.SECRET_KEY``. If you
ever believe that your secret key has been compromised, change it immediately. Changing your secret
key will also immediately invalidate all access tokens generated from it.


More information
----------------

The django-access-tokens project was developed at `Mohawk <http://www.mohawkhq.com/>`_, and
is released as Open Source under the MIT license.

You can get the code from the `django-access-tokens project site <http://github.com/mohawkhq/django-access-tokens>`_.


Contributors
------------

The following people were involved in the development of this project.

- Dave Hall - `Blog <http://blog.etianen.com/>`_ | `GitHub <http://github.com/etianen>`_ | `Twitter <http://twitter.com/etianen>`_ | `Google Profile <http://www.google.com/profiles/david.etianen>`_