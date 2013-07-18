from django.core import signing

from dj_access_tokens.scope import _is_sub_scope


DEFAULT_SALT = "dj_access_tokens.token"


def generate(scope=(), key=None, salt=DEFAULT_SALT):
    return signing.dumps(scope, key=key, salt=salt)


def validate(token, scope=(), key=None, salt=DEFAULT_SALT, max_age=None):
    # Load the token scope.
    try:
        token_scope = signing.loads(token, key=key, salt=salt, max_age=max_age)
    except signing.BadSignature:
        return False
    # Check the scopes.
    return _is_sub_scope(token_scope, scope)