from django.core import signing

from access_tokens.scope import _is_sub_scope, default_scope_serializer


DEFAULT_SALT = "access_tokens.token"


class TokenGenerator(object):

    def __init__(self, scope_serializer=default_scope_serializer):
        self._scope_serializer = scope_serializer

    def generate(self, scope=(), key=None, salt=DEFAULT_SALT):
        serialized_scope = self._scope_serializer.serialize_scope(scope)
        return signing.dumps(serialized_scope, key=key, salt=salt)

    def validate(self, token, scope=(), key=None, salt=DEFAULT_SALT, max_age=None):
        # Load the token scope.
        try:
            serialized_token_scope = signing.loads(token, key=key, salt=salt, max_age=max_age)
        except signing.BadSignature:
            return False
        # Deserialize the scope.
        token_scope = self._scope_serializer.deserialize_scope(serialized_token_scope)
        # Check the scopes.
        return _is_sub_scope(token_scope, scope)


default_token_generator = TokenGenerator()


generate = default_token_generator.generate
validate = default_token_generator.validate