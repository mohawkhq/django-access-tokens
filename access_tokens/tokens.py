from django.core import signing

from access_tokens.scope import _is_sub_scope, default_scope_serializer


DEFAULT_SALT = "access_tokens.token"


class TokenGenerator(object):

    def __init__(self, scope_serializer=default_scope_serializer, default_salt=DEFAULT_SALT):
        self._scope_serializer = scope_serializer
        self._default_salt = default_salt

    def _get_salt(self, salt=None):
        if salt is None:
            salt = self._default_salt
        salt += ":" + self._scope_serializer.get_scope_protocol_version()
        return salt

    def generate(self, scope=(), key=None, salt=None):
        serialized_scope = self._scope_serializer.serialize_scope(scope)
        return signing.dumps(serialized_scope, key=key, salt=self._get_salt(salt))

    def validate(self, token, scope=(), key=None, salt=None, max_age=None):
        # Load the token scope.
        try:
            serialized_token_scope = signing.loads(token, key=key, salt=self._get_salt(salt), max_age=max_age)
        except signing.BadSignature:
            return False
        # Deserialize the scope.
        token_scope = self._scope_serializer.deserialize_scope(serialized_token_scope)
        # Check the scopes.
        return _is_sub_scope(token_scope, scope)


default_token_generator = TokenGenerator()


generate = default_token_generator.generate
validate = default_token_generator.validate