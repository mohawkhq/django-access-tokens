"""
Token generation and validation.
"""

from django.core import signing

from access_tokens.scope import _is_sub_scope, default_scope_serializer


DEFAULT_SALT = "access_tokens.token"


class TokenGenerator(object):

    """A token generator."""

    def __init__(self, scope_serializer=default_scope_serializer):
        """Initializes the TokenGenerator."""
        self._scope_serializer = scope_serializer

    def _get_protocol_version(self):
        """
        Returns the token protocol version, which is incorporated
        in the token generator's salt.

        This prevents incompatible protocol versions from causing errors.
        """
        return "1.0.0"

    def _get_salt(self, salt=None):
        """
        Returns a composite salt based on the provided salt,
        the token protocol version, and the scope serializer
        protocol version.
        """
        if salt is None:
            salt = DEFAULT_SALT
        return ":".join((
            salt,
            self._get_protocol_version(),
            self._scope_serializer.get_scope_protocol_version(),
        ))

    def generate(self, scope=(), key=None, salt=None):
        """
        Generates an access token for the given scope.
        """
        serialized_scope = self._scope_serializer.serialize_scope(scope)
        return signing.dumps(serialized_scope, key=key, salt=self._get_salt(salt))

    def validate(self, token, scope=(), key=None, salt=None, max_age=None):
        """
        Validates that the given token provides the grants requested by the given
        scope.
        """
        # Load the token scope.
        try:
            serialized_token_scope = signing.loads(token, key=key, salt=self._get_salt(salt), max_age=max_age)
        except signing.BadSignature:
            return False
        # Deserialize the scope.
        token_scope = self._scope_serializer.deserialize_scope(serialized_token_scope)
        # Check the scopes.
        return _is_sub_scope(scope, token_scope)


# Instantiate a default token generator.


default_token_generator = TokenGenerator()


# Create shortcut methods for the default token generator.


generate = default_token_generator.generate
validate = default_token_generator.validate