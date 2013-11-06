import time, unittest

from django.db import models
from django.test import TestCase
from django.conf import settings

from access_tokens import tokens, scope


# Define some test models.


class TestModel(models.Model):

    pass


class TestModel2(models.Model):

    pass


# Create all possible combinations of token generators.


default_token_generator = tokens.default_token_generator

basic_scope_serializer = scope.ScopeSerializer()
basic_token_generator = tokens.TokenGenerator(basic_scope_serializer)

content_type_scope_serializer = type("ContentTypeScopeSerializer", (
    scope.ContentTypeScopeSerializerMixin,
    scope.ScopeSerializer,
), {})()
content_type_token_generator = tokens.TokenGenerator(content_type_scope_serializer)

auth_permission_scope_serializer = type("AuthPermissionScopeSerializer", (
    scope.AuthPermissionScopeSerializerMixin,
    scope.ScopeSerializer,
), {})()
auth_permission_token_generator = tokens.TokenGenerator(auth_permission_scope_serializer)

kitchen_sink_scope_serializer = type("KitchenSinkScopeSerializer", (
    scope.ContentTypeScopeSerializerMixin,
    scope.AuthPermissionScopeSerializerMixin,
    scope.ScopeSerializer,
), {})()
kitchen_sink_token_generator = tokens.TokenGenerator(kitchen_sink_scope_serializer)


# Test all possible combinations of token generators.


class TestAccessTokens(TestCase):

    token_generator = default_token_generator

    def setUp(self):
        self.obj = TestModel.objects.create()
        self.obj2 = TestModel2.objects.create()

    # Token compatibility tests.

    def testMismatchedTokenFormatDoesNotError(self):
        for token_generator in (default_token_generator, basic_token_generator, content_type_token_generator, auth_permission_token_generator, kitchen_sink_token_generator):
            self.assertEqual(
                self.token_generator.validate(token_generator.generate(scope.access_all("read")), scope.access_all("read")),
                token_generator._scope_serializer.get_scope_protocol_version() == self.token_generator._scope_serializer.get_scope_protocol_version(),
            )
            self.assertEqual(
                token_generator.validate(self.token_generator.generate(scope.access_all("read")), scope.access_all("read")),
                token_generator._scope_serializer.get_scope_protocol_version() == self.token_generator._scope_serializer.get_scope_protocol_version(),
            )

    # Invalid token tests.

    def testInvalidTokenGrantsNothing(self):
        self.assertFalse(self.token_generator.validate("bad_token", scope.access_all()))

    def testIncorrectSaltGrantsNothing(self):
        valid_token = self.token_generator.generate(scope.access_all())
        self.assertFalse(self.token_generator.validate(valid_token, scope.access_all(), salt="bad_salt"))

    def testIncorrectKeyGrantsNothing(self):
        valid_token = self.token_generator.generate(scope.access_all())
        self.assertFalse(self.token_generator.validate(valid_token, scope.access_all(), key="bad_key"))

    def testExpiredAccessTokenGrantsNothing(self):
        valid_token = self.token_generator.generate(scope.access_all())
        time.sleep(0.1)
        self.assertFalse(self.token_generator.validate(valid_token, scope.access_all(), max_age=0.05))

    # Valid token tests.

    def assertScope(self, scope, parent_scope, expected):
        token = self.token_generator.generate(parent_scope)
        self.assertEqual(self.token_generator.validate(token, scope), expected)

    def assertScopeValid(self, scope, parent_scope):
        return self.assertScope(scope, parent_scope, True)

    def assertScopeInvalid(self, scope, parent_scope):
        return self.assertScope(scope, parent_scope, False)

    def testScopePermissionGrants(self):
        # Asking for no permissions.
        self.assertScopeValid(
            scope.access_all(),
            scope.access_all(),
        )
        self.assertScopeValid(
            scope.access_all(),
            scope.access_all("read"),
        )
        self.assertScopeValid(
            scope.access_all(),
            scope.access_all("read", "write"),
        )
        # Asking for read permissions.
        self.assertScopeInvalid(
            scope.access_all("read"),
            scope.access_all(),
        )
        self.assertScopeValid(
            scope.access_all("read"),
            scope.access_all("read"),
        )
        self.assertScopeValid(
            scope.access_all("read"),
            scope.access_all("read", "write"),
        )
        # Asking for read and write permissions.
        self.assertScopeInvalid(
            scope.access_all("read", "write"),
            scope.access_all(),
        )
        self.assertScopeInvalid(
            scope.access_all("read", "write"),
            scope.access_all("read"),
        )
        self.assertScopeValid(
            scope.access_all("read", "write"),
            scope.access_all("read", "write"),
        )

    def testScopeModelGrants(self):
        # Ask for no access.
        self.assertScopeValid(
            (),
            scope.access_all("read"),
        )
        self.assertScopeValid(
            (),
            scope.access_app("access_tokens", "read"),
        )
        self.assertScopeValid(
            (),
            scope.access_model(TestModel, "read"),
        )
        self.assertScopeValid(
            (),
            scope.access_obj(self.obj, "read"),
        )
        self.assertScopeValid(
            (),
            (),
        )
        # Ask for access, but no permissions
        self.assertScopeValid(
            scope.access_all(),
            scope.access_all("read"),
        )
        self.assertScopeValid(
            scope.access_all(),
            scope.access_app("access_tokens", "read"),
        )
        self.assertScopeValid(
            scope.access_all(),
            scope.access_model(TestModel, "read"),
        )
        self.assertScopeValid(
            scope.access_all(),
            scope.access_obj(self.obj, "read"),
        )
        self.assertScopeValid(
            scope.access_all(),
            (),
        )
        # Ask for obj access.
        self.assertScopeValid(
            scope.access_obj(self.obj, "read"),
            scope.access_all("read"),
        )
        self.assertScopeValid(
            scope.access_obj(self.obj, "read"),
            scope.access_app("access_tokens", "read"),
        )
        self.assertScopeValid(
            scope.access_obj(self.obj, "read"),
            scope.access_model(TestModel, "read"),
        )
        self.assertScopeValid(
            scope.access_obj(self.obj, "read"),
            scope.access_obj(self.obj, "read"),
        )
        self.assertScopeInvalid(
            scope.access_obj(self.obj, "read"),
            (),
        )
        # Ask for model access.
        self.assertScopeValid(
            scope.access_model(TestModel, "read"),
            scope.access_all("read"),
        )
        self.assertScopeValid(
            scope.access_model(TestModel, "read"),
            scope.access_app("access_tokens", "read"),
        )
        self.assertScopeValid(
            scope.access_model(TestModel, "read"),
            scope.access_model(TestModel, "read"),
        )
        self.assertScopeInvalid(
            scope.access_model(TestModel, "read"),
            scope.access_obj(self.obj, "read"),
        )
        self.assertScopeInvalid(
            scope.access_model(TestModel, "read"),
            (),
        )
        # Ask for app access.
        self.assertScopeValid(
            scope.access_app("access_tokens", "read"),
            scope.access_all("read"),
        )
        self.assertScopeValid(
            scope.access_app("access_tokens", "read"),
            scope.access_app("access_tokens", "read"),
        )
        self.assertScopeInvalid(
            scope.access_app("access_tokens", "read"),
            scope.access_model(TestModel, "read"),
        )
        self.assertScopeInvalid(
            scope.access_app("access_tokens", "read"),
            scope.access_obj(self.obj, "read"),
        )
        self.assertScopeInvalid(
            scope.access_app("access_tokens", "read"),
            (),
        )
        # Ask for global access.
        self.assertScopeValid(
            scope.access_all("read"),
            scope.access_all("read"),
        )
        self.assertScopeInvalid(
            scope.access_all("read"),
            scope.access_app("access_tokens", "read"),
        )
        self.assertScopeInvalid(
            scope.access_all("read"),
            scope.access_model(TestModel, "read"),
        )
        self.assertScopeInvalid(
            scope.access_all("read"),
            scope.access_obj(self.obj, "read"),
        )
        self.assertScopeInvalid(
            scope.access_all("read"),
            (),
        )

    def testKitchenSink(self):
        # Access specific models using a global read token.
        self.assertScopeValid(
            scope.access_obj(self.obj, "read") + scope.access_obj(self.obj2, "read"),
            scope.access_all("read"),
        )
        # Then fail it by asking for a new permission.
        self.assertScopeInvalid(
            scope.access_obj(self.obj, "read", "write") + scope.access_obj(self.obj2, "read"),
            scope.access_all("read"),
        )
        # Access specific objects using a specific read and write token.
        self.assertScopeValid(
            scope.access_obj(self.obj, "read", "write") + scope.access_obj(self.obj2, "read", "write"),
            scope.access_model(TestModel, "read", "write") + scope.access_model(TestModel2, "read", "write"),
        )
        # Then fail it because access wasn't granted to the second model.
        self.assertScopeInvalid(
            scope.access_obj(self.obj, "read", "write") + scope.access_obj(self.obj2, "read", "write"),
            scope.access_model(TestModel, "read", "write"),
        )
        # Then give it back with a token for the whole app.
        self.assertScopeValid(
            scope.access_obj(self.obj, "read", "write") + scope.access_obj(self.obj2, "read", "write"),
            scope.access_model(TestModel, "read", "write") + scope.access_app("access_tokens", "read", "write"),
        )
        # Finally, give read access to everything, write access to a specific model, and it should work.
        self.assertScopeValid(
            scope.access_obj(self.obj, "read", "write"),
            scope.access_model(self.obj, "write") + scope.access_all("read"),
        )


class TestAccessTokensBasicTokenGenerator(TestAccessTokens):

    token_generator = basic_token_generator


@unittest.skipUnless(
    "django.contrib.contenttypes" in settings.INSTALLED_APPS,
    "django.contrib.contenttypes app not installed",
)
class TestAccessTokensContentTypeTokenGenerator(TestAccessTokens):

    token_generator = content_type_token_generator

    def testContentTypeTokenGeneratorCreatesEquivalentGlobalTokens(self):
        self.assertEqual(
            len(self.token_generator.generate(scope.access_all())),
            len(basic_token_generator.generate(scope.access_all())),
        )

    def testContentTypeTokenGeneratorCreatesEquivalentAppTokens(self):
        self.assertEqual(
            len(self.token_generator.generate(scope.access_app("access_tokens"))),
            len(basic_token_generator.generate(scope.access_app("access_tokens"))),
        )

    def testContentTypeTokenGeneratorCreatesSmallerModelTokens(self):
        self.assertLess(
            len(self.token_generator.generate(scope.access_model(TestModel))),
            len(basic_token_generator.generate(scope.access_model(TestModel))),
        )

    def testContentTypeTokenGeneratorCreatesSmallerObjectTokens(self):
        self.assertLess(
            len(self.token_generator.generate(scope.access_obj(self.obj))),
            len(basic_token_generator.generate(scope.access_obj(self.obj))),
        )


@unittest.skipUnless(
    "django.contrib.auth" in settings.INSTALLED_APPS,
    "django.contrib.auth app not installed",
)
class TestAccessTokensAuthPermissionTokenGenerator(TestAccessTokens):

    token_generator = auth_permission_token_generator

    def testAuthPermissionTokenGeneratorCreatesEquivalentUnknownPermissionTokens(self):
        self.assertEqual(
            len(self.token_generator.generate(scope.access_all("read"))),
            len(basic_token_generator.generate(scope.access_all("read"))),
        )

    def testContentTypeTokenGeneratorCreatesSmallerKnownPermissionTokens(self):
        self.assertLess(
            len(self.token_generator.generate(scope.access_all("auth.change_permission"))),
            len(basic_token_generator.generate(scope.access_all("auth.change_permission"))),
        )


@unittest.skipUnless(
    "django.contrib.contenttypes" in settings.INSTALLED_APPS,
    "django.contrib.contenttypes app not installed",
)
@unittest.skipUnless(
    "django.contrib.auth" in settings.INSTALLED_APPS,
    "django.contrib.auth app not installed",
)
class TestAccessTokensKitchenSinkTokenGenerator(TestAccessTokensContentTypeTokenGenerator, TestAccessTokensAuthPermissionTokenGenerator):

    token_generator = kitchen_sink_token_generator