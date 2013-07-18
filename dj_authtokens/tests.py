import time
from itertools import product
from operator import add

from django.db import models
from django.test import TestCase

from dj_authtokens import tokens, scope


class TestModel(models.Model):

    pass


class TestModel2(models.Model):

    pass


class TestAuthTokens(TestCase):

    def setUp(self):
        self.obj = TestModel.objects.create()
        self.obj2 = TestModel2.objects.create()

    def testInvalidTokenGrantsNothing(self):
        self.assertFalse(tokens.validate("bad_token", scope.access_all()))

    def testIncorrectSaltGrantsNothing(self):
        valid_token = tokens.generate(scope.access_all())
        self.assertFalse(tokens.validate(valid_token, scope.access_all(), salt="bad_salt"))

    def testIncorrectKeyGrantsNothing(self):
        valid_token = tokens.generate(scope.access_all())
        self.assertFalse(tokens.validate(valid_token, scope.access_all(), key="bad_key"))

    def testExpiredAccessTokenGrantsNothing(self):
        valid_token = tokens.generate(scope.access_all())
        time.sleep(0.1)
        self.assertFalse(tokens.validate(valid_token, scope.access_all(), max_age=0.05))

    # Valid token tests.

    def getScopeTestData(self):
        return (
            # PERMISSIONS.
            # Asking for no permissions.
            (
                scope.access_all(),
                scope.access_all(),
                True,
            ),
            (
                scope.access_all(),
                scope.access_all("read"),
                True,
            ),
            (
                scope.access_all(),
                scope.access_all("read", "write"),
                True,
            ),
            # Asking for read permissions.
            (
                scope.access_all("read"),
                scope.access_all(),
                False,
            ),
            (
                scope.access_all("read"),
                scope.access_all("read"),
                True,
            ),
            (
                scope.access_all("read"),
                scope.access_all("read", "write"),
                True,
            ),
            # Asking for read and write permissions.
            (
                scope.access_all("read", "write"),
                scope.access_all(),
                False,
            ),
            (
                scope.access_all("read", "write"),
                scope.access_all("read"),
                False,
            ),
            (
                scope.access_all("read", "write"),
                scope.access_all("read", "write"),
                True,
            ),
            # MODELS.
            # Empty.
            (
                (),
                scope.access_all(),
                True,
            ),
            (
                (),
                scope.access_app("dj_authtokens"),
                True,
            ),
            (
                (),
                scope.access_model(TestModel),
                True,
            ),
            (
                (),
                scope.access_obj(self.obj),
                True,
            ),
            (
                (),
                (),
                True,
            ),
            # Obj.
            (
                scope.access_obj(self.obj),
                scope.access_all(),
                True,
            ),
            (
                scope.access_obj(self.obj),
                scope.access_app("dj_authtokens"),
                True,
            ),
            (
                scope.access_obj(self.obj),
                scope.access_model(TestModel),
                True,
            ),
            (
                scope.access_obj(self.obj),
                scope.access_obj(self.obj),
                True,
            ),
            (
                scope.access_obj(self.obj),
                (),
                False,
            ),
            # Model.
            (
                scope.access_model(TestModel),
                scope.access_all(),
                True,
            ),
            (
                scope.access_model(TestModel),
                scope.access_app("dj_authtokens"),
                True,
            ),
            (
                scope.access_model(TestModel),
                scope.access_model(TestModel),
                True,
            ),
            (
                scope.access_model(TestModel),
                scope.access_obj(self.obj),
                False,
            ),
            (
                scope.access_model(TestModel),
                (),
                False,
            ),
            # App.
            (
                scope.access_app("dj_authtokens"),
                scope.access_all(),
                True,
            ),
            (
                scope.access_app("dj_authtokens"),
                scope.access_app("dj_authtokens"),
                True,
            ),
            (
                scope.access_app("dj_authtokens"),
                scope.access_model(TestModel),
                False,
            ),
            (
                scope.access_app("dj_authtokens"),
                scope.access_obj(self.obj),
                False,
            ),
            (
                scope.access_app("dj_authtokens"),
                (),
                False,
            ),
            # All.
            (
                scope.access_all(),
                scope.access_all(),
                True,
            ),
            (
                scope.access_all(),
                scope.access_app("dj_authtokens"),
                False,
            ),
            (
                scope.access_all(),
                scope.access_model(TestModel),
                False,
            ),
            (
                scope.access_all(),
                scope.access_obj(self.obj),
                False,
            ),
            (
                scope.access_all(),
                (),
                False,
            ),
        )

    def assertScopeCorrect(self, scope, parent_scope, expected):
        token = tokens.generate(scope)
        self.assertEqual(tokens.validate(token, parent_scope), expected)

    def testScopes(self):
        for test_row in self.getScopeTestData():
            self.assertScopeCorrect(*test_row)

    def testKitchenSink(self):
        # Access specific models using a global read token.
        self.assertScopeCorrect(
            scope.access_obj(self.obj, "read") + scope.access_obj(self.obj2, "read"),
            scope.access_all("read"),
            True,
        )
        # Then fail it by asking for a new permission.
        self.assertScopeCorrect(
            scope.access_obj(self.obj, "read", "write") + scope.access_obj(self.obj2, "read"),
            scope.access_all("read"),
            False,
        )
        # Access specific objects using a specific read and write token.
        self.assertScopeCorrect(
            scope.access_obj(self.obj, "read", "write") + scope.access_obj(self.obj2, "read", "write"),
            scope.access_model(TestModel, "read", "write") + scope.access_model(TestModel2, "read", "write"),
            True,
        )
        # Then fail it because access wasn't granted to the second model.
        self.assertScopeCorrect(
            scope.access_obj(self.obj, "read", "write") + scope.access_obj(self.obj2, "read", "write"),
            scope.access_model(TestModel, "read", "write"),
            False,
        )
        # Then give it back with a token for the whole app.
        self.assertScopeCorrect(
            scope.access_obj(self.obj, "read", "write") + scope.access_obj(self.obj2, "read", "write"),
            scope.access_model(TestModel, "read", "write") + scope.access_app("dj_authtokens", "read", "write"),
            True,
        )
        # Finally, give read access to everything, write access to a specific model, and it should work.
        self.assertScopeCorrect(
            scope.access_obj(self.obj, "read", "write"),
            scope.access_model(self.obj, "write") + scope.access_all("read"),
            True,
        )