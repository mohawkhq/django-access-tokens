import time

from django.db import models
from django.test import TestCase

import authtokens


class TestModel(models.Model):

    pass


class TestModel2(models.Model):

    pass


class TestAuthTokens(TestCase):

    def setUp(self):
        self.obj = TestModel.objects.create()
        self.obj2 = TestModel2.objects.create()

    def testInvalidTokenGrantsNothing(self):
        self.assertFalse(authtokens.validate("bad_token", authtokens.access_all()))

    def testIncorrectSaltGrantsNothing(self):
        valid_token = authtokens.generate(authtokens.access_all())
        self.assertFalse(authtokens.validate(valid_token, authtokens.access_all(), salt="bad_salt"))

    def testIncorrectKeyGrantsNothing(self):
        valid_token = authtokens.generate(authtokens.access_all())
        self.assertFalse(authtokens.validate(valid_token, authtokens.access_all(), key="bad_key"))

    def testExpiredAccessTokenGrantsNothing(self):
        valid_token = authtokens.generate(authtokens.access_all())
        time.sleep(0.1)
        self.assertFalse(authtokens.validate(valid_token, authtokens.access_all(), max_age=0.05))

    # Valid token tests.

    def assertValid(self, scope=(), parent_scope=()):
        token = authtokens.generate(scope)
        self.assertTrue(authtokens.validate(token, parent_scope))

    def assertInvalid(self, scope=(), parent_scope=(), **kwargs):
        token = authtokens.generate(scope)
        self.assertFalse(authtokens.validate(token, parent_scope))

    def testPermissionGrantsValid(self):
        # Asking for no permissions.
        self.assertValid(
            authtokens.access_all(),
            authtokens.access_all(),
        )
        self.assertValid(
            authtokens.access_all(),
            authtokens.access_all("read"),
        )
        self.assertValid(
            authtokens.access_all(),
            authtokens.access_all("read", "write"),
        )
        # Asking for read permissions.
        self.assertInvalid(
            authtokens.access_all("read"),
            authtokens.access_all(),
        )
        self.assertValid(
            authtokens.access_all("read"),
            authtokens.access_all("read"),
        )
        self.assertValid(
            authtokens.access_all("read"),
            authtokens.access_all("read", "write"),
        )
        # Asking for read and write permissions.
        self.assertInvalid(
            authtokens.access_all("read", "write"),
            authtokens.access_all(),
        )
        self.assertInvalid(
            authtokens.access_all("read", "write"),
            authtokens.access_all("read"),
        )
        self.assertValid(
            authtokens.access_all("read", "write"),
            authtokens.access_all("read", "write"),
        )

    def testModelGrantsValid(self):
        # Empty.
        self.assertValid(
            (),
            authtokens.access_all(),
        )
        self.assertValid(
            (),
            authtokens.access_app("authtokens"),
        )
        self.assertValid(
            (),
            authtokens.access_model(TestModel),
        )
        self.assertValid(
            (),
            authtokens.access_obj(self.obj),
        )
        # Obj.
        self.assertValid(
            authtokens.access_obj(self.obj),
            authtokens.access_all(),
        )
        self.assertValid(
            authtokens.access_obj(self.obj),
            authtokens.access_app("authtokens"),
        )
        self.assertValid(
            authtokens.access_obj(self.obj),
            authtokens.access_model(TestModel),
        )
        self.assertValid(
            authtokens.access_obj(self.obj),
            authtokens.access_obj(self.obj),
        )
        # Model.
        self.assertValid(
            authtokens.access_model(TestModel),
            authtokens.access_all(),
        )
        self.assertValid(
            authtokens.access_model(TestModel),
            authtokens.access_app("authtokens"),
        )
        self.assertValid(
            authtokens.access_model(TestModel),
            authtokens.access_model(TestModel),
        )
        self.assertInvalid(
            authtokens.access_model(TestModel),
            authtokens.access_obj(self.obj),
        )
        # App.
        self.assertValid(
            authtokens.access_app("authtokens"),
            authtokens.access_all(),
        )
        self.assertValid(
            authtokens.access_app("authtokens"),
            authtokens.access_app("authtokens"),
        )
        self.assertInvalid(
            authtokens.access_app("authtokens"),
            authtokens.access_model(TestModel),
        )
        self.assertInvalid(
            authtokens.access_app("authtokens"),
            authtokens.access_obj(self.obj),
        )
        # All.
        self.assertValid(
            authtokens.access_all(),
            authtokens.access_all(),
        )
        self.assertInvalid(
            authtokens.access_all(),
            authtokens.access_app("authtokens"),
        )
        self.assertInvalid(
            authtokens.access_all(),
            authtokens.access_model(TestModel),
        )
        self.assertInvalid(
            authtokens.access_all(),
            authtokens.access_obj(self.obj),
        )