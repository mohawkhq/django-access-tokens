"""
Scope generation, comparison and serialization.

The methods `access_obj`, `access_model`, `access_app` and `access_all`
can be used to generate a scope that represents access to the specified
model instance, model, app or globally.

Scopes can be appended to each other using the plus operator, allowing
multiple scopes to be combined.
"""

from itertools import chain, izip_longest

from django.conf import settings


# Scope generation.


def _make_grant(model_grant, permissions_grant):
    """
    Formats a grant for the give permissions on the given
    model specifier.
    """
    return ((model_grant, permissions_grant),)


def access_obj(obj, *permissions):
    """
    Returns a scope that represents access for the given
    permissions to the given object.
    """
    return _make_grant(
        (
            obj._meta.app_label,
            obj._meta.module_name,
            obj.pk,
        ),
        permissions,
    )


def access_model(model, *permissions):
    """
    Returns a scope that represents access for the given
    permissions to the given model.
    """
    return _make_grant(
        (
            model._meta.app_label,
            model._meta.module_name,
        ),
        permissions,
    )


def access_app(app_label, *permissions):
    """
    Returns a scope that represents access for the given
    permissions to the given app.
    """
    return _make_grant(
        (
            app_label,
        ),
        permissions,
    )


def access_all(*permissions):
    """
    Returns a scope that represents access for the given
    permissions globally across all apps.
    """
    return _make_grant(
        (),
        permissions,
    )


# Scope comparison.


def _is_sub_scope(scope, parent_scope):
    """
    Returns True if the given scope is a subset of the permissions
    defined in the parent scope.
    """
    return not any (
        frozenset(permissions_grant).difference(chain.from_iterable(
            parent_permissions_grant
            for parent_model_grant, parent_permissions_grant
            in parent_scope
            if all(
                parent_model_grant_part == model_grant_part
                for model_grant_part, parent_model_grant_part
                in izip_longest(
                    model_grant,
                    parent_model_grant,
                )
                if parent_model_grant_part is not None
            )
        ))
        for model_grant, permissions_grant
        in scope
        if permissions_grant
    )


# Scope serialization and deserialization.


class ScopeSerializer(object):

    """
    Serializes a scope into a compact representation.

    The default implementation does not compact the scope,
    but subclasses may define implementations of `serialize_model_grant`,
    `serialize_permission_grant`, `deserialize_model_grant` and
    `deserialize_permission_grant` to do so.
    """

    def get_scope_protocol_version(self):
        """
        Returns the scope protocol version, which is incorporated
        in the token generator's salt.

        This prevents incompatible protocol versions from causing errors.
        """
        return "1.0.0"

    def serialize_model_grant(self, model_grant):
        """
        Returns a compact representation of the given model grant.
        """
        return model_grant

    def serialize_permission_grant(self, permission_grant):
        """
        Returns a compact representation of the given permission grant.
        """
        return permission_grant

    def serialize_scope(self, scope):
        """
        Returns a compact representation of the given scope.
        """
        return [
            (
                self.serialize_model_grant(model_grant),
                map(self.serialize_permission_grant, permissions_grant),
            )
            for model_grant, permissions_grant
            in scope
        ]

    def deserialize_model_grant(self, serialized_model_grant):
        """
        Converts the serialized model grant into a correctly-formatted
        model grant.
        """
        return serialized_model_grant

    def deserialize_permission_grant(self, serialized_permission_grant):
        """
        Converts the serialized permission grant into a correctly-formatted
        permission grant.
        """
        return serialized_permission_grant

    def deserialize_scope(self, serialized_scope):
        """
        Converts the serialized scope into a correctly-formatted scope.
        """
        return [
            (
                self.deserialize_model_grant(serialized_model_grant),
                map(self.deserialize_permission_grant, serialized_permissions_grant),
            )
            for serialized_model_grant, serialized_permissions_grant
            in serialized_scope
        ]


class ContentTypeScopeSerializerMixin(object):

    """
    A mixin for a ScopeSerializer that provides a more compact
    representation of model grants by using the ContentTypes framework.
    """

    def __init__(self):
        """
        Initializes the ContentTypeScopeSerializerMixin.
        """
        super(ContentTypeScopeSerializerMixin, self).__init__();
        # Lazy-load content type model.
        from django.contrib.contenttypes.models import ContentType
        self._content_type_model = ContentType

    def serialize_model_grant(self, model_grant):
        """
        Returns a compact representation of the given model grant.
        """
        if len(model_grant) >= 2:
            return (self._content_type_model.objects.get_by_natural_key(*model_grant[:2]).id,) + model_grant[2:]
        return model_grant

    def deserialize_model_grant(self, serialized_model_grant):
        """
        Converts the serialized model grant into a correctly-formatted
        model grant.
        """
        if serialized_model_grant and isinstance(serialized_model_grant[0], int):
            model = self._content_type_model.objects.get_for_id(serialized_model_grant[0]).model_class()
            return [
                model._meta.app_label,
                model._meta.module_name,
            ] + serialized_model_grant[1:]
        return serialized_model_grant


class AuthPermissionScopeSerializerMixin(object):

    def __init__(self):
        """
        Initializes the AuthPermissionScopeSerializerMixin.
        """
        super(AuthPermissionScopeSerializerMixin, self).__init__();
        # Lazy-load Permission model.
        from django.contrib.auth.models import Permission
        self._permission_model = Permission

    def serialize_permission_grant(self, permission_grant):
        """
        Returns a compact representation of the given permission grant.
        """
        try:
            app_label, codename = permission_grant.split(".")
        except ValueError:
            pass
        else:
            try:
                permission = self._permission_model.objects.get(
                    content_type__app_label = app_label,
                    codename = codename,
                )
            except (self._permission_model.DoesNotExist, self._permission_model.MultipleObjectsReturned):
                pass
            else:
                return permission.id
        return permission_grant

    def deserialize_permission_grant(self, serialized_permission_grant):
        """
        Converts the serialized permission grant into a correctly-formatted
        permission grant.
        """
        if isinstance(serialized_permission_grant, int):
            return self._permission_model.objects.get(id=serialized_permission_grant)
        return serialized_permission_grant


# Create a default scope serializer that uses whatever serializer mixins are available.


DefaultScopeSerializer = type(
    "DefaultScopeSerializer",
    (
        (
            ContentTypeScopeSerializerMixin,
        ) if "django.contrib.contenttypes" in settings.INSTALLED_APPS else ()
    ) + (
        (
            AuthPermissionScopeSerializerMixin,
        ) if "django.contrib.auth" in settings.INSTALLED_APPS else ()
    ) + (
        ScopeSerializer,
    ),
    {},
)


# Instantiate a shared default scope serializer.


default_scope_serializer = DefaultScopeSerializer()