from itertools import chain, izip_longest

from django.conf import settings


# Scope generation.


def _make_grant(model_grant, permissions_grant):
    return ((model_grant, permissions_grant),)


def access_obj(obj, *permissions):
    return _make_grant(
        (
            obj._meta.app_label,
            obj._meta.module_name,
            obj.pk,
        ),
        permissions,
    )


def access_model(model, *permissions):
    return _make_grant(
        (
            model._meta.app_label,
            model._meta.module_name,
        ),
        permissions,
    )


def access_app(app_label, *permissions):
    return _make_grant(
        (
            app_label,
        ),
        permissions,
    )


def access_all(*permissions):
    return _make_grant(
        (),
        permissions,
    )


# Scope comparison.


def _is_sub_scope(scope, parent_scope):
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

    def get_scope_protocol_version(self):
        return "1.0.0"

    def serialize_model_grant(self, model_grant):
        return model_grant

    def serialize_permission_grant(self, permission_grant):
        return permission_grant

    def serialize_scope(self, scope):
        return [
            (
                self.serialize_model_grant(model_grant),
                map(self.serialize_permission_grant, permissions_grant),
            )
            for model_grant, permissions_grant
            in scope
        ]

    def deserialize_model_grant(self, serialized_model_grant):
        return serialized_model_grant

    def deserialize_permission_grant(self, serialized_permission_grant):
        return serialized_permission_grant

    def deserialize_scope(self, serialized_scope):
        return [
            (
                self.deserialize_model_grant(serialized_model_grant),
                map(self.deserialize_permission_grant, serialized_permissions_grant),
            )
            for serialized_model_grant, serialized_permissions_grant
            in serialized_scope
        ]


class ContentTypeScopeSerializerMixin(object):

    def __init__(self):
        super(ContentTypeScopeSerializerMixin, self).__init__();
        # Lazy-load content type model.
        from django.contrib.contenttypes.models import ContentType
        self._content_type_model = ContentType

    def get_scope_protocol_version(self):
        return super(ContentTypeScopeSerializerMixin, self).get_scope_protocol_version() + "+django.contrib.contenttypes.ContentType"

    def serialize_model_grant(self, model_grant):
        if len(model_grant) >= 2:
            return (self._content_type_model.objects.get_by_natural_key(*model_grant[:2]).id,) + model_grant[2:]
        return model_grant

    def deserialize_model_grant(self, serialized_model_grant):
        if serialized_model_grant and isinstance(serialized_model_grant[0], int):
            model = self._content_type_model.objects.get_for_id(serialized_model_grant[0]).model_class()
            return [
                model._meta.app_label,
                model._meta.module_name,
            ] + serialized_model_grant[1:]
        return serialized_model_grant


class AuthPermissionScopeSerializerMixin(object):

    def __init__(self):
        super(AuthPermissionScopeSerializerMixin, self).__init__();
        # Lazy-load Permission model.
        from django.contrib.auth.models import Permission
        self._permission_model = Permission

    def get_scope_protocol_version(self):
        return super(AuthPermissionScopeSerializerMixin, self).get_scope_protocol_version() + "+django.contrib.auth.Permission"

    def serialize_permission_grant(self, permission_grant):
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
        if isinstance(serialized_permission_grant, int):
            return self._permission_model.objects.get(id=serialized_permission_grant)
        return serialized_permission_grant


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


default_scope_serializer = DefaultScopeSerializer()