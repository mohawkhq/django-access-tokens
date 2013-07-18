import collections


def access_obj(obj, *permissions):
    return (
        (
            (
                obj._meta.app_label,
                obj._meta.module_name,
                obj.pk,
            ),
            permissions,
        ),
    )


def access_model(model, *permissions):
    return (
        (
            (
                model._meta.app_label,
                model._meta.module_name,
                None,
            ),
            permissions,
        ),
    )


def access_app(app_label, *permissions):
    return (
        (
            (
                app_label,
                None,
                None,
            ),
            permissions,
        ),
    )


def access_all(*permissions):
    return (
        (
            (
                None,
                None,
                None,
            ),
            permissions,
        ),
    )


def _is_sub_model_grant(model_grant, parent_model_grant):
    return all(
        parent_model_grant_part is None or parent_model_grant_part == model_grant_part
        for model_grant_part, parent_model_grant_part
        in zip(model_grant, parent_model_grant)
    )


def _is_sub_scope(scope, parent_scope):
    access_permission = object()
    # Work out what permissions are required.
    required_access = [
        (model_grant, set(permissions_grant) | set((access_permission,)))
        for model_grant, permissions_grant
        in scope
    ]
    # Go through all the parent scope grants.
    for parent_model_grant, parent_permissions_grant in parent_scope:
        for model_grant, required_permissions in required_access:
            if _is_sub_model_grant(model_grant, parent_model_grant):
                required_permissions.discard(access_permission)
                required_permissions.difference_update(parent_permissions_grant)
    # If no permissions remain to be fullfilled, then the scope is a sub-scope.
    return not any(
        required_permissions
        for _, required_permissions
        in required_access
    )