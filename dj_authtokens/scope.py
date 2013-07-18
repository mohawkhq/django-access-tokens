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


def _is_sub_permissions_grant(permissions_grant, parent_permissions_grant):
    return set(permissions_grant).issubset(parent_permissions_grant)


def _is_sub_grant(grant, parent_grant):
    model_grant, permissions_grant = grant
    parent_model_grant, parent_permissions_grant = parent_grant
    return _is_sub_model_grant(model_grant, parent_model_grant) and _is_sub_permissions_grant(permissions_grant, parent_permissions_grant)


def _is_sub_scope(scope, parent_scope):
    # Check each grant of the scope are allowed.
    return all(
        any(
            _is_sub_grant(grant, parent_grant)
            for parent_grant
            in parent_scope
        )
        for grant
        in scope
    )
