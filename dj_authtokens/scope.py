from itertools import chain


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


def _is_sub_scope(scope, parent_scope):
    return not any (
        frozenset(permissions_grant).difference(chain.from_iterable(
            parent_permissions_grant
            for parent_model_grant, parent_permissions_grant
            in parent_scope
            if all(
                parent_model_grant_part is None or parent_model_grant_part == model_grant_part
                for model_grant_part, parent_model_grant_part
                in zip(model_grant, parent_model_grant)
            )
        ))
        for model_grant, permissions_grant
        in scope
        if permissions_grant
    )