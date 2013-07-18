from itertools import chain, izip, izip_longest


def access_obj(obj, *permissions):
    return (
        (
            obj._meta.app_label,
            obj._meta.module_name,
            obj.pk,
        ),
        permissions,
    )


def access_model(model, *permissions):
    return (
        (
            model._meta.app_label,
            model._meta.module_name,
        ),
        permissions,
    )


def access_app(app_label, *permissions):
    return (
        (
            app_label,
        ),
        permissions,
    )


def access_all(*permissions):
    return (
        (),
        permissions,
    )


def _is_sub_scope(scope, parent_scope):
    return not any (
        frozenset(permissions_grant).difference(chain.from_iterable(
            parent_permissions_grant
            for parent_model_grant, parent_permissions_grant
            in izip(*((iter(parent_scope),) * 2))
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
        in izip(*((iter(scope),) * 2))
        if permissions_grant
    )