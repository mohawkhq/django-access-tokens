from itertools import chain, izip_longest


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