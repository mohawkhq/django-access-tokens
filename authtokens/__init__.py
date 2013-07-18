"""
A Django app for for generating secure scoped access tokens.

Developed by Mohawk.

<http://www.mohawkhq.com/>


Contributors
------------

- Dave Hall <http://blog.etianen.com/>
"""


__version__ = (1, 0, 3)


from authtokens.scopes import access_obj, access_model, access_app, access_app, access_all
from authtokens.tokens import generate, validate