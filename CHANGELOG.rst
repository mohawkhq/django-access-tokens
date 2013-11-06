django-access-tokens changelog
==============================


0.9.2 - 06/11/2013
------------------

**SECURITY UPDATE:** Fixing scoping of permissions where the token provides a
smaller subset of the required permissions. As an extreme case, an access token
granting no permissions could be used to access any permissions on the site.

**AFFECTED SITES:** Since a token cannot be generated without knowledge of the
secret key, attackers **cannot** access arbitrary resources using this exploit. However,
an access token that proves *some*, but not all of the required permissions for a
resource can be used to access that resource. If the access token provides additional
permissions not required by the resource, then authorization will still fail.

In essence, the security was back-to-front. Rather than tokens being required to be a
*superset* of the required permissions, tokens were, in fact, required to be a *subset*
of the required permissions.

Sites that provide access tokens for the exact set of required permissions are unaffected
by this exploit.

**RESOLUTION:** The logic for validating an access token has been updated to correctly
validate that a received access token is a *superset* of the required permissions.


0.9.1 - 01/10/2013
------------------

- Removing overly-specific protocol versioning.


0.9.0 - 14/08/2013
------------------

- First beta release.