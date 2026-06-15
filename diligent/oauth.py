"""The diligent baseline uses the same OAuth 2.1 Authorization Server as the
vulnerable one -- the difference is entirely on the resource-server side
(introspection + short TTLs), not in the token format. Re-exported here so the
package reads as self-contained."""

from vulnerable.oauth import (  # noqa: F401
    AuthorizationServer,
    TokenExpired,
    TokenInvalid,
    verify_jwt_stateless,
)
