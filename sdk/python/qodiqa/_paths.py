"""URL path-segment encoding for resource identifiers.

Every identifier interpolated into a request path is percent-encoded as ONE path segment — the same semantics as the
JavaScript SDK's ``encodeURIComponent`` — so an id containing ``/``, ``?``, ``#`` or ``%`` can never address a
different route.
"""

from __future__ import annotations

from urllib.parse import quote


def seg(value: object) -> str:
    """Percent-encode ``value`` as a single URL path segment (no safe characters)."""
    return quote(str(value), safe="")
