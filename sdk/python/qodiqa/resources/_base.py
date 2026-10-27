"""Base resource class shared by all QODIQA resources."""

from __future__ import annotations

from typing import Any, Dict, Optional, Union

from .._http import AsyncHttpClient, HttpClient
from ..auth import AuthProvider
from ..models import PaginationParams



def _pagination_query(params: Optional[PaginationParams]) -> Dict[str, Any]:
    """Map PaginationParams to the server's query parameters.

    the README and every example pass ``pageSize`` / ``sortOrder`` (the server's own names), but only the
    snake_case spellings ``page_size`` / ``sort_order`` were read, so ``{"page": 1, "pageSize": 5}`` silently became ``{"page": 1}``.
    Both spellings are accepted now (the snake_case one wins when both are given).
    """
    if not params:
        return {}
    p: Dict[str, Any] = dict(params)
    result: Dict[str, Any] = {}
    if p.get("page") is not None:
        result["page"] = p["page"]
    page_size = p.get("page_size") if p.get("page_size") is not None else p.get("pageSize")
    if page_size is not None:
        result["pageSize"] = page_size
    sort_order = p.get("sort_order") if p.get("sort_order") is not None else p.get("sortOrder")
    if sort_order is not None:
        result["sortOrder"] = sort_order
    return result


class BaseResource:
    """Synchronous base resource."""

    def __init__(self, http: HttpClient, auth: AuthProvider) -> None:
        self._http = http
        self._auth = auth

    def _pagination_params(
        self, params: Optional[PaginationParams]
    ) -> Dict[str, Any]:
        return _pagination_query(params)


class AsyncBaseResource:
    """Asynchronous base resource."""

    def __init__(self, http: AsyncHttpClient, auth: AuthProvider) -> None:
        self._http = http
        self._auth = auth

    def _pagination_params(
        self, params: Optional[PaginationParams]
    ) -> Dict[str, Any]:
        return _pagination_query(params)
