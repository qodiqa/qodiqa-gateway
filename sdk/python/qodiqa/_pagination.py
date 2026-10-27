"""QODIQA SDK pagination helpers.

Provides :class:`PageIterator` (items) and :class:`PagePage` (pages) for both
synchronous and asynchronous pagination over list endpoints.

These expect the fetcher to return the raw server pagination envelope —
``entries`` (list) and ``hasNextPage`` (bool), matching
``src/utils/pagination.js``'s shared ``withPaginationMeta()`` helper, used by
``transparency.list_entries()``. Some other list endpoints (e.g.
``webhooks.list()`` -> ``endpoints``, ``certification.list()`` ->
``certifications``) use a differently-named array under their own response —
those aren't compatible with these generic iterators without a wrapper
fetcher that renames the key.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Callable, Dict, Generic, Iterator, List, Optional, TypeVar

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Sync pagination
# ---------------------------------------------------------------------------

PageFetcher = Callable[[int, int], Any]


class PagePage(Generic[T]):
    """Iterate over pages of results.

    Yields each raw ``PaginatedResponse``-like dict one at a time.

    Args:
        fetcher: Callable ``(page, page_size) -> PaginatedResponse``.
        start_page: First page to fetch.  Default: ``1``.
        page_size: Number of records per page.  Default: ``50``.

    Example::

        pages = PagePage(
            lambda p, s: client.transparency.list_entries({"page": p, "pageSize": s})["data"],
            page_size=20,
        )
        for page in pages:
            for entry in page["entries"]:
                print(entry["id"])
    """

    def __init__(
        self,
        fetcher: PageFetcher,
        *,
        start_page: int = 1,
        page_size: int = 50,
    ) -> None:
        self._fetcher = fetcher
        self._page = start_page
        self._page_size = page_size
        self._done = False

    def __iter__(self) -> Iterator[Any]:
        return self._generate()

    def _generate(self) -> Iterator[Any]:
        page = self._page
        while True:
            result = self._fetcher(page, self._page_size)
            yield result
            if not result.get("hasNextPage", False):
                break
            page += 1


class PageIterator(Generic[T]):
    """Iterate over individual items across all pages transparently.

    Args:
        fetcher: Callable ``(page, page_size) -> PaginatedResponse``.
        start_page: First page to fetch.  Default: ``1``.
        page_size: Number of records per page.  Default: ``50``.

    Example::

        items = PageIterator(
            lambda p, s: client.transparency.list_entries({"page": p, "pageSize": s})["data"],
            page_size=50,
        )
        for entry in items:
            print(entry["id"])
    """

    def __init__(
        self,
        fetcher: PageFetcher,
        *,
        start_page: int = 1,
        page_size: int = 50,
    ) -> None:
        self._fetcher = fetcher
        self._page = start_page
        self._page_size = page_size

    def __iter__(self) -> Iterator[T]:
        return self._generate()

    def _generate(self) -> Iterator[T]:
        page = self._page
        while True:
            result = self._fetcher(page, self._page_size)
            entries: List[T] = result.get("entries", [])
            yield from entries
            if not result.get("hasNextPage", False):
                break
            page += 1


# ---------------------------------------------------------------------------
# Async pagination
# ---------------------------------------------------------------------------

AsyncPageFetcher = Callable[[int, int], Any]  # returns Awaitable


class AsyncPagePage(Generic[T]):
    """Async iterator over pages of results.

    Example::

        async for page in AsyncPagePage(fetcher, page_size=20):
            for entry in page["entries"]:
                print(entry["id"])
    """

    def __init__(
        self,
        fetcher: AsyncPageFetcher,
        *,
        start_page: int = 1,
        page_size: int = 50,
    ) -> None:
        self._fetcher = fetcher
        self._page = start_page
        self._page_size = page_size

    def __aiter__(self) -> AsyncIterator[Any]:
        return self._generate()

    async def _generate(self) -> AsyncIterator[Any]:
        page = self._page
        while True:
            result = await self._fetcher(page, self._page_size)
            yield result
            if not result.get("hasNextPage", False):
                break
            page += 1


class AsyncPageIterator(Generic[T]):
    """Async iterator over individual items across all pages.

    Example::

        async for entry in AsyncPageIterator(fetcher, page_size=50):
            print(entry["id"])
    """

    def __init__(
        self,
        fetcher: AsyncPageFetcher,
        *,
        start_page: int = 1,
        page_size: int = 50,
    ) -> None:
        self._fetcher = fetcher
        self._page = start_page
        self._page_size = page_size

    def __aiter__(self) -> AsyncIterator[T]:
        return self._generate()

    async def _generate(self) -> AsyncIterator[T]:
        page = self._page
        while True:
            result = await self._fetcher(page, self._page_size)
            entries: List[T] = result.get("entries", [])
            for item in entries:
                yield item
            if not result.get("hasNextPage", False):
                break
            page += 1
