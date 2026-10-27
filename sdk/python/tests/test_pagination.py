"""Tests for pagination helpers."""

from __future__ import annotations

import pytest

from qodiqa._pagination import AsyncPageIterator, AsyncPagePage, PageIterator, PagePage


def make_fetcher(pages):
    """Return a sync fetcher that serves from a list of pages."""
    calls = []

    def fetcher(page: int, page_size: int):
        calls.append((page, page_size))
        return pages[page - 1]

    fetcher.calls = calls
    return fetcher


async def make_async_fetcher(pages):
    """Return an async fetcher wrapped in a coroutine factory."""
    calls = []

    async def fetcher(page: int, page_size: int):
        calls.append((page, page_size))
        return pages[page - 1]

    fetcher.calls = calls
    return fetcher


class TestPagePage:
    def test_yields_single_page_when_no_more(self) -> None:
        page1 = {"entries": [{"id": "a"}, {"id": "b"}], "hasNextPage": False}
        fetcher = make_fetcher([page1])
        pages = list(PagePage(fetcher))
        assert len(pages) == 1
        assert pages[0] is page1

    def test_yields_multiple_pages(self) -> None:
        page1 = {"entries": [{"id": "a"}], "hasNextPage": True}
        page2 = {"entries": [{"id": "b"}], "hasNextPage": False}
        fetcher = make_fetcher([page1, page2])
        pages = list(PagePage(fetcher))
        assert len(pages) == 2

    def test_respects_start_page(self) -> None:
        page2 = {"entries": [{"id": "c"}], "hasNextPage": False}
        calls = []

        def fetcher(p, s):
            calls.append(p)
            return page2

        list(PagePage(fetcher, start_page=2))
        assert calls[0] == 2

    def test_forwards_page_size(self) -> None:
        page1 = {"entries": [], "hasNextPage": False}
        calls = []

        def fetcher(p, s):
            calls.append(s)
            return page1

        list(PagePage(fetcher, page_size=25))
        assert calls[0] == 25

    def test_empty_records_page_stops(self) -> None:
        page1 = {"entries": [], "hasNextPage": False}
        fetcher = make_fetcher([page1])
        pages = list(PagePage(fetcher))
        assert len(pages) == 1


class TestPageIterator:
    def test_yields_all_items_across_pages(self) -> None:
        page1 = {"entries": [{"id": "a"}, {"id": "b"}], "hasNextPage": True}
        page2 = {"entries": [{"id": "c"}], "hasNextPage": False}
        fetcher = make_fetcher([page1, page2])
        items = list(PageIterator(fetcher))
        assert len(items) == 3
        assert items[0]["id"] == "a"
        assert items[2]["id"] == "c"

    def test_empty_result(self) -> None:
        page1 = {"entries": [], "hasNextPage": False}
        fetcher = make_fetcher([page1])
        items = list(PageIterator(fetcher))
        assert items == []

    def test_single_page(self) -> None:
        page1 = {"entries": [{"id": "x"}], "hasNextPage": False}
        fetcher = make_fetcher([page1])
        items = list(PageIterator(fetcher))
        assert len(items) == 1

    def test_default_page_size_is_50(self) -> None:
        page1 = {"entries": [], "hasNextPage": False}
        calls = []

        def fetcher(p, s):
            calls.append(s)
            return page1

        list(PageIterator(fetcher))
        assert calls[0] == 50


class TestAsyncPagePage:
    async def test_yields_single_page(self) -> None:
        page1 = {"entries": [{"id": "a"}], "hasNextPage": False}
        fetcher = await make_async_fetcher([page1])
        pages = [p async for p in AsyncPagePage(fetcher)]
        assert len(pages) == 1
        assert pages[0] is page1

    async def test_yields_multiple_pages(self) -> None:
        page1 = {"entries": [{"id": "a"}], "hasNextPage": True}
        page2 = {"entries": [{"id": "b"}], "hasNextPage": False}
        fetcher = await make_async_fetcher([page1, page2])
        pages = [p async for p in AsyncPagePage(fetcher)]
        assert len(pages) == 2

    async def test_respects_page_size(self) -> None:
        captured = []

        async def fetcher(p, s):
            captured.append(s)
            return {"entries": [], "hasNextPage": False}

        [p async for p in AsyncPagePage(fetcher, page_size=10)]
        assert captured[0] == 10


class TestAsyncPageIterator:
    async def test_yields_all_items(self) -> None:
        page1 = {"entries": [{"id": "a"}, {"id": "b"}], "hasNextPage": True}
        page2 = {"entries": [{"id": "c"}], "hasNextPage": False}
        fetcher = await make_async_fetcher([page1, page2])
        items = [i async for i in AsyncPageIterator(fetcher)]
        assert len(items) == 3

    async def test_empty_result(self) -> None:
        async def fetcher(p, s):
            return {"entries": [], "hasNextPage": False}

        items = [i async for i in AsyncPageIterator(fetcher)]
        assert items == []
