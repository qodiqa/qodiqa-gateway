"""the README spelling ``pageSize`` / ``sortOrder`` must reach the server (it used to be dropped)."""

from qodiqa.resources._base import _pagination_query


def test_camel_case_spellings_are_forwarded():
    assert _pagination_query({"page": 1, "pageSize": 5, "sortOrder": "desc"}) == {"page": 1, "pageSize": 5, "sortOrder": "desc"}


def test_snake_case_spellings_still_work():
    assert _pagination_query({"page": 2, "page_size": 10, "sort_order": "asc"}) == {"page": 2, "pageSize": 10, "sortOrder": "asc"}


def test_snake_case_wins_when_both_given():
    assert _pagination_query({"page_size": 7, "pageSize": 99}) == {"pageSize": 7}


def test_empty_and_none():
    assert _pagination_query(None) == {}
    assert _pagination_query({}) == {}
