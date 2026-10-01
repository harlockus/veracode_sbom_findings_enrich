from sbom_findings.client import encode_query, extract_collection, next_href, same_host_path
from sbom_findings.config import Settings
from sbom_findings.client import VeracodeClient


def test_query_uses_percent_encoding_and_lowercase_booleans():
    encoded = encode_query({"filter[workspace]": "vera demo", "linked": True, "page": 0})
    assert encoded == "filter%5Bworkspace%5D=vera%20demo&linked=true&page=0"


def test_extract_collection_accepts_hal_object_and_list():
    assert extract_collection({"_embedded": {"findings": [{"id": 1}]}}, ("findings",)) == [{"id": 1}]
    assert extract_collection({"_embedded": [{"id": 2}]}, ("findings",)) == [{"id": 2}]
    assert extract_collection({"issues": [{"id": 3}]}, ("issues",)) == [{"id": 3}]


def test_next_href_accepts_map_and_rel_list():
    assert next_href({"_links": {"next": {"href": "/next"}}}) == "/next"
    assert next_href({"_links": [{"rel": "next", "href": "/again"}]}) == "/again"
    assert next_href({"_link": {"next": {"href": "/singular"}}}) == "/singular"


def test_same_host_path_rejects_other_hosts():
    assert same_host_path("https://api.veracode.com/srcclr/v3/workspaces?page=1", "api.veracode.com").endswith(
        "page=1"
    )
    try:
        same_host_path("https://example.com/srcclr", "api.veracode.com")
    except Exception as exc:
        assert "host" in str(exc).lower()
    else:
        raise AssertionError("expected host rejection")


def test_paginate_follows_page_numbers_when_next_is_absent():
    settings = Settings("aa", "bb", "api.veracode.com", "us", "test", "", "")
    client = VeracodeClient(settings, sender=lambda *args: (_ for _ in ()).throw(AssertionError("network")))
    pages = {
        0: {"_embedded": {"issues": [{"id": "a"}]}, "page": {"number": 0, "total_pages": 2}},
        1: {"_embedded": {"issues": [{"id": "b"}]}, "page": {"number": 1, "total_pages": 2}},
    }

    def get_json(path, query=None):
        return pages[int((query or {}).get("page", 0))]

    client.get_json = get_json
    rows = client.paginate("/srcclr/v3/workspaces/ws/issues", {"page": 0, "size": 1}, keys=("issues",))
    assert [row["id"] for row in rows] == ["a", "b"]
