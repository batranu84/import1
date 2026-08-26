from shadowstrike.utils.endpoints import normalize_url, same_origin


def test_endpoint_normalization_collapses_identifiers():
    assert normalize_url("HTTPS://Example.test/api/users/123?x=1") == "https://example.test/api/users/{id}"
    assert normalize_url("https://example.test/a/550e8400-e29b-41d4-a716-446655440000") == "https://example.test/a/{uuid}"


def test_same_origin():
    assert same_origin("https://example.test", "https://example.test/a")
    assert not same_origin("https://example.test", "https://other.test/a")
