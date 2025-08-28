from security import validate_target_url


def test_reject_file_scheme():
    ok, msg = validate_target_url("file:///etc/passwd")
    assert not ok


def test_missing_host():
    ok, msg = validate_target_url("http://")
    assert not ok


def test_normalize_http():
    ok, url = validate_target_url("example.com")
    assert ok and url.startswith("http://")
