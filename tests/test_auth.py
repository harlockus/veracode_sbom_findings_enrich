from sbom_findings.auth import authorization_header, credential_hex


def test_credential_hex_uses_the_trailing_segment():
    value = "vera01-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee-" + "ab" * 32
    assert credential_hex(value) == "ab" * 32


def test_authorization_header_matches_the_pinned_hmac_vector():
    header = authorization_header(
        "vera01-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee-" + "0123456789abcdef" * 4,
        "vera01-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee-" + "fedcba9876543210" * 4,
        "API.veracode.com",
        "/appsec/v1/applications?page=0",
        "get",
        nonce_bytes=bytes.fromhex("00112233445566778899aabbccddeeff"),
        timestamp_ms=1700000000000,
    )
    assert header == (
        "VERACODE-HMAC-SHA-256 "
        "id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,"
        "ts=1700000000000,"
        "nonce=00112233445566778899aabbccddeeff,"
        "sig=ca4754fd7f09f4794a1171ae315d4ecfa1ce8e712ac080752746786dc47b374d"
    )
