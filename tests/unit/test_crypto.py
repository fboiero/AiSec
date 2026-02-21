"""Tests for crypto utilities."""

from aisec.utils.crypto import detect_pii, detect_secrets, sha256_hash


def test_detect_secrets_aws_key():
    text = "my key is AKIAIOSFODNN7EXAMPLE and that's it"
    results = detect_secrets(text)
    assert any(r["type"] == "aws_access_key" for r in results)


def test_detect_secrets_github_token():
    text = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"
    results = detect_secrets(text)
    assert any(r["type"] == "github_token" for r in results)


def test_detect_secrets_openai_key():
    text = "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456"
    results = detect_secrets(text)
    assert any(r["type"] == "openai_key" for r in results)


def test_detect_secrets_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nfoo\n-----END RSA PRIVATE KEY-----"
    results = detect_secrets(text)
    assert any(r["type"] == "private_key" for r in results)


def test_detect_secrets_no_secrets():
    text = "This is a normal text with no secrets."
    results = detect_secrets(text)
    assert results == []


def test_detect_pii_email():
    text = "Contact us at user@example.com for more info."
    results = detect_pii(text)
    assert any(r["type"] == "email" for r in results)


def test_detect_pii_ssn():
    text = "SSN: 123-45-6789"
    results = detect_pii(text)
    assert any(r["type"] == "ssn_us" for r in results)


def test_detect_pii_credit_card():
    text = "Card: 4111111111111111"
    results = detect_pii(text)
    assert any(r["type"] == "credit_card" for r in results)


def test_detect_pii_dni_argentina():
    text = "DNI: 30.123.456"
    results = detect_pii(text)
    assert any(r["type"] == "dni_argentina" for r in results)


def test_detect_pii_no_pii():
    text = "Just some regular text without PII."
    results = detect_pii(text)
    # May detect false positives on short numbers, filter email/ssn specifically
    emails = [r for r in results if r["type"] == "email"]
    ssns = [r for r in results if r["type"] == "ssn_us"]
    assert emails == []
    assert ssns == []


def test_sha256_hash_string():
    result = sha256_hash("hello")
    assert len(result) == 64
    assert result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_sha256_hash_bytes():
    result = sha256_hash(b"hello")
    assert result == sha256_hash("hello")
