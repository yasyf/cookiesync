from __future__ import annotations

import pytest

from cookiesync.cookie.crypto import (
    DecryptError,
    decrypt_value,
    derive_key,
    encrypt_value,
    pkcs7_pad,
    pkcs7_unpad,
)
from cookiesync.cookie.models import AesKey, HostKey, SafeStorageKey

KEY = derive_key(SafeStorageKey("peanuts"))
OTHER_KEY = derive_key(SafeStorageKey("almonds"))

# A deterministic golden vector for the v10 scheme: derive_key("peanuts") over
# value "hello-session-token" at host_key ".example.com". Locking the exact bytes
# pins the PBKDF2 params, the fixed IV, the domain-hash prefix, and PKCS7 padding.
GOLDEN_KEY_HEX = "d9a09d499b4e1b7461f28e67972c6dbd"
GOLDEN_HOST = HostKey(".example.com")
GOLDEN_VALUE = "hello-session-token"
GOLDEN_BLOB = bytes.fromhex(
    "763130bfd1db3abcef87f1fa5a40b21d11eaaa9a030da41e8699c59583ed42e9"
    "4a5d1c649d73f94aeb15d5dcd9947b962e805181247a0bdd90291dd8ced1eb01e89451"
)


def test_derive_key_is_deterministic_16_bytes() -> None:
    assert KEY == bytes.fromhex(GOLDEN_KEY_HEX)
    assert len(KEY) == 16


def test_golden_vector_decrypts() -> None:
    assert GOLDEN_BLOB[:3] == b"v10"
    assert decrypt_value(GOLDEN_BLOB, KEY, GOLDEN_HOST) == GOLDEN_VALUE


def test_golden_vector_encrypts_to_exact_bytes() -> None:
    assert encrypt_value(GOLDEN_VALUE, KEY, GOLDEN_HOST) == GOLDEN_BLOB


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("plain-ascii-token", id="ascii"),
        pytest.param("café—naïve—日本語—😀", id="utf8-multibyte"),
        pytest.param("", id="empty"),
        pytest.param("x" * 16, id="16-byte-boundary"),
        pytest.param("y" * 15, id="15-byte"),
        pytest.param("z" * 17, id="17-byte"),
        pytest.param("a=1; b=2; long-" + "v" * 4096, id="long"),
    ],
)
@pytest.mark.parametrize(
    "host_key",
    [
        pytest.param(HostKey(".example.com"), id="dot-host"),
        pytest.param(HostKey("example.com"), id="bare-host"),
    ],
)
def test_roundtrip(value: str, host_key: HostKey) -> None:
    assert decrypt_value(encrypt_value(value, KEY, host_key), KEY, host_key) == value


def test_empty_blob_decrypts_to_empty_string() -> None:
    assert decrypt_value(b"", KEY, GOLDEN_HOST) == ""


def test_v20_is_rejected() -> None:
    with pytest.raises(DecryptError, match="v20"):
        decrypt_value(b"v20" + b"\x00" * 32, KEY, GOLDEN_HOST)


def test_wrong_key_raises_no_silent_garbage() -> None:
    # A wrong AES key garbles the whole block: it must raise (bad padding or a
    # domain-hash mismatch), never return decoded garbage.
    blob = encrypt_value("secret", KEY, GOLDEN_HOST)
    with pytest.raises(DecryptError):
        decrypt_value(blob, OTHER_KEY, GOLDEN_HOST)


def test_wrong_host_key_raises() -> None:
    # The domain hash commits to the exact host_key, so decrypting under a
    # different host (with the right AES key) must fail on the hash check, not
    # silently strip 32 bytes and return the wrong tail.
    blob = encrypt_value("secret", KEY, GOLDEN_HOST)
    with pytest.raises(DecryptError, match="wrong key"):
        decrypt_value(blob, KEY, HostKey(".other.com"))


def test_non_block_aligned_ciphertext_raises() -> None:
    with pytest.raises(DecryptError, match="block size"):
        decrypt_value(b"v10" + b"\x00" * 17, KEY, GOLDEN_HOST)


@pytest.mark.parametrize("size", list(range(0, 33)))
def test_pkcs7_pad_unpad_inverse_over_all_remainders(size: int) -> None:
    data = b"\xab" * size
    padded = pkcs7_pad(data)
    assert len(padded) % 16 == 0
    assert len(padded) > len(data)
    assert pkcs7_unpad(padded) == data


def test_pkcs7_pad_full_block_adds_full_block() -> None:
    assert pkcs7_pad(b"\x00" * 16) == b"\x00" * 16 + bytes([16]) * 16


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\xab\x00", id="zero-pad-byte"),
        pytest.param(b"\x01\x02\x03\x05", id="pad-exceeds-length"),
        pytest.param(b"\xab\xab\x02\x03", id="inconsistent-pad"),
    ],
)
def test_pkcs7_unpad_rejects_bad_padding(bad: bytes) -> None:
    with pytest.raises(DecryptError):
        pkcs7_unpad(bad)


def test_legacy_plaintext_blob_decodes_verbatim() -> None:
    assert decrypt_value(b"legacy-plain-value", AesKey(b"\x00" * 16), GOLDEN_HOST) == "legacy-plain-value"
