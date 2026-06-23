"""Chrome macOS cookie encryption and decryption (the ``v10`` scheme).

key   = PBKDF2-HMAC-SHA1(safe_storage_password, b"saltysalt", 1003, dklen=16)
value = AES-128-CBC(key, iv=16x 0x20) over the ciphertext, PKCS7-(un)padded, with a
        32-byte SHA256(host_key) domain-hash prefix Chrome v24+ prepends — verified on
        decrypt (a hash mismatch is a wrong key, not garbage), and committed on encrypt
        against the exact stored ``host_key`` (leading dot included).

``v20`` (app-bound) values cannot be (de)crypted with the Safe Storage key and are rejected.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cookiesync.cookie.models import AesKey, HostKey, SafeStorageKey

SALT = b"saltysalt"
ITERATIONS = 1003
KEY_LENGTH = 16
IV = b"\x20" * 16


class DecryptError(Exception):
    """A cookie value could not be decrypted (v20, malformed, or wrong key)."""


def derive_key(password: SafeStorageKey) -> AesKey:
    """Derive the 16-byte AES key from the raw 'Safe Storage' password."""
    return AesKey(hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), SALT, ITERATIONS, dklen=KEY_LENGTH))


def pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - len(data) % 16
    return data + bytes([pad]) * pad


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise DecryptError("empty plaintext")
    pad = data[-1]
    if pad < 1 or pad > 16 or pad > len(data):
        raise DecryptError(f"bad PKCS7 padding length {pad}")
    if data[-pad:] != bytes([pad]) * pad:
        raise DecryptError("inconsistent PKCS7 padding")
    return data[:-pad]


def domain_hash(host_key: HostKey) -> bytes:
    return hashlib.sha256(host_key.encode("utf-8")).digest()


def decrypt_value(encrypted: bytes, key: AesKey, host_key: HostKey) -> str:
    """Decrypt one Chrome cookie ``encrypted_value``. Raise ``DecryptError`` on failure."""
    if not encrypted:
        return ""
    match encrypted[:3]:
        case b"v20":
            raise DecryptError("v20 app-bound cookie (not decryptable with the Safe Storage key)")
        case b"v10":
            ciphertext = encrypted[3:]
        case _:
            try:
                return encrypted.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise DecryptError("unrecognized cookie encoding") from exc
    if not ciphertext or len(ciphertext) % 16 != 0:
        raise DecryptError("ciphertext is not a positive multiple of the block size")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(IV)).decryptor()
    plain = pkcs7_unpad(decryptor.update(ciphertext) + decryptor.finalize())
    if len(plain) < 32 or plain[:32] not in {domain_hash(host_key), domain_hash(HostKey(host_key.lstrip(".")))}:
        raise DecryptError("domain-hash prefix mismatch (wrong key)")
    try:
        return plain[32:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptError("decrypted value is not valid UTF-8 (likely wrong key)") from exc


def encrypt_value(plaintext: str, key: AesKey, host_key: HostKey) -> bytes:
    """Encrypt one cookie value into Chrome's ``v10`` blob, committing to the exact ``host_key``."""
    encryptor = Cipher(algorithms.AES(key), modes.CBC(IV)).encryptor()
    block = pkcs7_pad(domain_hash(host_key) + plaintext.encode("utf-8"))
    return b"v10" + encryptor.update(block) + encryptor.finalize()
