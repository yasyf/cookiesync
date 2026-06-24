#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography"]
# ///
"""Parity oracle for the Go cookie pipeline.

This embeds the recovered cookiesync Python crypto (crypto.py) and the
extract live-filter / decrypt logic (pipeline.py: _decrypt_row, _is_live, extract)
VERBATIM, so the Go test can prove its Extract produces the byte-identical decrypted,
host-filtered, live-filtered cookie set against the very same SQLite store.

Usage:
    uv run pipeline_oracle.py <cookies.db> <url> <now_unix> <include_expired:0|1>

It reads every row of the store, host-filters with the same domain-match the Go
`Applies` uses, decrypts with the fixed key derive_key("peanuts"), drops v20 and
otherwise-undecryptable rows, live-filters against now, and prints the resulting
cookies as a JSON array (sorted for a stable deep-diff).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---- crypto.py (verbatim) -------------------------------------------------
SALT = b"saltysalt"
ITERATIONS = 1003
KEY_LENGTH = 16
IV = b"\x20" * 16
WINDOWS_EPOCH_OFFSET = 11644473600


class DecryptError(Exception):
    pass


def derive_key(password: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), SALT, ITERATIONS, dklen=KEY_LENGTH)


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise DecryptError("empty plaintext")
    pad = data[-1]
    if pad < 1 or pad > 16 or pad > len(data):
        raise DecryptError(f"bad PKCS7 padding length {pad}")
    if data[-pad:] != bytes([pad]) * pad:
        raise DecryptError("inconsistent PKCS7 padding")
    return data[:-pad]


def domain_hash(host_key: str) -> bytes:
    return hashlib.sha256(host_key.encode("utf-8")).digest()


def decrypt_value(encrypted: bytes, key: bytes, host_key: str) -> str:
    if not encrypted:
        return ""
    head = encrypted[:3]
    if head == b"v20":
        raise DecryptError("v20 app-bound cookie (not decryptable with the Safe Storage key)")
    if head == b"v10":
        ciphertext = encrypted[3:]
    else:
        try:
            return encrypted.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecryptError("unrecognized cookie encoding") from exc
    if not ciphertext or len(ciphertext) % 16 != 0:
        raise DecryptError("ciphertext is not a positive multiple of the block size")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(IV)).decryptor()
    plain = pkcs7_unpad(decryptor.update(ciphertext) + decryptor.finalize())
    if len(plain) < 32 or plain[:32] not in {domain_hash(host_key), domain_hash(host_key.lstrip("."))}:
        raise DecryptError("domain-hash prefix mismatch (wrong key)")
    try:
        return plain[32:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptError("decrypted value is not valid UTF-8 (likely wrong key)") from exc


# ---- models.py chrome_micros_to_unix (verbatim semantics) ------------------
def chrome_micros_to_unix(micros: int) -> float:
    if micros <= 0:
        return -1
    return micros / 1_000_000 - WINDOWS_EPOCH_OFFSET


# ---- domains.py cookie_applies (verbatim) ----------------------------------
def normalize_host(url: str) -> str:
    v = url.strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]
    v = v.split("?", 1)[0]
    if "@" in v:
        v = v.split("@", 1)[1]
    v = v.split(":", 1)[0]
    return v.strip(".")


def cookie_applies(host_key: str, host: str) -> bool:
    hk = host_key.lower()
    rh = host.lower()
    if hk.startswith("."):
        return rh == hk[1:] or rh.endswith(hk)
    return rh == hk


# ---- pipeline.py _is_live (verbatim) ---------------------------------------
def is_live(expires_utc: int, *, now: float, include_expired: bool) -> bool:
    expires = chrome_micros_to_unix(expires_utc)
    return include_expired or expires == -1 or expires >= now


def table_columns(db: sqlite3.Connection) -> list[str]:
    return [row[1] for row in db.execute("PRAGMA table_info(cookies)").fetchall()]


def main() -> None:
    db_path, url, now_s, include_s = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4] == "1"
    key = derive_key("peanuts")
    host = normalize_host(url)
    db = sqlite3.connect(db_path)
    cols = table_columns(db)
    rows = db.execute(f"SELECT {', '.join(cols)} FROM cookies").fetchall()
    out = []
    for values in rows:
        cell = dict(zip(cols, values, strict=True))
        host_key = cell["host_key"]
        if not cookie_applies(host_key, host):
            continue
        ev = cell.get("encrypted_value") or b""
        if isinstance(ev, str):
            ev = ev.encode("utf-8")
        try:
            value = decrypt_value(bytes(ev), key, host_key)
        except DecryptError:
            continue
        if not is_live(int(cell["expires_utc"]), now=now_s, include_expired=include_s):
            continue
        out.append(
            {
                "host_key": host_key,
                "name": cell["name"],
                "value": value,
                "path": cell["path"],
                "expires_utc": int(cell["expires_utc"]),
                "last_update_utc": int(cell.get("last_update_utc", 0) or 0),
            }
        )
    out.sort(key=lambda c: (c["host_key"], c["name"], c["path"], c["last_update_utc"]))
    print(json.dumps(out))


if __name__ == "__main__":
    main()
