from __future__ import annotations

from pathlib import Path

import pytest

from cookiesync.cookie.browsers import APPLICATION_SUPPORT, REGISTRY, BrowserName


def test_chrome_registry_entry() -> None:
    chrome = REGISTRY[BrowserName("chrome")]
    assert chrome.display == "Chrome"
    assert chrome.data_root == APPLICATION_SUPPORT / "Google" / "Chrome"
    assert chrome.keychain_service == "Chrome Safe Storage"


def test_arc_registry_entry_uses_user_data_subdir() -> None:
    arc = REGISTRY[BrowserName("arc")]
    assert arc.display == "Arc"
    assert arc.data_root == APPLICATION_SUPPORT / "Arc" / "User Data"
    assert arc.data_root.name == "User Data"
    assert arc.keychain_service == "Arc Safe Storage"


def test_chrome_profile_paths() -> None:
    chrome = REGISTRY[BrowserName("chrome")]
    root = APPLICATION_SUPPORT / "Google" / "Chrome"
    assert chrome.profile_dir("Profile 3") == root / "Profile 3"
    assert chrome.cookies_db("Profile 3") == root / "Profile 3" / "Cookies"
    assert chrome.local_state() == root / "Local State"


def test_application_support_is_under_home() -> None:
    assert APPLICATION_SUPPORT == Path.home() / "Library" / "Application Support"


def test_missing_browser_raises_keyerror() -> None:
    with pytest.raises(KeyError):
        REGISTRY[BrowserName("firefox")]
