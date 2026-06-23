"""The browser registry: where each supported browser keeps its cookie store and Safe Storage key.

A ``Browser`` resolves a profile's on-disk paths (cookie DB, Local State) and names
the Keychain service holding its Safe Storage password.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import NewType

BrowserName = NewType("BrowserName", str)

APPLICATION_SUPPORT = Path.home() / "Library" / "Application Support"


@dataclass(frozen=True, slots=True)
class Browser:
    """A Chromium-family browser and its on-disk layout.

    Example:
        >>> REGISTRY["chrome"].cookies_db("Default")
    """

    name: BrowserName
    display: str
    data_root: Path
    keychain_service: str

    def profile_dir(self, profile: str) -> Path:
        """The directory holding one profile's state under this browser's data root."""
        return self.data_root / profile

    def cookies_db(self, profile: str) -> Path:
        """The SQLite cookie store for one profile."""
        return self.profile_dir(profile) / "Cookies"

    def local_state(self) -> Path:
        """The ``Local State`` JSON file at this browser's data root."""
        return self.data_root / "Local State"


REGISTRY: dict[BrowserName, Browser] = {
    BrowserName("chrome"): Browser(
        name=BrowserName("chrome"),
        display="Chrome",
        data_root=APPLICATION_SUPPORT / "Google" / "Chrome",
        keychain_service="Chrome Safe Storage",
    ),
    BrowserName("arc"): Browser(
        name=BrowserName("arc"),
        display="Arc",
        data_root=APPLICATION_SUPPORT / "Arc" / "User Data",
        keychain_service="Arc Safe Storage",
    ),
}
