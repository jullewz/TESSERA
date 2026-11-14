"""Operating-system detection and per-platform default locations.

Tessera supports three platform families:

* ``linux``   - any Linux distribution (also used for other POSIX systems)
* ``macos``   - Apple macOS
* ``windows`` - Windows 10 and later
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from typing import Literal

PlatformName = Literal["linux", "macos", "windows"]


def current_platform() -> PlatformName:
    """Return the platform family Tessera is running on."""
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


IS_WINDOWS = current_platform() == "windows"


def default_case_sensitive(platform: PlatformName | None = None) -> bool:
    """Filesystems on Windows and macOS are case-insensitive by default."""
    return (platform or current_platform()) == "linux"


def config_dir(platform: PlatformName | None = None) -> Path:
    """Directory holding ``tessera.toml`` and the sealing key."""
    plat = platform or current_platform()
    home = Path.home()
    if plat == "windows":
        base = os.environ.get("APPDATA")
        return Path(base) / "tessera" if base else home / "AppData" / "Roaming" / "tessera"
    if plat == "macos":
        return home / "Library" / "Application Support" / "tessera"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return (Path(xdg) if xdg else home / ".config") / "tessera"


def data_dir(platform: PlatformName | None = None) -> Path:
    """Directory holding the baseline database."""
    plat = platform or current_platform()
    home = Path.home()
    if plat == "windows":
        base = os.environ.get("LOCALAPPDATA")
        return Path(base) / "tessera" if base else home / "AppData" / "Local" / "tessera"
    if plat == "macos":
        return home / "Library" / "Application Support" / "tessera"
    xdg = os.environ.get("XDG_DATA_HOME")
    return (Path(xdg) if xdg else home / ".local" / "share") / "tessera"


def hostname() -> str:
    """Best-effort host name, used to label baselines."""
    try:
        return socket.gethostname() or "unknown"
    except OSError:
        return "unknown"


def enable_windows_vt_mode() -> bool:
    """Turn on ANSI escape processing in the Windows 10+ console.

    Returns ``True`` when the console accepts ANSI sequences. On other
    platforms this is a no-op that returns ``True``.
    """
    if not IS_WINDOWS:
        return True
    try:
        import ctypes  # noqa: PLC0415 (Windows only)
        from ctypes import wintypes  # noqa: PLC0415

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        std_output_handle = -11
        enable_vt = 0x0004
        handle = kernel32.GetStdHandle(std_output_handle)
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        if mode.value & enable_vt:
            return True
        return bool(kernel32.SetConsoleMode(handle, mode.value | enable_vt))
    except (OSError, AttributeError, ImportError):
        return False
