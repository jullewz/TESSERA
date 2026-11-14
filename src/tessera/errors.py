"""Exception hierarchy. Every error carries the process exit code it maps to."""

from __future__ import annotations

EXIT_OK = 0
EXIT_CHANGES = 1
EXIT_USAGE = 2
EXIT_INTEGRITY = 3
EXIT_INTERNAL = 4


class TesseraError(Exception):
    """Base class for all expected, user-facing failures."""

    exit_code = EXIT_INTERNAL

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


class UsageError(TesseraError):
    """The command was invoked incorrectly or its input files are unusable."""

    exit_code = EXIT_USAGE


class ConfigError(TesseraError):
    """The configuration file is missing, malformed or invalid."""

    exit_code = EXIT_USAGE


class StoreError(TesseraError):
    """The baseline database cannot be opened, read or written."""

    exit_code = EXIT_INTERNAL


class BaselineNotFoundError(StoreError):
    """A requested baseline does not exist."""

    exit_code = EXIT_USAGE


class KeyFileError(TesseraError):
    """The sealing key is missing, unreadable or malformed."""

    exit_code = EXIT_USAGE


class IntegrityError(TesseraError):
    """A seal, Merkle root or proof failed verification."""

    exit_code = EXIT_INTEGRITY
