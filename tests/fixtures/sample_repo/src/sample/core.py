"""Core computation logic for the sample package."""

import os
import sys


def compute(value: int) -> int:
    """Return value doubled."""
    return value * 2


def get_platform() -> str:
    """Return the current platform string."""
    return sys.platform


def get_env_var(name: str) -> str | None:
    """Return an environment variable value, or None if absent."""
    return os.environ.get(name)
