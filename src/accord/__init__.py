"""Accord version 1 reference implementation: wire messages and transcript checker."""

from typing import Any

__all__ = ["check"]


def check(transcript: Any) -> dict[str, Any]:
    """Return the Accord result for one transcript. See accord.checker.check."""
    from .checker import check as _check

    return _check(transcript)
