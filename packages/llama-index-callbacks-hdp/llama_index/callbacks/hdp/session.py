"""Shared ContextVar session state for the HDP LlamaIndex integration.

All three layers (instrumentation handler, legacy callback handler, node
postprocessor) share a single ContextVar to hold the active HDP token for
the duration of a query. ContextVar is asyncio-safe: each task gets its own
copy, preventing cross-request token leakage.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Optional

_hdp_token: ContextVar[Optional[dict]] = ContextVar("_hdp_token", default=None)


def get_token() -> Optional[dict]:
    """Return the active HDP token dict, or None if no query is in progress."""
    return _hdp_token.get()


def set_token(token: dict) -> None:
    """Store a token dict as the active HDP token for the current context."""
    _hdp_token.set(token)


def clear_token() -> None:
    """Clear the active HDP token."""
    _hdp_token.set(None)
