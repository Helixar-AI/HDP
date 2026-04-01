"""LangGraph node wrapper for HDP.

Wraps LangGraph state-graph node functions so each node execution is
recorded as a delegation hop in the HDP chain.

LangGraph nodes are plain Python functions — they do not participate in
LangChain's callback system. This module provides a lightweight wrapper
that calls ``middleware._extend_chain()`` before each node runs.

Usage::

    from hdp_langchain.graph import hdp_node

    # As a decorator (recommended)
    @hdp_node(middleware, agent_id="researcher")
    def researcher_node(state):
        ...
        return state

    # As a wrapper around an existing function
    wrapped_node = hdp_node(middleware)(existing_node_fn)

    # In a StateGraph
    graph = StateGraph(MyState)
    graph.add_node("researcher", hdp_node(middleware)(researcher_node))

Note: ``langgraph`` is an optional dependency. This module does not import
it at the top level — only your node functions need to be compatible with
LangGraph's ``(state) -> state`` contract.
"""

from __future__ import annotations

import functools
import logging
from typing import TYPE_CHECKING, Any, Callable, Optional, TypeVar

if TYPE_CHECKING:
    from .middleware import HdpMiddleware

logger = logging.getLogger(__name__)

_State = TypeVar("_State")


def hdp_node(
    middleware: "HdpMiddleware",
    node_fn: Optional[Callable] = None,
    *,
    agent_id: Optional[str] = None,
) -> Any:
    """Wrap a LangGraph node function to record a delegation hop per invocation.

    Can be used as a decorator or as a plain wrapper::

        # Decorator with explicit agent_id
        @hdp_node(middleware, agent_id="researcher")
        def researcher_node(state):
            ...

        # Decorator using function name as agent_id
        @hdp_node(middleware)
        def reviewer_node(state):
            ...

        # Wrapper
        wrapped = hdp_node(middleware, my_fn, agent_id="my-agent")

    Args:
        middleware: An ``HdpMiddleware`` instance that owns the delegation chain.
        node_fn:    Optional node function to wrap immediately (skips decorator syntax).
        agent_id:   Label recorded in the hop. Defaults to ``node_fn.__name__``.

    Returns:
        A wrapped function when ``node_fn`` is provided, or a decorator otherwise.
    """
    def decorator(fn: Callable) -> Callable:
        name = agent_id or fn.__name__

        @functools.wraps(fn)
        def wrapper(state: Any, *args: Any, **kwargs: Any) -> Any:
            if middleware._token is None:
                middleware.before_kickoff()
            try:
                middleware._extend_chain(
                    agent_id=name,
                    action_summary=f"LangGraph node '{name}' executed",
                    agent_type="sub-agent",
                )
            except Exception as exc:
                logger.warning("HDP hdp_node failed (non-blocking): %s", exc)
            return fn(state, *args, **kwargs)

        return wrapper

    if node_fn is not None:
        return decorator(node_fn)
    return decorator
