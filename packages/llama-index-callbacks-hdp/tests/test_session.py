"""Tests for ContextVar session state — isolation across concurrent async tasks."""

from __future__ import annotations

import asyncio
import pytest
from llama_index.callbacks.hdp.session import clear_token, get_token, set_token


class TestSessionBasics:
    def test_get_token_returns_none_by_default(self):
        clear_token()
        assert get_token() is None

    def test_set_and_get_token(self):
        token = {"hdp": "0.1", "header": {"token_id": "abc"}}
        set_token(token)
        assert get_token() is token
        clear_token()

    def test_clear_token(self):
        set_token({"hdp": "0.1"})
        clear_token()
        assert get_token() is None

    def test_set_overwrites_previous(self):
        set_token({"id": "first"})
        set_token({"id": "second"})
        assert get_token()["id"] == "second"
        clear_token()


class TestContextVarIsolation:
    @pytest.mark.asyncio
    async def test_tasks_do_not_share_token(self):
        """Each asyncio task should have its own ContextVar copy."""
        results = {}

        async def task_a():
            clear_token()
            set_token({"task": "a"})
            await asyncio.sleep(0.01)
            results["a"] = get_token()

        async def task_b():
            clear_token()
            set_token({"task": "b"})
            await asyncio.sleep(0.01)
            results["b"] = get_token()

        await asyncio.gather(task_a(), task_b())
        assert results["a"]["task"] == "a"
        assert results["b"]["task"] == "b"

    @pytest.mark.asyncio
    async def test_child_task_inherits_parent_but_is_isolated(self):
        """Child tasks inherit the parent's ContextVar at creation time but modifications
        in the child do not affect the parent."""
        clear_token()
        set_token({"owner": "parent"})

        child_saw: dict = {}

        async def child():
            child_saw["initial"] = get_token()
            set_token({"owner": "child"})
            child_saw["after_set"] = get_token()

        await asyncio.create_task(child())
        # Parent's token must be unchanged
        assert get_token()["owner"] == "parent"
        assert child_saw["initial"]["owner"] == "parent"
        assert child_saw["after_set"]["owner"] == "child"
        clear_token()
