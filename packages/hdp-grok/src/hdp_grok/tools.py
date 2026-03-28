"""HDP tool schemas for Grok / xAI API (OpenAI-compatible format)."""
from __future__ import annotations

HDP_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "hdp_issue_token",
            "description": (
                "Issue a new root HDP token when human delegation begins. "
                "Use at the start of a session or when the user authorises a new task."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of permitted action scopes",
                    },
                    "expires_in": {
                        "type": "integer",
                        "description": "Optional token lifetime in seconds (default: 3600)",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "hdp_extend_chain",
            "description": (
                "Extend the delegation chain when handing off to a sub-agent or external tool."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "delegatee_id": {
                        "type": "string",
                        "description": "Identifier of the receiving agent or tool",
                    },
                    "additional_scope": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Any extra permissions for this hop",
                    },
                },
                "required": ["delegatee_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "hdp_verify_token",
            "description": (
                "Verify an HDP token before performing sensitive actions. "
                "Returns full provenance details."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "The HDP token string to verify",
                    }
                },
                "required": ["token"],
            },
        },
    },
]


def get_hdp_tools() -> list[dict]:
    """Return HDP_TOOLS — convenience alias."""
    return HDP_TOOLS
