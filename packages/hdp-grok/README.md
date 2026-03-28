# hdp-grok

**HDP (Human Delegation Provenance) middleware for Grok / xAI API** — attach a cryptographic audit trail to any Grok conversation with a few lines of code.

Every tool call Grok makes on behalf of a human is recorded in a tamper-evident chain of Ed25519 signatures, verifiable offline with a single public key.

```
pip install hdp-grok
```

---

## Quick start

```python
import json
import os
from openai import OpenAI
from hdp_grok import HdpMiddleware, get_hdp_tools

client = OpenAI(
    api_key=os.environ["XAI_API_KEY"],
    base_url="https://api.x.ai/v1",
)

middleware = HdpMiddleware(
    signing_key=os.getenv("HDP_SIGNING_KEY"),  # base64url Ed25519 private key
    principal_id="user@example.com",
)

messages = [{"role": "user", "content": "Please issue an HDP token and extend the chain to sub-agent-1."}]

while True:
    response = client.chat.completions.create(
        model="grok-3",
        messages=messages,
        tools=get_hdp_tools(),
    )
    choice = response.choices[0]

    if choice.finish_reason == "tool_calls":
        messages.append(choice.message)
        for tc in choice.message.tool_calls:
            result = middleware.handle_tool_call(
                name=tc.function.name,
                args=json.loads(tc.function.arguments),
            )
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result)})
    else:
        print(choice.message.content)
        break
```

---

## How it works

`hdp-grok` exposes three tool schemas that Grok can call during a conversation:

| Tool | What it does |
|---|---|
| `hdp_issue_token` | Signs a root HDP token for the current session and principal |
| `hdp_extend_chain` | Appends a signed delegation hop to the chain (e.g. handing off to a sub-agent) |
| `hdp_verify_token` | Verifies the full token chain using the middleware's public key |

`HdpMiddleware` holds the session state — signing key, current token, hop counter — for the lifetime of a conversation. Pass `get_hdp_tools()` to `tools=` once; route every `hdp_*` tool call through `middleware.handle_tool_call()`.

---

## Generating a signing key

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64

key = Ed25519PrivateKey.generate()
raw = key.private_bytes_raw()
print(base64.urlsafe_b64encode(raw).rstrip(b"=").decode())
# → store this as HDP_SIGNING_KEY
```

---

## API reference

### `HdpMiddleware`

```python
HdpMiddleware(
    signing_key: bytes | str | None = None,
    # bytes  — raw 32-byte Ed25519 private key
    # str    — base64url or hex (with or without 0x prefix)
    # None   — reads HDP_SIGNING_KEY env var
    key_id: str = "default",
    default_expires_in: int = 3600,   # seconds
    session_id: str | None = None,    # auto UUID v4 if None
    principal_id: str | None = None,
)
```

| Method | Returns | Notes |
|---|---|---|
| `issue_token(scope, expires_in)` | `{"token": "<json>"}` | Raises `ValueError` if `principal_id` not set |
| `extend_chain(delegatee_id, additional_scope)` | `{"new_token": "<json>"}` | Raises `HdpTokenMissingError` / `HdpTokenExpiredError` |
| `verify_token(token_str)` | `{"valid": bool, "hop_count": int, ...}` | Uses public key derived at init |
| `handle_tool_call(name, args)` | `dict` | Routes any `hdp_*` tool call; handles camelCase from Grok |
| `export_current_token()` | `dict \| None` | Live in-memory token |
| `reset()` | `None` | Clears token and hop counter; keeps session |

### `get_hdp_tools() → list[dict]`

Returns the three OpenAI-compatible tool schemas ready to pass to `tools=`.

---

## Wire format compatibility

Tokens produced by `hdp-grok` use the same Ed25519 + RFC 8785 wire format as the TypeScript `@helixar_ai/hdp` SDK. A token issued in Python is verifiable in TypeScript and vice versa.

---

## License

CC-BY-4.0
