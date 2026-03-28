"""Minimal xAI / Grok example with HDP token chain.

Usage:
    export XAI_API_KEY=your_key
    export HDP_SIGNING_KEY=your_base64url_key
    python examples/grok_with_hdp.py
"""
import json
import os

from openai import OpenAI

from hdp_grok import HdpMiddleware, get_hdp_tools


def main() -> None:
    """Run a simple tool-use loop with Grok and HDP middleware."""
    client = OpenAI(
        api_key=os.environ["XAI_API_KEY"],
        base_url="https://api.x.ai/v1",
    )

    middleware = HdpMiddleware(
        signing_key=os.getenv("HDP_SIGNING_KEY"),
        principal_id="user@example.com",
    )

    messages = [
        {
            "role": "user",
            "content": "Please issue an HDP token and extend the chain to sub-agent-1.",
        }
    ]
    tools = get_hdp_tools()

    while True:
        response = client.chat.completions.create(
            model="grok-3",
            messages=messages,
            tools=tools,
        )
        choice = response.choices[0]

        if choice.finish_reason == "tool_calls":
            messages.append(choice.message)
            for tc in choice.message.tool_calls:
                result = middleware.handle_tool_call(
                    name=tc.function.name,
                    args=json.loads(tc.function.arguments),
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(result),
                    }
                )
        else:
            print(choice.message.content)
            break

    print("Final middleware state:", middleware)


if __name__ == "__main__":
    main()
