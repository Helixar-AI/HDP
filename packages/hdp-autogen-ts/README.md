# @helixar_ai/hdp-autogen

**HDP (Human Delegation Provenance) middleware for AutoGen (TypeScript)** — attach a cryptographic audit trail to any multi-agent conversation.

```
npm install @helixar_ai/hdp-autogen
```

---

## Quick start

```typescript
import { HdpAgentWrapper, hdpMiddleware } from "@helixar_ai/hdp-autogen";
import { generateKeyPair } from "@helixar_ai/hdp";

const { privateKey, publicKey } = generateKeyPair();

// Class-based: wrap an AutoGen agent
const wrapper = new HdpAgentWrapper({
  signingKey: privateKey,
  sessionId: "research-2026-q1",
  principal: { id: "researcher@lab.edu", idType: "email" },
  scope: { intent: "Summarise papers", authorizedTools: ["web_search"] },
});

await wrapper.init();
wrapper.onSpeakerTurn("researcher", "Summarising recent LLM papers...");
wrapper.onSpeakerTurn("reviewer", "The summary looks good.");

const token = wrapper.exportToken();
```

### Functional middleware

```typescript
const mw = hdpMiddleware({
  signingKey: privateKey,
  sessionId: "s1",
  principal: { id: "alice", idType: "handle" },
  scope: { intent: "research" },
});

await mw.observe({ agent: "researcher", content: "Hello" });
// mw.required() returns the current token or null
```

---

## Error handling

`onSpeakerTurn()` and `observe()` are **non-blocking** — signing failures are caught internally and logged, so agent execution is never interrupted.

For tool-call scope enforcement, use `onToolCall()`:

```typescript
// Non-blocking (default): returns { allowed: false, violation: "..." }
const result = wrapper.onToolCall("execute_code", { code: "rm -rf /" });
if (!result.allowed) {
  console.warn("Scope violation:", result.violation);
}
```

---

## OpenAI-compatible tool schemas

```typescript
import { getHdpTools, HDP_TOOLS } from "@helixar_ai/hdp-autogen";

// HDP_TOOLS is a static array of 3 tool schemas:
// hdp_issue_token, hdp_extend_chain, hdp_verify_token
// Compatible with AutoGen's OpenAI tool_calls format
```

---

## Cross-language compatibility

Tokens are wire-compatible with the Python `hdp-autogen` package. A token created in TypeScript can be verified in Python and vice versa — both use RFC 8785 canonical JSON + Ed25519.

---

## Releasing

Published to [npm](https://www.npmjs.com/package/@helixar_ai/hdp-autogen) via GitHub Actions. Two ways to release:

**Standalone** (publishes only this package):
```bash
git tag node/hdp-autogen/v0.1.2 && git push origin node/hdp-autogen/v0.1.2
```

Pipeline: `test-hdp-autogen-ts` → `vet-hdp-autogen-ts` ([ReleaseGuard](https://github.com/Helixar-AI/ReleaseGuard)) → `publish-hdp-autogen-ts-standalone`

**With all Node packages** (publishes core + mcp + cli + autogen):
```bash
git tag v0.1.2 && git push origin v0.1.2
```

| Detail | Value |
|---|---|
| **npm package** | [`@helixar_ai/hdp-autogen`](https://www.npmjs.com/package/@helixar_ai/hdp-autogen) |
| **Standalone tag** | `node/hdp-autogen/v*` |
| **Bundle tag** | `v*` (with all Node packages) |
| **Workflow** | `.github/workflows/release.yml` |
| **Auth** | `NPM_TOKEN` secret |

---

## Spec

Human Delegation Provenance (HDP) is an IETF draft:
[draft-helixar-hdp-agentic-delegation](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/)

## License

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — Helixar Limited
