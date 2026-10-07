# @helixar_ai/hdp-autogen

TypeScript middleware and a stateful wrapper for recording HDP provenance in AutoGen applications.

```sh
npm install @helixar_ai/hdp-autogen
```

## Record agent activity

```typescript
import { generateKeyPair } from "@helixar_ai/hdp";
import { HdpAgentWrapper } from "@helixar_ai/hdp-autogen";

const { privateKey } = await generateKeyPair();
const wrapper = new HdpAgentWrapper({
  signingKey: privateKey,
  sessionId: "research-session-1",
  principal: { id: "researcher", id_type: "opaque" },
  scope: {
    intent: "Summarise recent papers",
    authorized_tools: ["web_search"],
  },
  onScopeViolation: finding => auditLog({ tool: finding.tool }),
});

await wrapper.init();
await wrapper.onSpeakerTurn("researcher", "Find recent papers on agent safety.");
wrapper.onToolCall("web_search");
const token = wrapper.exportToken();
```

`onToolCall(tool)` reports an out-of-scope finding to `onScopeViolation` when configured and returns normally. The caller then invokes the tool through its usual execution path. Speaker-turn signing failures are absorbed by the wrapper so instrumentation does not stop agent code.

## Inspect records in middleware

```typescript
import { hdpMiddleware } from "@helixar_ai/hdp-autogen";

const wrapped = hdpMiddleware(handler, {
  verify: { publicKey },
  onMissing: () => auditLog({ finding: "HDP token missing" }),
  onInvalid: result => auditLog({ failedStep: result.failedStep, errorCode: result.error.code }),
  onValid: token => auditLog({ token_id: token.header.token_id }),
});

const response = await wrapped({
  headers: { "HDP-Token": encodedToken },
  content: "Continue the task",
});
```

HDP tokens are records, not access controls. Missing, undecodable, expired, or invalid records do not change whether middleware calls the handler. `onInvalid` receives a `VerificationResult`; decoding failures use input-validation step 0. Expiry and other audit findings are separate from integrity verification.

`hdp_required: true` and `strict: true` are deprecated and throw during construction because an HDP record cannot gate a request or tool call. `HdpScopeViolationError` remains exported for compatibility, is deprecated, and is never thrown.

The functional middleware accepts a handler and options. It has no `observe()` method or `{ allowed, violation }` return value.

## Tool schemas

`HDP_TOOLS` and `getHdpTools()` expose three OpenAI-compatible schemas: `hdp_issue_token`, `hdp_extend_chain`, and `hdp_verify_token`.

Tokens use the HDP v0.1 wire format and are compatible with the Python AutoGen package.

## Cross-language compatibility

Tokens are wire-compatible with the Python `hdp-autogen` package. A token created in TypeScript can be verified in Python and vice versa. Both use RFC 8785 canonical JSON and Ed25519.

## Releasing

Published to [npm](https://www.npmjs.com/package/@helixar_ai/hdp-autogen) via GitHub Actions. Two ways to release:

**Standalone** (publishes only this package):
```bash
git tag node/hdp-autogen/v0.2.0 && git push origin node/hdp-autogen/v0.2.0
```

Pipeline: `test-hdp-autogen-ts` → `vet-hdp-autogen-ts` ([ReleaseGuard](https://github.com/Helixar-AI/ReleaseGuard)) → `publish-hdp-autogen-ts-standalone`

**With all Node packages** (publishes core + mcp + cli + autogen):
```bash
git tag v0.2.0 && git push origin v0.2.0
```

| Detail | Value |
|---|---|
| **npm package** | [`@helixar_ai/hdp-autogen`](https://www.npmjs.com/package/@helixar_ai/hdp-autogen) |
| **Standalone tag** | `node/hdp-autogen/v*` |
| **Bundle tag** | `v*` (with all Node packages) |
| **Workflow** | `.github/workflows/release.yml` |
| **Auth** | `NPM_TOKEN` secret |

## Specification

This package follows [draft-helixar-hdp-agentic-delegation-03](https://datatracker.ietf.org/doc/html/draft-helixar-hdp-agentic-delegation-03) ([latest revision](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/)).

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), Helixar Limited.
