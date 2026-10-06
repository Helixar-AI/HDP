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
  principal: { id: "researcher", id_type: "handle" },
  scope: {
    intent: "Summarise recent papers",
    authorized_tools: ["web_search"],
  },
  onScopeViolation: finding => auditLog(finding),
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
  onInvalid: result => auditLog(result),
  onValid: token => auditLog(token),
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

## Specification

HDP is specified in the [IETF draft](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/).

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), Helixar Limited.
