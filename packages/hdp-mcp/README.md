# @helixar_ai/hdp-mcp

MCP middleware for inspecting HDP provenance records.

```sh
npm install @helixar_ai/hdp-mcp@0.2.0
```

## Usage

```typescript
import { hdpMiddleware } from "@helixar_ai/hdp-mcp";

const wrapped = hdpMiddleware(myToolHandler, {
  verify: { publicKey },
  onMissing: () => auditLog({ finding: "HDP token missing" }),
  onInvalid: result => auditLog({ failedStep: result.failedStep, errorCode: result.error.code }),
  onValid: token => auditLog({ token_id: token.header.token_id }),
});

const response = await wrapped({
  headers: { "HDP-Token": encodedToken },
  tool: "search",
  params: { query: "agent safety" },
});
```

HDP tokens are records, not access controls. Missing, undecodable, expired, or invalid records do not change whether the middleware calls the handler. `onInvalid` receives a `VerificationResult`; decoding failures use input-validation step 0. Expiry and other audit findings are separate from integrity verification.

`hdp_required: true` is deprecated and throws during middleware construction because an HDP record cannot gate a request. Omitting the option, or setting it to `false`, leaves requests ungated. The `X-HDP-Token` header is accepted as a deprecated input alias; use `HDP-Token` for new requests.

## Specification

This package follows [draft-helixar-hdp-agentic-delegation-03](https://datatracker.ietf.org/doc/html/draft-helixar-hdp-agentic-delegation-03) ([latest revision](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/)).

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), Helixar Limited.
