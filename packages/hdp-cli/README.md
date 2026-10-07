# hdp-validate

Command-line schema and structure checker for HDP v0.1 records.

## Usage

```sh
npm install -g hdp-validate@0.2.0
hdp-validate token.json
cat token.json | hdp-validate
```

The CLI checks the token schema, protocol version, and required hop signatures. It does not verify Ed25519 signatures because verification requires the issuer public key. A token whose `expires_at` has passed remains structurally valid; the CLI prints a note that the authorization period has ended. Hops at or after `expires_at` are also noted as recorded after that period.

HDP tokens are records, not access controls. Expiry does not make a record invalid and does not affect the CLI exit code.

## Exit codes

- `0`: token structure is valid, including records whose authorization period has ended.
- `1`: invalid JSON, schema violation, unsupported version, or missing hop signature.
- `2`: usage error or unreadable input file.

## Specification

This package follows [draft-helixar-hdp-agentic-delegation-03](https://datatracker.ietf.org/doc/html/draft-helixar-hdp-agentic-delegation-03) ([latest revision](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/)).

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), Helixar Limited.
