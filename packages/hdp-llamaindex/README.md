# hdp-llamaindex

Metapackage for users who discover HDP first.

```bash
pip install hdp-llamaindex==0.2.0
```

This installs `llama-index-callbacks-hdp` and re-exports all classes from the `hdp_llamaindex` namespace.

HDP tokens are records and cannot gate actions. `verify_chain` exposes `recorded_after_period` separately from its integrity result. The compatibility options `strict=True` and `on_violation="raise"` raise `ValueError` during construction.

For full documentation see [llama-index-callbacks-hdp](../llama-index-callbacks-hdp/README.md).

## Specification

This package follows [draft-helixar-hdp-agentic-delegation-03](https://datatracker.ietf.org/doc/html/draft-helixar-hdp-agentic-delegation-03) ([latest revision](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/)).
