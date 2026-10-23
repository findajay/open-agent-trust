# Contributing

Issues, discussions and pull requests are all welcome.

## Development setup

Prerequisites: [uv](https://docs.astral.sh/uv/) and `make`. On Windows, use Git Bash or
WSL, or run the `uv run …` commands from the Makefile directly.

```bash
make install   # dependencies from uv.lock
make check     # lint, format check, strict types and tests: what CI runs
make demo      # end-to-end demo into a fresh directory
```

## Ground rules

- **Protocol changes start with the spec.** Change `protocol/agentproof-v0.1.md` in the
  same pull request as the code and regenerate the schemas (`make schemas`). If signing
  or canonicalization changes, regenerate the test vectors too (`make vectors`).
- **Every verifier check has a test that makes it fail.** A check that can't fail isn't
  a check.
- **Keep the core small.** A new runtime dependency needs a reason in the pull request.
  Integrations go under `src/openagenttrust/integrations/` behind an optional extra.
- **No copied code without a license review.** Don't paste code from other projects. If
  adapting third-party code is worthwhile, open an issue first so the license,
  attribution and `NOTICE` entry can be agreed.
- Use strict typing (`mypy --strict`) and `ruff` formatting, and add tests for behavior
  changes.

## Commit and pull request style

Use short imperative subject lines ("Add revocation list support"), and explain *why*
in the body. Link the issue. Pull requests need green CI and one maintainer review.

## License

By contributing, you agree that your contributions are licensed under the Apache License
2.0, as stated in section 5 of the license.
