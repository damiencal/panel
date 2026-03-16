# Contributing

## Before you open a pull request

- run `cargo fmt`
- run `cargo clippy -- -D warnings`
- run `cargo test`
- add or update tests when behavior changes
- document public interfaces when needed

## Setting up pre-commit hooks

The repository ships a pre-commit hook in `.githooks/` that mirrors CI checks (`cargo fmt --check` and `cargo clippy -D warnings`).

Install it once with either of:

```sh
# via npm (recommended – also run automatically by npm install)
npm run prepare

# or directly
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit
```

## Contribution flow

1. Fork the repository.
2. Create a feature branch.
3. Make focused commits.
4. Open a pull request with a clear summary and test notes.

## Contributor License Agreement

This project requires acceptance of the contributor agreement in [CLA.md](CLA.md).

By submitting a contribution, you agree that the maintainer may distribute your contribution under the repository AGPL license and may also relicense it under GPLv3 or separate commercial terms.

When opening a pull request, include this exact statement in the PR body:

`I have read and agree to the CLA in CLA.md for this contribution.`

If you are contributing on behalf of a company, make sure you have authority to agree to [CLA.md](CLA.md) for that company before submitting.

## Licensing model

- The community edition in this repository is licensed under the AGPL in [LICENSE](LICENSE).
- Separate GPLv3 grants and commercial terms are described in [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).
- The `Multi-Server Cloud Service` feature is reserved for separate commercial licensing unless the maintainer explicitly releases a specific implementation under AGPL.