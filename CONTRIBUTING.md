# Contributing to AntiOS

Thanks for taking the time to improve the project.

## Development setup

AntiOS requires Python 3.11 or newer. Most unit tests run on Windows and Linux; Windows-specific integration tests require Windows.

    py -3.11 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install -U pip pytest
    python -m pip install -e .
    python -m pytest

## Repository workflow

Keep the Git history easy to read.

- One task or feature should normally use one branch and one pull request.
- Prefer a small number of meaningful commits. Do not commit every local retry, typo or CI experiment.
- Keep tests and documentation for a feature in the same PR when they belong to that feature.
- Use short, descriptive commit and PR titles such as feat:, fix:, test: or docs:.
- PRs are normally squash-merged into master.
- Do not create extra PRs, workflow files or architecture documents only to make activity look larger.

A pull request should explain what changed, why it changed, any compatibility or safety impact, and how it was tested.

## CI

The repository intentionally keeps GitHub Actions small:

- ci.yml — tests, source audit, Windows security acceptance and Linux package smoke;
- codeql.yml — CodeQL analysis;
- release.yml — release builds and optional hardened Windows packaging;
- store.yml — Microsoft Store package build;
- website.yml — website verification and GitHub Pages deployment.

Do not add a new workflow when an existing job can reasonably own the check.

## Security and safety

Changes should preserve a few project rules:

- failed or incomplete inspection must not silently become a clean result;
- destructive actions should be explicit and reversible where practical;
- weak behavioral or posture signals must not independently authorize quarantine;
- AntiOS must not disable or impersonate another security product as part of coexistence;
- logs and reports should avoid unnecessary secrets or personal data;
- do not add credential theft, anti-cheat bypasses, hardware-identity spoofing or similar evasion features.

## Tests

Behavior changes should include tests when practical. Windows-specific behavior should be covered by a Windows test or acceptance check instead of being inferred from Linux-only tests.

## Security reports

Do not publish working exploit steps or bypass details in a public issue or PR. Use the private reporting route described in [SECURITY.md](SECURITY.md).

## License

The public AntiOS source tree is licensed under Apache-2.0. By submitting a contribution for inclusion, you agree that it can be distributed under that license unless explicitly agreed otherwise.

Do not submit third-party code or data that you do not have the right to redistribute.
