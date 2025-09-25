# Contributing to HyperionScan

Thanks for taking the time to improve HyperionScan! This guide explains how to get your development environment ready, propose changes, and collaborate effectively.

## 1. Ways to Contribute

1. **Bug reports** – Explain the issue, reproduction steps, expected vs actual behavior, and environment details.
2. **Feature proposals** – Provide context, user impact, proposed API/CLI changes, and alternatives considered.
3. **Code contributions** – Fix bugs, add features, improve docs, or enhance tests/tooling.
4. **Security research** – Follow the process outlined in `SECURITY.md` for any vulnerability disclosures.

## 2. Prerequisites

- Rust 1.74+ (`rustup` recommended)
- Python 3.8+ for AI agents
- Node.js 18+ (optional, plugin development)
- PowerShell 7+ or POSIX shell for the setup scripts
- `cargo fmt`, `cargo clippy`, and `ruff` installed locally

## 3. Development Workflow

1. **Fork + clone** the repository.
2. **Create a topic branch** off `main` (`feature/<topic>` or `fix/<topic>`).
3. **Install dependencies**:
   ```bash
   cargo fetch
   pip install -r ml_agents/requirements.txt  # if using AI agents
   ```
4. **Make changes** with clear commits scoped to a single concern.
5. **Run checks** (see below).
6. **Open a pull request** targeting `main`.

## 4. Required Checks

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
pytest tests          # if Python components changed
ruff check ml_agents  # for Python linting
```

Please update or add tests alongside your changes whenever possible.

## 5. Code Style & Expectations

- Prefer explicit types and descriptive variable names.
- Keep modules small and cohesive; extract helpers for repeated logic.
- Document public functions and complex blocks with concise comments.
- Use `tracing` for structured logging.
- Avoid panics in library code; return `Result` with context.

## 6. Commit & PR Guidelines

- Follow the format `type(scope): summary` when possible (e.g., `feat(scanner): add Cairo support`).
- Reference related issues (e.g., `Fixes #123`).
- Keep PR descriptions focused: what changed, why, and how it was tested.
- Include screenshots/logs for UX or CLI-affecting changes.

## 7. Issue Triage Labels

- `bug`, `enhancement`, `documentation`, `security`, `good first issue`, `help wanted`
- Add severity labels (`critical`, `high`, `medium`, `low`) for scanner regressions.

## 8. Community Expectations

All contributors must follow the [Code of Conduct](CODE_OF_CONDUCT.md). Respectful collaboration is non-negotiable.

## 9. Questions?

Open a GitHub discussion or reach out via issues. For sensitive disclosures, follow the instructions in `SECURITY.md`.

Thank you for helping safeguard smart contract ecosystems with HyperionScan!
