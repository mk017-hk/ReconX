# Contributing to ReconX

Thanks for taking the time to contribute!

---

## Getting started

```bash
git clone https://github.com/mk017-hk/ReconX.git
cd ReconX
pip install -e ".[dev]"
```

---

## Running tests

```bash
pytest tests/ -v
```

All tests must pass before submitting a pull request.

---

## Code style

- Follow PEP 8.
- Use type hints on all new public functions.
- Keep functions focused — if it's over ~60 lines, consider splitting it.
- No bare `except Exception:` — catch specific exceptions where possible.

---

## Submitting a pull request

1. Fork the repository and create a feature branch from `master`.
2. Write tests for any new functionality.
3. Make sure `pytest` passes locally.
4. Open a pull request with a clear description of what changed and why.

---

## Reporting bugs

Open an issue at <https://github.com/mk017-hk/ReconX/issues> and include:

- ReconX version (`reconx --version`)
- Python version
- OS
- The command you ran
- The full error output

---

## Legal

By contributing you agree that your contributions will be licensed under the project's MIT licence.

ReconX is for **authorised security testing only**. Do not contribute features designed to facilitate unauthorised access.
