# Contributing

Use Python 3.10 or newer. Clone the repository, create a virtual environment,
and run `python -m pip install -e . build ruff coverage`.

Run `python -m unittest discover -s tests -v`, `ruff check src tests`,
`ruff format --check src tests`, and `python -m build` before proposing changes.
Include a small synthetic example and a regression test for changed behavior.
Never attach real private data, browser profiles, or credentials to an issue.

Keep the core deterministic, offline and dependency-free. Document unsupported
semantics rather than silently accepting them. Contributions are under MIT.
