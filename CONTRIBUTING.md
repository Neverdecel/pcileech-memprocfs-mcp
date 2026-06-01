# Contributing

Thanks for your interest in improving this project! Contributions of all kinds
are welcome — bug reports, new tools, docs, and tests.

## Development setup

```bash
git clone https://github.com/Neverdecel/nevercheese-pcileech-memprocfs-mcp.git
cd nevercheese-pcileech-memprocfs-mcp

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

No DMA hardware is required for development — the test suite runs entirely on
mocks.

## Before you open a PR

Run both checks locally. CI runs the same ones and will block on failure.

```bash
# 1. Tests (164 checks, no hardware needed)
python test_server.py

# 2. Formatting
black --check --line-length 100 .
```

To auto-format:

```bash
black --line-length 100 .
```

## Adding a tool

Tools live in `main.py` (schema + async handler + output formatting) and call
into `vmm_wrapper.py` / `pointer_scanner.py` / `engine_tools.py`. When you add a
tool:

1. Register its schema in `list_tools()` and wire up the handler.
2. Add a unit test in `test_server.py` (use mocks — see existing tests).
3. **Update the tool count** in `test_server.py` (`test_mcp_tools`) and in the
   tool table in `README.md` and `docs/tools.md`. The test asserts the exact
   count, so this is enforced.

## Commit & PR guidelines

- Keep PRs focused; one logical change per PR.
- Reference any related issue (e.g. `Fixes #12`).
- Make sure CI is green.

## Releasing (maintainers)

Releases are automated. Push a version tag and the
[`Release`](.github/workflows/release.yml) workflow builds the distribution,
attaches it to the GitHub Release, and publishes to PyPI via Trusted Publishing:

```bash
# bump version in pyproject.toml, commit, then:
git tag v3.1.0
git push origin v3.1.0
```
