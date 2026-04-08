# Releasing

## Scope

This project is currently distributed from GitHub tags rather than PyPI.
Consumers should install pinned tags such as `v0.1.0`.

## Release Checklist

1. Update `pyproject.toml` with the next semantic version.
2. Update `CHANGELOG.md`:
   move release notes from `Unreleased` into a new versioned section.
3. Verify packaging locally:

```bash
python -m build
```

4. Verify code quality locally:

```bash
ruff check .
ruff format --check .
```

5. Commit the release changes.
6. Create an annotated tag:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
```

7. Push the branch and tag:

```bash
git push origin master
git push origin vX.Y.Z
```

8. Create a GitHub Release for the tag and summarize:
   - user-facing changes
   - breaking changes, if any
   - migration notes, if any

## Versioning Policy

- Patch: backwards-compatible fixes
- Minor: backwards-compatible features and config additions
- Major: breaking API, behavior, or integration changes

## Install Guidance

Document releases using tag-pinned installs, for example:

```bash
pip install "newton-auth[django] @ git+https://github.com/Newton-School/newton-auth-python.git@vX.Y.Z"
```
