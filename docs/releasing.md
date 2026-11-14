# Releasing

Maintainer checklist for publishing a new version.

1. **Make sure `main` is green** on all CI platforms.
2. **Update the version** in `src/tessera/__init__.py` following [Semantic Versioning](https://semver.org/).
3. **Update `CHANGELOG.md`:** move entries from *Unreleased* into a new version section with today's date, and update
   the comparison links at the bottom.
4. **Regenerate the README visuals** when the output format changed:
   ```bash
   python scripts/make_demo.py
   ```
5. **Run the full check locally:**
   ```bash
   python -m pytest && ruff check . && ruff format --check . && mypy
   python -m build            # needs: python -m pip install build
   ```
6. **Commit, tag and push:**
   ```bash
   git commit -am "Release v0.2.0"
   git tag -s v0.2.0 -m "Tessera v0.2.0"
   git push origin main --tags
   ```
7. The **release workflow** (`.github/workflows/release.yml`) builds the sdist and wheel, runs the tests against the
   built wheel and attaches the artifacts with SHA-256 checksums to a GitHub release.
8. Optional: publish to PyPI with trusted publishing once the project is registered there.

## Distribution name

The import package and command are `tessera`. The distribution name is `tessera-fim`, to avoid clashing with other
projects named Tessera. Check name availability on PyPI before the first upload.
