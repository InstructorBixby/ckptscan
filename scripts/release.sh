#!/usr/bin/env bash
# Cut a version. Run from a clean tree on main.
#
# This is a script and not a pipeline job because the tag is the thing
# the pipeline reacts to, so anything that has to happen BEFORE the tag
# has to happen here. Twice I have tagged, pushed, and then found the
# version in pyproject.toml still said the old number.
set -euo pipefail

cd "$(dirname "$0")/.."

test -z "$(git status --porcelain)" || { echo "tree is dirty"; exit 1; }

ver=$(python -c \
    "import tomllib;print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
pkg=$(python -c "import ckptscan;print(ckptscan.__version__)")
test "$ver" = "$pkg" || { echo "pyproject $ver != __init__ $pkg"; exit 1; }
grep -q "## \[$ver\]" CHANGELOG.md || { echo "no changelog entry for $ver"; exit 1; }

ruff check .
mypy
pytest -q
python scripts/regen_rules.py --check

# A release that cannot detect its own corpus is not a release. This
# has stopped me once, on a false-positive fix that quietly broke a
# detection -- the clean half got quieter and so did the unsafe half.
rm -rf build/corpus
python -m ckptscan.commands.mkcorpus --out build/corpus --quiet
for f in build/corpus/unsafe/*; do
  python -m ckptscan.commands.main --quiet "$f" \
    && { echo "MISSED: $f"; exit 1; }
done
python -m ckptscan.commands.main build/corpus/clean

rm -rf dist
python -m build
(cd dist && sha256sum * | tee SHA256SUMS)

git tag -a "v$ver" -m "ckptscan $ver"
echo "tagged v$ver -- push it when you mean it"
