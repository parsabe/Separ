#!/bin/sh
# Create Separ's private venv from the vendored, hash-pinned wheels (review 2026-11, item 6).
# Run by the .deb postinst and the .rpm %post (as /opt/separ/install-venv) and by install.sh.
# Needs no internet, no python3-venv/ensurepip and never the distribution's pydantic.
#   SEPAR_PREFIX  where wheels/ is and venv/ goes (default /opt/separ)
#   SEPAR_WHEELS  the wheel directory (default $SEPAR_PREFIX/wheels)
set -eu
PREFIX="${SEPAR_PREFIX:-/opt/separ}"
WHEELS="${SEPAR_WHEELS:-$PREFIX/wheels}"
PY=""
TAG=""
for cand in python3.12 python3.13 python3.14 python3; do
    command -v "$cand" >/dev/null 2>&1 || continue
    "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null \
        || continue
    TAG=$("$cand" -c 'import sys; print("cp%d%d" % sys.version_info[:2])')
    if [ -f "$WHEELS/requirements-$TAG.txt" ]; then
        PY="$cand"
        break
    fi
done
if [ -z "$PY" ]; then
    echo "separ: needs Python 3.12, 3.13 or 3.14 (e.g. install python3.12), then run $0" >&2
    exit 1
fi
# built in place: the scripts' shebangs name the venv's own path, so it cannot be moved after
rm -rf "$PREFIX/venv"
"$PY" -m venv --without-pip "$PREFIX/venv"
PIP=$(ls "$WHEELS"/pip-*.whl | head -n 1)
if ! "$PREFIX/venv/bin/python" "$PIP/pip" install --quiet --no-index --no-cache-dir \
    --disable-pip-version-check --require-hashes --find-links "$WHEELS" \
    -r "$WHEELS/requirements-$TAG.txt"; then
    rm -rf "$PREFIX/venv"
    echo "separ: installing the vendored wheels failed" >&2
    exit 1
fi
echo "separ: private venv ready in $PREFIX/venv ($("$PREFIX/venv/bin/python" --version 2>&1))"
