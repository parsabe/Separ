# Separ: test, audit, packages, and regenerate evaluation results.
#   make test         the test suite
#   make reproduce    regenerate every result table from scratch (docs/results.md, docs/evaluation/)
#   make all          lint, tests, privacy audit, robustness matrix and the publishability check
PY ?= .venv/bin/python
PYTHON ?= python3.12

.PHONY: test lint audit matrix publishable reproduce serve gui health scan-rootkit lab deb rpm wheels packages all clean

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

audit:
	$(PY) -m separ.audit tests/golden

matrix:
	$(PY) -m separ.variants --golden tests/golden --out build/robustness-matrix.csv

publishable:
	$(PY) scripts/check_publishable.py

reproduce:
	$(PY) scripts/reproduce.py

serve:
	$(PY) -m separ.cli serve

gui:  # launch Reference Monitor GUI in default desktop browser
	$(PY) -m separ.cli gui

health:  # is the daemon alive? exit 0 healthy, 1 not running or stale, 2 running with a problem
	$(PY) -m separ.cli health

scan-rootkit:  # exit 0 allow, 1 hold (findings to review), 2 block
	$(PY) -m separ.cli scan-rootkit

lab:
	$(PY) -m separ.cli lab

deb:  # build standalone .deb installer package in dist/
	$(PY) packaging/build_packages.py --deb

rpm:  # build standalone .rpm installer package in dist/
	$(PY) packaging/build_packages.py --rpm

wheels:  # vendored, pinned wheels for install.sh in dist/wheels-<arch>/
	$(PY) packaging/build_packages.py --wheels-only

packages:  # build both .deb and .rpm installer packages in dist/
	$(PY) packaging/build_packages.py --all

all: lint test audit matrix publishable

clean:
	rm -rf build .pytest_cache .ruff_cache .hypothesis
