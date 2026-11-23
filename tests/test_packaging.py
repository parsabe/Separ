"""Review 2026-11, item 6: one Python floor (3.12) everywhere, and packages that bring their own
pinned pydantic 2 instead of the distribution's 1.x. These checks read the build files; the CI job
`install-test` installs the built packages in Ubuntu 24.04, Debian 13 and Rocky 9 containers."""

from __future__ import annotations

import importlib.util
import re
import tomllib
from pathlib import Path

import refmon
from refmon.cli import main as cli_main

ROOT = Path(__file__).resolve().parents[1]


def _builder():
    spec = importlib.util.spec_from_file_location(
        "build_packages", ROOT / "packaging" / "build_packages.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _pins() -> dict[str, str]:
    lines = (ROOT / "packaging" / "requirements-runtime.txt").read_text().splitlines()
    return dict(ln.split("==") for ln in lines if ln.strip() and not ln.startswith("#"))


def test_python_312_is_the_floor_everywhere():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert pyproject["project"]["requires-python"] == ">=3.12"
    assert _builder().MIN_PYTHON == (3, 12)
    assert "(3, 12)" in (ROOT / "packaging" / "install-venv.sh").read_text()
    for path in ("install.sh", "packaging/install-venv.sh", "packaging/build_packages.py"):
        text = (ROOT / path).read_text()
        assert not re.search(r"3\.1[01]\b|\(3, 1[01]\)", text), path


def test_every_runtime_dependency_is_pinned_and_pydantic_is_2():
    pins = _pins()
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    for dep in pyproject["project"]["dependencies"]:
        name = re.split(r"[<>=!~ ]", dep)[0].lower()
        assert name in {p.lower() for p in pins}, dep
    major, minor = (int(x) for x in pins["pydantic"].split(".")[:2])
    assert (major, minor) >= (2, 7)
    for name in ("pydantic-core", "annotated-types", "typing-extensions", "pyyaml", "cryptography"):
        assert name in pins


def test_packages_never_depend_on_distribution_python_libraries():
    text = (ROOT / "packaging" / "build_packages.py").read_text()
    deps = [
        ln for ln in text.splitlines() if ln.startswith(("Depends:", "Requires:", "Recommends:"))
    ]
    assert len(deps) == 2, deps
    for distro_lib in (
        "python3-pydantic",
        "python3-yaml",
        "python3-pyyaml",
        "python3-cryptography",
    ):
        assert not any(distro_lib in ln for ln in deps)
    assert "Architecture: all" not in text and "BuildArch:      noarch" not in text
    assert "--no-index" in (ROOT / "packaging" / "install-venv.sh").read_text()
    assert "--require-hashes" in (ROOT / "packaging" / "install-venv.sh").read_text()


def test_one_version_everywhere(capsys):
    builder = _builder()
    assert refmon.__version__ == builder.VERSION
    try:
        cli_main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    assert capsys.readouterr().out.strip() == f"separ {refmon.__version__}"


def test_a_version_tag_releases_only_install_tested_packages():
    """Round 2, A4: the release job runs on tags v* (not *-base), after the container install
    checks, and attaches the .deb, the .rpm and their checksums."""
    import yaml

    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    jobs = ci["jobs"]
    release = jobs["release"]
    assert "refs/tags/v" in release["if"] and "-base" in release["if"]
    assert {"test", "packages", "install-test"} <= set(release["needs"])
    assert release["permissions"] == {"contents": "write"}
    images = {inc["image"] for inc in jobs["install-test"]["strategy"]["matrix"]["include"]}
    assert images == {"ubuntu:24.04", "debian:13", "rockylinux:9"}
    script = "\n".join(step.get("run", "") for step in release["steps"])
    for asset in ("separ_*_amd64.deb", "separ-*.x86_64.rpm", "SHA256SUMS"):
        assert asset in script
    readme = (ROOT / "README.md").read_text()
    assert "github.com/parsabe/Separ/releases/download" in readme
