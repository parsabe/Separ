#!/usr/bin/env python3
"""Build per-architecture .deb and .rpm packages of Separ (review 2026-11, item 6).

Separ needs Python >= 3.12 and pydantic >= 2.7. Distribution packages cannot provide that
(python3-pydantic is 1.x on Ubuntu 24.04 and Debian 12), so the packages carry their own pinned
wheels (packaging/requirements-runtime.txt, one set per supported CPython: 3.12, 3.13, 3.14) and
install them at install time into a private venv, /opt/separ/venv, with
`pip install --no-index --require-hashes`: installing needs no internet. The compiled wheels
(pydantic-core, pyyaml, cffi, cryptography) make the packages architecture-specific.

Usage:
    python packaging/build_packages.py [--deb] [--rpm] [--all] [--arch amd64|arm64]
                                       [--wheel-cache DIR] [--wheels-only]

Building downloads the pinned wheels once (or reads them from --wheel-cache, for an offline
build); `--wheels-only` writes dist/wheels-<arch>/ for install.sh.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src" / "refmon"
PACKAGING_DIR = ROOT_DIR / "packaging"
BUILD_DIR = ROOT_DIR / "build" / "package_staging"
DIST_DIR = ROOT_DIR / "dist"
REQUIREMENTS = PACKAGING_DIR / "requirements-runtime.txt"


def _version() -> str:
    text = (SRC_DIR / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("no __version__ in src/refmon/__init__.py")
    return match.group(1)


VERSION = _version()
RELEASE = "1"
PKG_NAME = "separ"
MIN_PYTHON = (3, 12)
PYTHONS = ("3.12", "3.13", "3.14")  # one wheel set each; the installer picks the host's
PIP_VERSION = "26.1.2"  # vendored so the venv needs neither ensurepip nor python3-venv
PREFIX = "/opt/separ"
MAINTAINER = "Separ Development Team <separ@example.org>"
HOMEPAGE = "https://github.com/parsabe/Separ"
SUMMARY = "Behavioral Reference Monitor & Live Attack Barrier"
DESCRIPTION = (
    "Separ detects, contains and explains attacks on endpoints and servers\n"
    "by judging behaviour rather than static signatures. It provides\n"
    "real-time CLI mediation tools (separ guard, separ lab) and an\n"
    "interactive Reference Monitor GUI (separ gui) similar to Wireshark\n"
    "for behavioral incident analysis."
)
# Debian name, RPM name, the manylinux platform tags pip may use
ARCHES = {
    "amd64": ("amd64", "x86_64", ("manylinux_2_28_x86_64", "manylinux2014_x86_64")),
    "arm64": ("arm64", "aarch64", ("manylinux_2_28_aarch64", "manylinux2014_aarch64")),
}

CLI_WRAPPER = f"""#!/bin/sh
# Separ launcher: runs the private venv that the package's post-install step created.
VENV="{PREFIX}/venv"
if [ ! -x "$VENV/bin/separ" ]; then
    echo "separ: $VENV is missing; run {PREFIX}/install-venv (as root) to create it" >&2
    exit 1
fi
exec "$VENV/bin/separ" "$@"
"""


def host_arch() -> str:
    machine = platform.machine().lower()
    return "arm64" if machine in ("aarch64", "arm64") else "amd64"


def _pip(*args: str) -> None:
    subprocess.run([sys.executable, "-m", "pip", *args], check=True)


def vendor_wheels(dest: Path, arch: str, cache: Path | None = None) -> list[Path]:
    """The pinned wheels for every supported CPython, pip itself and the Separ wheel, plus a
    hash-pinned requirements file per CPython (requirements-cp312.txt, ...)."""
    dest.mkdir(parents=True, exist_ok=True)
    platforms = ARCHES[arch][2]
    for py in PYTHONS:
        args = ["download", "--quiet", "--only-binary=:all:", "--no-deps",
                "--python-version", py, "--implementation", "cp", "-d", str(dest),
                "-r", str(REQUIREMENTS)]  # fmt: skip
        for plat in platforms:
            args += ["--platform", plat]
        if cache is not None:
            args += ["--no-index", "--find-links", str(cache)]
        _pip(*args)
    pip_args = ["download", "--quiet", "--no-deps", "--only-binary=:all:", "-d", str(dest),
                f"pip=={PIP_VERSION}"]  # fmt: skip
    if cache is not None:
        pip_args += ["--no-index", "--find-links", str(cache)]
    _pip(*pip_args)
    for old in dest.glob("separ-*.whl"):
        old.unlink()
    _pip("wheel", "--quiet", "--no-deps", "-w", str(dest), str(ROOT_DIR))
    wheels = sorted(dest.glob("*.whl"))
    pins = [ln.split("==") for ln in REQUIREMENTS.read_text().splitlines()
            if ln.strip() and not ln.startswith("#")]  # fmt: skip
    for py in PYTHONS:
        tag = "cp" + py.replace(".", "")
        lines = []
        for name, ver in [*pins, ["separ", VERSION]]:
            norm = name.replace("-", "_").lower()
            matches = [
                w for w in wheels
                if w.name.lower().startswith(f"{norm}-{ver}-")
                and (f"-{tag}-" in w.name or "-abi3-" in w.name or "-py3-none-" in w.name
                     or "-py2.py3-none-" in w.name)
            ]  # fmt: skip
            if not matches:
                raise SystemExit(f"no wheel of {name}=={ver} for {tag} on {arch}")
            hashes = " ".join(
                f"--hash=sha256:{hashlib.sha256(w.read_bytes()).hexdigest()}" for w in matches
            )
            lines.append(f"{name}=={ver} {hashes}")
        (dest / f"requirements-{tag}.txt").write_text("\n".join(lines) + "\n")
    sums = [f"{hashlib.sha256(w.read_bytes()).hexdigest()}  {w.name}" for w in wheels]
    (dest / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    return wheels


def clean_dir(d: Path) -> None:
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True, exist_ok=True)


def stage_files(stage_root: Path, arch: str, cache: Path | None = None) -> None:
    """Populate the Linux filesystem tree under stage_root."""
    bin_dir = stage_root / "usr" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for bname in ("separ", "refmon"):
        bin_file = bin_dir / bname
        bin_file.write_text(CLI_WRAPPER, encoding="utf-8")
        bin_file.chmod(0o755)

    # the vendored wheels and the script that turns them into the private venv
    opt = stage_root / PREFIX.lstrip("/")
    vendor_wheels(opt / "wheels", arch, cache)
    for f in (opt / "wheels").iterdir():
        f.chmod(0o644)
    installer = opt / "install-venv"
    shutil.copy2(PACKAGING_DIR / "install-venv.sh", installer)
    installer.chmod(0o755)

    # the golden replay files the dashboard and the self-test can replay
    golden = stage_root / "usr" / "share" / "separ" / "golden"
    golden.mkdir(parents=True, exist_ok=True)
    for f in sorted((ROOT_DIR / "tests" / "golden").iterdir()):
        if f.is_file():
            shutil.copy2(f, golden / f.name)
            (golden / f.name).chmod(0o644)

    # Desktop entry & icon
    app_dir = stage_root / "usr" / "share" / "applications"
    app_dir.mkdir(parents=True, exist_ok=True)
    for dname in ("separ.desktop", "refmon.desktop"):
        desktop_src = PACKAGING_DIR / dname
        if desktop_src.is_file():
            shutil.copy2(desktop_src, app_dir / dname)
            (app_dir / dname).chmod(0o644)

    icon_dir = stage_root / "usr" / "share" / "icons" / "hicolor" / "scalable" / "apps"
    icon_dir.mkdir(parents=True, exist_ok=True)
    for iname in ("separ.svg", "refmon.svg"):
        icon_src = PACKAGING_DIR / iname
        if icon_src.is_file():
            shutil.copy2(icon_src, icon_dir / iname)
            (icon_dir / iname).chmod(0o644)

    # Documentation & License
    for doc_name in ("separ", "refmon"):
        doc_dir = stage_root / "usr" / "share" / "doc" / doc_name
        doc_dir.mkdir(parents=True, exist_ok=True)
        readme_src = ROOT_DIR / "README.md"
        if readme_src.is_file():
            shutil.copy2(readme_src, doc_dir / "README.md")
            (doc_dir / "README.md").chmod(0o644)

        license_src = ROOT_DIR / "LICENSE"
        if license_src.is_file():
            shutil.copy2(license_src, doc_dir / "copyright")
            (doc_dir / "copyright").chmod(0o644)

    stage_server_config(stage_root)
    stage_browser(stage_root)


def stage_server_config(stage_root: Path) -> None:
    """Stage /etc/separ configuration templates, mapping files and systemd unit."""
    etc_separ = stage_root / "etc" / "separ"
    etc_separ.mkdir(parents=True, exist_ok=True)
    etc_src = PACKAGING_DIR / "etc" / "separ"
    if etc_src.is_dir():
        for f in etc_src.iterdir():
            if f.is_file():
                shutil.copy2(f, etc_separ / f.name)
                (etc_separ / f.name).chmod(0o644)

    mappings_dest = etc_separ / "mappings"
    mappings_dest.mkdir(parents=True, exist_ok=True)
    mappings_src = ROOT_DIR / "src" / "refmon" / "ingest" / "mappings"
    if mappings_src.is_dir():
        for f in mappings_src.iterdir():
            if f.suffix in (".yaml", ".yml"):
                shutil.copy2(f, mappings_dest / f.name)
                (mappings_dest / f.name).chmod(0o644)

    system_unit_dir = stage_root / "usr" / "lib" / "systemd" / "system"
    system_unit_dir.mkdir(parents=True, exist_ok=True)
    svc_src = PACKAGING_DIR / "system" / "separ.service"
    if svc_src.is_file():
        shutil.copy2(svc_src, system_unit_dir / "separ.service")
        (system_unit_dir / "separ.service").chmod(0o644)
        refmon_svc = system_unit_dir / "refmon.service"
        if not refmon_svc.exists():
            refmon_svc.symlink_to("separ.service")


def stage_browser(stage_root: Path) -> None:
    """v2.1: the browser extension (as files and as an .xpi), its policy templates and the per-user
    systemd unit. Nothing is enabled by installing the package: an admin runs
    `separ browser-install --system` and applies the browser policy (browser/README.md)."""
    import zipfile

    ext_src = ROOT_DIR / "browser" / "extension"
    for share_base in ("separ", "refmon"):
        share = stage_root / "usr" / "share" / share_base / "browser"
        (share / "extension").mkdir(parents=True, exist_ok=True)
        xpi = share / f"{share_base}-browser.xpi"
        with zipfile.ZipFile(xpi, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(ext_src.iterdir()):
                if f.is_file():
                    shutil.copy2(f, share / "extension" / f.name)
                    (share / "extension" / f.name).chmod(0o644)
                    zf.write(f, f.name)
        xpi.chmod(0o644)
        for name in ("firefox-policies.json", "chromium-policy.json"):
            shutil.copy2(PACKAGING_DIR / "browser" / name, share / name)
            (share / name).chmod(0o644)
        readme = ROOT_DIR / "browser" / "README.md"
        shutil.copy2(readme, share / "README.md")
        (share / "README.md").chmod(0o644)
    unit_dir = stage_root / "usr" / "lib" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    for uname in ("separ-user.service", "refmon-user.service"):
        usrc = PACKAGING_DIR / "browser" / uname
        if usrc.is_file():
            shutil.copy2(usrc, unit_dir / uname)
            (unit_dir / uname).chmod(0o644)


def build_deb(arch: str, cache: Path | None = None) -> Path:
    """Build the Debian .deb package for one architecture."""
    deb_arch = ARCHES[arch][0]
    print(f"== Building Debian package (.deb, {deb_arch}) ==")
    deb_staging = BUILD_DIR / "deb"
    clean_dir(deb_staging)
    data_dir = deb_staging / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    stage_files(data_dir, arch, cache)

    # Installed-Size calculation (KiB)
    total_size = sum(f.stat().st_size for f in data_dir.glob("**/*") if f.is_file())
    installed_size_kb = max(1, (total_size + 1023) // 1024)

    # Control files
    debian_dir = deb_staging / "DEBIAN"
    debian_dir.mkdir(parents=True, exist_ok=True)

    # Format Debian extended description (each line indented with single space)
    desc_lines = []
    for line in DESCRIPTION.strip().splitlines():
        s = line.strip()
        desc_lines.append(f" {s}" if s else " .")
    deb_description = f"Description: {SUMMARY}\n" + "\n".join(desc_lines)

    control_content = f"""Package: {PKG_NAME}
Version: {VERSION}
Section: utils
Priority: optional
Architecture: {deb_arch}
Installed-Size: {installed_size_kb}
Maintainer: {MAINTAINER}
Homepage: {HOMEPAGE}
Depends: python3 (>= 3.12) | python3.12
{deb_description}
"""
    (debian_dir / "control").write_text(control_content, encoding="utf-8")
    (debian_dir / "control").chmod(0o644)

    # Postinst script for desktop database update if desktop-file-utils is installed
    postinst_content = f"""#!/bin/sh
set -e
# the private venv from the vendored, hash-pinned wheels (no internet)
{PREFIX}/install-venv
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
exit 0
"""
    postinst = debian_dir / "postinst"
    postinst.write_text(postinst_content, encoding="utf-8")
    postinst.chmod(0o755)
    prerm = debian_dir / "prerm"
    prerm.write_text(
        f"""#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = purge ]; then
    rm -rf {PREFIX}/venv
fi
exit 0
""",
        encoding="utf-8",
    )
    prerm.chmod(0o755)

    # Compute md5sums of data files
    md5_lines = []
    for f in sorted(data_dir.glob("**/*")):
        if f.is_file():
            rel_path = f.relative_to(data_dir)
            md5 = hashlib.md5(f.read_bytes()).hexdigest()
            md5_lines.append(f"{md5}  {rel_path}\n")
    (debian_dir / "md5sums").write_text("".join(md5_lines), encoding="utf-8")
    (debian_dir / "md5sums").chmod(0o644)

    # Build control.tar.gz (must use GNU tar format, no PAX extended headers)
    control_tar = deb_staging / "control.tar.gz"
    with tarfile.open(control_tar, "w:gz", format=tarfile.GNU_FORMAT) as tar:
        root_ti = tarfile.TarInfo(name="./")
        root_ti.type = tarfile.DIRTYPE
        root_ti.mode = 0o755
        root_ti.uid = 0
        root_ti.gid = 0
        root_ti.uname = "root"
        root_ti.gname = "root"
        root_ti.mtime = int(debian_dir.stat().st_mtime)
        root_ti.pax_headers = {}
        tar.addfile(root_ti)

        for entry in ("control", "postinst", "prerm", "md5sums"):
            p = debian_dir / entry
            if p.is_file():
                ti = tar.gettarinfo(str(p), arcname=f"./{entry}")
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                ti.mtime = int(p.stat().st_mtime)
                ti.pax_headers = {}
                with p.open("rb") as f:
                    tar.addfile(ti, f)

    # Build data.tar.gz (must use GNU tar format, no PAX extended headers)
    data_tar = deb_staging / "data.tar.gz"
    with tarfile.open(data_tar, "w:gz", format=tarfile.GNU_FORMAT) as tar:
        root_ti = tarfile.TarInfo(name="./")
        root_ti.type = tarfile.DIRTYPE
        root_ti.mode = 0o755
        root_ti.uid = 0
        root_ti.gid = 0
        root_ti.uname = "root"
        root_ti.gname = "root"
        root_ti.mtime = int(data_dir.stat().st_mtime)
        root_ti.pax_headers = {}
        tar.addfile(root_ti)

        for root, dirs, files in os.walk(data_dir):
            for d in sorted(dirs):
                full_d = Path(root) / d
                rel_d = full_d.relative_to(data_dir)
                ti = tar.gettarinfo(str(full_d), arcname=f"./{rel_d}")
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                ti.mtime = int(full_d.stat().st_mtime)
                ti.pax_headers = {}
                tar.addfile(ti)
            for f in sorted(files):
                full_f = Path(root) / f
                rel_f = full_f.relative_to(data_dir)
                ti = tar.gettarinfo(str(full_f), arcname=f"./{rel_f}")
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                ti.mtime = int(full_f.stat().st_mtime)
                ti.pax_headers = {}
                with full_f.open("rb") as fp:
                    tar.addfile(ti, fp)

    # debian-binary
    deb_binary = deb_staging / "debian-binary"
    deb_binary.write_text("2.0\n", encoding="ascii")

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    deb_output = DIST_DIR / f"{PKG_NAME}_{VERSION}_{deb_arch}.deb"
    if deb_output.exists():
        deb_output.unlink()

    # Use ar to create .deb archive with exact ordering: debian-binary, control.tar.gz, data.tar.gz
    cmd = [
        "ar",
        "rcs",
        str(deb_output),
        str(deb_binary),
        str(control_tar),
        str(data_tar),
    ]
    subprocess.run(cmd, check=True)
    print(f"Created: {deb_output} ({deb_output.stat().st_size:,} bytes)")
    return deb_output


def build_rpm(arch: str, cache: Path | None = None) -> Path:
    """Build the Red Hat .rpm package for one architecture with rpmbuild."""
    rpm_arch = ARCHES[arch][1]
    print(f"== Building RPM package (.rpm, {rpm_arch}) ==")
    rpm_topdir = BUILD_DIR / "rpmbuild"
    clean_dir(rpm_topdir)
    for sub in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS", "tmp"):
        (rpm_topdir / sub).mkdir(parents=True, exist_ok=True)

    stage_dir = rpm_topdir / "BUILD" / f"{PKG_NAME}-{VERSION}"
    stage_dir.mkdir(parents=True, exist_ok=True)
    stage_files(stage_dir, arch, cache)

    spec_content = f"""Name:           {PKG_NAME}
Version:        {VERSION}
Release:        {RELEASE}%{{?dist}}
Summary:        {SUMMARY}
License:        GPL-3.0-or-later
URL:            {HOMEPAGE}
BuildArch:      {rpm_arch}
AutoReqProv:    no
Requires:       (python3.12 or python3.13 or python3.14)
%global debug_package %{{nil}}
%global __os_install_post %{{nil}}

%description
{DESCRIPTION}

%prep

%build

%install
rm -rf %{{buildroot}}
mkdir -p %{{buildroot}}
cp -a {stage_dir}/* %{{buildroot}}/

%post
# the private venv from the vendored, hash-pinned wheels (no internet)
{PREFIX}/install-venv
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi

%preun
if [ "$1" -eq 0 ]; then
    rm -rf {PREFIX}/venv
fi

%files
{PREFIX}
/usr/bin/separ
/usr/bin/refmon
/usr/share/separ
/usr/share/refmon
/usr/share/applications/separ.desktop
/usr/share/applications/refmon.desktop
/usr/share/icons/hicolor/scalable/apps/separ.svg
/usr/share/icons/hicolor/scalable/apps/refmon.svg
/usr/lib/systemd/user/separ-user.service
/usr/lib/systemd/user/refmon-user.service
/usr/lib/systemd/system/separ.service
/usr/lib/systemd/system/refmon.service
%dir /etc/separ
%config(noreplace) /etc/separ/ingest.yaml
/etc/separ/ingest.yaml.example
/etc/separ/policy.yaml.example
/etc/separ/README.md
/etc/separ/mappings
%doc /usr/share/doc/separ/README.md
%doc /usr/share/doc/separ/copyright
%doc /usr/share/doc/refmon/README.md
%doc /usr/share/doc/refmon/copyright

%changelog
* Mon Nov 23 2026 Separ Team <separ@example.org> - {VERSION}-{RELEASE}
- Private venv from vendored pinned wheels; per-architecture package.
* Mon Nov 02 2026 Refmon Team <refmon@example.org> - 2.0.0-1
- Release version 2.0.0 with Live Reference Monitor GUI and Audio Alerts.
"""
    spec_path = rpm_topdir / "SPECS" / f"{PKG_NAME}.spec"
    spec_path.write_text(spec_content, encoding="utf-8")

    cmd = [
        "rpmbuild",
        "-bb",
        "--define",
        f"_topdir {rpm_topdir}",
        "--define",
        f"_tmppath {rpm_topdir}/tmp",
        "--define",
        "_build_id_links none",
        "--target",
        rpm_arch,
        str(spec_path),
    ]
    subprocess.run(cmd, check=True)

    rpm_files = list((rpm_topdir / "RPMS").glob("**/*.rpm"))
    if not rpm_files:
        raise RuntimeError("rpmbuild completed but no .rpm file was found")

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    rpm_output = DIST_DIR / f"{PKG_NAME}-{VERSION}-{RELEASE}.{rpm_arch}.rpm"
    if rpm_output.exists():
        rpm_output.unlink()
    shutil.copy2(rpm_files[0], rpm_output)
    print(f"Created: {rpm_output} ({rpm_output.stat().st_size:,} bytes)")
    return rpm_output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deb", action="store_true", help="build .deb package")
    parser.add_argument("--rpm", action="store_true", help="build .rpm package")
    parser.add_argument("--all", action="store_true", help="build both .deb and .rpm")
    parser.add_argument("--arch", choices=sorted(ARCHES), default=host_arch())
    parser.add_argument("--wheel-cache", default=None, help="offline: take wheels from here")
    parser.add_argument(
        "--wheels-only", action="store_true", help="write dist/wheels-<arch>/ for install.sh"
    )
    args = parser.parse_args()
    if sys.version_info < MIN_PYTHON:
        raise SystemExit("building the packages needs Python >= 3.12")
    cache = Path(args.wheel_cache) if args.wheel_cache else None

    if args.wheels_only:
        out = DIST_DIR / f"wheels-{args.arch}"
        clean_dir(out)
        vendor_wheels(out, args.arch, cache)
        print(f"wheels for {', '.join(PYTHONS)} on {args.arch}: {out}")
        return 0
    build_both = args.all or (not args.deb and not args.rpm)
    built = []
    if build_both or args.deb:
        built.append(build_deb(args.arch, cache))
    if build_both or args.rpm:
        built.append(build_rpm(args.arch, cache))

    print("\nSummary of built packages:")
    for p in built:
        print(f"  - {p.name} ({p.stat().st_size:,} bytes) in {p.parent}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
