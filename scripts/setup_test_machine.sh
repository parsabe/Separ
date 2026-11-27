#!/usr/bin/env bash
# Set up a second machine to test Separ from a copy of this repository, then run everything.
#
#   scripts/setup_test_machine.sh                  prerequisites, venv, then the full test run
#   scripts/setup_test_machine.sh --install-only   prerequisites and venv only, run nothing
#   scripts/setup_test_machine.sh --run-only       the test run only (prerequisites already there)
#
# Options (combine freely):
#   --no-latex     skip TeX Live (no paper, no IT guides; saves about 2 GB of packages)
#   --packages     also build the .deb and .rpm installer packages (make packages; needs rpm)
#   --falco        also install Falco and run the measured baseline (sudo scripts/falco_baseline.sh);
#                  this rewrites docs/evaluation/falco-baseline-v2.4.json with this machine's result
#   --no-system    do not install system packages (you installed them yourself)
#   --fresh        delete and rebuild .venv
#   --yes          do not ask before installing system packages
#
# Run it as your normal user from the repository root; it calls sudo only to install packages
# (and for --falco). Supported: Debian, Ubuntu, Kali (apt) and Fedora, RHEL, Rocky, Alma (dnf).
#
# Copy the repository with its branches and tags (the reproduction needs the tags v2.3.1-base and
# v2.4). On this machine:
#   git bundle create separ.bundle --all          # then copy separ.bundle to the other machine
# On the other machine:
#   git clone separ.bundle Separ && cd Separ
#   git checkout docs/paper-and-it-guide          # or the branch you want to test
#   scripts/setup_test_machine.sh
#
# A GPU is not used: Separ has no machine learning (deterministic rules and counted baselines only),
# so a fast CPU and enough RAM are what make the test run faster.
#
# Logs and results go to build/test-machine/<time>/. The run regenerates tracked files (docs/results.md,
# docs/evaluation/, documentation/numbers.tex and figures, the PDFs); `git status` shows what changed
# on this machine, and `git restore .` discards it.
set -uo pipefail

INSTALL=1
RUN=1
LATEX=1
PACKAGES=0
FALCO=0
SYSTEM=1
FRESH=0
ASSUME_YES=0

usage() {
	sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'
	exit "${1:-0}"
}

for arg in "$@"; do
	case "$arg" in
	--install-only) RUN=0 ;;
	--run-only) INSTALL=0 ;;
	--no-latex) LATEX=0 ;;
	--packages) PACKAGES=1 ;;
	--falco) FALCO=1 ;;
	--no-system) SYSTEM=0 ;;
	--fresh) FRESH=1 ;;
	--yes | -y) ASSUME_YES=1 ;;
	-h | --help) usage 0 ;;
	*)
		echo "unknown option: $arg" >&2
		usage 2
		;;
	esac
done

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
die() {
	printf '\033[31merror:\033[0m %s\n' "$*" >&2
	exit 1
}

# ---- 0. where and who --------------------------------------------------------------------------
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || die "cannot enter $ROOT"
grep -q '^name = "separ"' pyproject.toml 2>/dev/null || die "run this from a copy of the Separ repository"
[ "$(id -u)" != 0 ] || die "run as your normal user, not as root (the script calls sudo itself)"
VENV=$ROOT/.venv
PY=$VENV/bin/python

if [ -r /etc/os-release ]; then
	# shellcheck disable=SC1091
	. /etc/os-release
fi
OS_IDS=" ${ID:-} ${ID_LIKE:-} "
PM=""
case "$OS_IDS" in
*" debian "* | *" ubuntu "* | *" kali "*) PM=apt ;;
*" fedora "* | *" rhel "* | *" centos "* | *" rocky "* | *" almalinux "*) PM=dnf ;;
esac

# ---- 1. system packages ------------------------------------------------------------------------
APT_BASE=(git make zip curl ca-certificates gnupg python3 python3-venv python3-pip python3-dev
	build-essential nftables)
APT_LATEX=(latexmk texlive-latex-base texlive-latex-recommended texlive-latex-extra
	texlive-fonts-recommended texlive-fonts-extra texlive-pictures texlive-lang-german)
DNF_BASE=(git make zip curl ca-certificates gnupg2 python3 python3-pip python3-devel gcc nftables)
# Fedora and RHEL resolve each LaTeX file to its own package
DNF_LATEX=(latexmk 'tex(latex)' 'tex(newtxtext.sty)' 'tex(newtxmath.sty)' 'tex(microtype.sty)'
	'tex(tikz.sty)' 'tex(adjustbox.sty)' 'tex(xurl.sty)' 'tex(natbib.sty)' 'tex(hyperref.sty)'
	'tex(listings.sty)' 'tex(enumitem.sty)' 'tex(booktabs.sty)' 'tex(tcolorbox.sty)'
	'tex(fontawesome5.sty)' 'tex(placeins.sty)' 'tex(tabularx.sty)' 'tex(mathtools.sty)'
	'tex(geometry.sty)' 'tex(ngerman.ldf)' 'tex(plainnat.bst)' 'tex(phvr8t.tfm)')

install_system() {
	local pkgs=()
	case "$PM" in
	apt)
		pkgs=("${APT_BASE[@]}")
		[ "$LATEX" = 1 ] && pkgs+=("${APT_LATEX[@]}")
		[ "$PACKAGES" = 1 ] && pkgs+=(rpm)
		# a python3.12 package exists on some releases whose python3 is older (Ubuntu 24.04 has 3.12)
		apt-cache show python3.12-venv >/dev/null 2>&1 && pkgs+=(python3.12 python3.12-venv)
		;;
	dnf)
		pkgs=("${DNF_BASE[@]}")
		[ "$LATEX" = 1 ] && pkgs+=("${DNF_LATEX[@]}")
		[ "$PACKAGES" = 1 ] && pkgs+=(rpm-build)
		dnf -q list python3.12 >/dev/null 2>&1 && pkgs+=(python3.12)
		;;
	*)
		info "unknown distribution (${PRETTY_NAME:-no /etc/os-release}): install these yourself,"
		info "then run again with --no-system: git make zip python3 (>= 3.12) with venv, nftables,"
		info "latexmk and a TeX Live with newtx, tikz, adjustbox, xurl, tcolorbox, fontawesome5, babel-german"
		exit 1
		;;
	esac
	say "1. System packages ($PM)"
	info "${pkgs[*]}"
	if [ "$ASSUME_YES" != 1 ]; then
		read -r -p "   Install these with sudo? [Y/n] " ans
		case "${ans:-y}" in [Yy]*) ;; *) die "stopped; run again with --no-system to skip this step" ;; esac
	fi
	if [ "$PM" = apt ]; then
		sudo apt-get update || die "apt-get update failed"
		sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${pkgs[@]}" ||
			die "apt-get install failed"
	else
		sudo dnf install -y "${pkgs[@]}" || die "dnf install failed"
	fi
}

install_falco() {
	say "1b. Falco (for the measured baseline)"
	if command -v falco >/dev/null; then
		info "already installed: $(falco --version 2>/dev/null | head -n 1)"
		return 0
	fi
	if [ "$PM" = apt ]; then
		curl -fsSL https://falco.org/repo/falcosecurity-packages.asc |
			sudo gpg --dearmor --yes -o /usr/share/keyrings/falco-archive-keyring.gpg || return 1
		echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" |
			sudo tee /etc/apt/sources.list.d/falcosecurity.list >/dev/null
		sudo apt-get update || return 1
		# no service, no driver download: the baseline starts Falco itself with modern eBPF
		sudo FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=none FALCOCTL_ENABLED=no \
			apt-get install -y falco || return 1
	elif [ "$PM" = dnf ]; then
		sudo rpm --import https://falco.org/repo/falcosecurity-packages.asc || return 1
		sudo curl -fsSL -o /etc/yum.repos.d/falcosecurity.repo https://falco.org/repo/falcosecurity-rpm.repo || return 1
		sudo FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=none FALCOCTL_ENABLED=no \
			dnf install -y falco || return 1
	else
		return 1
	fi
	# the package may enable a service on some systems; the baseline needs none
	sudo systemctl disable --now 'falco*' >/dev/null 2>&1 || true
}

# ---- 2. Python >= 3.12 and the venv ----------------------------------------------------------------
find_python() {
	local c
	# every match on PATH, and a system Python only, never one inside a venv (an activated venv
	# comes first on PATH)
	for c in $(type -ap python3.12 python3.13 python3.14 python3); do
		"$c" -c 'import sys, venv; sys.exit(0 if sys.version_info >= (3, 12) and sys.prefix == sys.base_prefix else 1)' 2>/dev/null &&
			{
				echo "$c"
				return 0
			}
	done
	# uv, if it is already installed, can provide a Python of its own
	if command -v uv >/dev/null 2>&1; then
		uv python install 3.12 >/dev/null 2>&1 && uv python find 3.12 2>/dev/null && return 0
	fi
	return 1
}

make_venv() {
	say "2. Python virtual environment (.venv)"
	local base
	base=$(find_python) || die "no Python >= 3.12 with venv. On Ubuntu 22.04 or Debian 12 install uv
   (see docs.astral.sh/uv) and run this script again; it then uses 'uv python install 3.12'."
	info "Python: $base ($("$base" --version 2>&1))"
	if [ "$FRESH" = 1 ] || ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
		rm -rf "$VENV"
		"$base" -m venv "$VENV" || die "creating .venv failed"
	else
		info "reusing the existing .venv (--fresh rebuilds it)"
	fi
	"$PY" -m pip install --quiet --upgrade pip || die "upgrading pip failed"
	local extras=".[dev,paper]"
	"$PY" -m pip install --quiet -e "$extras" || die "pip install -e $extras failed"
	[ "$PACKAGES" = 1 ] && { "$PY" -m pip install --quiet hatchling || die "pip install hatchling failed"; }
	info "installed: $("$VENV/bin/separ" --version 2>&1)"
}

check_tags() {
	local missing=()
	for t in v2.3.1-base v2.4; do
		git rev-parse -q --verify "refs/tags/$t" >/dev/null || missing+=("$t")
	done
	if [ ${#missing[@]} -gt 0 ]; then
		info "missing git tags: ${missing[*]} (the reproduction step needs them; copy the repository"
		info "with 'git bundle create separ.bundle --all', see the header of this script)"
		return 1
	fi
}

if [ "$INSTALL" = 1 ]; then
	say "0. Machine"
	info "${PRETTY_NAME:-unknown OS}, kernel $(uname -r | grep -oE '^[0-9.]+'), $(nproc) CPUs, $(free -g | awk '/^Mem:/{print $2}') GB RAM"
	info "repository: branch $(git branch --show-current 2>/dev/null || echo '?'), commit $(git rev-parse --short HEAD 2>/dev/null || echo '?')"
	[ "$SYSTEM" = 1 ] && install_system
	if [ "$FALCO" = 1 ]; then
		install_falco || info "Falco could not be installed (download.falco.org may be down; try later). Continuing without it."
	fi
	make_venv
	check_tags || true
fi

[ "$RUN" = 1 ] || {
	say "Done (install only). Run the tests with: scripts/setup_test_machine.sh --run-only"
	exit 0
}

# ---- 3. the test run -----------------------------------------------------------------------------
[ -x "$PY" ] || die "no .venv yet: run without --run-only first"
export PATH="$VENV/bin:$PATH"
OUT=$ROOT/build/test-machine/$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
declare -a NAMES=() RESULTS=() TIMES=()

step() { # step NAME COMMAND... : runs it, logs to $OUT/NAME.log, records OK/FAIL and seconds
	local name=$1
	shift
	printf '   %-28s ' "$name"
	local t0=$SECONDS rc
	"$@" >"$OUT/$name.log" 2>&1
	rc=$?
	local dt=$((SECONDS - t0))
	NAMES+=("$name")
	TIMES+=("$dt")
	if [ $rc = 0 ]; then
		RESULTS+=(OK)
		printf '\033[32mOK\033[0m    %4ss\n' "$dt"
	else
		RESULTS+=("FAIL($rc)")
		printf '\033[31mFAIL\033[0m  %4ss  (see %s)\n' "$dt" "${OUT#"$ROOT"/}/$name.log"
	fi
}

say "3. Test run (logs in ${OUT#"$ROOT"/}/)"
step version separ --version
step lint-ruff "$PY" -m ruff check .
step lint-format "$PY" -m ruff format --check .
step tests "$PY" -m pytest -q
step privacy-audit "$PY" -m separ.audit tests/golden
step robustness-matrix "$PY" -m separ.variants --golden tests/golden --out "$OUT/robustness-matrix.csv"
step publishable "$PY" scripts/check_publishable.py
if check_tags >/dev/null; then
	# regenerates docs/results.md and docs/evaluation/; a diff afterwards means this machine differs
	step reproduce "$PY" scripts/reproduce.py --skip-tests
	# the numbers live in docs/evaluation/; docs/results.md always changes in its "tests" block
	# (--skip-tests) and its publishability block, so it is not compared
	git diff --stat -- docs/evaluation/ >"$OUT/reproduce-diff.txt" 2>&1
else
	info "reproduce: skipped (tags v2.3.1-base and v2.4 missing)"
fi
# all 35 Attack Lab templates (harmless stand-ins), in their own lab folder
step attack-lab separ lab --test-all --no-color --workdir "$OUT/attack-lab" --report-dir "$OUT/lab-runs"
step lab-reference "$PY" scripts/lab_reference_run.py --out "$OUT/lab-reference-run.json"
if [ "$LATEX" = 1 ] && command -v latexmk >/dev/null; then
	step paper make -C documentation numbers figures pdf
	step it-guides make -C it-service-desk
else
	info "paper and IT guides: skipped (no LaTeX)"
fi
[ "$PACKAGES" = 1 ] && step packages "$PY" packaging/build_packages.py --all
if [ "$FALCO" = 1 ] && command -v falco >/dev/null; then
	say "3b. Falco baseline (needs sudo; Falco runs only while the templates run)"
	sudo -v || die "sudo is needed for the Falco baseline"
	step falco-baseline sudo "$ROOT/scripts/falco_baseline.sh"
fi

# ---- 4. summary ----------------------------------------------------------------------------------
say "4. Summary"
{
	echo "machine: ${PRETTY_NAME:-unknown OS}, kernel $(uname -r | grep -oE '^[0-9.]+'), $(nproc) CPUs"
	echo "commit:  $(git rev-parse --short HEAD 2>/dev/null) on $(git branch --show-current 2>/dev/null)"
	echo "python:  $("$PY" --version 2>&1)"
	for i in "${!NAMES[@]}"; do printf '%-28s %-9s %5ss\n' "${NAMES[$i]}" "${RESULTS[$i]}" "${TIMES[$i]}"; done
} | tee "$OUT/summary.txt"
grep -E '[0-9]+ (passed|failed)' "$OUT/tests.log" | tail -n 1 | sed 's/^/   pytest: /'
if [ -s "$OUT/reproduce-diff.txt" ]; then
	info "reproduce changed committed evaluation data on this machine (git diff docs/evaluation/):"
	sed 's/^/     /' "$OUT/reproduce-diff.txt"
elif [ -f "$OUT/reproduce-diff.txt" ]; then
	info "reproduce: the committed evaluation data in docs/evaluation/ reproduced exactly"
fi
cat <<'EOF'

   Known on the development branch (not caused by this machine): the publishability check and the
   test test_the_repository_itself report the address in SEPAR_FIXES.md until that is resolved.

   Next, by hand (the IT guide explains each one):
     .venv/bin/separ lab                              the interactive Attack Lab (menu)
     .venv/bin/separ setup --laptop --mode observe    a per-user daemon in observe mode
     .venv/bin/separ gui                              the dashboard in the browser
     .venv/bin/separ health                           is the daemon alive and what is degraded
   `git status` shows the files this run regenerated; `git restore .` discards them.
EOF
