#!/bin/sh
# Separ - Installation Script for Linux (Servers and Laptops)
#
# Usage:
#   sudo ./install.sh [--wheels DIR]   # system-wide: /opt/separ/venv, /usr/local/bin, /etc/separ
#   ./install.sh [--wheels DIR]        # this user: ~/.local/share/separ/venv, ~/.local/bin
#
# Separ needs Python >= 3.12 and runs from a private venv built from vendored, hash-pinned wheels
# (no internet, never the distribution's pydantic). DIR defaults to dist/wheels-<arch>, made with:
#   python3.12 packaging/build_packages.py --wheels-only

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
case "$(uname -m)" in
    aarch64|arm64) ARCH=arm64 ;;
    *) ARCH=amd64 ;;
esac
WHEELS="${SCRIPT_DIR}/dist/wheels-${ARCH}"
while [ $# -gt 0 ]; do
    case "$1" in
        --wheels) WHEELS="$2"; shift 2 ;;
        --wheels=*) WHEELS="${1#--wheels=}"; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

echo "========================================================"
echo " Separ: Behavioral Reference Monitor & Incident Barrier"
echo "========================================================"

# Detect privilege level
if [ "$(id -u)" -eq 0 ]; then
    INSTALL_MODE="system"
    PREFIX="/opt/separ"
    BIN_DIR="/usr/local/bin"
    DESKTOP_DIR="/usr/share/applications"
    ICON_DIR="/usr/share/icons/hicolor/scalable/apps"
    CONFIG_DIR="/etc/separ"
    SYSTEMD_DIR="/etc/systemd/system"
    echo "Installing system-wide (${PREFIX}, /usr/local/bin, /etc/separ)..."
else
    INSTALL_MODE="user"
    PREFIX="${HOME}/.local/share/separ"
    BIN_DIR="${HOME}/.local/bin"
    DESKTOP_DIR="${HOME}/.local/share/applications"
    ICON_DIR="${HOME}/.local/share/icons/hicolor/scalable/apps"
    CONFIG_DIR="${HOME}/.config/separ"
    SYSTEMD_DIR="${HOME}/.config/systemd/user"
    echo "Installing for current user (${PREFIX})..."
fi

if [ ! -f "${WHEELS}/requirements-cp312.txt" ]; then
    echo "No vendored wheels in ${WHEELS}." >&2
    echo "Make them once (on any machine with Python 3.12 and internet):" >&2
    echo "  python3.12 packaging/build_packages.py --wheels-only --arch ${ARCH}" >&2
    echo "then run: $0 --wheels dist/wheels-${ARCH}" >&2
    exit 1
fi

# Ensure target directories exist
mkdir -p "${PREFIX}" "${BIN_DIR}" "${DESKTOP_DIR}" "${ICON_DIR}" "${CONFIG_DIR}"
chmod 755 "${CONFIG_DIR}"

# 1. The private venv from the vendored wheels (Python >= 3.12; no internet)
echo "Creating the private venv in ${PREFIX}/venv from ${WHEELS}..."
SEPAR_PREFIX="${PREFIX}" SEPAR_WHEELS="${WHEELS}" sh "${SCRIPT_DIR}/packaging/install-venv.sh"

# 2. Install executable launcher
echo "Installing executable launcher to ${BIN_DIR}/separ..."
printf '#!/bin/sh\n# Separ launcher: the private venv made by install.sh\nexec "%s/venv/bin/separ" "$@"\n' \
    "${PREFIX}" > "${BIN_DIR}/separ"
chmod 755 "${BIN_DIR}/separ"
ln -sf separ "${BIN_DIR}/refmon" 2>/dev/null || true

# 3. Install Desktop Launcher & Icon
echo "Installing desktop launcher to ${DESKTOP_DIR}/separ.desktop..."
if [ -f "${SCRIPT_DIR}/packaging/separ.desktop" ]; then
    cp "${SCRIPT_DIR}/packaging/separ.desktop" "${DESKTOP_DIR}/separ.desktop"
    chmod 644 "${DESKTOP_DIR}/separ.desktop"
fi
if [ -f "${SCRIPT_DIR}/packaging/separ.svg" ]; then
    cp "${SCRIPT_DIR}/packaging/separ.svg" "${ICON_DIR}/separ.svg"
    chmod 644 "${ICON_DIR}/separ.svg"
fi
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "${DESKTOP_DIR}" 2>/dev/null || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -f -t "$(dirname "${ICON_DIR}")" 2>/dev/null || true

# 4. Install Initial Configuration & Mappings
echo "Setting up configuration in ${CONFIG_DIR}..."
if [ -d "${SCRIPT_DIR}/packaging/etc/separ" ]; then
    cp -r "${SCRIPT_DIR}/packaging/etc/separ/"* "${CONFIG_DIR}/" 2>/dev/null || true
fi
mkdir -p "${CONFIG_DIR}/mappings"
if [ -d "${SCRIPT_DIR}/src/refmon/ingest/mappings" ]; then
    cp "${SCRIPT_DIR}/src/refmon/ingest/mappings/"*.yaml "${CONFIG_DIR}/mappings/" 2>/dev/null || true
fi

# 5. Install Systemd Service
if [ "${INSTALL_MODE}" = "system" ] && [ -d "${SYSTEMD_DIR}" ]; then
    if [ -f "${SCRIPT_DIR}/packaging/system/separ.service" ]; then
        cp "${SCRIPT_DIR}/packaging/system/separ.service" "${SYSTEMD_DIR}/separ.service"
        chmod 644 "${SYSTEMD_DIR}/separ.service"
        command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload 2>/dev/null || true
    fi
elif [ "${INSTALL_MODE}" = "user" ]; then
    mkdir -p "${SYSTEMD_DIR}"
    if [ -f "${SCRIPT_DIR}/packaging/browser/separ-user.service" ]; then
        cp "${SCRIPT_DIR}/packaging/browser/separ-user.service" "${SYSTEMD_DIR}/separ-user.service"
        chmod 644 "${SYSTEMD_DIR}/separ-user.service"
    fi
fi

echo ""
echo "========================================================"
echo " Installation Complete!"
echo "========================================================"
echo "Executable: ${BIN_DIR}/separ (private venv: ${PREFIX}/venv)"
echo "Config dir: ${CONFIG_DIR}"
echo ""
echo "Next Steps:"
echo "  1. Define and sign your policy:"
echo "     separ setup"
echo "  2. Launch the desktop GUI monitor:"
echo "     separ gui  (or click 'Separ' in your Application Menu)"
echo "  3. On servers, start background service:"
echo "     sudo systemctl enable --now separ.service"
echo "========================================================"
