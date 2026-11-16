#!/bin/sh
# Separ - Installation Script for Linux (Servers and Laptops)
#
# Usage:
#   sudo ./install.sh        # System-wide installation (Servers / IT Admins)
#   ./install.sh             # User-level installation (~/.local for personal laptop)

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

echo "========================================================"
echo " Separ: Behavioral Reference Monitor & Incident Barrier"
echo "========================================================"

# Detect privilege level
if [ "$(id -u)" -eq 0 ]; then
    INSTALL_MODE="system"
    BIN_DIR="/usr/local/bin"
    SHARE_DIR="/usr/local/share/separ"
    DESKTOP_DIR="/usr/share/applications"
    ICON_DIR="/usr/share/icons/hicolor/scalable/apps"
    CONFIG_DIR="/etc/separ"
    SYSTEMD_DIR="/etc/systemd/system"
    echo "Installing system-wide (/usr/local, /etc/separ)..."
else
    INSTALL_MODE="user"
    BIN_DIR="${HOME}/.local/bin"
    SHARE_DIR="${HOME}/.local/share/separ"
    DESKTOP_DIR="${HOME}/.local/share/applications"
    ICON_DIR="${HOME}/.local/share/icons/hicolor/scalable/apps"
    CONFIG_DIR="${HOME}/.config/separ"
    SYSTEMD_DIR="${HOME}/.config/systemd/user"
    echo "Installing for current user (${HOME}/.local)..."
fi

# Ensure target directories exist
mkdir -p "${BIN_DIR}" "${SHARE_DIR}" "${DESKTOP_DIR}" "${ICON_DIR}" "${CONFIG_DIR}"

# 1. Install Python package modules
echo "Installing package modules into ${SHARE_DIR}..."
cp -r "${SCRIPT_DIR}/src/refmon" "${SHARE_DIR}/"
cp -r "${SCRIPT_DIR}/src/separ" "${SHARE_DIR}/"

# 2. Install executable launcher
echo "Installing executable launcher to ${BIN_DIR}/separ..."
cat << 'EOF' > "${BIN_DIR}/separ"
#!/bin/sh
# Separ Reference Monitor executable launcher
for py in python3.12 python3.11 python3.10 python3; do
    if command -v "$py" >/dev/null 2>&1; then
        if "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
            exec "$py" -c '
import sys
from pathlib import Path

# Search standard installed package locations
for candidate in (
    str(Path.home() / ".local/share/separ"),
    "/usr/local/share/separ",
    "/usr/share/separ",
    "/usr/share/refmon",
):
    if Path(candidate).is_dir() and candidate not in sys.path:
        sys.path.insert(0, candidate)

from refmon.cli import main
if __name__ == "__main__":
    sys.exit(main())
' "$@"
        fi
    fi
done
echo "Error: Separ requires Python >= 3.10 (e.g. python3.12). None found on PATH." >&2
exit 1
EOF
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
echo "Executable: ${BIN_DIR}/separ"
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
