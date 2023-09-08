#!/bin/bash

# Uncomment to debug script.
#set -x

SCRIPT_PATH=$(cd "$(dirname "${0}")" && pwd)
SCRIPT_NAME=$(basename "${0}")
VERSION="1.8"
COPYRIGHT_YEAR=$(date +%Y)
SERVICE_DISPLAY_NAME="Health Check Service"
SERVICE_NAME="health_check"
INSTALL_DIR="/opt/${SERVICE_NAME}"
CONF_DIR="/etc/${SERVICE_NAME}"

SERVICE_SCRIPT_DIR="/etc/init.d"
SERVICE_SCRIPT_DST_NAME=${SERVICE_NAME}
SERVICE_SCRIPT_DST="${SERVICE_SCRIPT_DIR}/${SERVICE_SCRIPT_DST_NAME}"

SYSTEMCTL_DIR="/etc/systemd/system"
SYSTEMCTL_SCRIPT_DST_NAME="${SERVICE_NAME}.service"
SYSTEMCTL_SCRIPT_DST="${SYSTEMCTL_DIR}/${SYSTEMCTL_SCRIPT_DST_NAME}"

function is_systemctl_installed() {
    sudo systemctl 1>/dev/null 2>&1
    if [[ "$?" -eq "0" ]]; then
        echo 1
    else
        echo 0
    fi
}

echo "----------------------------------------------------------------------"
echo " ${SERVICE_DISPLAY_NAME} uninstaller"
echo " Script version: ${VERSION}"
echo " (C) ${COPYRIGHT_YEAR}"
echo ""

if [ "$EUID" -ne 0 ]
    then echo "Please run as root"
    exit 1
fi

echo "Stopping ${SERVICE_DISPLAY_NAME}"
if [[ "$(is_systemctl_installed)" == "1" ]]; then
    systemctl stop ${SYSTEMCTL_SCRIPT_DST_NAME}

    echo "Disabling ${SERVICE_DISPLAY_NAME} from starting at boot"
    systemctl disable ${SYSTEMCTL_SCRIPT_DST_NAME}
else
    service ${SERVICE_SCRIPT_DST_NAME} stop
fi

echo "Removing ${SERVICE_DISPLAY_NAME} files"
rm ${SYSTEMCTL_SCRIPT_DST}
rm ${SERVICE_SCRIPT_DST}
rm -r ${INSTALL_DIR}
rm -r ${CONF_DIR}

echo ""

exit 0
