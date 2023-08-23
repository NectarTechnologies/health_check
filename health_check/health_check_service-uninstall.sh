#!/bin/bash

# Uncomment to debug script.
#set -x

SCRIPT_PATH=$(cd "$(dirname "${0}")" && pwd)
SCRIPT_NAME=$(basename "${0}")
VERSION="1.1"
COPYRIGHT_YEAR=$(date +%Y)
SERVICE_DISPLAY_NAME="Health Check Service"
SERVICE_NAME="health_check"
INSTALL_DIR="/opt/${SERVICE_NAME}_service"

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
systemctl stop ${SERVICE_NAME}.service

echo "Disabling ${SERVICE_DISPLAY_NAME} from starting at boot"
systemctl disable ${SERVICE_NAME}.service

echo "Removing ${SERVICE_DISPLAY_NAME} files"
rm /etc/systemd/system/${SERVICE_NAME}.service
rm -r ${INSTALL_DIR}

echo "Done"
echo ""

exit 0
