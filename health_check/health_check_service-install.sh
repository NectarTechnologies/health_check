#!/bin/bash

# Uncomment to debug script.
#set -x

SCRIPT_PATH=$(cd "$(dirname "${0}")" && pwd)
SCRIPT_NAME=$(basename "${0}")
VERSION="1.0"
COPYRIGHT_YEAR=$(date +%Y)
SERVICE_DISPLAY_NAME="Health Check Service"
SERVICE_NAME="health_check"
INSTALL_DIR="/opt/${SERVICE_NAME}_service"

function check_dir() {
    DIR="${1}"
    if [[ ! -d "${DIR}" ]]; then
        echo "Creating directory: \"${DIR}\""
        mkdir -p ${DIR}
    fi
}

echo "----------------------------------------------------------------------"
echo " ${SERVICE_DISPLAY_NAME} installer"
echo " Script version: ${VERSION}"
echo " (C) ${COPYRIGHT_YEAR}"
echo ""

if [ "$EUID" -ne 0 ]
    then echo "Please run as root"
    exit 1
fi

check_dir "${INSTALL_DIR}/"

echo "Coping ${SERVICE_DISPLAY_NAME} files"
cp ${SCRIPT_PATH}/${SERVICE_NAME}.service /etc/systemd/system/${SERVICE_NAME}.service
cp ${SCRIPT_PATH}/health_check_service.py ${INSTALL_DIR}/
cp ${SCRIPT_PATH}/health_check_client.py ${INSTALL_DIR}/
cp ${SCRIPT_PATH}/health_check_types.py ${INSTALL_DIR}/
cp ${SCRIPT_PATH}/health_check_types_enum.py ${INSTALL_DIR}/
cp ${SCRIPT_PATH}/favicon.ico ${INSTALL_DIR}/

echo "Setting ${SERVICE_DISPLAY_NAME} permissions"
chmod 664 /etc/systemd/system/${SERVICE_NAME}.service

echo "Enabling the ${SERVICE_DISPLAY_NAME} to start automatically at boot"
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}.service

echo "Starting the ${SERVICE_DISPLAY_NAME}"
systemctl start ${SERVICE_NAME}.service

echo "Done"
echo ""
echo "To connect to the ${SERVICE_DISPLAY_NAME} server console session use this command:"
echo "  sudo tmux attach -d -t ${SERVICE_NAME}"
echo ""

exit 0