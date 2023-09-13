#!/bin/bash

# Uncomment to debug script.
#set -x

SCRIPT_PATH=$(cd "$(dirname "${0}")" && pwd)
SCRIPT_NAME=$(basename "${0}")
VERSION="1.36"
COPYRIGHT_YEAR=$(date +%Y)
SERVICE_DISPLAY_NAME="Health Check Service"
SERVICE_NAME="health_check"
CONF_FILE_NAME="${SERVICE_NAME}.conf"
CONF_DIR="/etc/${SERVICE_NAME}"
INSTALL_DIR="/opt/${SERVICE_NAME}"
CHECK_SCRIPTS_DIR="${INSTALL_DIR}/check_scripts"
IGNORE_SERVICE_START_FAILURES="false"
NO_WAIT_TIME_OUT="false"
EXTRA_ARGS=""

SERVICE_SCRIPT_DIR="/etc/init.d"
SERVICE_SCRIPT_SRC_NAME="${SERVICE_NAME}__service"
SERVICE_SCRIPT_SRC="${SCRIPT_PATH}/${SERVICE_SCRIPT_SRC_NAME}"
SERVICE_SCRIPT_DST_NAME=${SERVICE_NAME}
SERVICE_SCRIPT_DST="${SERVICE_SCRIPT_DIR}/${SERVICE_SCRIPT_DST_NAME}"

SYSTEMCTL_DIR="/etc/systemd/system"
SYSTEMCTL_SCRIPT_SRC_NAME="${SERVICE_NAME}__systemctl"
SYSTEMCTL_SCRIPT_SRC="${SCRIPT_PATH}/${SYSTEMCTL_SCRIPT_SRC_NAME}"
SYSTEMCTL_SCRIPT_DST_NAME="${SERVICE_NAME}.service"
SYSTEMCTL_SCRIPT_DST="${SYSTEMCTL_DIR}/${SYSTEMCTL_SCRIPT_DST_NAME}"

function check_dir() {
    DIR="${1}"
    if [[ ! -d "${DIR}" ]]; then
        echo "Creating directory: \"${DIR}\""
        mkdir -p ${DIR}
    fi
}

function is_systemctl_installed() {
    sudo systemctl 1>/dev/null 2>&1
    if [[ "$?" -eq "0" ]]; then
        echo 1
    else
        echo 0
    fi
}

function show_banner() {
    echo "----------------------------------------------------------------------"
    echo " ${SERVICE_DISPLAY_NAME} installer"
    echo " Script version: ${VERSION}"
    echo " (C) ${COPYRIGHT_YEAR}"
}

function show_usage() {
    show_banner
    echo ""
    echo "usage: ${SCRIPT_NAME} [-h] [-w WORKING_DIR] [--version]"
    echo ""
    echo "Adds container names to /etc/hosts file."
    echo ""
    echo "options:"
    echo "  -h, --help               Show this help message and exit."
    echo "  -i, --ignore_service_start_failures"
    echo "                           Ignore service start failures."
    echo "  -v, --version            Show version information and exit."
    echo ""
}

# Parse command line args.
while (( "$#" )); do
    case "$1" in
        -h|--help)
            show_usage
            shift;;
        -i|--ignore_service_start_failures)
            IGNORE_SERVICE_START_FAILURES="true"
            shift;;
        -n|--no_wait_timeout)
            NO_WAIT_TIME_OUT="true"
            shift;;
        -v|--version)
            show_banner
            shift;;
        # Catch all other args so that we can pass them along.
	      *)
            ALL_OTHER_ARGS="${ALL_OTHER_ARGS} ${1}";
            shift;;
    esac
done

if [ "$EUID" -ne 0 ]
    then echo "Please run as root"
    exit 1
fi

show_banner

echo ""
check_dir "${INSTALL_DIR}/"
echo "Coping files to ${INSTALL_DIR}/"
cp ${SCRIPT_PATH}/favicon.ico ${INSTALL_DIR}/
cp ${SCRIPT_PATH}/health_check* ${INSTALL_DIR}/
check_dir "${CHECK_SCRIPTS_DIR}"
cp ${SCRIPT_PATH}/check_scripts/* ${CHECK_SCRIPTS_DIR}/
echo "Setting 'execute' permissions on: ${CHECK_SCRIPTS_DIR}/*"
chmod -R +x ${CHECK_SCRIPTS_DIR}/*

echo ""
check_dir "${CONF_DIR}/"
echo "Coping ${SCRIPT_PATH}/${CONF_FILE_NAME} --> ${CONF_DIR}/${CONF_FILE_NAME}"
cp ${SCRIPT_PATH}/${CONF_FILE_NAME} ${CONF_DIR}/${CONF_FILE_NAME}
echo "Setting permissions on: ${CONF_DIR}/${CONF_FILE_NAME}"
chmod 644 ${CONF_DIR}/${CONF_FILE_NAME}

echo ""
echo "Coping ${SYSTEMCTL_SCRIPT_SRC} --> ${SYSTEMCTL_SCRIPT_DST}"
cp ${SYSTEMCTL_SCRIPT_SRC} ${SYSTEMCTL_SCRIPT_DST}
echo "Setting permissions on: ${SYSTEMCTL_SCRIPT_DST}"
chmod 644 ${SYSTEMCTL_SCRIPT_DST}

echo ""
echo "Coping ${SERVICE_SCRIPT_SRC} --> ${SERVICE_SCRIPT_DST}"
cp ${SERVICE_SCRIPT_SRC} ${SERVICE_SCRIPT_DST}
echo "Setting permissions on: ${SERVICE_SCRIPT_DST}"
chmod 755 ${SERVICE_SCRIPT_DST}

if [[ "$(is_systemctl_installed)" == "1" ]]; then
    echo "Enabling the ${SERVICE_DISPLAY_NAME} to start automatically at boot"
    systemctl daemon-reload
    systemctl enable ${SYSTEMCTL_SCRIPT_DST_NAME}
    systemctl start ${SYSTEMCTL_SCRIPT_DST_NAME}
else
    echo ""
    echo "IMPORTANT: systemctl is not installed so ${SERVICE_DISPLAY_NAME} will not start"
    echo "           automatically at boot but can be started manually with this command:"
    echo "               sudo service ${SERVICE_SCRIPT_DST_NAME} start"
    echo ""
    if [[ "${IGNORE_SERVICE_START_FAILURES}" == "true" ]]; then
        echo "Ignoring service start failures."
        EXTRA_ARGS="${EXTRA_ARGS} --ignore_service_start_failures"
    fi

    if [[ "${NO_WAIT_TIME_OUT}" == "true" ]]; then
        echo "Setting start wait to zero."
        EXTRA_ARGS="${EXTRA_ARGS} --no_wait_timeout"
    fi
    service ${SERVICE_SCRIPT_DST_NAME} start ${EXTRA_ARGS}
    if [[ $? -ne 0 ]]; then
        echo "ERROR: Installer failed to start ${SERVICE_DISPLAY_NAME}"
        exit 1
    fi
fi

echo ""
echo "To connect to the ${SERVICE_DISPLAY_NAME} server console session use this command:"
echo "  sudo tmux attach -d -t ${SERVICE_NAME}_service"
echo ""

exit 0
