#!/bin/bash
# MIT License
#
# Copyright (C) 2023 Nectar Technologies
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
####################################################################################################
# Description:
#   Initializes the test environment.
#   Adds bash_profile_include.sh to .bashrc (or .bash_profile)
#   Adds aliases to .bashrc (or .bash_profile)

SCRIPT_PATH=$(cd "$(dirname "${0}")" && pwd)
SCRIPT_NAME=$(basename "${0}")
VERSION="1.3"

PROJECT_NAME="health_check"
REPO_NAME="health_check"
SRC_CONTROL="github.com"
ORG_NAME="NectarTechnologies"

_OS=""

TMUX_SESSION_NAME="${PROJECT_NAME}-initialization"

LOGIN_SCRIPT_LINUX="${HOME}/.bashrc"
LOGIN_SCRIPT_MAC="${HOME}/.bash_profile"
LOGIN_SCRIPT=""

ENV_FILE_SUFFIX_MAC="mac"
ENV_FILE_SUFFIX_LINUX="linux"
ENV_FILE_SUFFIX=""

WORKSPACE_BASE_DIR="${HOME}/workspace"

# For use when running on host machine.
PROJECT_ENV_FILE=""  # Gets set later.

function show_banner() {
    echo "======================================================================"
    echo " ${SCRIPT_NAME}, Version ${VERSION}"
    echo " OS: \"${_OS}\""
    echo "======================================================================"
}

function update_login_script() {
    LOGIN_SCRIPT=${1}
    if [[ "$(grep ${BASH_ENV_SCRIPT} ${LOGIN_SCRIPT})" == "" ]]; then
        echo ""
        echo "Updating ${LOGIN_SCRIPT} with a line for \"${BASH_ENV_SCRIPT}\""
        echo "" >> ${LOGIN_SCRIPT}
        echo "pushd ${BASH_ENV_SCRIPT_PATH} 1>/dev/null 2>&1" >> ${LOGIN_SCRIPT}
        echo ". ${BASH_ENV_SCRIPT}" >> ${LOGIN_SCRIPT}
        echo "popd 1>/dev/null 2>&1" >> ${LOGIN_SCRIPT}
        echo "" >> ${LOGIN_SCRIPT}
    fi
}

function find_and_update_login_script() {
    if [[ -f "${LOGIN_SCRIPT}" ]]; then
        update_login_script ${LOGIN_SCRIPT}
    else
        echo "Could not find \"${LOGIN_SCRIPT}\" to update it."
        exit 1
    fi
}

function tmux_kill_session() {
    tmux kill-session -t ${TMUX_SESSION_NAME} 2>/dev/null
}

function tmux_start_session() {
    tmux new-session -d -s ${TMUX_SESSION_NAME}
}

function tmux_execute_cmd() {
    CMD=${1}
    tmux send-keys -t ${TMUX_SESSION_NAME} "${CMD}"
    tmux send-keys -t ${TMUX_SESSION_NAME} "Enter"
}

function tmux_wait_for_session_to_exit() {
    sleep 0.5
    while [[ "$(tmux list-sessions 2>&1 |grep ${TMUX_SESSION_NAME})" != "" ]]; do
        sleep 0.5
    done
}

# Check if workspace directory exists.
if [ -d "${WORKSPACE_BASE_DIR}" ]; then
    echo "Found \"${WORKSPACE_BASE_DIR}\""
else
    echo "Cannot find \"${WORKSPACE_BASE_DIR}\""
    echo "Cannot proceed."
    exit 1
fi

# Determine if we're running on Linux or Mac.
if [[ "$(uname)" == "Darwin" ]]; then
    LOGIN_SCRIPT=${LOGIN_SCRIPT_MAC}
    ENV_FILE_SUFFIX=${ENV_FILE_SUFFIX_MAC}
    _OS="mac"
else
    LOGIN_SCRIPT=${LOGIN_SCRIPT_LINUX}
    ENV_FILE_SUFFIX=${ENV_FILE_SUFFIX_LINUX}
    _OS="linux"
fi

show_banner

SRC_REPO_DIR="${WORKSPACE_BASE_DIR}/src/${SRC_CONTROL}/${ORG_NAME}/${REPO_NAME}"
PROJECT_ENV_FILE="${SRC_REPO_DIR}/.env"

BASH_ENV_SCRIPT_PATH="${SRC_REPO_DIR}/setup"
BASH_ENV_SCRIPT="${BASH_ENV_SCRIPT_PATH}/bash_profile_include.sh"

INIT_COMMAND="init_${PROJECT_NAME}"

ENV_FILE="${WORKSPACE_BASE_DIR}/.env.${PROJECT_NAME}.${ENV_FILE_SUFFIX}"

echo "Copying environment variables from ${ENV_FILE} to: ${PROJECT_ENV_FILE}"
cp ${ENV_FILE} ${PROJECT_ENV_FILE}

echo "Exporting environment variables from: ${ENV_FILE}"
export $(grep -v '^#' "${ENV_FILE}" | xargs)

# Kill any leftover tmux session.
tmux_kill_session

echo ""
echo "-----------------------------------------------------------------------------------------"
echo "Setting up environment"

echo ""
echo "Changing to repo directory \"${SRC_REPO_DIR}\""
pushd ${SRC_REPO_DIR} 1>/dev/null 2>&1

popd 1>/dev/null 2>&1

find_and_update_login_script

echo ""
echo "Setup complete"
echo ""
echo ""
echo "New aliases for the \"${PROJECT_NAME}\" repo:"
echo "  To initialize the new virtual environment (already done): \"init_${PROJECT_NAME}\""
echo "  To activate (enter) the new virtual environment         : \"act_${PROJECT_NAME}\""
echo "  To deactivate (leave) the new virtual environment       : \"deact\""
echo ""

INIT_LOG="${WORKSPACE_BASE_DIR}/${INIT_COMMAND}.log"
echo ""
echo "-----------------------------------------------------------------------------------------"
echo "Initializing test environment (for details, see: ${INIT_LOG})"
# Start a new tmux session so that we can load the new env vars.
tmux_start_session
# This will also exit the tmux session
tmux_execute_cmd "${INIT_COMMAND} 2>&1 |tee ${INIT_LOG} && exit"
tmux_wait_for_session_to_exit

echo ""
echo "To load the new env settings please logout and start a new terminal session."
echo ""

exit 0
