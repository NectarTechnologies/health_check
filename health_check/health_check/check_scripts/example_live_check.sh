#!/bin/bash
#
# This script will check that all the required processes are running (aka "LIVE").
#
# Return code is zero if the service is live, non-zero otherwise.
#
# Additional stdout and / or stderr output is acceptable but must be in JSON format.
#

SCRIPT_PATH=$(cd "$(dirname "${0}")" && pwd)
SCRIPT_NAME=$(basename "${0}")
VERSION="1.1"

MAIN_SERVICE_NAME="Foo Bar Service"

function process_is_running() {
    PROCESS_1="${1}"
    PROCESS_2="${2}"
    if [[ "${PROCESS_2}" == "" ]]; then
        PROCESS_2="${PROCESS_1}" # Works the same with 2 params.
    fi

    if ps aux |grep ${PROCESS_1} |grep -v grep |grep ${PROCESS_2}; then
        # Is running.
        echo 1
    else
        # Is not running.
        echo 0
    fi
}

function tmux_session_exists() {
    SESSION="${1}"
    if tmux list-sessions 2>&1 |grep ${SESSION}; then
        echo 1
    else
        echo 0
    fi
}

function output_json() {
    _MSG="${1}"
    echo "{\"msg\": \"${_MSG}\"}"
}

# EXAMPLE 1:
#   Check if a single process is running, in this case the SSH daemon.
PROCESS_1="/usr/sbin/sshd"
if [[ "$(process_is_running ${PROCESS_1})" == "0" ]]; then
    output_json "Service not running: ${PROCESS_1}"
    exit 1
fi

# EXAMPLE 2:
#   Check if a specific tmux session is running.
#TMUX_SESSION_NAME="foo-bar"
#if [[ "$(tmux_session_exists ${TMUX_SESSION_NAME})" == "0" ]]; then
#    output_json "Process not running: ${MAIN_SERVICE_NAME} (tmux session not running: ${TMUX_SESSION_NAME})"
#    exit 1
#fi

# EXAMPLE 3:
#   Check if two processes are running, in this case, python and an app called foobar2000.py.
#PROCESS_1="python"
#PROCESS_2="foobar2000.py"
#if [[ "$(process_is_running ${PROCESS_1} ${PROCESS_2})" == "0" ]]; then
#    output_json "Service not running: ${MAIN_SERVICE_NAME} (Process ${PROCESS_1} not running.)"
#    exit 1
#fi

output_json "All processes are running."

exit 0
