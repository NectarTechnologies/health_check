#!/bin/bash
#
# This script will check that all the required processes are responding properly (aka "READY").
#
# Return code is zero if the service is "ready", non-zero otherwise.
#
# Additional stdout and / or stderr output is acceptable but must be in JSON format.
#

SCRIPT_PATH=$(cd "$(dirname "${0}")" && pwd)
SCRIPT_NAME=$(basename "${0}")
VERSION="1.0"

function output_json() {
    _MSG="${1}"
    echo "{\"msg\": \"${_MSG}\"}"
}

# TODO: Perform service or app specific checks to determine if the service is "ready".
#       In the case of "not ready" also return a non-zero exit code.

# For now just return "ready".
output_json "App is ready and responsive"
exit 0
