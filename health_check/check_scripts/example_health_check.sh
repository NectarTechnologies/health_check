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
################################################################################
# Description:
#   This script will check that all the required processes are responding properly (aka "HEALTHY").
#
#   Return code is zero if the service is "healthy", non-zero otherwise.
#
#   Additional stdout and / or stderr output is acceptable but must be in JSON format.
#

SCRIPT_PATH=$(cd "$(dirname "${0}")" && pwd)
SCRIPT_NAME=$(basename "${0}")
VERSION="1.8"

function what_os() {
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "mac"
    else
        echo "linux"
    fi
}

UPTIME_DAYS=$(uptime |awk -F " up " '{split($0,a); print a[2]}' |awk -F "," '{split($0,b); print b[1]}')
UPTIME_HR_MIN=$(uptime |awk -F " up " '{split($0,a); print a[2]}' |awk -F "," '{split($0,b); print b[2]}')
if [[ "${UPTIME_HR_MIN}" == *"users"* ]]; then
    UPTIME_HR_MIN=${UPTIME_DAYS}
    UPTIME_DAYS=""
    SYSTEM_LOAD=$(uptime |awk -F ":" '{print $4}' |xargs)
else
     UPTIME_DAYS="${UPTIME_DAYS},"
     SYSTEM_LOAD=$(uptime |awk -F ":" '{print $5}' |xargs)
fi

if [[ "$(what_os)" == "mac" ]]; then
    CPU_NAME=$(system_profiler SPHardwareDataType |grep "Processor Name" |awk -F ": " '{print $2}')
    CPU_HZ=$(system_profiler SPHardwareDataType |grep "Processor Speed" |awk -F ": " '{print $2}')
    CPU_MODEL="${CPU_NAME} @ ${CPU_HZ}"
    CPU_CORES=$(system_profiler SPHardwareDataType |grep "Total Number of Cores" |awk -F ": " '{print $2}')
    CPU_IDLE=""
    CPU_IOWAIT=""
    CPU_USER=""
    CPU_SYSTEM=$(top -R -F -n 0 -l 2 -s 0 | grep -E "^CPU" | tail -1 | awk '{ print $3 + $5"%" }' |awk -F "%" '{print $1}')

    # TODO: Add that same CPU stats that are being collected for Linux.
    echo "{" \
    "\"system_load\": \"${SYSTEM_LOAD}\"," \
    "\"uptime\": \"${UPTIME_DAYS}${UPTIME_HR_MIN}\"," \
    "\"cpu\": {" \
        "\"model\": \"${CPU_MODEL}}\"," \
        "\"core_count\": \"${CPU_CORES}\"," \
        "\"usage_percent\": {" \
          "\"system\": \"${CPU_SYSTEM}\"" \
        "}" \
    "}" \
"}"

else
    CPU_MODEL=$(cat /proc/cpuinfo |grep 'model name' |uniq |awk -F ":" '{print $2}' |xargs)
    CPU_CORES=$(nproc)
    CPU_IDLE=$(mpstat |grep all |awk '{print $12}')
    CPU_IOWAIT=$(mpstat |grep all |awk '{print $6}')
    CPU_USER=$(mpstat |grep all |awk '{print $3}')
    CPU_SYSTEM=$(mpstat |grep all |awk '{print $5}')
    echo "{" \
    "\"system_load\": \"${SYSTEM_LOAD}\"," \
    "\"uptime\": \"${UPTIME_DAYS}${UPTIME_HR_MIN}\"," \
    "\"cpu\": {" \
        "\"model\": \"${CPU_MODEL}}\"," \
        "\"core_count\": \"${CPU_CORES}\"," \
        "\"usage_percent\": {" \
          "\"idle\": \"${CPU_IDLE}\"," \
          "\"iowait\": \"${CPU_IOWAIT}\"," \
          "\"user\": \"${CPU_USER}\"," \
          "\"system\": \"${CPU_SYSTEM}\"" \
        "}" \
    "}," \
    "\"memory\": {" \
        "\"total_mb\": \"$(free -m |grep Mem |awk '{print $2}')\"," \
        "\"used_mb\": \"$(free -m |grep Mem |awk '{print $3}')\"," \
        "\"free_mb\": \"$(free -m |grep Mem |awk '{print $4}')\"" \
    "}," \
    "\"disk\": {" \
        "\"free\": \"$(df -h / |awk '{print $4}' |grep -vE 'Size|Used|Avail')\"" \
    "}" \
"}"
fi

# TODO: Add additional app-specific data / stats.

# TODO: Add any checks what would cause this service to be "unhealthy".

# TODO: Additional ideas of additional app-specific data to include:
# - Average response time
# - Number of requests
# - Number of errors
# - Number of timeouts
# - Number of retries
# - Number of failures
# - Number of successes
# - Number of connections
# - Number of open files
# - Number of threads
# - Number of processes
# - Number of sockets
# - Number of connections
# - etc.

# TODO: In the case of "unhealthy" also return a non-zero exit code.

exit 0
