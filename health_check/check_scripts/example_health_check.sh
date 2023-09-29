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
VERSION="1.6"

UPTIME_DAYS=$(uptime |awk -F " up " '{split($0,a); print a[2]}' |awk -F "," '{split($0,b); print b[1]}')
UPTIME_HR_MIN=$(uptime |awk -F " up " '{split($0,a); print a[2]}' |awk -F "," '{split($0,b); print b[2]}')
if [[ "${UPTIME_HR_MIN}" == *"users"* ]]; then
    UPTIME_HR_MIN=${UPTIME_DAYS}
    UPTIME_DAYS=""
else
     UPTIME_DAYS="${UPTIME_DAYS},"
fi

# TODO: Implement "uptime" stats.
echo "{" \
    "\"system_load\": \"$(uptime |awk -F ":" '{print $5}' |xargs)\"," \
    "\"uptime\": \"${UPTIME_DAYS}${UPTIME_HR_MIN}\"," \
    "\"cpu\": {" \
        "\"model\": \"$(cat /proc/cpuinfo |grep 'model name' |uniq |awk -F ":" '{print $2}' |xargs)\"," \
        "\"core_count\": \"$(nproc)\"," \
        "\"idle_percent\": \"$(mpstat |grep all |awk '{print $12}')\"," \
        "\"iowait_percent\": \"$(mpstat |grep all |awk '{print $6}')\"," \
        "\"user_percent\": \"$(mpstat |grep all |awk '{print $3}')\"," \
        "\"system_percent\": \"$(mpstat |grep all |awk '{print $5}')\"" \
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

# TODO: Add additional app-specific data / stats.

# TODO: Add any checks what would cause this service to be "unhealthy".
#       In the case of "unhealthy" also return a non-zero exit code.

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

exit 0
