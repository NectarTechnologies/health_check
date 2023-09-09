#!/bin/bash
#
# This script will check that all the required processes are responding properly (aka "HEALTHY").
#
# Return code is zero if the service is "healthy", non-zero otherwise.
#
# Additional stdout and / or stderr output is acceptable but must be in JSON format.
#

SCRIPT_PATH=$(cd "$(dirname "${0}")" && pwd)
SCRIPT_NAME=$(basename "${0}")
VERSION="1.1"

# TODO: Implement "uptime" stats.
echo "{" \
    "\"system_load\": \"$(uptime |awk -F ":" '{print $5}' |xargs)\"," \
    "\"uptime\": \"\"," \
    "\"cpu\": {" \
        "\"model\": \"$(cat /proc/cpuinfo |grep 'model name' |uniq |awk -F ":" '{print $2}' |xargs)\"," \
        "\"core_count\": \"$(nproc)\"," \
        "\"idle_percent\": \"$(mpstat |grep all |awk '{print $12}')\"," \
        "\"iowait_percent\": \"$(mpstat |grep all |awk '{print $6}')\"," \
        "\"user_percent\": \"$(mpstat |grep all |awk '{print $3}')\"," \
        "\"system_percent\": \"$(mpstat |grep all |awk '{print $5}')\"" \
    "}," \
    "\"memory\": {" \
        "\"total_gb\": \"$(free -m |grep Mem |awk '{print $2}')\"," \
        "\"used_gb\": \"$(free -m |grep Mem |awk '{print $3}')\"," \
        "\"free_gb\": \"$(free -m |grep Mem |awk '{print $4}')\"" \
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