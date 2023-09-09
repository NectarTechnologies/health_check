#!/bin/bash
#
# "LIVE" check example script.
#
# Return code is zero if the service is live, non-zero otherwise.
#
# Additional stdout and / or stderr output is acceptable but must be in JSON format.
#

SCRIPT_PATH=$(cd "$(dirname "${0}")" && pwd)
SCRIPT_NAME=$(basename "${0}")
VERSION="1.0"

# Check if the SSH daemon is running.
# - Filter out the grep command itself.
# - Throw away any output from this command, we only care about the return code in this example.
ps aux |grep /usr/sbin/sshd |grep -vE 'grep' 1>/dev/null 2>&1

exit $?
