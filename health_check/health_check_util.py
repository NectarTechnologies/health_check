"""
MIT License

Copyright (C) 2023 Nectar Technologies

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


##########################################################################################
Description:
  Health check utility class.
    This class is used to define the health check utility functions.
"""
import subprocess

from enum import Enum
from datetime import datetime, timezone, date  # pylint: disable=import-error,wrong-import-order


class HealthCheckUtil:  # pylint: disable=too-few-public-methods
    """
    Health check utility class.
    """
    SUCCESS = 0

    @staticmethod
    def run_command(cmd=None):
        """
        Runs an arbitrary cli command.
        :return: (tuple of string) A tuple of the return code of the script and the combined stdout and stderr.
        """
        return_code = None
        output = ""
        if cmd:
            with subprocess.Popen(
                    cmd,
                    shell=False,
                    bufsize=0,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT) as proc:
                while True:
                    _output_line = proc.stdout.readline().decode()
                    output = output + _output_line
                    if not _output_line and proc.poll() is not None:
                        break
                return_code = proc.poll()
        return output, return_code

    @staticmethod
    def get_iso8601_time_stamp(remove_colons=False):
        """
        Gets the current time stamp.
        :param remove_colons: (bool) If True, removes colons from the time stamp to make it compatible with
            Windows when used in a file name.
        :return: (string) The current time stamp.
        """
        # Generate an ISO 8601 conformant date-time stamp for the current time which also includes the timezone.
        datetime_iso8601 = datetime.now(timezone.utc).astimezone().isoformat()
        if remove_colons:
            # Remove colons from the time stamp to make it compatible with Windows when used in a file name.
            datetime_iso8601 = datetime_iso8601.replace(':', '')
        return datetime_iso8601


class LogLevel(Enum):  # pylint: disable=too-few-public-methods
    """
    Log levels. Used to control the verbosity of the log output.
    Order of log levels from highest to least verbose (top is most verbose):
        DEBUG
        INFO
        WARNING
        ERROR
    """
    DEBUG = 1, 'DEBUG'
    INFO = 2, 'INFO'
    WARNING = 3, 'WARNING'
    ERROR = 4, 'ERROR'
