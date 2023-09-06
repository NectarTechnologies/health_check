"""
Health check utility class.
"""
import subprocess

from enum import Enum


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
