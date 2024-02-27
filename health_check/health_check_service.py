# pylint: disable=fixme
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


################################################################################
Description:
  Simple, lightweight service to allow for TCP and HTTP health checks and additional custom checks.
  Primarily used for health checks of microservices inside containers but can be used for bare metal servers too.

TODO: Implement logging to a file in addition to the stdout (default to /var/blah-blah-blah.log).
TODO: Implement log rotation so log files do not fill the disk.
TODO: Implement a cli flag to specify the log file name and path.
TODO: Implement a "push" mode where the service will push the health check status to a remote server.
TODO: Implement ability to configure log levels for remote logging server independently of local log levels.
"""

import os
import sys
import socket
import argparse
import traceback
import json
import platform
import configparser

from datetime import date  # pylint: disable=import-error,wrong-import-order
from time import sleep  # pylint: disable=import-error,wrong-import-order
from health_check_types import (HealthCheckVersion, HealthCheckTcp,  # pylint: disable=import-error,wrong-import-order
                                HealthCheckLive, HealthCheckReady, HealthCheckHealth, HealthCheckFavicon,
                                HealthCheckUnknown)
from health_check_types import HealthCheckTypes as HC  # pylint: disable=import-error,wrong-import-order
from health_check_util import (LogLevel, HealthCheckUtil)  # pylint: disable=import-error,wrong-import-order


class HealthCheckService:  # pylint: disable=too-many-instance-attributes
    """
    Simple service to allow for TCP and HTTP health checks.

    Order of precedence for setting the variables:
            1. Command line argument
            2. Passed in argument
            3. Config file
            4. Default values
    """

    # Constants.
    _VERSION = "1.92"
    _current_year = date.today().year
    _copyright = f"(C) {_current_year}"
    _service_name = "Health Check Service"
    shutdown_msg = f"{_service_name} shutting down."
    http_header_delimiter = b"\r\n"
    CONFIG_FILE_NAME = "health_check.conf"
    DEFAULT_CONFIG_FILE = os.path.join("/etc", "health_check", CONFIG_FILE_NAME)
    INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))

    # Variables that can be passed into __init__().
    listen_ip = '0.0.0.0'
    listen_port = 5757
    retry_count = 5  # number of times to retry starting the service

    # Internal variables.
    retry_wait_time = 3  # seconds
    current_try_count = 0  # current try count
    _log_level_name_max_length = 0  # length of longest log level name
    log_level_default = LogLevel.INFO  # default log level
    options = None  # command line options
    sock = None  # socket

    live_check_script = None  # path to live check script
    live_check_script_default = os.path.join(INSTALL_DIR, "check_scripts", "live_check.sh")
    live_check_script_example = os.path.join(INSTALL_DIR, "check_scripts", "example_live_check.sh")

    ready_check_script = None  # path to ready check script
    ready_check_script_default = os.path.join(INSTALL_DIR, "check_scripts", "ready_check.sh")
    ready_check_script_example = os.path.join(INSTALL_DIR, "check_scripts", "example_ready_check.sh")

    health_check_script = None  # path to health check script
    health_check_script_default = os.path.join(INSTALL_DIR, "check_scripts", "health_check.sh")
    health_check_script_example = os.path.join(INSTALL_DIR, "check_scripts", "example_health_check.sh")

    include_data_details = None  # include data details in the health check script responses
    config_file = None
    config = None
    favicon_path = f"{INSTALL_DIR}/favicon.ico"  # Default, but can get overwritten by config file or passed in param.
    monitored_service_name = None  # The name of the "patient" that the health check is for.
    show_config_on_startup = True  # Outputs all the config parameters upon startup.
    tcp_check_internal_ports = []  # List of internal TCP ports to check.
    tcp_check_external_ports = []  # List of external TCP ports to check.

    def __init__(self,  # pylint: disable=too-many-branches,too-many-statements,too-many-arguments,too-many-locals
                 listen_ip=None, listen_port=None, retry_count=None, log_level=None, live_check_script=None,
                 ready_check_script=None, health_check_script=None, include_data_details=False, config_file=None,
                 favicon_path=None, monitored_service_name=None, show_config_on_startup=True,
                 tcp_check_internal_ports=None, tcp_check_external_ports=None):
        """
        Constructor.

        :param listen_ip: (str) The IP address to bind to. Default is 0.0.0.0 (all IP addresses).

        :param listen_port: (int) The TCP listen_port to listen on. Default is 5757.

        :param retry_count: (int) The number of times to retry starting the service. Default is 5.

        :param log_level: (str) Logging level. Values: DEBUG, INFO, WARNING, ERROR. Default: INFO.

        :param live_check_script: (str) Path to local script to run to check "live" status. Script return code must
            return zero for "live" and non-zero for "not live". Any stdout or stderr output will be returned in the
            "msg" string.

        :param ready_check_script: (str) Path to local script to run to check "ready" status. Script return code must
            return zero for "ready" and non-zero for "not ready". Any stdout or stderr output will be returned in the
            "msg" string.

        :param health_check_script: (str) Path to local script to run to check "health" status. Script return code must
            return zero for "healthy" and non-zero for "not healthy". Any stdout or stderr output will be returned in
            the "msg" string.

        :param include_data_details: (bool) If True, then include data details in the health check script responses.

        :param config_file: (str) Path to the config file.

        :param favicon_path: (str) The path to the favicon.ico file to use for the health check service.

        :param monitored_service_name: (str) The name of the "service" that the health check is for.
            This should be something like the name of the microservice that is being health checked.
            This name will be included in the health check responses.

        :param show_config_on_startup: (bool) If True, then show the config parameters on startup.

        :param tcp_check_internal_ports: (list of int) List of internal TCP ports to check.

        :param tcp_check_external_ports: (list of int) List of external TCP ports to check.
        """

        super().__init__()

        self._log_level_name_max_length = self.find_len_of_longest_log_level_name()

        parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawTextHelpFormatter)

        parser.add_argument('-v', '--version', dest='show_version', action="store_true",
                            default=False, help='Show version.\n')

        parser.add_argument('-l', '--log_level', dest='log_level', action="append",
                            help="Logging level. Values: DEBUG, INFO, WARNING, ERROR. Default: INFO.\n")

        parser.add_argument('-i', '--listen_ip', dest='listen_ip', action="append",
                            help='IP address to bind to. Default is "0.0.0.0" (all IP addresses).\n')

        parser.add_argument('-p', '--listen_port', dest='listen_port', action="append",
                            help='TCP port to listen on. Default is TCP port "5757"\n')

        parser.add_argument('--live_check_script', dest='live_check_script', action="append",
                            help='Path to local script to run to check "live" status. Script return code must \n'
                                 'return zero for "live" and non-zero for "not live". Any stdout or stderr \n'
                                 'output will be returned in the "msg" string.\n')

        parser.add_argument('--ready_check_script', dest='ready_check_script', action="append",
                            help='Path to local script to run to check "ready" status. Script return code must \n'
                                 'return zero for "ready" and non-zero for "not ready". Any stdout or stderr \n'
                                 'output will be returned in the "msg" string.\n')

        parser.add_argument('--health_check_script', dest='health_check_script', action="append",
                            help='Path to local script to run to check "health" status. Script return code must \n'
                                 'return zero for "healthy" and non-zero for "not healthy". Any stdout or stderr \n'
                                 'output will be returned in the "msg" string.\n')

        parser.add_argument('--include_data_details', dest='include_data_details', action="store_true",
                            default=False, help='Include data details of the health check script(s) in the health \n'
                                                'check responses. Can also be controlled via a query string \n'
                                                'in the incoming HTTP request URL. Example:\n'
                                                '    http://1.2.3.4:5757/ready?include_data_details=true\n')

        parser.add_argument('--monitored_service_name', dest='monitored_service_name', action="append",
                            help='The name of the "patient" that the health check is for. This should be something \n'
                                 'like the name of the microservice that is being health checked. This name will be \n'
                                 'included in the health check responses.\n')

        parser.add_argument('--config_file', dest='config_file', action="append",
                            help='Path to the config file. If none is specified then the service will \n'
                                 'search for a config file in the following locations starting with \n'
                                 'the top path first:\n'
                                 f'    {self.DEFAULT_CONFIG_FILE}\n'
                                 f'    {os.path.dirname(os.path.abspath(__file__))}/{self.CONFIG_FILE_NAME}\n')

        parser.add_argument('--show_config_on_startup', dest='show_config_on_startup',
                            action="store_true", default=True, help='Show the config parameters on startup.\n')

        parser.add_argument('--tcp_check_internal_ports', dest='tcp_check_internal_ports', action="append",
                            help='List of internal TCP ports to check.\n')

        parser.add_argument('--tcp_check_external_ports', dest='tcp_check_external_ports', action="append",
                            help='List of external TCP ports to check.\n')

        try:
            self.options, _ = parser.parse_known_args(sys.argv[:])
        except Exception as exc:  # pylint: disable=broad-except
            self._log(msg=f"Encountered unknown exception: {exc}", level=LogLevel.ERROR, indent_level=0)
            sys.exit(1)

        if self.options.show_version:
            self.show_banner()
            sys.exit(0)

        if self.options.config_file is not None:
            self.config_file = os.path.abspath(self.options.config_file[0])
        else:
            if config_file is not None:
                self.config_file = os.path.abspath(config_file)
            else:
                if os.path.isfile(os.path.abspath(self.DEFAULT_CONFIG_FILE)):
                    self.config_file = os.path.abspath(self.DEFAULT_CONFIG_FILE)
                else:
                    _config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.CONFIG_FILE_NAME)
                    if os.path.isfile(_config_file):
                        self.config_file = _config_file

        # pylint: disable=too-many-nested-blocks,too-many-boolean-expressions
        if self.config_file and os.path.isfile(self.config_file) and os.access(self.config_file, os.R_OK):
            self.config = configparser.ConfigParser()
            self.config.read(self.config_file)
            self.process_config_params()
        else:
            self._log(msg=f'Config file [{self.config_file}] does not exist or cannot be read. '
                          'Will use passed in parameters or attempting to run with default parameters.',
                      level=LogLevel.WARNING)

        if self.options.log_level is not None:
            if "DEBUG" in self.options.log_level[0].upper():
                self.log_level_default = LogLevel.DEBUG
            elif "INFO" in self.options.log_level[0].upper():
                self.log_level_default = LogLevel.INFO
            elif "WARNING" in self.options.log_level[0].upper():
                self.log_level_default = LogLevel.WARNING
            elif "ERROR" in self.options.log_level[0].upper():
                self.log_level_default = LogLevel.ERROR
            else:
                self.log_level_default = LogLevel.INFO
        else:
            if log_level is not None:
                if "DEBUG" in log_level:
                    self.log_level_default = LogLevel.DEBUG
                elif "INFO" in log_level:
                    self.log_level_default = LogLevel.INFO
                elif "WARNING" in log_level:
                    self.log_level_default = LogLevel.WARNING
                elif "ERROR" in log_level:
                    self.log_level_default = LogLevel.ERROR
                else:
                    self.log_level_default = LogLevel.INFO

        if self.options.monitored_service_name is not None:
            self.monitored_service_name = self.options.monitored_service_name[0]
        else:
            if monitored_service_name is not None:
                self.monitored_service_name = monitored_service_name

        if self.options.listen_ip is not None:
            self.listen_ip = self.options.listen_ip[0]
        else:
            if listen_ip is not None:
                self.listen_ip = listen_ip

        if self.options.listen_port is not None:
            self.listen_port = int(self.options.listen_port[0])
        else:
            if listen_port is not None:
                self.listen_port = int(listen_port)

        if retry_count is not None:
            self.retry_count = int(retry_count)

        if self.options.live_check_script is not None:
            self.live_check_script = self.options.live_check_script[0]
        else:
            if live_check_script is not None:
                self.live_check_script = live_check_script
        if self.live_check_script is not None:
            if not os.path.isfile(os.path.abspath(self.live_check_script)):
                self._log(msg=f'Specified LIVE check script does not exist: {self.live_check_script}',
                          level=LogLevel.WARNING)
                self._log(msg=f'Checking for: {self.live_check_script_default}')
                if os.path.isfile(self.live_check_script_default):
                    self._log(msg=f'Found LIVE check script: "{self.live_check_script_default}"')
                    self.live_check_script = self.live_check_script_default
                else:
                    self._log(msg=f'Default LIVE check script does not exist: {self.live_check_script_default}',
                              level=LogLevel.WARNING)
                    self._log(msg=f'Checking for: {self.ready_check_script_example}')
                    if os.path.isfile(self.ready_check_script_example):
                        self._log(msg=f'Found LIVE check script: "{self.ready_check_script_example}"')
                        self.live_check_script = self.ready_check_script_example
                    else:
                        self._log(msg=f'Example LIVE check script does not exist: {self.live_check_script_example}',
                                  level=LogLevel.WARNING)
                        self._log(msg='No READY check script could be found. Cannot continue.', level=LogLevel.ERROR)
                        sys.exit(1)

        if self.options.ready_check_script is not None:
            self.ready_check_script = self.options.ready_check_script[0]
        else:
            if ready_check_script is not None:
                self.ready_check_script = ready_check_script
        if self.ready_check_script is not None:
            if not os.path.isfile(os.path.abspath(self.ready_check_script)):
                self._log(msg=f'Specified READY check script does not exist: {self.ready_check_script}',
                          level=LogLevel.WARNING)
                self._log(msg=f'Checking for: {self.ready_check_script_default}')
                if os.path.isfile(self.ready_check_script_default):
                    self._log(msg=f'Found READY check script: "{self.ready_check_script_default}"')
                    self.ready_check_script = self.ready_check_script_default
                else:
                    self._log(msg=f'Default READY check script does not exist: {self.ready_check_script_default}',
                              level=LogLevel.WARNING)
                    self._log(msg=f'Checking for: {self.ready_check_script_example}')
                    if os.path.isfile(self.ready_check_script_example):
                        self._log(msg=f'Found READY check script: "{self.ready_check_script_example}"')
                        self.ready_check_script = self.ready_check_script_example
                    else:
                        self._log(msg=f'Example READY check script does not exist: {self.ready_check_script_example}',
                                  level=LogLevel.WARNING)
                        self._log(msg='No READY check script could be found. Cannot continue.', level=LogLevel.ERROR)
                        sys.exit(1)

        if self.options.health_check_script is not None:
            self.health_check_script = self.options.health_check_script[0]
        else:
            if health_check_script is not None:
                self.health_check_script = health_check_script
        if self.health_check_script is not None:
            if not os.path.isfile(os.path.abspath(self.health_check_script)):
                self._log(msg=f'Specified HEALTH check script does not exist: {self.health_check_script}',
                          level=LogLevel.WARNING)
                self._log(msg=f'Checking for: {self.health_check_script_default}')
                if os.path.isfile(self.health_check_script_default):
                    self._log(msg=f'Found HEALTH check script: "{self.health_check_script_default}"')
                    self.health_check_script = self.health_check_script_default
                else:
                    self._log(msg=f'Default HEALTH check script does not exist: {self.health_check_script_default}',
                              level=LogLevel.WARNING)
                    self._log(msg=f'Checking for: {self.health_check_script_example}')
                    if os.path.isfile(self.health_check_script_example):
                        self._log(msg=f'Found HEALTH check script: "{self.health_check_script_example}"')
                        self.health_check_script = self.health_check_script_example
                    else:
                        self._log(msg=f'Example HEALTH check script does not exist: {self.health_check_script_example}',
                                  level=LogLevel.WARNING)
                        self._log(msg='No HEALTH check script could be found. Cannot continue.', level=LogLevel.ERROR)
                        sys.exit(1)

        if self.options.include_data_details is not None:
            self.include_data_details = self.options.include_data_details
        else:
            if include_data_details is not None:
                self.include_data_details = include_data_details

        if self.options.include_data_details:
            self.include_data_details = True

        if favicon_path is not None:
            self.favicon_path = favicon_path

        if self.options.show_config_on_startup is not None:
            self.show_config_on_startup = self.options.show_config_on_startup
        else:
            if show_config_on_startup is not None:
                self.show_config_on_startup = show_config_on_startup

        if self.options.tcp_check_internal_ports is not None:
            self.tcp_check_internal_ports = self.options.tcp_check_internal_ports
        else:
            if tcp_check_internal_ports is not None:
                if tcp_check_internal_ports != "":
                    for port in tcp_check_internal_ports.split(","):
                        self.tcp_check_internal_ports.append(int(port))

        if self.options.tcp_check_external_ports is not None:
            self.tcp_check_external_ports = self.options.tcp_check_external_ports
        else:
            if tcp_check_external_ports is not None:
                if tcp_check_external_ports != "":
                    for port in tcp_check_external_ports.split(","):
                        self.tcp_check_external_ports.append(int(port))

    def process_config_params(self):  # pylint: disable=too-many-branches,too-many-statements
        """
        Update class variables with values from the config file.
        """
        # Update class variables with values from the config file. Use the class name as the section name.
        if self.config.has_section(self.__class__.__name__):
            for key, value in self.config[self.__class__.__name__].items():
                if key == "listen_ip":
                    self.listen_ip = value
                elif key == "listen_port":
                    self.listen_port = int(value)
                elif key == "retry_count":
                    self.retry_count = int(value)
                elif key == "retry_wait_time":
                    self.retry_wait_time = int(value)
                elif key == "log_level":
                    if "DEBUG" in value.upper():
                        self.log_level_default = LogLevel.DEBUG
                    elif "INFO" in value.upper():
                        self.log_level_default = LogLevel.INFO
                    elif "WARNING" in value.upper():
                        self.log_level_default = LogLevel.WARNING
                    elif "ERROR" in value.upper():
                        self.log_level_default = LogLevel.ERROR
                    else:
                        self.log_level_default = LogLevel.INFO
                elif key == "live_check_script":
                    if value == 'None':
                        self.live_check_script = None
                    else:
                        self.live_check_script = value
                elif key == "ready_check_script":
                    if value == 'None':
                        self.ready_check_script = None
                    else:
                        self.ready_check_script = value
                elif key == "health_check_script":
                    if value == 'None':
                        self.health_check_script = None
                    else:
                        self.health_check_script = value
                elif key == "include_data_details":
                    if "true" in value.lower():
                        self.include_data_details = True
                    else:
                        self.include_data_details = False
                elif key == "favicon_path":
                    self.favicon_path = value
                elif key == "monitored_service_name":
                    self.monitored_service_name = value
                elif key == "show_config_on_startup":
                    if "true" in value.lower():
                        self.show_config_on_startup = True
                    else:
                        self.show_config_on_startup = False
                elif key == "tcp_check_internal_ports":
                    if 'None' in value or value == "":
                        self.tcp_check_internal_ports = []
                    else:
                        for port in value.split(","):
                            self.tcp_check_internal_ports.append(int(port))
                elif key == "tcp_check_external_ports":
                    if 'None' in value or value == "":
                        self.tcp_check_external_ports = []
                    else:
                        for port in value.split(","):
                            self.tcp_check_external_ports.append(int(port))
                else:
                    self._log(msg=f'Unknown config file parameter "{key}"', level=LogLevel.WARNING)

    def show_config(self):
        """
        Shows the config parameters.
        """
        self._log(msg=f"Config file: {self.config_file}", level=LogLevel.INFO)
        self._log(msg=f"listen_ip: {self.listen_ip}", level=LogLevel.INFO)
        self._log(msg=f"listen_port: {self.listen_port}", level=LogLevel.INFO)
        self._log(msg=f"retry_count: {self.retry_count}", level=LogLevel.INFO)
        self._log(msg=f"retry_wait_time: {self.retry_wait_time}", level=LogLevel.INFO)
        self._log(msg=f"log_level: {self.log_level_default}", level=LogLevel.INFO)
        self._log(msg=f"live_check_script: {self.live_check_script}", level=LogLevel.INFO)
        self._log(msg=f"ready_check_script: {self.ready_check_script}", level=LogLevel.INFO)
        self._log(msg=f"health_check_script: {self.health_check_script}", level=LogLevel.INFO)
        self._log(msg=f"include_data_details: {self.include_data_details}", level=LogLevel.INFO)
        self._log(msg=f"favicon_path: {self.favicon_path}", level=LogLevel.INFO)
        self._log(msg=f"monitored_service_name: {self.monitored_service_name}", level=LogLevel.INFO)
        self._log(msg=f"show_config_on_startup: {self.show_config_on_startup}", level=LogLevel.INFO)

    @staticmethod
    def find_len_of_longest_log_level_name():
        """
        Finds the length of the longest log level name.
        :return: (int) The length of the longest log level name.
        """
        return max(len(level.value[1]) for level in LogLevel)

    def _log(self, msg="", level=LogLevel.INFO, indent_level=1, show_prefix=True):
        """
        Prints a log message if logging is enabled.
        Adds a date and time stamp (including timezone) to the beginning of each log line that is in the ISO8601
        format but with the colon characters removed so that this string can be as part of a file name in Windows
        which does not support the colon character in file names.
            Example:
                '2023-06-12T120325.544939-0600'
        :param msg: (str) The message to print.
        :param level: (str) The log level.  Default is "info".
        :param indent_level: (int) The number of indents to add to the beginning portion of the log message.
            Default is 1. Each indent level is 4 spaces.
        :param show_prefix: (bool) If True, then show the date-time stamp and log level prefix. Default is True.
        """
        if indent_level > 0:
            indent = "    " * indent_level
            msg = f"{indent}{msg}"

        if level is None:
            level = LogLevel.INFO

        if level is not None and level.value[0] >= self.log_level_default.value[0]:
            if show_prefix:
                datetime_iso8601 = HealthCheckUtil.get_iso8601_time_stamp(remove_colons=True)
                # Add logging level into a fixed with string with the max length of the longest log level name.
                _log_level = f"[{level.value[1]}]"
                msg = f"{datetime_iso8601} {_log_level:<{self._log_level_name_max_length+2}}: {msg}"
            else:
                msg = f"{msg}"
            print(msg)

    def show_listening_message(self):
        """
        Shows a message that the service is listening for incoming connections.
        """
        self._log(msg="---------------------------------------------------------------", indent_level=0)
        self._log(msg="Listening for incoming connections...", indent_level=0)

    def get_uptime(self):
        """
        :return (str) The uptime of the system in seconds.
        """
        if "Darwin" in platform.system():
            cmd = ["date", "+%s"]
            now, _ = HealthCheckUtil.run_command(cmd=cmd)

            # Example of output of command "sysctl -n kern.boottime":
            #  "{ sec = 1692260516, usec = 210443 } Thu Aug 17 02:21:56 2023\n"
            cmd = ["sysctl", "-n", "kern.boottime"]
            boot_time, _ = HealthCheckUtil.run_command(cmd=cmd)
            boot_time = boot_time.split(',')[0].split('=')[1].strip()

            return int(now) - int(boot_time)

        if "Linux" in platform.system():
            # Get the system uptime for linux in seconds.
            cmd = ["cat", "/proc/uptime"]
            up_time, _ = HealthCheckUtil.run_command(cmd=cmd)
            up_time = up_time.split('.')[0].strip()

            return up_time

        self._log(msg=f'Unsupported OS platform: "{platform.system()}"', level=LogLevel.WARNING)
        return None

    def do_favicon_check(self):
        """
        Performs a favicon check.

        :return: The favicon object of the health check service.

        :return: (3-tuple of HealthCheckFavicon, bytearray, bytearray) The version check object, http response code,
            and http response message.
        """
        hc_favicon = HealthCheckFavicon(favicon_path=self.favicon_path)

        if hc_favicon.is_successful():
            http_response_code = b"200"
            http_response_msg = b"OK"
        else:
            http_response_code = b"503"
            http_response_msg = b"Service Unavailable"

        return hc_favicon, http_response_code, http_response_msg

    @staticmethod
    def do_version_check():
        """
        Performs a version check.

        :return: The version object of the health check service.

        :return: (3-tuple of HealthCheckVersion, bytearray, bytearray) The version check object, http response code,
            and http response message.
        """
        hc_version = HealthCheckVersion()
        hc_version.set_status(hc_version.status_success())
        hc_version.data["service_name"] = HealthCheckService._service_name
        hc_version.data["version"] = HealthCheckService._VERSION
        http_response_code = b"200"
        http_response_msg = b"OK"
        return hc_version, http_response_code, http_response_msg

    def do_tcp_check(self):
        """
        Performs a TCP check. Returns a status of "OPEN" if the TCP ports are open or "CLOSED" if the TCP ports are
        closed.

        :return: (3-tuple of HealthCheckTcp, bytearray, bytearray) The TCP check object, http response code,
            and http response message.
        """
        # Since we're testing the "internal" ports we'll use the local IP address.
        host = "127.0.0.1"
        ip_tcp_list = []
        for port in self.tcp_check_internal_ports:
            ip_tcp_list.append((host, port))

        hc_tcp = HealthCheckTcp(ip_tcp_list=ip_tcp_list, exclude_port_list=[self.listen_port])
        hc_tcp.run_check(include_data_details=True)
        hc_tcp.get_status_dict()
        hc_tcp.data["tcp_check"]["tcp_external_ports"] = self.tcp_check_external_ports
        if hc_tcp.is_up():
            http_response_code = b"200"
            http_response_msg = b"OK"
        else:
            http_response_code = b"503"
            http_response_msg = b"Service Unavailable"

        return hc_tcp, http_response_code, http_response_msg

    def do_live_check(self, include_data_details=False):
        """
        Performs a live check. Returns a status of "LIVE" if the service being monitored has started
        (even if it is not yet "READY"). Returns "NOT_LIVE" if the service is not detected as started.

        :param include_data_details: (bool) If True, then include data details in the health check script responses.

        :return: (3-tuple of HealthCheckLive, bytearray, bytearray) The LIVE check object, http response code,
            and http response message.
        """
        hc_live = HealthCheckLive(run_script=self.live_check_script)
        hc_live.run_check(include_data_details=include_data_details)

        self._log(msg=f"hc_live object: \n{hc_live.pretty_str()}", level=LogLevel.DEBUG)

        if hc_live.is_live():
            http_response_code = b"200"
            http_response_msg = b"OK"
        else:
            http_response_code = b"503"
            http_response_msg = b"Service Unavailable"

        return hc_live, http_response_code, http_response_msg

    def do_ready_check(self, include_data_details=False):
        """
        Performs a live check. Returns a status of "READY" if the service being monitored is "LIVE" and
        is ready to accept requests. Returns "NOT_READY" if the service is not "LIVE" or not ready to accept requests.

        :param include_data_details: (bool) If True, then include data details in the health check script responses.

        :return: (3-tuple of HealthCheckReady, bytearray, bytearray) The READY check object, http response code,
            and http response message.
        """
        # First do a "live" check.
        hc_live, http_response_code, http_response_msg = self.do_live_check(include_data_details=include_data_details)

        hc_ready = HealthCheckReady(run_script=self.ready_check_script)
        hc_ready.hc_live = hc_live

        if hc_live.is_live(include_data_details=include_data_details):
            hc_ready.is_ready(include_data_details=include_data_details)
            self._log(msg=f"hc_ready object: \n{hc_ready.pretty_str()}", level=LogLevel.DEBUG)
            http_response_code = b"200"
            http_response_msg = b"OK"
        else:
            self._log(msg=f"hc_ready object: \n{hc_ready.pretty_str()}", level=LogLevel.DEBUG)
            hc_ready.set_status(hc_ready.status_failure())
            hc_ready.set_msg(f'Received a {hc_live.get_status()} status from the {hc_live.name()} check with '
                             f'message: {hc_live.get_status_dict()}')

        return hc_ready, http_response_code, http_response_msg

    def do_health_check(self, include_data_details=False):
        """
        Performs a health check. Returns a status of "HEALTHY" if the service being monitored is "LIVE", "READY", and
        is healthy. Returns "NOT_HEALTHY" if the service is not "LIVE", not "READY", or not healthy.

        :param include_data_details: (bool) If True, then include data details in the health check script responses.

        :return: (3-tuple of HealthCheckHealth, bytearray, bytearray) The HEALTH check object, http response code,
            and http response message.
        """
        # First do a "ready" check (which in turn will also do a "live" check).
        hc_ready, http_response_code, http_response_msg = \
            self.do_ready_check(include_data_details=include_data_details)

        hc_health = HealthCheckHealth(run_script=self.health_check_script)
        hc_health.hc_live = hc_ready.hc_live
        hc_health.hc_ready = hc_ready

        if hc_ready.is_ready(include_data_details=include_data_details):
            hc_health.is_healthy(include_data_details=include_data_details)
            self._log(msg=f"hc_health object: \n{hc_health.pretty_str()}", level=LogLevel.DEBUG)
            http_response_code = b"200"
            http_response_msg = b"OK"
        else:
            self._log(msg=f"hc_health object: \n{hc_health.pretty_str()}", level=LogLevel.DEBUG)
            hc_health.set_status(hc_health.status_failure())
            hc_health.build_status_dict()
            hc_health.set_msg(f'Received a {hc_ready.get_status()} status from the {hc_ready.name()} check '
                              f'with message: [{hc_ready.get_status_dict()["msg"]}],')

        return hc_health, http_response_code, http_response_msg

    def process_boolean_query_string_arg(self, query_string_arg=None):
        """
        Processes a boolean query string argument.
        :param query_string_arg: (str) The query string argument.
        :return: (bool) The boolean value of the query string argument. Returns None if the query string argument is
            not "true", "True", "false", or "False".
        """
        # Handle cases of "include_data_details" being "true", "True", "false", or "False".
        if query_string_arg.lower() == "true":
            return True

        if query_string_arg.lower() == "false":
            return False

        self._log(msg=f'Unknown query string argument boolean value: "{query_string_arg}"', level=LogLevel.WARNING)
        return None

    def health_check_service_run_loop(self):  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
        """
        Run loop for the health check service. Process incoming health check requests.
        """
        connection = None
        self.show_listening_message()
        while True:  # pylint: disable=too-many-nested-blocks
            try:
                connection, client_address = self.sock.accept()

                # Set a timeout on the socket so that we don't block forever waiting for data.
                # This avoids a deadlock waiting for a client to send data when it is not going to.
                connection.settimeout(True)
                data = None
                try:
                    # Check if connection has any data bytes.
                    data = connection.recv(1024)

                except socket.error as sock_exc:
                    if "timed out" in str(sock_exc):
                        self._log(msg="Request: No data", level=LogLevel.DEBUG)
                    else:
                        self._log(msg=f"Socket error: {sock_exc}", level=LogLevel.DEBUG)

                self._log(msg=f"Client connected: (IP: {client_address[0]}, TCP port: {client_address[1]})")

                if data is None or data == b'':
                    # Handle the request as a TCP only with no payload.
                    self._log(msg='Status: "OPEN" (TCP)', level=LogLevel.INFO)
                else:
                    # How many data bytes do we have?
                    if len(data) < 4:
                        self._log(msg=f"Request: {data}")
                        self._log(msg="Response: NONE")

                    # Else there is enough data to contain at least the HTTP request method "GET ".
                    else:
                        self._log(msg=f"Request bytes: {data}", level=LogLevel.DEBUG)

                        data = data.decode()
                        query_string_args_dict = {}
                        status_msg = ''
                        _details = self.include_data_details

                        # If data starts with "GET ", then it is an HTTP request.
                        if data.startswith("GET "):
                            # Is a query string present?
                            header_first_line = data.split("\r\n")[0]
                            if "?" in header_first_line:
                                # Parse all the query string arguments into a dict.
                                query_string_raw = header_first_line.split("?")[1].split(" ")[0]
                                query_string_args = query_string_raw.split("&")
                                for query_string_arg in query_string_args:
                                    query_string_args_dict[query_string_arg.split("=")[0]] = \
                                        query_string_arg.split("=")[1]

                                if "include_data_details" in query_string_args_dict:
                                    _details = self.process_boolean_query_string_arg(
                                        query_string_arg=query_string_args_dict["include_data_details"])

                            # Extract the HTTP endpoint requested.
                            http_method = data.split(" ")[0]
                            http_endpoint = data.split(" ")[1:][0]

                            self._log(msg=f"Request: {http_method} {http_endpoint}")

                            http_ver = b"HTTP/1.1"

                            # Default to an error state.
                            http_response_code = b'503'
                            http_response_msg = b'Service Unavailable'

                            http_header_cache_control = b"Cache-Control: private, max-age=0, no-store, no-cache\r\n" \
                                                        b"Pragma: no-cache\r\n"
                            http_header_content_type = b"Content-Type: application/json\r\n"

                            http_body = {"monitored_service": self.monitored_service_name}

                            http_body_is_binary_file = False
                            status_msg = ''
                            http_response_log_level = LogLevel.INFO

                            # Check which HTTP endpoint was requested.
                            if data.startswith(f"GET {HC.get_health_endpoint()}"):
                                check_obj, http_response_code, http_response_msg = self.do_health_check(_details)
                                # Merge the health check data with the default http_body dict.
                                http_body = {**http_body, **check_obj.get_status_dict()}

                            elif data.startswith(f"GET {HC.get_ready_endpoint()}"):
                                check_obj, http_response_code, http_response_msg = self.do_ready_check(_details)
                                # Merge the health check data with the default http_body dict.
                                http_body = {**http_body, **check_obj.get_status_dict()}

                            elif data.startswith(f"GET {HC.get_live_endpoint()}"):
                                check_obj, http_response_code, http_response_msg = self.do_live_check(_details)
                                # Merge the health check data with the default http_body dict.
                                http_body = {**http_body, **check_obj.get_status_dict()}

                            elif data.startswith(f"GET {HC.get_tcp_endpoint()}"):
                                check_obj, http_response_code, http_response_msg = self.do_tcp_check()
                                # Merge the health check data with the default http_body dict.
                                http_body = {**http_body, **check_obj.get_status_dict()}

                            elif data.startswith(f"GET {HC.get_version_endpoint()}"):
                                check_obj, http_response_code, http_response_msg = self.do_version_check()
                                # Merge the health check data with the default http_body dict.
                                http_body = {**http_body, **check_obj.get_status_dict()}

                            elif data.startswith(f"GET {HC.get_favicon_endpoint()}"):
                                # Return the favicon.ico binary file.
                                http_header_content_type = b"Content-Type: image/x-icon\r\n" \
                                                           b"Accept-Ranges: bytes\r\n"

                                hc_favicon, http_response_code, http_response_msg = self.do_favicon_check()

                                if hc_favicon.is_successful():
                                    http_body = hc_favicon.get_binary_data()
                                    http_body_is_binary_file = True
                                    status_msg = hc_favicon.get_status_dict()["msg"]
                                else:
                                    http_body = hc_favicon.get_status_dict()

                            else:
                                # Merge the health check data with the default http_body dict.
                                http_body = {**http_body, **HealthCheckUnknown().get_status_dict()}
                                http_response_log_level = LogLevel.ERROR

                            # Build the header and body of the HTTP response.
                            http_header = http_ver + b' ' + http_response_code + b' ' + http_response_msg + b'\r\n' + \
                                http_header_content_type + http_header_cache_control

                            http_response_bytes = b''
                            http_body_json = None

                            if http_body:
                                if http_body_is_binary_file:
                                    # Add the length of the binary file to the HTTP header.
                                    http_header_content_length = b"Content-Length: " + \
                                                                 str(len(http_body)).encode() + b"\r\n"
                                    http_header = http_header + http_header_content_length

                                    # Build the full packet (header + body).
                                    http_response_bytes = http_header + self.http_header_delimiter + http_body

                                    self._log(msg=f"Response: {status_msg}", level=http_response_log_level)
                                else:
                                    # Convert the dict to JSON.
                                    http_body_json = json.dumps(http_body, indent=4)

                                    # Add the length of the JSON string to the HTTP header.
                                    http_header_content_length = (b"Content-Length: " +
                                                                  str(len(http_body_json)).encode() + b"\r\n")
                                    http_header = http_header + http_header_content_length

                                    # Encode the JSON string to bytes.
                                    http_body_json_encoded = http_body_json.encode()

                                    # Build the full packet (header + body).
                                    http_response_bytes = (http_header + self.http_header_delimiter +
                                                           http_body_json_encoded)

                                    self._log(msg=f"Response: \n{http_body_json}", level=http_response_log_level)
                            else:
                                http_response_bytes = http_header + self.http_header_delimiter
                                self._log(msg="Response: None", level=http_response_log_level)

                            self._log(msg=f"Response bytes: {http_response_bytes}", level=LogLevel.DEBUG)

                            connection.sendall(http_response_bytes)

            except KeyboardInterrupt:
                self._log(msg=f"{self.shutdown_msg} (KeyboardInterrupt).", level=LogLevel.WARNING, indent_level=0)
                break

            except Exception as exc:
                self._log(msg="Encountered unknown exception: {exc}", level=LogLevel.ERROR, indent_level=0)
                raise exc

            finally:
                if connection:
                    connection.close()
                    self._log(msg="Connection closed.")

            self.show_listening_message()

    def show_banner(self):
        """
        Shows the banner.
        """
        self._log(msg="==========================================================================",
                  indent_level=0, show_prefix=False)
        self._log(msg=f" {self._service_name} v{self._VERSION}", indent_level=0, show_prefix=False)
        self._log(msg=f" {self._copyright}", indent_level=0, show_prefix=False)
        self._log(msg="==========================================================================",
                  indent_level=0, show_prefix=False)

    def show_health_check_scripts(self):
        """
        Shows the health check scripts that will be used.
        """
        self._log(msg="Using the following health check scripts:", indent_level=0, show_prefix=False)

        if self.live_check_script is None:
            script_path = "None"
        else:
            script_path = os.path.abspath(self.live_check_script)
        self._log(msg=f"  live_check_script  : {script_path}", indent_level=0, show_prefix=False)

        if self.ready_check_script is None:
            script_path = "None"
        else:
            script_path = os.path.abspath(self.ready_check_script)
        self._log(msg=f"  ready_check_script : {script_path}", indent_level=0, show_prefix=False)

        if self.health_check_script is None:
            script_path = "None"
        else:
            script_path = os.path.abspath(self.health_check_script)
        self._log(msg=f"  health_check_script: {script_path}", indent_level=0, show_prefix=False)

    def start(self):  # pylint: disable=too-many-branches,too-many-statements
        """
        Starts the service.  Will retry up to retry_count times.
        :return:
        """
        self.show_banner()

        if self.show_config_on_startup:
            self.show_config()

        self._log(msg=f"Config file: {self.config_file}", indent_level=0, show_prefix=False)
        self._log(msg=f"Log level: {self.log_level_default.value[1]}", indent_level=0, show_prefix=False)

        self.show_health_check_scripts()

        self._log(msg="", indent_level=0, show_prefix=False)
        self._log(msg=f"Service listening on: "
                      f"{self.listen_ip}:{self.listen_port} (TCP)", indent_level=0)

        while self.current_try_count < self.retry_count:
            try:
                self.current_try_count = self.current_try_count + 1

                # Create a TCP/IP socket
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.bind((self.listen_ip, self.listen_port))
                self.sock.listen(1)
                self.health_check_service_run_loop()
                break

            except socket.error:
                self._log(msg=f"Unable to start {self._service_name}, retrying in "
                              f"{self.retry_wait_time}s. Encountered socket error:\n{traceback.format_exc()}",
                          level=LogLevel.ERROR, indent_level=0)
                try:
                    sleep(self.retry_wait_time)
                    continue
                except KeyboardInterrupt:
                    self._log(msg=f"{self.shutdown_msg} (KeyboardInterrupt).", level=LogLevel.WARNING, indent_level=0)
                    break

            except KeyboardInterrupt:
                self._log(msg=f"{self.shutdown_msg} (KeyboardInterrupt).", level=LogLevel.WARNING, indent_level=0)
                break

            except Exception:  # pylint: disable=broad-except
                self._log(msg=f"Encountered unknown exception:\n{traceback.format_exc()}",
                          level=LogLevel.ERROR, indent_level=0)
                break

            finally:
                self.sock.close()

        if self.current_try_count > self.retry_count:
            self._log(msg=f"Unable to start {self._service_name} on "
                          f"{self.listen_ip} port {self.listen_port}",
                      level=LogLevel.ERROR, indent_level=0)
            return


if __name__ == '__main__':
    service = HealthCheckService()
    service.start()
