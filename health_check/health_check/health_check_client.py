# pylint: disable=fixme
"""
Simple, lightweight client that calls the health_check_service API TCP and HTTP health checks.
Primarily used for health checks of microservices inside containers but can be used for bare metal servers too.

TODO: Implement logging to a file in addition to the stdout (default to /var/blah-blah-blah.log).
TODO: Implement a cli flag to specify the log file name and path.
"""

import os
import sys
import socket
import argparse
import traceback
import json
import configparser
import time

from datetime import date  # pylint: disable=import-error,wrong-import-order
from time import sleep  # pylint: disable=import-error,wrong-import-order
from health_check_types import (HealthCheckVersion, HealthCheckTcp,  # pylint: disable=import-error,wrong-import-order
                                HealthCheckLive, HealthCheckReady, HealthCheckHealth, HealthCheckFavicon,
                                HealthCheckTypes, HealthCheckIcmp)
from health_check_types_enum import HealthCheckTypesEnum as HCEnum  # pylint: disable=import-error,wrong-import-order
from health_check_util import (LogLevel, HealthCheckUtil)  # pylint: disable=import-error,wrong-import-order


class HealthCheckClient:  # pylint: disable=too-many-instance-attributes
    """
    Simple client that calls the health_check_service API TCP and HTTP health checks.

    Order of precedence for setting the variables:
            1. Command line argument
            2. Passed in argument
            3. Config file
            4. Default values
    """

    # Constants.
    _VERSION = "1.79"
    _current_year = date.today().year
    _copyright = f"(C) {_current_year}"
    _service_name = "Health Check Client"
    shutdown_msg = f"{_service_name} shutting down."
    http_header_delimiter = b"\r\n"
    CONFIG_FILE_NAME = "health_check.conf"
    DEFAULT_CONFIG_FILE = os.path.join("/etc", "health_check", CONFIG_FILE_NAME)

    # Variables that can be passed into __init__().
    remote_host = None
    remote_port = 5757
    retry_count = 5  # number of times to retry starting the service
    check_icmp = False  # If True, then check that the server responds to an ICMP echo request.
    check_tcp = False  # If True, then check that the TCP port of the server can be connected to.
    check_live = False  # If True, then check that the HTTP endpoint "/live" returns "LIVE".
    check_ready = False  # If True, then check that the HTTP endpoint "/ready" returns "READY".
    check_health = False  # If True, then check that the HTTP endpoint "/health" returns "HEALTHY".
    check_server_version = False  # If True, then check the version returned the HTTP endpoint "/version".
    check_favicon = False  # If True, then check if the favicon is returned by the HTTP endpoint "/favicon.ico".

    # Internal variables.
    server_ip_addr = None
    remote_server = None  # A tuple of (remote_host, remote_port) where remote_host can be a hostname or IP address.
    retry_wait_time = 3  # seconds
    _log_level_name_max_length = 0  # length of longest log level name
    log_level_default = LogLevel.INFO  # default log level
    options = None  # command line options
    sock = None  # socket
    _current_health_check_type = HCEnum.TCP  # Default to TCP health check.
    include_data_details = None  # include data details in the health check script responses
    config_file = DEFAULT_CONFIG_FILE
    show_config_on_startup = False  # Outputs all the config parameters upon startup.
    no_output_only_exit_code = False  # If False, then only return the return exit code and no other output.

    retryable_errors = (
        socket.error,
        socket.gaierror
    )

    def __init__(self,  # pylint: disable=too-many-branches,too-many-statements,too-many-arguments,too-many-locals
                 remote_host=None,
                 remote_port=None,
                 retry_count=None,
                 log_level=None,
                 check_icmp=None,
                 check_tcp=None,
                 check_live=None,
                 check_ready=None,
                 check_health=None,
                 check_favicon=None,
                 check_server_version=None,
                 include_data_details=None,
                 config_file=None,
                 show_config_on_startup=False,
                 no_output_only_exit_code=False):
        """
        Constructor.

        :param remote_host: (str) The IP address of the server to connect to.

        :param remote_port: (int) The TCP port of the server to connect to.

        :param retry_count: (int) The number of times to retry connecting to server.

        :param log_level: (str) Logging level. Values: DEBUG, INFO, WARNING, ERROR. Default: INFO.

        :param check_icmp: (bool) If True, then check that the server responds to an ICMP echo request.

        :param check_tcp: (bool) If True, then check that the TCP port of the server can be connected to.
            Default is True.

        :param check_live: (bool) If True, then check that the HTTP endpoint "/live" returns "LIVE".
            Default is False.
                Example of "LIVE" response:
                    {"status": "LIVE"}
                Example of "NOT_LIVE" response:
                    {"status": "NOT_LIVE"}

        :param check_ready: (bool) If True, then check that the HTTP endpoint "/ready" returns "READY".
            Default is False.
                Example of "READY" response:
                    {"status": "READY"}
                Example of "NOT_READY" response:
                    {"status": "NOT_READY"}

        :param check_health: (bool) If True, then check that the HTTP endpoint "/health" returns "HEALTHY".
            Default is False.
                Example of "HEALTHY" response:
                    {"status": "HEALTHY"}
                Example of "UNHEALTHY" response:
                    {"status": "UNHEALTHY"}

        :param check_favicon: (bool) If True, then check if the favicon.ico is returned by the server.
            Default is False.

        :param check_server_version: (bool) If True, then check the version returned the HTTP endpoint "/version".
            Default is False.

        :param include_data_details: (bool) If True, then include data details of the health check script(s) in the
            health check responses.

        :param config_file: (str) Path to the config file.

        :param show_config_on_startup: (bool) If True, then output all the config parameters upon startup.

        :param no_output_only_exit_code: (bool) If True, only return the return exit code and no other output.
        """

        super().__init__()

        self._log_level_name_max_length = self.find_len_of_longest_log_level_name()

        parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawTextHelpFormatter)

        parser.add_argument('-v', '--version', dest='show_version', action="store_true",
                            default=False,
                            help='Show version.\n')

        parser.add_argument('-z', '--server_version', dest='show_server_version', action="store_true",
                            default=False,
                            help='Show server version.\n')

        parser.add_argument('-f', '--check_if_favicon_exists', dest='check_favicon', action="store_true",
                            default=False,
                            help='Check if the favicon.ico is returned by the server.\n')

        parser.add_argument('-l', '--log_level', dest='log_level', action="append",
                            help="Logging level. Values: DEBUG, INFO, WARNING, ERROR. Default: INFO.\n")

        parser.add_argument('-s', '--remote_host', dest='remote_host', action="append",
                            help='Host name (or IP address) of the server to connect to.\n')

        parser.add_argument('-p', '--remote_port', dest='remote_port', action="append",
                            help='TCP port of the server to connect to. Default is TCP port "5757"\n')

        parser.add_argument('-r', '--retries', dest='retry_count', action="append",
                            help='The number of times to retry connecting to server.\n')

        parser.add_argument('-c', '--check_icmp', dest='check_icmp', action="store_true",
                            default=None,
                            help='If True, then check that the server responds to an ICMP echo request.\n')

        parser.add_argument('-t', '--check_tcp', dest='check_tcp', action="store_true",
                            default=None,
                            help='If True, then check that the TCP port of the server can be connected to.\n')

        parser.add_argument('-i', '--check_live', dest='check_live', action="store_true",
                            default=None,
                            help='If True, then check that the HTTP endpoint "/live" returns "LIVE".\n')

        parser.add_argument('-a', '--check_ready', dest='check_ready', action="store_true",
                            default = None,
                            help='If True, then check that the HTTP endpoint "/ready" returns "READY".\n')

        parser.add_argument('-e', '--check_health', dest='check_health', action="store_true",
                            default=None,
                            help='If True, then check that the HTTP endpoint "/health" returns "HEALTHY".\n')

        parser.add_argument('-o', '--list_config', dest='list_config', action="store_true",
                            help='Display the current config parameters.\n')

        parser.add_argument('--include_data_details', dest='include_data_details', action="store_true",
                            default=False, help='Include data details of the health check script(s) in the health \n'
                                                'check responses. Can also be controlled via a query string \n'
                                                'in the incoming HTTP request URL. Example:\n'
                                                '    http://1.2.3.4:5757/ready?include_data_details=true\n')

        parser.add_argument('--config_file', dest='config_file', action="append",
                            help='Path to the config file. If none is specified then the service will \n'
                                 'search for a config file in the following locations starting with \n'
                                 'the top path first:\n'
                                 f'    {self.DEFAULT_CONFIG_FILE}\n'
                                 f'    {os.path.dirname(os.path.abspath(__file__))}/{self.CONFIG_FILE_NAME}\n')

        parser.add_argument('--show_config_on_startup', dest='show_config_on_startup', action="store_true",
                            default=False, help='Output all the config parameters upon startup.\n')

        parser.add_argument('--no_output_only_exit_code', dest='no_output_only_exit_code', action="store_true",
                            default=None, help='If False, then only return the return exit code and no other output.\n')

        try:
            self.options, _ = parser.parse_known_args(sys.argv[:])
        except Exception as exc:  # pylint: disable=broad-except
            self._log(msg=f"Encountered unknown exception parsing cli args: {exc}", level=LogLevel.ERROR)
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
                _config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.CONFIG_FILE_NAME)
                if os.path.isfile(_config_file):
                    self.config_file = _config_file
                else:
                    if os.path.isfile(os.path.abspath(self.DEFAULT_CONFIG_FILE)):
                        self.config_file = os.path.abspath(self.DEFAULT_CONFIG_FILE)

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
                if "DEBUG" in log_level.upper():
                    self.log_level_default = LogLevel.DEBUG
                elif "INFO" in log_level.upper():
                    self.log_level_default = LogLevel.INFO
                elif "WARNING" in log_level.upper():
                    self.log_level_default = LogLevel.WARNING
                elif "ERROR" in log_level.upper():
                    self.log_level_default = LogLevel.ERROR
                else:
                    self.log_level_default = LogLevel.INFO

        if self.log_level_default == LogLevel.DEBUG:
            self.show_banner()

        if self.options.remote_host is not None:
            self.remote_host = self.options.remote_host[0]
        else:
            if remote_host is not None:
                self.remote_host = remote_host

        if self.options.remote_port is not None:
            self.remote_port = int(self.options.remote_port[0])
        else:
            if remote_port is not None:
                self.remote_port = int(remote_port)

        if self.options.retry_count is not None:
            self.retry_count = int(self.options.retry_count[0])
        else:
            if retry_count is not None:
                self.retry_count = int(retry_count)

        if self.options.check_icmp is not None:
            self.check_icmp = self.options.check_icmp
        else:
            if check_icmp is not None:
                self.check_icmp = bool(check_icmp)

        if self.options.check_tcp is not None:
            self.check_tcp = self.options.check_tcp
        else:
            if check_tcp is not None:
                self.check_tcp = bool(check_tcp)

        if self.options.check_live is not None:
            self.check_live = self.options.check_live
        else:
            if check_live is not None:
                self.check_live = bool(check_live)

        if self.options.check_ready is not None:
            self.check_ready = self.options.check_ready
        else:
            if check_ready is not None:
                self.check_ready = bool(check_ready)

        if self.options.check_health is not None:
            self.check_health = self.options.check_health
        else:
            if check_health is not None:
                self.check_health = bool(check_health)

        if self.options.check_favicon is not None:
            self.check_favicon = self.options.check_favicon
        else:
            if check_favicon is not None:
                self.check_favicon = bool(check_favicon)

        if self.options.show_server_version:
            self.check_server_version = True
        else:
            if check_server_version is not None:
                self.check_server_version = bool(check_server_version)

        if self.options.include_data_details is not None:
            self.include_data_details = self.options.include_data_details
        else:
            if include_data_details is not None:
                self.include_data_details = bool(include_data_details)

        if self.options.show_config_on_startup is not None:
            self.show_config_on_startup = self.options.show_config_on_startup
        else:
            if show_config_on_startup is not None:
                self.show_config_on_startup = bool(show_config_on_startup)

        if self.options.no_output_only_exit_code is not None:
            self.no_output_only_exit_code = self.options.no_output_only_exit_code
        else:
            if no_output_only_exit_code is not None:
                self.no_output_only_exit_code = bool(no_output_only_exit_code)

        if self.options.list_config is True:
            self.no_output_only_exit_code = False
            self.show_config()
            sys.exit(0)

        # If all health check types are False, then default to TCP health check.
        # pylint: disable=too-many-boolean-expressions
        if not self.check_icmp and \
            not self.check_tcp and \
            not self.check_live and \
            not self.check_ready and \
            not self.check_health and \
            not self.check_server_version and \
            not self.check_favicon:
            self.check_tcp = True

    def show_banner(self):
        """
        Shows the banner.
        """
        self._log(msg="==========================================================================")
        self._log(msg=f" {self._service_name} v{self._VERSION}")
        self._log(msg=f" {self._copyright}")
        self._log(msg="==========================================================================")

    def process_config_params(self):  # pylint: disable=too-many-branches
        """
        Update class variables with values from the config file.
        """
        # Update class variables with values from the config file. Use the class name as the section name.
        if self.config.has_section(self.__class__.__name__):
            for key, value in self.config[self.__class__.__name__].items():
                if key == "remote_host":
                    self.remote_host = value
                elif key == "remote_port":
                    self.remote_port = int(value)
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
                elif key == "include_data_details":
                    if "true" in value.lower():
                        self.include_data_details = True
                    else:
                        self.include_data_details = False
                elif key == "show_config_on_startup":
                    if "true" in value.lower():
                        self.show_config_on_startup = True
                    else:
                        self.show_config_on_startup = False
                else:
                    self._log(msg=f'Unknown config file parameter "{key}"', level=LogLevel.WARNING)

    def show_config(self):
        """
        Shows the config parameters.
        """
        self._log(msg="Config Parameters:")
        self._log(msg=f"    config_file: {self.config_file}")
        self._log(msg=f"    remote_host: {self.remote_host}")
        self._log(msg=f"    remote_port: {self.remote_port}")
        self._log(msg=f"    retry_count: {self.retry_count}")
        self._log(msg=f"    retry_wait_time: {self.retry_wait_time}")
        self._log(msg=f"    log_level: {self.log_level_default.name}")
        self._log(msg=f"    include_data_details: {self.include_data_details}")
        self._log(msg=f"    show_config_on_startup: {self.show_config_on_startup}")

    @staticmethod
    def find_len_of_longest_log_level_name():
        """
        Finds the length of the longest log level name.
        :return: (int) The length of the longest log level name.
        """
        return max(len(level.value[1]) for level in LogLevel)

    def _log(self, msg=None, level=LogLevel.INFO, indent_level=0, show_prefix=False):
        """
        Prints a log message if logging is enabled.
        Adds a date and time stamp (including timezone) to the beginning of each log line that is in the ISO8601
        format but with the colon characters removed so that this string can be as part of a file name in Windows
        which does not support the colon character in file names.
            Example:
                '2023-06-12T120325.544939-0600'
        :param msg: (str) The message to print. If message is a dict, then it will be converted to a str.
        :param level: (str) The log level.  Default is "info".
        :param indent_level: (int) The number of indents to add to the beginning portion of the log message.
            Default is 0. Each indent level is 4 spaces.
        :param show_prefix: (bool) If True, then show the date-time stamp and log level prefix. Default is False.
        """
        if msg is None:
            msg = ""

        # if isinstance(msg, dict):
        #     # Convert the dict to a str.
        #     msg = str(msg)

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

            if not self.no_output_only_exit_code:
                print(msg)

    def show_connecting_message(self):
        """
        Shows a message that the client is connecting to a server.
        """
        if self._current_health_check_type not in HCEnum:
            raise RuntimeError(f"Invalid check_type: {self._current_health_check_type.name}")

        self._log(msg=f"Connecting to: {self.remote_server[0]}:{self.remote_server[1]} "
                      f"(Health Check Type: {self._current_health_check_type.name})",
                  level=LogLevel.DEBUG)

    @staticmethod
    def is_valid_ip_address(host=None):
        """
        Checks if the host is a valid IP address.
        :param host: (str) The host to check.
        :return: (bool) True if host is a valid IP address, False otherwise.
        """
        try:
            socket.inet_aton(host)
            return True
        except socket.error:
            return False

    def build_query_string(self):
        """
        Builds the query string to be appended to the HTTP request.
        :return: (byte array) The query string to be appended to the HTTP request.
        """
        if self.include_data_details:
            return b'?include_data_details=true'
        return b''

    def do_health_check(self):  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
        """
        Perform a specific health check.
        :return: (int) Return code of the health check. 0 = success, non-zero = failure.
        """
        return_code = 1  # Default to a non-success (i.e. non-zero) return code.
        self.show_connecting_message()

        response_msg = {
            "status": "None",
            "health_check_type": "None",
            "last_check_time": "None",
            "last_check_time_epoch": "None",
            "msg": "None"
        }

        hc_type = None

        if self.check_icmp:
            hc_type = HealthCheckIcmp(destination=self.remote_server[0])
            hc_type.run_check(include_data_details=True)
            response_msg = hc_type.get_status_dict()
            response_msg_json = json.dumps(response_msg, indent=4)
            self._log(msg=response_msg_json, level=LogLevel.INFO)
            return hc_type.get_return_code()

        http_header_request_method = b'GET '
        http_header_request_endpoint = b''
        http_header_request_version = b' HTTP/1.1\r\n'
        http_header_cache_control = b"Cache-Control: private, max-age=0, no-store, no-cache\r\n" \
                                    b"Pragma: no-cache\r\n"
        http_header_accept_encoding = b"Accept-Encoding: gzip, deflate\r\n"

        if self.is_valid_ip_address(self.remote_host):
            http_header_request_host = b'Host: ' + self.remote_host.encode() + b'\r\n'
        else:
            http_header_request_host = b'Host: ' + self.remote_server[0].encode() + b'\r\n'

        try:
            try:
                # Connect to the server.
                self.sock.connect(self.remote_server)
            except Exception as exc:
                response_msg["status"] = "DOWN"
                if "Connection refused" in str(exc):
                    response_msg["msg"] = f'Connection refused to "{self.remote_server}"'
                else:
                    response_msg["msg"] = f'Health Check Service not reachable: "{self.remote_server}"'
                response_msg["last_check_time"] = HealthCheckTypes.get_timestamp()
                response_msg["last_check_time_epoch"] = time.time()
                response_msg_json = json.dumps(response_msg, indent=4)
                self._log(msg=response_msg_json, level=LogLevel.ERROR)
                return 1

            if self.check_tcp:
                hc_type = HealthCheckTcp()
                response_msg["health_check_type"] = hc_type.name()
                http_header_request_endpoint = f"{hc_type.endpoint()}".encode()

            elif self.check_live:
                hc_type = HealthCheckLive()
                response_msg["health_check_type"] = hc_type.name()
                http_header_request_endpoint = f"{hc_type.endpoint()}".encode()

            elif self.check_ready:
                hc_type = HealthCheckReady()
                response_msg["health_check_type"] = hc_type.name()
                http_header_request_endpoint = f"{hc_type.endpoint()}".encode()

            elif self.check_health:
                hc_type = HealthCheckHealth()
                response_msg["health_check_type"] = hc_type.name()
                http_header_request_endpoint = f"{hc_type.endpoint()}".encode()

            elif self.check_server_version:
                hc_type = HealthCheckVersion()
                response_msg["health_check_type"] = hc_type.name()
                http_header_request_endpoint = f"{hc_type.endpoint()}".encode()

            elif self.check_favicon:
                hc_type = HealthCheckFavicon()
                response_msg["status"] = f'"{hc_type.get_favicon_endpoint()}" exists.'
                response_msg["health_check_type"] = hc_type.name()
                http_header_request_endpoint = f"{hc_type.endpoint()}".encode()

            # Build HTTP request header.
            http_header = \
                http_header_request_method + http_header_request_endpoint + self.build_query_string() + \
                http_header_request_version + \
                http_header_cache_control + \
                http_header_accept_encoding + \
                http_header_request_host + \
                self.http_header_delimiter

            try:
                self._log(msg=f"Bytes Sent: {http_header}", level=LogLevel.DEBUG)
                # Send HTTP request header.
                self.sock.sendall(http_header)
            except socket.error as sock_exc:
                if "timed out" in str(sock_exc):
                    self._log(msg=f'Health check request to "{self.remote_server}" timed out.', level=LogLevel.DEBUG)
                else:
                    self._log(msg=f"Socket error: {sock_exc}", level=LogLevel.DEBUG)
                raise sock_exc

            # Receive HTTP response header.
            # Expecting to receive JSON response.
            http_response_raw = self.sock.recv(16384)

            # If we do not receive any data.
            if not http_response_raw:
                response_msg["status"] = "DOWN"
                response_msg["msg"] = "No data received."
                response_msg["last_check_time"] = HealthCheckTypes.get_timestamp()
                response_msg["last_check_time_epoch"] =  time.time()
                response_msg_json = json.dumps(response_msg, indent=4)
                self._log(msg=response_msg_json, level=LogLevel.ERROR)
                if hc_type is not None:
                    hc_type.set_status(hc_type.status_failure())
                    hc_type.set_return_code(1)
                    hc_type.get_status_dict()
                    return hc_type.get_return_code()

            self._log(msg=f"Bytes Received: {http_response_raw}", level=LogLevel.DEBUG)

            # Separate the HTTP header and HTTP body.
            http_response_header, http_response_body = http_response_raw.split(sep=b"\r\n\r\n", maxsplit=1)

            # Convert the HTTP header to a string.
            http_response_header = http_response_header.decode()

            # Convert the HTTP header to a dict.
            http_response_header_list = http_response_header.split('\r\n')
            http_response_header_dict = {}
            for http_response_header_item in http_response_header_list:
                if http_response_header_item != '':
                    if ': ' in http_response_header_item:
                        http_response_header_item_key, http_response_header_item_value = \
                            http_response_header_item.split(': ', 1)
                        http_response_header_dict[http_response_header_item_key] = http_response_header_item_value
                    else:
                        if 'HTTP/' in http_response_header_item:
                            http_response_header_dict['http_version'] = (
                                http_response_header_item.split('/')[1].split(' '))[0]
                            http_response_header_dict['response_code'] = http_response_header_item.split(' ')[1]
                            http_response_header_dict['response_msg'] = http_response_header_item.split(' ')[2]
                        else:
                            if 'unknown' in http_response_header_dict:
                                http_response_header_dict['unknown'].append(http_response_header_item)
                            http_response_header_dict['unknown'] = [http_response_header_item]

            # Check if the HTTP response code is 200.
            if http_response_header_dict['response_code'] == '200':
                hc_type.set_status(hc_type.status_success())
                hc_type.set_return_code(0)
            else:
                hc_type.set_status(hc_type.status_failure())
                hc_type.set_return_code(1)

            if self.check_tcp:  # pylint: disable=too-many-nested-blocks
                if 'Content-Type' in http_response_header_dict:
                    if http_response_header_dict['Content-Type'] == 'application/json':
                        try:
                            # Attempt to convert the JSON to a dictionary.
                            _http_response_body = http_response_body.decode()
                            _http_response_body = json.loads(_http_response_body)
                        except json.decoder.JSONDecodeError:
                            err_msg = "Could not decode JSON data from health check response."
                            self._log(msg=f"{err_msg}: [{http_response_body}]", level=LogLevel.ERROR)
                        else:
                            # Check if the health check response contains the "tcp_external_ports" key.
                            if "tcp_external_ports" in _http_response_body["data"]["tcp_check"]:
                                # The health_check_service only checked the "internal" TCP ports
                                # and will return the status for each internal port along with
                                # a list of "external" TCP ports that should be checked by the
                                # health_check_client. So first step is to parse the list of
                                # external ports from the response from the server.
                                external_ports_list = \
                                    _http_response_body["data"]["tcp_check"]["tcp_external_ports"]

                                # Now that we have the list of external TCP ports to check, we'll
                                # need to check each one of them.
                                ext_ip_port_list = []
                                for external_port in external_ports_list:
                                    ext_ip_port_list.append((self.remote_server[0], external_port))

                                _hc_type = HealthCheckTcp(ip_tcp_list=ext_ip_port_list)
                                _hc_type.run_check(include_data_details=True)
                                ext_dict = _hc_type.get_status_dict()

                                _http_response_body["data"]["tcp_check"]["tcp_external_ports"] = \
                                    ext_dict["data"]["tcp_check"]["tcp_internal_ports"]
                                http_response_body = json.dumps(_http_response_body, indent=4)


            if self.check_favicon:
                # Check if the favicon.ico file was returned.
                if "Content-Type: image/x-icon" in http_response_header:
                    response_msg["status"] = hc_type.status_success()
                else:
                    response_msg["status"] = hc_type.status_failure()
                response_msg_json = json.dumps(response_msg, indent=4)
                self._log(msg=response_msg_json, level=LogLevel.INFO)

            else:
                # Check if http_response_body is a string
                if not isinstance(http_response_body, str):
                    # Convert the HTTP body to a string.
                    http_response_body = http_response_body.decode()
                self._log(msg=f"{http_response_body}", level=LogLevel.INFO)

        except KeyboardInterrupt:
            self._log(msg=f"{self.shutdown_msg} (KeyboardInterrupt).", level=LogLevel.WARNING)

        except Exception as exc:
            self._log(msg="Encountered unknown exception: {exc}", level=LogLevel.ERROR)
            raise exc

        if hc_type is not None:
            return_code = hc_type.get_return_code()

        return return_code

    def run(self):  # pylint: disable=too-many-branches,too-many-statements
        """
        Runs the client.  Will retry up to retry_count times if connection to server fails.
        :return: (int) Return code of the health check. 0 = success, non-zero = failure.
        """
        if self.show_config_on_startup or self.log_level_default == LogLevel.DEBUG:
            self.show_config()

        return_code = None
        success = False
        current_try_count = 0

        while current_try_count <= self.retry_count:
            try:
                self._log(msg="Creating TCP/IP socket.", level=LogLevel.DEBUG)
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                # Check if we're dealing with an IP address or a host name.
                if self.is_valid_ip_address(self.remote_host):
                    # Since we have a valid IP address, then use it as is.
                    self.remote_server = (self.remote_host, self.remote_port)
                else:
                    # Since we do not have a valid IP address, then assume it is a host name and resolve
                    # it to an IP address.
                    self._log(msg="Resolving server host name to IP.", level=LogLevel.DEBUG)
                    self.server_ip_addr = socket.gethostbyname(self.remote_host)
                    self.remote_server = (self.server_ip_addr, self.remote_port)

                return_code = self.do_health_check()
                success = True
                break

            except self.retryable_errors as exc:
                current_try_count = current_try_count + 1
                msg = f"Cannot perform health check (retrying in {self.retry_wait_time} seconds)."
                if self.log_level_default == LogLevel.DEBUG:
                    self._log(msg=msg + f"\n{traceback.format_exc()}", level=LogLevel.ERROR)
                else:
                    self._log(msg=msg + f" {exc}", level=LogLevel.ERROR)
                try:
                    sleep(self.retry_wait_time)
                    continue
                except KeyboardInterrupt:
                    self._log(msg=f"{self.shutdown_msg} (KeyboardInterrupt).", level=LogLevel.WARNING)
                    return_code = 1
                    break

            except KeyboardInterrupt:
                self._log(msg=f"{self.shutdown_msg} (KeyboardInterrupt).", level=LogLevel.WARNING)
                return_code = 1
                break

            except Exception as exc:  # pylint: disable=broad-except
                msg = "Encountered unknown exception:"
                if self.log_level_default == LogLevel.DEBUG:
                    self._log(msg=msg + f"\n{traceback.format_exc()}", level=LogLevel.ERROR)
                else:
                    self._log(msg=msg + f" {exc}", level=LogLevel.ERROR)
                return_code = 1
                break

            finally:
                self.sock.close()

        if not success:
            self._log(msg=f"Unable to connect to {self.remote_server[0]} port {self.remote_server[1]}",
                      level=LogLevel.ERROR)
            return_code = 1

        return return_code


if __name__ == '__main__':
    hc_client = HealthCheckClient()
    exit_code = hc_client.run()
    sys.exit(exit_code)
