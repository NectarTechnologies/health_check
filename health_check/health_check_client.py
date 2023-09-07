# pylint: disable=fixme
"""
Simple, lightweight client that calls the health_check_service API TCP and HTTP health checks.
Primarily used for health checks of microservices inside containers but can be used for any health check on a server.

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

from datetime import datetime, timezone, date  # pylint: disable=import-error,wrong-import-order
from time import sleep  # pylint: disable=import-error,wrong-import-order
from health_check_types import (HealthCheckVersion, HealthCheckTcp,  # pylint: disable=import-error,wrong-import-order
                                HealthCheckLive, HealthCheckReady, HealthCheckHealth, HealthCheckFavicon)
from health_check_types_enum import HealthCheckTypesEnum as HCEnum  # pylint: disable=import-error,wrong-import-order
from health_check_util import LogLevel  # pylint: disable=import-error,wrong-import-order


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
    _VERSION = "1.22"
    _current_year = date.today().year
    _copyright = f"(C) {_current_year}"
    _service_name = "Health Check Client"
    shutdown_msg = f"{_service_name} shutting down."
    http_header_delimiter = b"\r\n"
    CONFIG_FILE_NAME = "health_check.conf"
    DEFAULT_CONFIG_FILE = f"/etc/health_check/{CONFIG_FILE_NAME}"

    # Variables that can be passed into __init__().
    server_host = None
    server_port = 5757
    retry_count = 5  # number of times to retry starting the service
    check_tcp = False  # If True, then check that the TCP port of the server can be connected to.
    check_http_live = False  # If True, then check that the HTTP endpoint "/live" returns "LIVE".
    check_http_ready = False  # If True, then check that the HTTP endpoint "/ready" returns "READY".
    check_http_health = False  # If True, then check that the HTTP endpoint "/health" returns "HEALTHY".
    check_server_version = False  # If True, then check the version returned the HTTP endpoint "/version".
    check_favicon = False  # If True, then check if the favicon is returned by the HTTP endpoint "/favicon.ico".

    # Internal variables.
    server_ip_addr = None
    remote_server = None  # A tuple of (server_host, server_port) where server_host can be a hostname or IP address.
    retry_wait_time = 3  # seconds
    current_try_count = 0  # current try count
    _log_level_name_max_length = 0  # length of longest log level name
    log_level_default = LogLevel.INFO  # default log level
    options = None  # command line options
    sock = None  # socket
    _current_health_check_type = HCEnum.TCP  # Default to TCP health check.
    include_data_details = None  # include data details in the health check script responses
    config_file = DEFAULT_CONFIG_FILE

    retryable_errors = (
        socket.error,
        socket.gaierror
    )

    def __init__(self,  # pylint: disable=too-many-branches,too-many-statements,too-many-arguments,too-many-locals
                 server_host=None,
                 server_port=None,
                 retry_count=None,
                 log_level=None,
                 check_tcp=None,
                 check_http_live=None,
                 check_http_ready=None,
                 check_http_health=None,
                 check_favicon=None,
                 check_server_version=None,
                 include_data_details=None,
                 config_file=None):
        """
        Constructor.

        :param server_host: (str) The IP address of the server to connect to.

        :param server_port: (int) The TCP port of the server to connect to.

        :param retry_count: (int) The number of times to retry connecting to server.

        :param log_level: (str) Logging level. Values: DEBUG, INFO, WARNING, ERROR. Default: INFO.

        :param check_tcp: (bool) If True, then check that the TCP port of the server can be connected to.
            Default is True.

        :param check_http_live: (bool) If True, then check that the HTTP endpoint "/live" returns "LIVE".
            Default is False.
                Example of "LIVE" response:
                    {"status": "LIVE"}
                Example of "NOT_LIVE" response:
                    {"status": "NOT_LIVE"}

        :param check_http_ready: (bool) If True, then check that the HTTP endpoint "/ready" returns "READY".
            Default is False.
                Example of "READY" response:
                    {"status": "READY"}
                Example of "NOT_READY" response:
                    {"status": "NOT_READY"}

        :param check_http_health: (bool) If True, then check that the HTTP endpoint "/health" returns "HEALTHY".
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

        parser.add_argument('-l', '--log-level', dest='log_level', action="append",
                            help="Logging level. Values: DEBUG, INFO, WARNING, ERROR. Default: INFO.\n")

        parser.add_argument('-s', '--server-host', dest='server_host', action="append",
                            help='Host name (or IP address) of the server to connect to.\n')

        parser.add_argument('-p', '--server_port', dest='server_port', action="append",
                            help='TCP port of the server to connect to. Default is TCP port "5757"\n')

        parser.add_argument('-r', '--retries', dest='retry_count', action="append",
                            help='The number of times to retry connecting to server.\n')

        parser.add_argument('-t', '--check-tcp', dest='check_tcp', action="store_true",
                            default=None,
                            help='If True, then check that the TCP port of the server can be connected to.\n')

        parser.add_argument('-i', '--check-http-live', dest='check_http_live', action="store_true",
                            default=None,
                            help='If True, then check that the HTTP endpoint "/live" returns "LIVE".\n')

        parser.add_argument('-a', '--check-http-ready', dest='check_http_ready', action="store_true",
                            default = None,
                            help='If True, then check that the HTTP endpoint "/ready" returns "READY".\n')

        parser.add_argument('-e', '--check-http-health', dest='check_http_health', action="store_true",
                            default=None,
                            help='If True, then check that the HTTP endpoint "/health" returns "HEALTHY".\n')

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
                                 f'    {os.path.abspath(__file__)}/{self.CONFIG_FILE_NAME}\n')

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
                    else:
                        self.config_file = None

        # pylint: disable=too-many-nested-blocks,too-many-boolean-expressions
        if self.config_file and os.path.isfile(self.config_file) and os.access(self.config_file, os.R_OK):
            self.config = configparser.ConfigParser()
            self.config.read(self.config_file)
            self.process_config_params()
        else:
            self._log(msg=f'Config file [{self.config_file}] does not exist or cannot be read.',
                      level=LogLevel.WARNING)
            self._log(msg='Attempting to run with default parameters.', level=LogLevel.WARNING)

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

        if self.options.server_host is not None:
            self.server_host = self.options.server_host[0]
        else:
            if server_host is None:
                self._log(msg="Parameter server_host is required. See --help for more info.", level=LogLevel.ERROR)
                sys.exit(1)

        if self.options.server_port is not None:
            self.server_port = int(self.options.server_port[0])
        else:
            if server_port is not None:
                self.server_port = server_port

        if self.options.retry_count is not None:
            self.retry_count = int(self.options.retry_count[0])
        else:
            if retry_count is not None:
                self.retry_count = retry_count

        if self.options.check_tcp is not None:
            self.check_tcp = self.options.check_tcp
        else:
            if check_tcp is not None:
                self.check_tcp = check_tcp

        if self.options.check_http_live is not None:
            self.check_http_live = self.options.check_http_live
        else:
            if check_http_live is not None:
                self.check_http_live = check_http_live

        if self.options.check_http_ready is not None:
            self.check_http_ready = self.options.check_http_ready
        else:
            if check_http_ready is not None:
                self.check_http_ready = check_http_ready

        if self.options.check_http_health is not None:
            self.check_http_health = self.options.check_http_health
        else:
            if check_http_health is not None:
                self.check_http_health = check_http_health

        if self.options.check_favicon is not None:
            self.check_favicon = self.options.check_favicon
        else:
            if check_favicon is not None:
                self.check_favicon = check_favicon

        if self.options.show_server_version:
            self.check_server_version = True
        else:
            if check_server_version is not None:
                self.check_server_version = check_server_version

        if self.options.include_data_details is not None:
            self.include_data_details = self.options.include_data_details
        else:
            if include_data_details is not None:
                self.include_data_details = include_data_details

        # If all health check types are False, then default to TCP health check.
        # pylint: disable=too-many-boolean-expressions
        if not self.check_tcp and \
            not self.check_http_live and \
            not self.check_http_ready and \
            not self.check_http_health and \
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
                if key == "server_host":
                    self.server_host = value
                elif key == "server_port":
                    self.server_port = int(value)
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
                else:
                    self._log(msg=f'Unknown config file parameter "{key}"', level=LogLevel.WARNING)

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

        if isinstance(msg, dict):
            # Convert the dict to a str.
            msg = str(msg)

        if indent_level > 0:
            indent = "    " * indent_level
            msg = f"{indent}{msg}"

        if level is None:
            level = LogLevel.INFO

        if level is not None and level.value[0] >= self.log_level_default.value[0]:
            if show_prefix:
                # Generate an ISO 8601 conformant date-time stamp for the current time which also includes the timezone.
                datetime_iso8601 = datetime.now(timezone.utc).astimezone().isoformat()
                # Remove colons from the time stamp to make it compatible with Windows when used in a file name.
                datetime_iso8601.replace(':', '')
                # Add logging level into a fixed with string with the max length of the longest log level name.
                _log_level = f"[{level.value[1]}]"
                msg = f"{datetime_iso8601} {_log_level:<{self._log_level_name_max_length+2}}: {msg}"
            else:
                msg = f"{msg}"
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
        """
        self.show_connecting_message()

        response_msg = {}

        http_header_request_method = b'GET '
        http_header_request_endpoint = b''
        http_header_request_version = b' HTTP/1.1\r\n'
        http_header_cache_control = b"Cache-Control: private, max-age=0, no-store, no-cache\r\n" \
                                    b"Pragma: no-cache\r\n"
        http_header_accept_encoding = b"Accept-Encoding: gzip, deflate\r\n"

        if self.is_valid_ip_address(self.server_host):
            http_header_request_host = b'Host: ' + self.server_host.encode() + b'\r\n'
        else:
            http_header_request_host = b'Host: ' + self.remote_server[0].encode() + b'\r\n'

        # Connect to the server.
        self.sock.connect(self.remote_server)

        # Check which health check type was requested.
        hc_type = None
        try:
            if self.check_tcp:
                hc_type = HealthCheckTcp()
                response_msg["status"] = hc_type.status_success()
                response_msg["health_check_type"] = hc_type.name()
                response_msg_json = json.dumps(response_msg, indent=4)
                self._log(msg=response_msg_json, level=LogLevel.INFO)
                return

            if self.check_http_live:
                hc_type = HealthCheckLive()
                response_msg["health_check_type"] = hc_type.name()
                http_header_request_endpoint = f"{hc_type.endpoint()}".encode()

            elif self.check_http_ready:
                hc_type = HealthCheckReady()
                response_msg["health_check_type"] = hc_type.name()
                http_header_request_endpoint = f"{hc_type.endpoint()}".encode()

            elif self.check_http_health:
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
                response_msg_json = json.dumps(response_msg, indent=4)
                self._log(msg=response_msg_json, level=LogLevel.ERROR)
                return

            self._log(msg=f"Bytes Received: {http_response_raw}", level=LogLevel.DEBUG)

            # Separate the HTTP header and HTTP body.
            http_response_header, http_response_body = http_response_raw.split(sep=b"\r\n\r\n", maxsplit=1)

            # Convert the HTTP header to a string.
            http_response_header = http_response_header.decode()

            if self.check_favicon:
                # Check if the favicon.ico file was returned.
                if "Content-Type: image/x-icon" in http_response_header:
                    response_msg["status"] = hc_type.status_success()
                else:
                    response_msg["status"] = hc_type.status_failure()
                response_msg_json = json.dumps(response_msg, indent=4)
                self._log(msg=response_msg_json, level=LogLevel.INFO)

            else:
                # Convert the HTTP body to a string.
                http_response_body = http_response_body.decode()
                self._log(msg=f"{http_response_body}", level=LogLevel.INFO)

        except KeyboardInterrupt:
            self._log(msg=f"{self.shutdown_msg} (KeyboardInterrupt).", level=LogLevel.WARNING)

        except Exception as exc:
            self._log(msg="Encountered unknown exception: {exc}", level=LogLevel.ERROR)
            raise exc

    def run(self):  # pylint: disable=too-many-branches,too-many-statements
        """
        Runs the client.  Will retry up to retry_count times if connection to server fails.
        :return:
        """
        while self.current_try_count < self.retry_count:
            try:
                self.current_try_count = self.current_try_count + 1

                self._log(msg="Creating TCP/IP socket.", level=LogLevel.DEBUG)
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                # Check if we're dealing with an IP address or a host name.
                if self.is_valid_ip_address(self.server_host):
                    # Since we have a valid IP address, then use it as is.
                    self.remote_server = (self.server_host, self.server_port)
                else:
                    # Since we do not have a valid IP address, then assume it is a host name and resolve
                    # it to an IP address.
                    self._log(msg="Resolving server host name to IP.", level=LogLevel.DEBUG)
                    self.server_ip_addr = socket.gethostbyname(self.server_host)
                    self.remote_server = (self.server_ip_addr, self.server_port)

                self.do_health_check()
                break

            except self.retryable_errors as exc:
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
                    break

            except KeyboardInterrupt:
                self._log(msg=f"{self.shutdown_msg} (KeyboardInterrupt).", level=LogLevel.WARNING)
                break

            except Exception as exc:  # pylint: disable=broad-except
                msg = "Encountered unknown exception:"
                if self.log_level_default == LogLevel.DEBUG:
                    self._log(msg=msg + f"\n{traceback.format_exc()}", level=LogLevel.ERROR)
                else:
                    self._log(msg=msg + f" {exc}", level=LogLevel.ERROR)
                break

            finally:
                self.sock.close()

        if self.current_try_count >= self.retry_count:
            self._log(msg=f"Unable to connect to {self.remote_server[0]} port {self.remote_server[1]}",
                      level=LogLevel.ERROR)
            return


if __name__ == '__main__':
    hc_client = HealthCheckClient()
    hc_client.run()
