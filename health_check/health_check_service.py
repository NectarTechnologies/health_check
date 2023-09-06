# pylint: disable=fixme
"""
Simple, lightweight service to allow for TCP and HTTP health checks and additional custom checks.
Primarily used for health checks of microservices inside containers but can be used for any health check on a server.

TODO: Implement a cli flag to specify a config file that contains the IP address, TCP port, and retry count.
TODO: Implement config file that specifies the external scripts to run for "live", "ready", and "health" checks.
TODO: Once the config file is implemented, update the "live", "ready", and "health" checks to use the config file.
TODO: Implement logging to a file in addition to the stdout (default to /var/blah-blah-blah.log).
TODO: Implement log rotation so log files do not fill the disk.
TODO: Implement a cli flag to specify the log file name and path.
TODO: Implement custom health checks (project specific).
TODO: Implement a "push" mode where the service will push the health check status to a remote server.
"""

import os
import sys
import socket
import argparse
import traceback
import json
import platform

from datetime import datetime, timezone, date  # pylint: disable=import-error,wrong-import-order
from time import sleep  # pylint: disable=import-error,wrong-import-order
from health_check_types import (HealthCheckVersion, HealthCheckTcp,  # pylint: disable=import-error,wrong-import-order
                                HealthCheckLive, HealthCheckReady, HealthCheckHealth, HealthCheckFavicon,
                                HealthCheckUnknown)
from health_check_types import HealthCheckTypes as HC  # pylint: disable=import-error,wrong-import-order
from health_check_util import HealthCheckUtil  # pylint: disable=import-error,wrong-import-order
from health_check_util import LogLevel  # pylint: disable=import-error,wrong-import-order


class HealthCheckService:  # pylint: disable=too-many-instance-attributes
    """
    Simple service to allow for TCP and HTTP health checks.
    """

    # Constants.
    _VERSION = "1.47"
    _current_year = date.today().year
    _copyright = f"(C) {_current_year}"
    _service_name = "Health Check Service"
    shutdown_msg = f"{_service_name} shutting down."
    http_header_delimiter = b"\r\n"

    # Variables that can be passed into __init__().
    ip_addr = '0.0.0.0'
    port = 5757
    retry_count = 5  # number of times to retry starting the service

    # Internal variables.
    retry_wait_time = 3  # seconds
    current_try_count = 0  # current try count
    _log_level_name_max_length = 0  # length of longest log level name
    log_level_default = LogLevel.INFO  # default log level
    options = None  # command line options
    sock = None  # socket
    live_check_script = None  # path to live check script
    ready_check_script = None  # path to ready check script
    health_check_script = None  # path to health check script
    include_data_details = None  # include data details in the health check script responses

    def __init__(self,  # pylint: disable=too-many-branches,too-many-statements,too-many-arguments
                 ip_addr=None, port=None, retry_count=None, live_check_script=None, ready_check_script=None,
                 health_check_script=None, include_data_details=False):
        """
        Constructor.

        :param ip_addr: (str) The IP address to bind to. Default is 0.0.0.0 (all IP addresses).

        :param port: (int) The TCP port to listen on. Default is 5757.

        :param retry_count: (int) The number of times to retry starting the service. Default is 5.

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
        """

        super().__init__()

        self._log_level_name_max_length = self.find_len_of_longest_log_level_name()

        if ip_addr is not None:
            self.ip_addr = ip_addr

        if port is not None:
            self.port = port

        if retry_count is not None:
            self.retry_count = retry_count

        if live_check_script is not None:
            self.live_check_script = live_check_script

        if ready_check_script is not None:
            self.ready_check_script = ready_check_script

        if health_check_script is not None:
            self.health_check_script = health_check_script

        if include_data_details is not None:
            self.include_data_details = include_data_details

        parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

        parser.add_argument('-v', '--version', dest='show_version', action="store_true",
                            default=False, help='Show version.\n')

        parser.add_argument('-l', '--log-level', dest='log_level', action="append",
                            help="Logging level. Values: DEBUG, INFO, WARNING, ERROR. Default: INFO.\n")

        parser.add_argument('-i', '--ip-address', dest='ip_addr', action="append",
                            help='IP address to bind to. Default is "0.0.0.0" (all IP addresses).\n')

        parser.add_argument('-p', '--port', dest='port', action="append",
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

        try:
            self.options, _ = parser.parse_known_args(sys.argv[:])
        except Exception as exc:  # pylint: disable=broad-except
            self._log(msg=f"Encountered unknown exception: {exc}", level=LogLevel.ERROR, indent_level=0)
            sys.exit(1)

        if self.options.log_level is not None:
            if "DEBUG" in self.options.log_level:
                self.log_level_default = LogLevel.DEBUG
            elif "INFO" in self.options.log_level:
                self.log_level_default = LogLevel.INFO
            elif "WARNING" in self.options.log_level:
                self.log_level_default = LogLevel.WARNING
            elif "ERROR" in self.options.log_level:
                self.log_level_default = LogLevel.ERROR
            else:
                self.log_level_default = LogLevel.INFO

        if self.options.ip_addr is not None:
            self.ip_addr = self.options.ip_addr[0]

        if self.options.port is not None:
            self.port = int(self.options.port[0])

        if self.options.live_check_script is not None:
            self.live_check_script = self.options.live_check_script[0]

        if self.options.ready_check_script is not None:
            self.ready_check_script = self.options.ready_check_script[0]

        if self.options.health_check_script is not None:
            self.health_check_script = self.options.health_check_script[0]

        if self.options.show_version:
            self.show_banner()
            sys.exit(0)

        if self.live_check_script is not None:
            if not os.path.isfile(os.path.abspath(self.live_check_script)):
                self._log(msg=f'Live check script "{self.live_check_script}" does not exist.',
                          level=LogLevel.ERROR)
                sys.exit(1)

        if self.ready_check_script is not None:
            if not os.path.isfile(os.path.abspath(self.ready_check_script)):
                self._log(msg=f'Ready check script "{self.ready_check_script}" does not exist.',
                          level=LogLevel.ERROR)
                sys.exit(1)

        if self.health_check_script is not None:
            if not os.path.isfile(os.path.abspath(self.health_check_script)):
                self._log(msg=f'Health check script "{self.health_check_script}" does not exist.',
                          level=LogLevel.ERROR)
                sys.exit(1)

        if self.options.include_data_details:
            self.include_data_details = True

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

    @staticmethod
    def do_version_check():
        """
        Performs a version check.
        :return: The version object of the health check service.
        """
        hc_version = HealthCheckVersion()
        hc_version.set_status(hc_version.status_success())
        hc_version.data["service_name"] = HealthCheckService._service_name
        hc_version.data["version"] = HealthCheckService._VERSION
        return hc_version

    def do_tcp_check(self):
        """
        Performs a TCP check. Returns a status of "UP" if the TCP port is open or "DOWN" if the TCP port is closed.

        :return: (HealthCheckTcp) The TCP check object.
        """
        hc_tcp = HealthCheckTcp()
        hc_tcp.set_status(hc_tcp.status_success())
        return hc_tcp

    def do_live_check(self, include_data_details=False):
        """
        Performs a live check. Returns a status of "LIVE" if the service being monitored has started
        (even if it is not yet "READY"). Returns "NOT_LIVE" if the service is not detected as started.

        :param include_data_details: (bool) If True, then include data details in the health check script responses.
        :return: (HealthCheckLive) The live check object.
        """
        hc_live = HealthCheckLive(run_script=self.live_check_script)
        hc_live.run_check(include_data_details=include_data_details)
        self._log(msg=f"hc_live object: \n{hc_live.pretty_str()}", level=LogLevel.DEBUG)
        return hc_live

    def do_ready_check(self, include_data_details=False):
        """
        Performs a live check. Returns a status of "READY" if the service being monitored is "LIVE" and
        is ready to accept requests. Returns "NOT_READY" if the service is not "LIVE" or not ready to accept requests.

        :param include_data_details: (bool) If True, then include data details in the health check script responses.
        :return: (HealthCheckReady) The ready check object.
        """
        # First do a "live" check.
        hc_live = self.do_live_check(include_data_details=include_data_details)

        hc_ready = HealthCheckReady(run_script=self.ready_check_script)

        if hc_live.is_live(include_data_details=include_data_details):
            hc_ready.is_ready(include_data_details=include_data_details)
            self._log(msg=f"hc_ready object: \n{hc_ready.pretty_str()}", level=LogLevel.DEBUG)
        else:
            self._log(msg=f"hc_ready object: \n{hc_ready.pretty_str()}", level=LogLevel.DEBUG)
            hc_ready.set_status(hc_ready.status_failure())
            hc_ready.set_msg(f'Received a {hc_live.get_status()} status from the {hc_live.name()} check with '
                             f'message: {hc_live.get_status_dict()}')
        return hc_ready

    def do_health_check(self, include_data_details=False):
        """
        Performs a health check. Returns a status of "HEALTHY" if the service being monitored is "LIVE", "READY", and
        is healthy. Returns "NOT_HEALTHY" if the service is not "LIVE", not "READY", or not healthy.

        :param include_data_details: (bool) If True, then include data details in the health check script responses.
        :return: (HealthCheckHealth) The health check object.
        """
        # First do a "ready" check (which in turn will also do a "live" check).
        hc_ready = self.do_ready_check(include_data_details=include_data_details)

        hc_health = HealthCheckHealth(run_script=self.health_check_script)

        if hc_ready.is_ready(include_data_details=include_data_details):
            hc_health.is_healthy(include_data_details=include_data_details)
            self._log(msg=f"hc_health object: \n{hc_health.pretty_str()}", level=LogLevel.DEBUG)
        else:
            self._log(msg=f"hc_health object: \n{hc_health.pretty_str()}", level=LogLevel.DEBUG)
            hc_health.set_status(hc_health.status_failure())
            hc_health.set_msg(f'Received a {hc_ready.get_status()} status from the {hc_ready.name()} check '
                              f'with message: [{hc_ready.get_status_dict()["msg"]}],')
        return hc_health

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
                    self._log(msg=f'Status: "{self.do_tcp_check().get_status_dict()["status"]}"',
                              level=LogLevel.INFO)
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
                            http_response_code = b"200"
                            http_response_msg = b"OK"
                            http_header_cache_control = b"Cache-Control: private, max-age=0, no-store, no-cache\r\n" \
                                                        b"Pragma: no-cache\r\n"
                            http_header_content_type = b"Content-Type: application/json\r\n"

                            http_body = {}

                            http_body_is_binary_file = False
                            status_msg = ''
                            http_response_log_level = LogLevel.INFO

                            # Check which HTTP endpoint was requested.
                            if data.startswith(f"GET {HC.get_health_endpoint()}"):
                                http_body = self.do_health_check(_details).get_status_dict()

                            elif data.startswith(f"GET {HC.get_live_endpoint()}"):
                                http_body = self.do_live_check(_details).get_status_dict()

                            elif data.startswith(f"GET {HC.get_ready_endpoint()}"):
                                http_body = self.do_ready_check(_details).get_status_dict()

                            elif data.startswith(f"GET {HC.get_version_endpoint()}"):
                                http_body = self.do_version_check().get_status_dict()

                            elif data.startswith(f"GET {HC.get_favicon_endpoint()}"):
                                # Return the favicon.ico binary file.
                                http_header_content_type = b"Content-Type: image/x-icon\r\n" \
                                                           b"Accept-Ranges: bytes\r\n"

                                hc_favicon = HealthCheckFavicon()

                                if hc_favicon.is_successful():
                                    http_body = hc_favicon.get_binary_data()
                                    http_body_is_binary_file = True
                                    status_msg = hc_favicon.get_status_dict()["msg"]
                                else:
                                    http_body = hc_favicon.get_status_dict()

                            else:
                                http_body = HealthCheckUnknown().get_status_dict()
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

        self._log(msg=f"Log level: {self.log_level_default.value[1]}", indent_level=0, show_prefix=False)

        self.show_health_check_scripts()

        self._log(msg="", indent_level=0, show_prefix=False)
        self._log(msg=f"Service listening on: "
                      f"{self.ip_addr}:{self.port} (TCP)", indent_level=0)

        while self.current_try_count < self.retry_count:
            try:
                self.current_try_count = self.current_try_count + 1

                # Create a TCP/IP socket
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.bind((self.ip_addr, self.port))
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
                          f"{self.ip_addr} port {self.port}",
                      level=LogLevel.ERROR, indent_level=0)
            return


if __name__ == '__main__':
    service = HealthCheckService()
    service.start()
