# pylint: disable=fixme
"""
Simple, lightweight service to allow for TCP and HTTP health checks and additional custom checks.
Primarily used for health checks of microservices inside containers but can be used for any health check on a server.

TODO: Implement a cli flag to specify a config file that contains the IP address, TCP port, and retry count.
TODO: Implement config file that specifies the external scripts to run for "live", "ready", and "health" checks.
TODO: Once the config file is implemented, update the "live", "ready", and "health" checks to use the config file.
TODO: Implement logging to a file in addition to the stdout (default to /var/blah-blah-blah.log).
TODO: Implement a cli flag to specify the log file name and path.
TODO: Implement custom health checks (project specific).
"""

import os
import sys
import socket
import argparse
import traceback
import json
import platform
import subprocess

from datetime import datetime, timezone, date  # pylint: disable=import-error,wrong-import-order
from time import sleep  # pylint: disable=import-error,wrong-import-order
from enum import Enum
from health_check_types import (HealthCheckVersion, HealthCheckTcp,  # pylint: disable=import-error,wrong-import-order
                                HealthCheckLive, HealthCheckReady, HealthCheckHealth, HealthCheckFavicon,
                                HealthCheckUnknown)
from health_check_types import HealthCheckTypes as HC  # pylint: disable=import-error,wrong-import-order


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


class HealthCheckService:  # pylint: disable=too-many-instance-attributes
    """
    Simple service to allow for TCP and HTTP health checks.
    """

    # Constants.
    _VERSION = "1.33"
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

    def __init__(self, ip_addr=None, port=None, retry_count=None):  # pylint: disable=too-many-branches
        """
        Constructor.

        :param ip_addr: (str) The IP address to bind to. Default is 0.0.0.0 (all IP addresses).

        :param port: (int) The TCP port to listen on. Default is 5757.

        :param retry_count: (int) The number of times to retry starting the service. Default is 5.
        """

        super().__init__()

        self._log_level_name_max_length = self.find_len_of_longest_log_level_name()

        if ip_addr is not None:
            self.ip_addr = ip_addr

        if port is not None:
            self.port = port

        if retry_count is not None:
            self.retry_count = retry_count

        parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

        parser.add_argument('-v', '--version', dest='show_version', action="store_true",
                            default=False, help='Show version.\n')

        parser.add_argument('-l', '--log-level', dest='log_level', action="append",
                            help="Logging level. Values: DEBUG, INFO, WARNING, ERROR. Default: INFO.\n")

        parser.add_argument('-i', '--ip-address', dest='ip_addr', action="append",
                            help='IP address to bind to. Default is "0.0.0.0" (all IP addresses).\n')

        parser.add_argument('-p', '--port', dest='port', action="append",
                            help='TCP port to listen on. Default is TCP port "5757"\n')

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

        if self.options.show_version:
            self.show_banner()
            sys.exit(0)

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

    @staticmethod
    def do_version_check():
        """
        Performs a version check.
        :return: The version object of the health check service.
        """
        hc_version = HealthCheckVersion()
        hc_version.set_status(hc_version.status_success())
        hc_version.set_msg(f"{__class__.__name__} v{HealthCheckService._VERSION}")
        return hc_version

    @staticmethod
    def do_tcp_check():
        """
        Performs a TCP check. Returns a status of "UP" if the TCP port is open or "DOWN" if the TCP port is closed.

        :return: (HealthCheckTcp) The TCP check object.
        """
        hc_tcp = HealthCheckTcp()
        hc_tcp.set_status(hc_tcp.status_success())
        return hc_tcp

    @staticmethod
    def do_live_check():
        """
        Performs a live check. Returns a status of "LIVE" if the service being monitored has started
        (even if it is not yet "READY") or "NOT_LIVE" if the service is not detected as started.

        :return: (HealthCheckLive) The live check object.
        """
        hc_live = HealthCheckLive()

        # TODO: Implement custom "live" check(s) here.

        # TODO: Implement if / else.
        # If "alive"
        hc_live.set_status(hc_live.status_success())
        # Else
        # hc_live.set_status(hc_live.status_failure())

        return hc_live

    @staticmethod
    def do_ready_check():
        """
        Performs a live check. Returns a status of "READY" if the service being monitored is "LIVE" and
        is ready to accept requests or "NOT_READY" if the service is not "LIVE" or not ready to accept requests.

        :return: (HealthCheckReady) The ready check object.
        """
        hc_ready = HealthCheckReady()

        # First do a "live" check.
        hc_live = HealthCheckService.do_live_check()

        if hc_live.is_live():

            # TODO: Implement custom "ready" check(s) here.

            # TODO: Implement if / else.
            # If "ready"
            hc_ready.set_status(hc_ready.status_success())
            # Else
            # hc_ready.set_status(hc_ready.status_failure())

        else:
            # Do need to do any additional checks if the service is not "LIVE".
            hc_ready.set_status(hc_ready.status_failure())
            hc_ready.set_msg(f'Received a {hc_live.get_status()} status from the {hc_live.name()} check.')

        return hc_ready

    @staticmethod
    def run_command(cmd=None):
        """
        Runs an arbitrary cli command.

        :return: (str) The combined stdout and stderr.
        """
        stdout = ""
        if cmd:
            with subprocess.Popen(
                    cmd,
                    shell=False,
                    bufsize=0,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT) as proc:
                while True:
                    _stdout_line = proc.stdout.readline().decode()
                    stdout = stdout + _stdout_line
                    if not _stdout_line:
                        break
        return stdout

    def get_uptime(self):
        """
        :return (str) The uptime of the system in seconds.
        """

        print(f"platform.system(): {platform.system()}")

        if "Darwin" in platform.system():
            cmd = ["date", "+%s"]
            now = HealthCheckService.run_command(cmd=cmd)

            # Example of output of command "sysctl -n kern.boottime":
            #  "{ sec = 1692260516, usec = 210443 } Thu Aug 17 02:21:56 2023\n"
            cmd = ["sysctl", "-n", "kern.boottime"]
            boot_time = HealthCheckService.run_command(cmd=cmd)
            boot_time = boot_time.split(',')[0].split('=')[1].strip()

            return int(now) - int(boot_time)

        if "Liunx" in platform.system():
            # Get the system uptime for linux in seconds.
            cmd = ["cat", "/proc/uptime"]
            up_time = HealthCheckService.run_command(cmd=cmd)
            up_time = up_time.split('.')[0].strip()

            return up_time

        self._log(msg=f'Unsupported OS platform: "{platform.system()}"', level=LogLevel.WARNING)
        return None

    @staticmethod
    def do_health_check():
        """
        Performs a health check. Returns a status of "HEALTHY" if the service being monitored is "LIVE", "READY", and
        is healthy or "NOT_HEALTHY" if the service is not "LIVE", not "READY", or not healthy.

        :return: (HealthCheckHealth) The health check object.
        """
        hc_health = HealthCheckHealth()

        # First do a "ready" check (which in turn will also do a "live" check).
        hc_ready = HealthCheckService.do_ready_check()

        if hc_ready.is_ready():
            # Examples of some basic stats:
            hc_health.stats["system_load"] = f"{os.getloadavg()[0]}, {os.getloadavg()[1]}, {os.getloadavg()[0]}"
            hc_health.stats["cpu_count"] = f"{os.cpu_count()}"
            hc_health.stats["uptime_seconds"] = f"{self.get_uptime()}"

            # TODO: Ideas of possible additional stats to include:
            #       - Memory usage
            #       - Disk usage
            #       - CPU usage
            #       - Average response time
            #       - Number of requests
            #       - Number of errors
            #       - Number of timeouts
            #       - Number of retries
            #       - Number of failures
            #       - Number of successes
            #       - Number of connections
            #       - Number of open files
            #       - Number of threads
            #       - Number of processes
            #       - Number of sockets
            #       - Number of connections
            #       - etc.

            # TODO: Implement custom "ready" check(s) here.

            # If healthy
            hc_health.set_status(hc_health.status_success())

            # If not healthy
            # hc_health.set_status(hc_health.status_failure())

        else:
            # Do need to do any additional checks if the service is not "LIVE".
            hc_health.set_status(hc_health.status_failure())
            hc_health.set_msg(f'Received a {hc_ready.get_status()} status from the {hc_ready.name()} check ' \
                              f'with message: [{hc_ready.get_status_dict()["msg"]}]')

        return hc_health

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

                        status_msg = ''

                        # If data starts with "GET ", then it is an HTTP request.
                        if data.decode().startswith("GET "):
                            # Extract the HTTP endpoint requested.
                            http_method = data.decode().split(" ")[0]
                            http_endpoint = data.decode().split(" ")[1:][0]

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
                            if data.decode().startswith(f"GET {HC.get_health_endpoint()}"):
                                http_body = self.do_health_check().get_status_dict()

                            elif data.decode().startswith(f"GET {HC.get_live_endpoint()}"):
                                http_body = self.do_live_check().get_status_dict()

                            elif data.decode().startswith(f"GET {HC.get_ready_endpoint()}"):
                                http_body = self.do_ready_check().get_status_dict()

                            elif data.decode().startswith(f"GET {HC.get_version_endpoint()}"):
                                http_body = self.do_version_check().get_status_dict()

                            elif data.decode().startswith(f"GET {HC.get_favicon_endpoint()}"):
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
                                    http_response_bytes = (http_header + self.http_header_delimiter + http_body)

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

    def start(self):  # pylint: disable=too-many-branches,too-many-statements
        """
        Starts the service.  Will retry up to retry_count times.
        :return:
        """
        self.show_banner()
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
