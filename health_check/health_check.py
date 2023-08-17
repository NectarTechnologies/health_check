# pylint: disable=fixme
"""
TCP server to allow for TCP health checks and additional custom checks.
Primarily used for health checks of microservices inside containers but can be used for any health check on a server.
"""

import sys
import socket
import argparse
import traceback

from datetime import datetime, timezone, date  # pylint: disable=import-error,wrong-import-order
from time import sleep  # pylint: disable=import-error,wrong-import-order
from enum import Enum


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


class HealthCheckServer:  # pylint: disable=too-many-instance-attributes
    """
    Simple TCP server to allow for TCP health checks.
    """

    _VERSION = "1.5"
    _current_year = date.today().year
    _copyright = f"(C) {_current_year}"
    _service_name = "Health Check Service"

    shutdown_msg = f"{_service_name} shutting down."
    ip_addr = '0.0.0.0'
    port = 5757
    retry_count = 5  # number of times to retry starting the server
    retry_wait_time = 3  # seconds
    current_try_count = 0  # current try count
    _log_level_name_max_length = 0  # length of longest log level name
    log_level_default = LogLevel.INFO  # default log level
    options = None  # command line options
    sock = None  # socket

    def __init__(self, ip_addr=None, port=None, retry_count=None):  # pylint: disable=too-many-branches

        super().__init__()

        self._log_level_name_max_length = self.find_len_of_longest_log_level_name()

        if ip_addr is None:
            self.ip_addr = HealthCheckServer.ip_addr
        else:
            self.ip_addr = ip_addr

        if port is None:
            self.port = HealthCheckServer.port
        else:
            self.port = port

        if retry_count is None:
            self.retry_count = HealthCheckServer.retry_count
        else:
            self.retry_count = retry_count

        parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

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

    @staticmethod
    def find_len_of_longest_log_level_name():
        """
        Finds the length of the longest log level name.
        :return: (int) The length of the longest log level name.
        """
        return max(len(level.value[1]) for level in LogLevel)

        # max_length = 0
        # for level in LogLevel:
        #     if len(level.value) > max_length:
        #         max_length = len(level.value)
        # return max_length

    def _log(self, msg="", level=LogLevel.INFO, indent_level=1):
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
        """
        if indent_level > 0:
            indent = "    " * indent_level
            msg = f"{indent}{msg}"

        if level is None:
            level = LogLevel.INFO

        if level is not None and level.value[0] >= self.log_level_default.value[0]:
            # Generate an ISO 8601 conformant date-time stamp for the current time which also includes the timezone.
            datetime_iso8601 = datetime.now(timezone.utc).astimezone().isoformat()
            # Remove colons from the time stamp to make it compatible with Windows when used in a file name.
            datetime_iso8601.replace(':', '')
            # Add logging level into a fixed with string with the max length of the longest log level name.
            _log_level = f"[{level.value[1]}]"
            msg = f"{datetime_iso8601} {_log_level:<{self._log_level_name_max_length+2}}: {msg}"
            print(msg)

    def show_listening_message(self):
        """
        Shows a message that the server is listening for incoming connections.
        """
        self._log(msg="---------------------------------------------------------------", indent_level=0)
        self._log(msg="Listening for incoming connections...", indent_level=0)

    def health_check_run_loop(self):  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
        """
        Process incoming health check requests.
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

                if data:
                    # How many data bytes do we have?
                    if len(data) < 4:
                        self._log(msg=f"Request: {data}")
                        self._log(msg="Response: NONE")

                    # Else there is enough data to contain at least the HTTP request method "GET ".
                    else:
                        self._log(msg=f"Request bytes: {data}", level=LogLevel.DEBUG)

                        # If data starts with "GET ", then it is an HTTP request.
                        if data.decode().startswith("GET "):
                            # Extract the HTTP endpoint requested.
                            http_method = data.decode().split(" ")[0]
                            http_endpoint = data.decode().split(" ")[1:][0]

                            self._log(msg=f"Request: {http_method} {http_endpoint}")

                            http_header = b"HTTP/1.1 200 OK\r\n" \
                                          b"Cache-Control: private, max-age=0, no-store\r\n"

                            http_body = b''
                            http_body_should_encode = True
                            http_response_bytes = b''
                            status_msg = ''
                            http_response_log_level = LogLevel.INFO
                            content_type = b"Content-Type: application/json\r\n"

                            # Check which HTTP endpoint was requested.
                            if data.decode().startswith("GET /health"):

                                # TODO: Implement custom health checks here that return a status of "HEALTHY"
                                #       or "UNHEALTHY" along with a lot of statistics.

                                status_msg = "HEALTHY"
                                http_body = '{"status": "' + status_msg + '"}'

                            elif data.decode().startswith("GET /ready"):

                                # TODO: Implement custom check here that returns a status of "READY"
                                #       if the service being monitored it ready to correctly perform work
                                #       or "NOT_READY" if it is not ready to correctly perform work.

                                status_msg = "READY"
                                http_body = '{"status": "' + status_msg + '"}'

                            elif data.decode().startswith("GET /live"):

                                # TODO: Implement custom check here that returns a status of "LIVE"
                                #       if the service being monitored has started (even if it is not yet "READY")
                                #       or "NOT_LIVE" if the service is not detected as started.

                                status_msg = "LIVE"
                                http_body = '{"status": "' + status_msg + '"}'

                            elif data.decode().startswith("GET /version"):
                                # Returns the version of this health checking service.
                                status_msg = f'{{"version": "{HealthCheckServer._VERSION}"}}'
                                http_body = '{"status": "' + status_msg + '"}'

                            elif data.decode().startswith("GET /favicon.ico"):
                                # Return the favicon.ico file.
                                status_msg = "favicon.ico (binary file)"
                                content_type = b"Content-Type: image/x-icon\r\n" \
                                               b"Accept-Ranges: bytes\r\n"
                                # Read the favicon.ico file into the http_body.
                                with open("favicon.ico", "rb") as favicon_file:
                                    http_body = favicon_file.read()
                                    http_body_should_encode = False

                            else:
                                status_msg = "UNKNOWN_ENDPOINT"
                                http_body = '{"status": "' + status_msg + '"}'
                                http_response_log_level = LogLevel.ERROR

                            http_header = http_header + content_type
                            if http_body:
                                if http_body_should_encode:
                                    http_response_bytes = http_header + b"\r\n" + http_body.encode()
                                else:
                                    http_response_bytes = http_header + b"\r\n" + http_body
                            else:
                                http_response_bytes = http_header + b"\r\n"
                            self._log(msg=f"Response bytes: {http_response_bytes}", level=LogLevel.DEBUG)
                            self._log(msg=f"Response: {status_msg}", level=http_response_log_level)

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

    def start(self):  # pylint: disable=too-many-branches,too-many-statements
        """
        Starts the server.  Will retry up to retry_count times.
        :return:
        """
        self._log(msg="==========================================================================", indent_level=0)
        self._log(msg=f" {HealthCheckServer._service_name} v{HealthCheckServer._VERSION}", indent_level=0)
        self._log(msg=f" {HealthCheckServer._copyright}", indent_level=0)
        self._log(msg="==========================================================================", indent_level=0)
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
                self.health_check_run_loop()
                break

            except socket.error:
                self._log(msg=f"Unable to start {HealthCheckServer._service_name}, retrying in 5s. "
                              f"Encountered socket error:\n{traceback.format_exc()}",
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
            self._log(msg=f"Unable to start {HealthCheckServer._service_name} on "
                          f"{self.ip_addr} port {self.port}",
                      level=LogLevel.ERROR, indent_level=0)
            return


if __name__ == '__main__':
    # For now, if executed as main, simply run default server with just logging enabled
    server = HealthCheckServer()
    server.start()
