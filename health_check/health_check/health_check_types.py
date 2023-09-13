# pylint: disable=fixme
"""
Health check types class.

Used by health_check_service.py
Used by health_check_client.py
"""
import os
import ast
import json
import time
import socket

from health_check_types_enum import HealthCheckTypesEnum as HCEnum  # pylint: disable=import-error,wrong-import-order
from health_check_util import HealthCheckUtil  # pylint: disable=import-error,wrong-import-order


class HealthCheckTypes:  # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """
    Health check types.
    """
    current_status = None
    health_check_type = None
    _msg = None
    _run_script = None
    _last_return_code = None
    data = {}
    include_data_details = False

    def __init__(self, hc_type=None):
        self.health_check_type = hc_type
        self.current_status = None
        self._msg = None
        self._run_script = None
        self._last_return_code = None
        self.data = {}

    def __str__(self):
        """
        :return: (str) Prints the string representation of the health check type instance in JSON format.
        """
        tmp_dict = {
            "current_status": self.current_status,
            "health_check_type": self.health_check_type,
            "_msg": self._msg,
            "_run_script": self._run_script,
            "_last_return_code": self._last_return_code,
            "data": self.data
        }
        return str(tmp_dict)

    def pretty_str(self):
        """
        :return: (str) Prints the string representation of the health check type instance in JSON format.
        """
        tmp = str(self).replace("None", '"None"')
        tmp = ast.literal_eval(tmp)
        return json.dumps(tmp, indent=4)

    def _raise_exception(self, msg=None):
        """
        Raise an exception.
        """
        raise RuntimeError(msg)

    @staticmethod
    def get_tcp_endpoint():
        """
        :return: (str) The tcp endpoint string.
        """
        return HCEnum.TCP.value[HCEnum.ENDPOINT.value]

    @staticmethod
    def get_live_endpoint():
        """
        :return: (str) The live endpoint string.
        """
        return HCEnum.HTTP_LIVE.value[HCEnum.ENDPOINT.value]

    @staticmethod
    def get_ready_endpoint():
        """
        :return: (str) The ready endpoint string.
        """
        return HCEnum.HTTP_READY.value[HCEnum.ENDPOINT.value]

    @staticmethod
    def get_health_endpoint():
        """
        :return: (str) The health endpoint string.
        """
        return HCEnum.HTTP_HEALTH.value[HCEnum.ENDPOINT.value]

    @staticmethod
    def get_version_endpoint():
        """
        :return: (str) The version endpoint string.
        """
        return HCEnum.VERSION.value[HCEnum.ENDPOINT.value]

    @staticmethod
    def get_favicon_endpoint():
        """
        :return: (str) The favicon endpoint string.
        """
        return HCEnum.FAVICON.value[HCEnum.ENDPOINT.value]

    def set_return_code(self, return_code=None):
        """
        Set the return code of the health check.
        """
        self._last_return_code = return_code

    def get_return_code(self):
        """
        :return: (int) The return code of the script.
        """
        if self._last_return_code is None:
            self._raise_exception("Return code is None.")
        return self._last_return_code

    def type_id(self):
        """
        :return: (str) The health check type ID.
        """
        if self.health_check_type is None:
            self._raise_exception("Health check type is None.")
        return self.health_check_type[HCEnum.TYPE_ID.value]

    def endpoint(self):
        """
        :return: (str) The health check endpoint string (i.e. relative URL).
        """
        if self.health_check_type is None:
            self._raise_exception("Health check type is None.")
        return self.health_check_type[HCEnum.ENDPOINT.value]

    def name(self):
        """
        :return: (str) The health check name string.
        """
        if self.health_check_type is None:
            self._raise_exception("Health check type is None.")
        return self.health_check_type[HCEnum.NAME.value]

    def status_success(self):
        """
        :return: (str) The health check success status string.
        """
        if self.health_check_type is None:
            self._raise_exception("Health check type is None.")
        return self.health_check_type[HCEnum.STATUS_SUCCESS.value]

    def status_failure(self):
        """
        :return: (str) The health check failure status string.
        """
        if self.health_check_type is None:
            self._raise_exception("Health check type is None.")
        return self.health_check_type[HCEnum.STATUS_FAILURE.value]

    def status_degraded(self):
        """
        :return: (str) The health check degraded status string.
        """
        if self.health_check_type is None:
            self._raise_exception("Health check type is None.")
        return self.health_check_type[HCEnum.STATUS_DEGRADED.value]

    def set_status(self, status=None):
        """
        Set the current status of the health check.

        :param status: (str) The status to set.
        """
        if status is None:
            self._raise_exception(f'Cannot set current_status to "{status}."')
        self.current_status = status

    def set_msg(self, msg=None):
        """
        Set the current msg of the health check.

        :param msg: (str) The msg to set.
        """
        if msg is None:
            self._raise_exception(f'Cannot set msg to "{msg}."')
        self._msg = msg

    def set_run_script(self, run_script=None):
        """
        Set the run script of the health check.
        """
        if run_script is None:
            self._raise_exception(f'Cannot set run_script to "{run_script}."')
        self._run_script = os.path.abspath(run_script)

    def is_successful(self, include_data_details=False):
        """
        :param include_data_details: (bool) True to populate the data dictionary with script details, False otherwise.
        :return: (bool) True if the health check is successful, False otherwise.
        """
        if self.current_status is None:
            self.run_check(include_data_details=include_data_details)
        return self.current_status == self.status_success()

    def get_status(self):
        """
        :return: (str) The current status of the health check.
        """
        return self.current_status

    @staticmethod
    def get_timestamp():
        """
        :return: (str) The current time stamp.
        """
        return HealthCheckUtil.get_iso8601_time_stamp(remove_colons=False)

    def build_status_dict(self):
        """
        :return: (dict) The current status of the health check.
        """
        return_dict = {
            "status": self.get_status(),
            "health_check_type": self.name(),
            "last_check_time": HealthCheckTypes.get_timestamp(),
            "last_check_time_epoch": time.time()
        }

        if self._msg is not None:
            return_dict["msg"] = self._msg
        else:
            return_dict["msg"] = ""

        if self.data:
            return_dict["data"] = self.data

        return return_dict

    def get_status_dict(self):
        """
        :return: (dict) The current status of the health check.
        """
        return_dict = self.build_status_dict()
        return return_dict

    def run_check(self, include_data_details=False):
        """
        Run the specific check.
        :param include_data_details: (bool) True to populate the data dictionary with script details, False otherwise.
        :return: (int) The return code of the script.
        """
        return_code = None
        if self._run_script is not None:
            err_msg = None
            script_output = None
            script_output_raw, return_code = HealthCheckUtil.run_command(self._run_script)

            # Expect script_output to be in JSON format.
            try:
                # Attempt to convert the output JSON to a dictionary.
                script_output = json.loads(script_output_raw)
            except json.decoder.JSONDecodeError:
                err_msg = "Could not decode JSON data from health check response."
                script_output = script_output_raw

            if return_code == HealthCheckUtil.SUCCESS:
                self.set_status(self.status_success())
            else:
                self.set_status(self.status_failure())

            if include_data_details:
                self._last_return_code = return_code
                self.data = {"script": {}}
                if err_msg is not None:
                    self.data["script"]["err_msg"] = err_msg
                self.data["script"]["path"] = self._run_script
                self.data["script"]["return_code"] = self._last_return_code
                self.data["script"]["output"] = script_output

        else:
            self.set_status(self.status_failure())
            self._msg = f"No run script defined for {self.name()} check."

        return return_code


class HealthCheckVersion(HealthCheckTypes):
    """
    Health check version.
    """
    def __init__(self):
        super().__init__(HCEnum.VERSION.value)
        self.set_status(self.status_success())


class HealthCheckIcmp(HealthCheckTypes):
    """
    Health check ICMP echo response (aka PING). Tests if a remote network endpoint will respond to
    an ICMP echo request.
    :param destination: (str) The destination host (hostname or IP address).
    """
    destination = None

    def __init__(self, destination=None):
        super().__init__(HCEnum.ICMP.value)

        if destination is None:
            self._raise_exception("Destination is None.")
        self.destination = destination

    def run_check(self, include_data_details=False):
        """
        This overrides the base class method.
        Test if the remote network endpoint will respond to an ICMP echo request.
        :param include_data_details: (bool) True to populate the data dictionary with script details, False otherwise.
        :return: (int) The return code of the script.
        """
        cmd = ['bash', '-c', f"ping -c 3 -W 2 -i 0.2 {self.destination}"]
        script_output, return_code = HealthCheckUtil.run_command(cmd)
        script_output_lines = script_output.splitlines()

        script_output = ""
        for line in script_output_lines:
            if "packet loss" in line or "min/avg/max" in line:
                script_output = script_output + line + "\n"

        if return_code == 0:
            self.set_status(self.status_success())
        else:
            self.set_status(self.status_failure())

        if include_data_details:
            self._last_return_code = return_code
            self.data = {"script": {
                    "return_code": self._last_return_code,
                    "output": script_output
                }
            }

        return return_code

    def is_successful(self, include_data_details=False):
        """
        This overrides the base class method.
        :param include_data_details: (bool) True to populate the data dictionary with script details, False otherwise.
        :return: (bool) True if the health check is successful, False otherwise.
        """
        self.run_check()
        return self.current_status == self.status_success()

    def is_up(self, include_data_details=False):
        """
        :param include_data_details: (bool) True to populate the data dictionary with script details, False otherwise.
        :return: (bool) True if the health check status is "up", False otherwise.
        """
        return self.is_successful(include_data_details=include_data_details)


class HealthCheckTcp(HealthCheckTypes):
    """
    Health check TCP. Tests if a remote TCP port is open.
    :param ip_tcp_list: (list of tuples of (str, int)) A list of tuples containing the IP address and TCP port to check.
    :param exclude_port_list: (list of int) A list of TCP ports to exclude from the check.
    """
    target_list = None  # (host, port)
    exclude_port_list = None  # [port1, port2, ...]

    # Items in list are tuples in this format:
    #   ((str, int), str, int)
    # Example:
    #   [((host, port), status, return_code),
    #    ((host, port), status, return_code),
    #    ...]
    result_list = []

    def __init__(self, ip_tcp_list=None, exclude_port_list=None):
        super().__init__(HCEnum.TCP.value)

        self.target_list = ip_tcp_list

        if exclude_port_list is None:
            self.exclude_port_list = []
        else:
            self.exclude_port_list = exclude_port_list

    def run_check(self, include_data_details=False):
        """
        This overrides the base class method.
        Check the remote TCP port of each target passed in.
        :param include_data_details: (bool) True to populate the data dictionary with script details, False otherwise.
        :return: (int) The return code of the script.
        """
        self.result_list = []
        self.set_status(self.status_success())  # Assume success until a failure is found.
        if self.target_list is None:
            self._last_return_code = 0
        else:
            for target in self.target_list:
                if target[1] not in self.exclude_port_list:
                    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj.settimeout(2)
                    return_code = socket_obj.connect_ex(target)
                    if return_code == 0:
                        self.result_list.append((target, self.status_success(), return_code))
                    else:
                        self.result_list.append((target, self.status_failure(), return_code))
                    socket_obj.close()
                else:
                    self.result_list.append((target, self.status_success(), 0))

        # If any TCP checks failed then the overall check failed.
        success_found = False
        failure_found = False
        failure_code = None
        for result in self.result_list:
            self._last_return_code = result[2]
            if result[1] == self.status_failure():
                self.set_status(self.status_failure())
                failure_found = True
                failure_code = result[2]
            else:
                success_found = True

        if failure_found:
            self._last_return_code = failure_code

        if success_found and failure_found:
            self.set_status(self.status_degraded())
            self.set_msg("Some TCP checks failed.")

        if include_data_details:
            self.data = {
                "tcp_check": {
                    "return_code": self._last_return_code,
                    "tcp_internal_ports": self.result_list,
                    "tcp_external_ports": []
                }
            }

        return self._last_return_code

    def is_successful(self, include_data_details=False):
        """
        This overrides the base class method.
        :param include_data_details: (bool) True to populate the data dictionary with script details, False otherwise.
        :return: (bool) True if the health check is successful, False otherwise.
        """
        self.run_check()
        return self.current_status == self.status_success()

    def is_up(self, include_data_details=False):
        """
        :param include_data_details: (bool) True to populate the data dictionary with script details, False otherwise.
        :return: (bool) True if the health check status is "up", False otherwise.
        """
        return self.is_successful(include_data_details=include_data_details)


class HealthCheckLive(HealthCheckTypes):
    """
    Health check live.
    """
    def __init__(self, run_script=None):
        super().__init__(HCEnum.HTTP_LIVE.value)
        if run_script is not None:
            self.set_run_script(run_script)

    def is_live(self, include_data_details=False):
        """
        :param include_data_details: (bool) True to populate the data dictionary with script details, False otherwise.
        :return: (bool) True if the health check status is "live", False otherwise.
        """
        return self.is_successful(include_data_details=include_data_details)


class HealthCheckReady(HealthCheckTypes):
    """
    Health check ready.
    """
    hc_live = None

    def __init__(self, run_script=None):
        super().__init__(HCEnum.HTTP_READY.value)
        if run_script is not None:
            self.set_run_script(run_script)

    def is_ready(self, include_data_details=False):
        """
        :param include_data_details: (bool) True to populate the data dictionary with script details, False otherwise.
        :return: (bool) True if the health check status is "ready", False otherwise.
        """
        return self.is_successful(include_data_details=include_data_details)

    def build_status_dict(self):
        """
        This overrides the base class method.
        :return: (dict) The current status of the health check.
        """
        return_dict = {
            "status": self.get_status(),
            "health_check_type": self.name(),
            "last_check_time": HealthCheckTypes.get_timestamp(),
            "last_check_time_epoch": time.time()
        }

        if self.hc_live is not None:
            return_dict["live_check"] = self.hc_live.get_status()

        if self._msg is not None:
            return_dict["msg"] = self._msg
        else:
            return_dict["msg"] = ""

        if self.data:
            return_dict["data"] = self.data

        return return_dict


class HealthCheckHealth(HealthCheckTypes):
    """
    Health check health.
    """
    hc_live = None
    hc_ready = None

    def __init__(self, run_script=None):
        super().__init__(HCEnum.HTTP_HEALTH.value)
        if run_script is not None:
            self.set_run_script(run_script)

    def is_healthy(self, include_data_details=False):
        """
        :param include_data_details: (bool) True to populate the data dictionary with script details, False otherwise.
        :return: (bool) True if the health check status is "healthy", False otherwise.
        """
        return self.is_successful(include_data_details=include_data_details)

    def build_status_dict(self):
        """
        This overrides the base class method.
        :return: (dict) The current status of the health check.
        """
        return_dict = {
            "status": self.get_status(),
            "health_check_type": self.name(),
            "last_check_time": HealthCheckTypes.get_timestamp(),
            "last_check_time_epoch": time.time()
        }

        if self.hc_live is not None:
            return_dict["live_check"] = self.hc_live.get_status()

        if self.hc_ready is not None:
            return_dict["ready_check"] = self.hc_ready.get_status()

        if self._msg is not None:
            return_dict["msg"] = self._msg
        else:
            return_dict["msg"] = ""

        if self.data:
            return_dict["data"] = self.data

        return return_dict


class HealthCheckFavicon(HealthCheckTypes):
    """
    Health check favicon.
    """
    favicon_path = None
    binary_data = None

    def __init__(self, favicon_path=None):
        super().__init__(HCEnum.FAVICON.value)
        if favicon_path is not None:
            self.favicon_path = favicon_path

        if self.read_binary_data():
            self._msg = "(binary file)"
        else:
            self._msg = f'File {self.favicon_path} not found)'

    def get_binary_data(self):
        """
        :return: (bytes) The favicon.ico file contents.
        """
        if self.binary_data is None:
            self.read_binary_data()
        return self.binary_data

    def read_binary_data(self):
        """
        Reads the favicon.ico file contents.
        :return: (bool) True if the favicon.ico file exists, False otherwise.
        """
        # Check if the favicon.ico file exists.
        if os.path.isfile(self.favicon_path):
            self.set_status(self.status_success())
            # Read the favicon.ico file into the http_body.
            with open(self.favicon_path, "rb") as favicon_file:
                self.binary_data = favicon_file.read()
            return True

        self.set_status(self.status_failure())
        return False

    def is_successful(self, include_data_details=False):
        """
        This overrides the base class method.
        :param include_data_details: (bool) True to populate the data dictionary with script details, False otherwise.
        :return: (bool) True if the health check is successful, False otherwise.
        """
        if self.current_status is None:
            self.get_binary_data()
        return self.current_status == self.status_success()


class HealthCheckUnknown(HealthCheckTypes):
    """
    Health check unknown.
    """
    def __init__(self):
        super().__init__(HCEnum.UNKNOWN.value)
        self.set_status(self.status_failure())
