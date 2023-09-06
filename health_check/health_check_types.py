# pylint: disable=fixme
"""
Health check types class.

Used by health_check_service.py
Used by health_check_client.py
"""
import os

from health_check_types_enum import HealthCheckTypesEnum as HCEnum  # pylint: disable=import-error,wrong-import-order
from health_check_util import HealthCheckUtil  # pylint: disable=import-error,wrong-import-order


class HealthCheckTypes:  # pylint: disable=too-few-public-methods
    """
    Health check types.
    """
    health_check_type = None
    current_status = None
    data = {}
    _msg = ""
    _run_script = None

    def __init__(self, hc_type=None):
        self.health_check_type = hc_type
        self.current_status = None
        self.data = {}
        self._msg = ""
        self._run_script = None

    def _raise_exception(self, msg=None):
        """
        Raise an exception.
        """
        raise RuntimeError(msg)

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

    def is_successful(self):
        """
        :return: (bool) True if the health check is successful, False otherwise.
        """
        if self.current_status is None:
            self.run_check()
        return self.current_status == self.status_success()

    def get_status(self):
        """
        :return: (str) The current status of the health check.
        """
        return self.current_status

    def get_status_dict(self):
        """
        :return: (dict) The current status of the health check.
        """
        if self.current_status is None:
            self._raise_exception("Health check has not yet been performed.")

        return_dict = {
            "status": self.get_status(),
            "health_check_type": self.name()
        }

        if self._msg:
            return_dict["msg"] = self._msg

        if self.data:
            return_dict["data"] = self.data

        return return_dict

    def run_check(self):
        """
        Run the specific check.
        :return: (int) The return code of the script.
        """
        return_code = None
        if self._run_script is not None:
            self.data, return_code = HealthCheckUtil.run_command(self._run_script)
            if return_code == HealthCheckUtil.SUCCESS:
                self.set_status(self.status_success())
            else:
                self.set_status(self.status_failure())
        else:
            self.set_status(self.status_failure())
            self.data["msg"] = f"No run script defined for {self.name()} check."

        return return_code


class HealthCheckVersion(HealthCheckTypes):
    """
    Health check version.
    """
    def __init__(self):
        super().__init__(HCEnum.VERSION.value)
        self.set_status(self.status_success())


class HealthCheckTcp(HealthCheckTypes):
    """
    Health check TCP.
    """
    def __init__(self):
        super().__init__(HCEnum.TCP.value)

    def is_up(self):
        """
        :return: (bool) True if the health check status is "up", False otherwise.
        """
        return self.is_successful()


class HealthCheckLive(HealthCheckTypes):
    """
    Health check live.
    """
    def __init__(self, run_script=None):
        super().__init__(HCEnum.HTTP_LIVE.value)
        if run_script is not None:
            self._run_script = run_script

    def is_live(self):
        """
        :return: (bool) True if the health check status is "live", False otherwise.
        """
        return self.is_successful()


class HealthCheckReady(HealthCheckTypes):
    """
    Health check ready.
    """
    def __init__(self, run_script=None):
        super().__init__(HCEnum.HTTP_READY.value)
        if run_script is not None:
            self._run_script = run_script

    def is_ready(self):
        """
        :return: (bool) True if the health check status is "ready", False otherwise.
        """
        return self.is_successful()


class HealthCheckHealth(HealthCheckTypes):
    """
    Health check health.
    """
    def __init__(self, run_script=None):
        super().__init__(HCEnum.HTTP_HEALTH.value)
        if run_script is not None:
            self._run_script = run_script

    def is_healthy(self):
        """
        :return: (bool) True if the health check status is "healthy", False otherwise.
        """
        return self.is_successful()

    def get_status_dict(self):
        """
        This extends the base class method by adding the data to the return dict.
        :return: (dict) The current status of the health check including any data.
        """
        return_dict = super().get_status_dict()
        if self.data:
            return_dict["data"] = self.data
        return return_dict


class HealthCheckFavicon(HealthCheckTypes):
    """
    Health check favicon.
    """
    file_path = "favicon.ico"
    binary_data = None

    def __init__(self, file_path=None):
        super().__init__(HCEnum.FAVICON.value)
        if file_path is not None:
            self.file_path = file_path

        if self.read_binary_data():
            self._msg = "(binary file)"
        else:
            self._msg = f'File {self.file_path} not found)'

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
        if os.path.isfile(self.file_path):
            self.set_status(self.status_success())
            # Read the favicon.ico file into the http_body.
            with open(self.file_path, "rb") as favicon_file:
                self.binary_data = favicon_file.read()
            return True

        self.set_status(self.status_failure())
        return False


class HealthCheckUnknown(HealthCheckTypes):
    """
    Health check unknown.
    """
    def __init__(self):
        super().__init__(HCEnum.UNKNOWN.value)
        self.set_status(self.status_failure())
