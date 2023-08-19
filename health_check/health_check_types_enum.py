# pylint: disable=fixme
"""
Health check types enum.

Used by health_check_service.py
Used by health_check_client.py
"""

from enum import Enum


class HealthCheckTypes(Enum):  # pylint: disable=too-few-public-methods
    """
    Health check types.
    Parameter 1: (int) The health check type ID.
    Parameter 2: (str) The HTTP endpoint to check. (for TCP health checks, this is the same as parameter 1 since there
        is no HTTP endpoint to check).
    Parameter 3: (str) The health check type name.
    Parameter 4: (str) The status to return if the health check is successful.
    Parameter 5: (str) The status to return if the health check is not successful.
    """
    TCP = 1, 'TCP', 'TCP', 'UP', 'DOWN'
    HTTP_LIVE = 2, '/live', 'LIVE', 'LIVE', 'NOT_LIVE'
    HTTP_READY = 3, '/ready', 'READY', 'READY', 'NOT_READY'
    HTTP_HEALTH = 4, '/health', 'HEALTH', 'HEALTHY', 'NOT_HEALTHY'
    VERSION = 5, '/version', 'VERSION', 'VERSION', 'VERSION'
    FAVICON = 6, '/favicon.ico', 'FAVICON', 'FAVICON', 'FAVICON'
    UNKNOWN = 7, 'NONE', 'UNKNOWN', 'NO_STATUS', 'NO_STATUS'

    # Constants to use as indices into the HealthCheckTypes tuple.
    TYPE_ID = 0
    ENDPOINT = 1
    NAME = 2
    STATUS_SUCCESS = 3
    STATUS_FAILURE = 4
