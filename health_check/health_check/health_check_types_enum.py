# pylint: disable=fixme
"""
Health check types enum.

Used by health_check_service.py
Used by health_check_client.py
"""

from enum import Enum


class HealthCheckTypesEnum(Enum):  # pylint: disable=too-few-public-methods
    """
    Health check types.
    Parameter 1: (int) The health check type ID.
    Parameter 2: (str) The HTTP endpoint to check. (for TCP health checks, this is the same as parameter 1 since there
        is no HTTP endpoint to check).
    Parameter 3: (str) The health check type name.
    Parameter 4: (str) The status to return if the health check is successful.
    Parameter 5: (str) The status to return if the health check is not successful.
    Parameter 6: (str) The status to return if the health check is "degraded".
    """
    ICMP = 0, 'ICMP', 'ICMP', 'UP', 'DOWN', 'NO_DEGRADED_STATUS'
    TCP = 1, '/tcp', 'TCP', 'UP', 'DOWN', "DEGRADED"
    HTTP_LIVE = 2, '/live', 'LIVE', 'LIVE', 'NOT_LIVE', "DEGRADED"
    HTTP_READY = 3, '/ready', 'READY', 'READY', 'NOT_READY', "DEGRADED"
    HTTP_HEALTH = 4, '/health', 'HEALTH', 'HEALTHY', 'NOT_HEALTHY', "DEGRADED"
    VERSION = 5, '/version', 'VERSION', 'SUCCESS', 'FAILED', 'NO_DEGRADED_STATUS'
    FAVICON = 6, '/favicon.ico', 'FAVICON', 'FAVICON_FOUND', 'FAVICON_NOT_FOUND', 'NO_DEGRADED_STATUS'
    UNKNOWN = 7, 'NONE', 'UNKNOWN', 'NO_UP_STATUS', 'NO_DOWN_STATUS', 'NO_DEGRADED_STATUS'

    # Constants to use as indices into the HealthCheckTypesEnum tuple.
    TYPE_ID = 0
    ENDPOINT = 1
    NAME = 2
    STATUS_SUCCESS = 3
    STATUS_FAILURE = 4
    STATUS_DEGRADED = 5
