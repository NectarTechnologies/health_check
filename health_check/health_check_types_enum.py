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


##########################################################################################
Description:
  Health check types enum.
  This enum is used to define the health check types that are supported by the health check
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
