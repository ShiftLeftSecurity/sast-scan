# This file is part of Scan.

# Scan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Scan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Scan.  If not, see <https://www.gnu.org/licenses/>.

import requests

import lib.config as config
from lib.logger import LOG


def track(track_obj):
    """
    Method to send a track message to the telemetry api
    :param track_obj:
    :return:
    """
    # Check if telemetry is disabled
    disable_telemetry = config.get("DISABLE_TELEMETRY", False)
    if (
        disable_telemetry == "true"
        or disable_telemetry == "1"
        or not config.get("TELEMETRY_URL")
    ):
        disable_telemetry = True
    else:
        disable_telemetry = False
    if track_obj and not disable_telemetry:
        try:
            track_obj["tool"] = "@ShiftLeft/scan"
            requests.post(config.get("TELEMETRY_URL"), json=track_obj)
        except Exception:
            LOG.debug("Unable to send telemetry")
