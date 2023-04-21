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
