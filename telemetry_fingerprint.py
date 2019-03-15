import uuid


class TelemetryFingerprint:
    """
    Windows 10 telemetry IDs
    """
    def __init__(self):
        self.device_id_guid = str(uuid.uuid4()).upper()

    def random_device_id_guid(self):
        """
        :return: Telemetry Device ID GUID
        """
        return self.device_id_guid
