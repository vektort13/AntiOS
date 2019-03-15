import random
import uuid
import string
import random_utils


class HardwareFingerprint:
    """
    Hardware-related GUIDs
    """
    def __init__(self):
        self.hw_profile_guid = ("{%s}" % str(uuid.uuid4()))
        self.performance_guid = ("{%s}" % str(uuid.uuid4()))
        self.machine_guid = str(uuid.uuid4())
        self.win_update_guid = str(uuid.uuid4())
        self.system_client_id = self.__random_system_client_id()

    def random_hw_profile_guid(self):
        """
        :return: Hardware profile GUID
        """
        return self.hw_profile_guid

    def random_performance_guid(self):
        """
        :return: Performance\BootCKCLSettings and Performance\BShutdownCKCLSettings GUID
        """
        return self.performance_guid

    def random_machine_guid(self):
        """
        :return: Cryptography MachineGuid
        """
        return self.machine_guid

    def random_win_update_guid(self):
        """
        :return: Windows update SusClientId
        """
        return self.win_update_guid

    def random_client_id_validation(self):
        """
        :return: Windows update SusClientIdValidation
        """
        return self.system_client_id

    #############################################################################
    # Internal methods

    @staticmethod
    def __random_id1():
        random_id1 = random.choices(string.digits+string.ascii_uppercase, k=19)
        random_id1_list = random_utils.disperse_string(random_id1)
        return random_id1_list

    @staticmethod
    def __random_id2():
        return random.choices(range(1, 255), k=5)

    @staticmethod
    def __random_system_client_id():
        system_client_id = [0] * 0x08
        system_client_id[0x00:0x03] = [0x06, 0x02, 0x28, 0x01]
        system_client_id[0x04:0x06] = random.sample(range(1, 255), 3)
        system_client_id[0x07] = 0
        # 0x08 - Start random part of ID
        system_client_id.extend(HardwareFingerprint.__random_id1())
        system_client_id.extend([0, 6, 0])
        system_client_id.extend(HardwareFingerprint.__random_id2())
        system_client_id.extend(random_utils.disperse_string("None"))
        return system_client_id
