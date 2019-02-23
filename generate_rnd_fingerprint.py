import os
import sys
import logging
import struct
import log_helper
import win_fingerprint
import hardware_fingerprint
import random_utils
import registry_helper

from registry_helper import RegistryKeyType, Wow64RegistryEntry

logger = log_helper.setup_logger(name="antidetect", level=logging.INFO, log_to_file=False)


def randoms_from_lists():
    random_host = random_utils.random_hostname()
    random_user = random_utils.random_username()
    random_mac = random_utils.random_mac_address()
    logger.info("Random hostname value is {0}".format(random_host))
    logger.info("Random username value is {0}".format(random_user))
    logger.info("Random MAC addresses value is {0}".format(random_mac))

    hive = "HKEY_LOCAL_MACHINE"
    registry_helper.write_registry(hive, "SYSTEM\CurrentControlSet\services\Tcpip\Parameters",
                                   "NV Hostname",
                                   RegistryKeyType.REG_SZ, random_host)
    registry_helper.write_registry(hive, "SYSTEM\CurrentControlSet\services\Tcpip\Parameters",
                                   "Hostname",
                                   RegistryKeyType.REG_SZ, random_host)
    registry_helper.write_registry(hive, "SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
                                   "ComputerName",
                                   RegistryKeyType.REG_SZ, random_host)
    registry_helper.write_registry(hive, "SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
                                   "ComputerName",
                                   RegistryKeyType.REG_SZ, random_host)
    registry_helper.write_registry(hive, "SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                                   "RegisteredOwner",
                                   RegistryKeyType.REG_SZ, random_user, Wow64RegistryEntry.KEY_WOW32_64)
    dirname = os.path.join(os.path.dirname(__file__), "bin")
    print(dirname)
    volumeid_path = os.path.join(dirname, "VolumeID{0}.exe {1}".format("64" if random_utils.is_x64os() else "",
                                                                       random_utils.random_volume_id()))
    print(volumeid_path)
    os.system(volumeid_path)


def generate_windows_fingerprint():

    system_fp = win_fingerprint.WinFingerprint()

    # Windows fingerprint
    hive = "HKEY_LOCAL_MACHINE"
    version_path = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"

    registry_helper.write_registry(hive, version_path, "BuildGUID",
                                   RegistryKeyType.REG_SZ,
                                   system_fp.random_build_guid(), Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_registry(hive, version_path, "BuildLab",
                                   RegistryKeyType.REG_SZ,
                                   system_fp.random_build_lab(), Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_registry(hive, version_path, "BuildLabEx",
                                   RegistryKeyType.REG_SZ,
                                   system_fp.random_build_lab_ex(), Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_registry(hive, version_path, "CurrentBuild",
                                   RegistryKeyType.REG_SZ,
                                   system_fp.random_current_build(), Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_registry(hive, version_path, "CurrentBuildNumber",
                                   RegistryKeyType.REG_SZ,
                                   system_fp.random_current_build(), Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_registry(hive, version_path, "CurrentVersion",
                                   RegistryKeyType.REG_SZ,
                                   system_fp.random_current_version(), Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_registry(hive, version_path, "DigitalProductId",
                                   RegistryKeyType.REG_BINARY,
                                   random_utils.bytes_list_to_array(system_fp.random_digital_product_id()))
    registry_helper.write_registry(hive, version_path, "DigitalProductId4",
                                   RegistryKeyType.REG_BINARY,
                                   random_utils.bytes_list_to_array(system_fp.random_digital_product_id4()))
    registry_helper.write_registry(hive, version_path, "EditionID",
                                   RegistryKeyType.REG_SZ,
                                   system_fp.random_edition_id(), Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_registry(hive, version_path, "InstallDate",
                                   RegistryKeyType.REG_DWORD,
                                   system_fp.random_install_date())
    registry_helper.write_registry(hive, version_path, "ProductId",
                                   RegistryKeyType.REG_SZ,
                                   system_fp.random_product_id(), Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_registry(hive, version_path, "ProductName",
                                   RegistryKeyType.REG_SZ,
                                   system_fp.random_product_name(), Wow64RegistryEntry.KEY_WOW32_64)

    # IE footprint
    registry_helper.write_registry(hive, "SOFTWARE\Microsoft\Internet Explorer", "svcKBNumber",
                                   RegistryKeyType.REG_SZ,
                                   system_fp.random_ie_service_update(), Wow64RegistryEntry.KEY_WOW32_64)

    registry_helper.write_registry(hive, "SOFTWARE\Microsoft\Internet Explorer\Registration", "ProductId",
                                   RegistryKeyType.REG_SZ,
                                   system_fp.random_product_id())
    registry_helper.write_registry(hive, "SOFTWARE\Microsoft\Internet Explorer\Registration", "DigitalProductId",
                                   RegistryKeyType.REG_BINARY,
                                   random_utils.bytes_list_to_array(system_fp.random_digital_product_id()))
    registry_helper.write_registry(hive, "SOFTWARE\Microsoft\Internet Explorer\Registration", "DigitalProductId4",
                                   RegistryKeyType.REG_BINARY,
                                   random_utils.bytes_list_to_array(system_fp.random_digital_product_id4()))

    ie_install_date = system_fp.random_ie_install_date()
    registry_helper.write_registry(hive, "SOFTWARE\Microsoft\Internet Explorer\Migration", "IE Installed Date",
                                   RegistryKeyType.REG_BINARY,
                                   struct.pack(">LL", ie_install_date[0], ie_install_date[1]),
                                   Wow64RegistryEntry.KEY_WOW32_64)

    logger.info("Random build GUID {0}".format(system_fp.random_build_guid()))
    logger.info("Random BuildLab {0}".format(system_fp.random_build_lab()))
    logger.info("Random BuildLabEx {0}".format(system_fp.random_build_lab_ex()))
    logger.info("Random Current Build {0}".format(system_fp.random_current_build()))
    logger.info("Random Current Build number {0}".format(system_fp.random_current_build()))
    logger.info("Random Current Version {0}".format(system_fp.random_current_version()))
    logger.info("Random Edition ID {0}".format(system_fp.random_edition_id()))
    logger.info("Random Install Date {0}".format(system_fp.random_install_date()))
    logger.info("Random product ID {0}".format(system_fp.random_product_id()))
    logger.info("Random Product name {0}".format(system_fp.random_product_name()))
    logger.debug("Random digital product ID {0}".format(system_fp.random_digital_product_id()))
    logger.debug("Random digital product ID 4 {0}".format(system_fp.random_digital_product_id4()))
    logger.debug("Random IE service update {0}".format(system_fp.random_ie_service_update()))
    logger.debug("Random IE install data {0}".format(system_fp.random_ie_install_date()))


def generate_hardware_fingerprint():

    hardware_fp = hardware_fingerprint.HardwareFingerprint()

    hive = "HKEY_LOCAL_MACHINE"
    # Hardware profile GUID
    registry_helper.write_registry(hive, "SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\\0001",
                                   "HwProfileGuid",
                                   RegistryKeyType.REG_SZ,
                                   hardware_fp.random_hw_profile_guid())

    # Machine GUID
    registry_helper.write_registry(hive, "SOFTWARE\Microsoft\Cryptography",
                                   "MachineGuid",
                                   RegistryKeyType.REG_SZ,
                                   hardware_fp.random_machine_guid())

    # Windows Update GUID
    registry_helper.write_registry(hive, "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate",
                                   "SusClientId",
                                   RegistryKeyType.REG_SZ,
                                   hardware_fp.random_win_update_guid())
    registry_helper.write_registry(hive, "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate",
                                   "SusClientIDValidation",
                                   RegistryKeyType.REG_BINARY,
                                   random_utils.bytes_list_to_array(hardware_fp.random_client_id_validation()))

    logger.info("Random Hardware profile GUID {0}".format(hardware_fp.random_hw_profile_guid()))
    logger.info("Random Hardware CKCL GUID {0}".format(hardware_fp.random_performance_guid()))
    logger.info("Random Machine GUID {0}".format(hardware_fp.random_machine_guid()))
    logger.info("Random Windows Update GUID {0}".format(hardware_fp.random_win_update_guid()))
    logger.debug("Random Windows Update Validation ID {0}".format(hardware_fp.random_win_update_guid()))


def main():
    """
    Generate and change/spoof Windows identification to protect user from local installed software
    :return: Exec return code
    """
    randoms_from_lists()
    generate_windows_fingerprint()
    generate_hardware_fingerprint()
    return 0


###########################################################################
if __name__ == '__main__':
    sys.exit(main())
