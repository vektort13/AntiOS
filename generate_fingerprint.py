import os
import sys
import argparse
import logging
import winreg
import random
import log_helper
import system_fingerprint
import hardware_fingerprint
import telemetry_fingerprint
import random_utils
import registry_helper


from registry_helper import RegistryKeyType, Wow64RegistryEntry
from system_utils import is_x64os, platform_version

logger = log_helper.setup_logger(name="antidetect", level=logging.INFO, log_to_file=False)


def generate_telemetry_fingerprint():
    """
    IDs related to Windows 10 Telemetry
    All the telemetry is getting around the DeviceID registry value
    It can be found in the following kays:
    HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SQMClient
    HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests
    """
    windows_ver = platform_version()
    if not windows_ver.startswith("Windows-10"):
        logger.warning("Telemetry ID replace available for Windows 10 only")
        return

    current_device_id = registry_helper.read_value(
        key_hive="HKEY_LOCAL_MACHINE",
        key_path="SOFTWARE\\Microsoft\\SQMClient",
        value_name="MachineId")
    if current_device_id[1] == winreg.REG_SZ:
        logger.info("Current Windows 10 Telemetry DeviceID is {0}".format(current_device_id[0]))
    else:
        logger.warning("Unexpected type of HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SQMClient Value:MachineId Type:%d" %
                       current_device_id[1])
        return

    telemetry_fp = telemetry_fingerprint.TelemetryFingerprint()
    device_id = telemetry_fp.random_device_id_guid()
    device_id_brackets = "{%s}" % telemetry_fp.random_device_id_guid()
    logger.info("New Windows 10 Telemetry DeviceID is {0}".format(device_id_brackets))

    registry_helper.write_value(key_hive="HKEY_LOCAL_MACHINE",
                                key_path="SOFTWARE\\Microsoft\\SQMClient",
                                value_name="MachineId",
                                value_type=winreg.REG_SZ,
                                key_value=device_id_brackets)

    # Replace queries
    query_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests"
    setting_requests = registry_helper.enumerate_key_subkeys(key_hive="HKEY_LOCAL_MACHINE",
                                                             key_path=query_path)
    logger.debug("SettingsRequest subkeys: {0}".format(setting_requests))

    for request in setting_requests:
        query_params = registry_helper.read_value(key_hive="HKEY_LOCAL_MACHINE",
                                                  key_path="%s\\%s" % (query_path, request),
                                                  value_name="ETagQueryParameters")
        if query_params[1] != winreg.REG_SZ:
            logger.warning("Unexpected type of %s\\%s Value:MachineId Type:%d" % (query_path, request, query_params[1]))
            return

        query_string = query_params[0]
        new_query_string = query_string.replace(current_device_id[0], device_id)
        registry_helper.write_value(key_hive="HKEY_LOCAL_MACHINE",
                                    key_path="%s\\%s" % (query_path, request),
                                    value_name="ETagQueryParameters",
                                    value_type=winreg.REG_SZ,
                                    key_value=new_query_string)

    logger.debug("DeviceID has been replaced from %s to %s" % (current_device_id, device_id))


def generate_network_fingerprint():
    """
    Generate network-related identifiers:
    Hostname (from pre-defined list)
    Username (from pre-defined list)
    MAC address (from pre-defined list)
    """
    random_host = random_utils.random_hostname()
    random_user = random_utils.random_username()
    random_mac = random_utils.random_mac_address()
    logger.info("Random hostname value is {0}".format(random_host))
    logger.info("Random username value is {0}".format(random_user))
    logger.info("Random MAC addresses value is {0}".format(random_mac))

    hive = "HKEY_LOCAL_MACHINE"
    logger.debug("Tcpip\\Parameters NV Hostname={0}".format(random_host))
    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
                                value_name="NV Hostname",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_host)

    logger.debug("Tcpip\\Parameters Hostname={0}".format(random_host))
    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
                                value_name="Hostname",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_host)

    logger.debug("Tcpip\\Parameters ComputerName={0}".format(random_host))
    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
                                value_name="ComputerName",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_host)

    logger.debug("ComputerName\\ActiveComputerName ComputerName={0}".format(random_host))
    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
                                value_name="ComputerName",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_host)

    logger.debug("Windows NT\\CurrentVersion RegisteredOwner={0}".format(random_user))
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                value_name="RegisteredOwner",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_user,
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)


def generate_windows_fingerprint():
    """
    Generate common Windows identifiers, responsible for fingerprinting:
    BuildGUID
    BuildLab
    BuildLabEx
    CurrentBuild
    CurrentBuildNumber
    CurrentVersion
    DigitalProductId
    DigitalProductId4
    EditionID
    InstallDate
    ProductId
    ProductName
    IE SvcKBNumber
    IE ProductId
    IE DigitalProductId
    IE DigitalProductId4
    IE Installed Date
    """
    system_fp = system_fingerprint.WinFingerprint()

    # Windows fingerprint
    hive = "HKEY_LOCAL_MACHINE"
    version_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

    logger.debug("Windows NT\\CurrentVersion BuildGUID")
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="BuildGUID",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_build_guid(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    logger.debug("Windows NT\\CurrentVersion BuildLab")
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="BuildLab",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_build_lab(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    logger.debug("Windows NT\\CurrentVersion BuildLabEx")
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="BuildLabEx",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_build_lab_ex(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    logger.debug("Windows NT\\CurrentVersion CurrentBuild")
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="CurrentBuild",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_current_build(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    logger.debug("Windows NT\\CurrentVersion CurrentBuildNumber")
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="CurrentBuildNumber",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_current_build(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    logger.debug("Windows NT\\CurrentVersion CurrentVersion")
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="CurrentVersion",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_current_version(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    logger.debug("Windows NT\\CurrentVersion DigitalProductId")
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="DigitalProductId",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(system_fp.random_digital_product_id()))

    logger.debug("Windows NT\\CurrentVersion DigitalProductId4")
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="DigitalProductId4",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(system_fp.random_digital_product_id4()))

    logger.debug("Windows NT\\CurrentVersion EditionID")
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="EditionID",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_edition_id(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    logger.debug("Windows NT\\CurrentVersion InstallDate")
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="InstallDate",
                                value_type=RegistryKeyType.REG_DWORD,
                                key_value=system_fp.random_install_date())

    logger.debug("Windows NT\\CurrentVersion ProductId")
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="ProductId",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_product_id(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    logger.debug("Windows NT\\CurrentVersion ProductName")
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="ProductName",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_product_name(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    # IE fingerprint
    logger.debug("Microsoft\\Internet Explorer svcKBNumber")
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer",
                                value_name="svcKBNumber",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_ie_service_update(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    logger.debug("Microsoft\\Internet Explorer ProductId")
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                value_name="ProductId",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_product_id())

    logger.debug("Microsoft\\Internet Explorer DigitalProductId")
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                value_name="DigitalProductId",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(system_fp.random_digital_product_id()))

    logger.debug("Internet Explorer\\Registration DigitalProductId")
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                value_name="DigitalProductId4",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(system_fp.random_digital_product_id4()))

    ie_install_date = system_fp.random_ie_install_date()
    logger.info("IEDate={0}".format(ie_install_date))

    logger.debug("Internet Explorer\\Migration IE Installed Date")
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Migration",
                                value_name="IE Installed Date",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=ie_install_date,
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

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
    """
    Generate hardware-related identifiers:
    HwProfileGuid
    MachineGuid
    Volume ID
    SusClientId
    SusClientIDValidation
    """

    hardware_fp = hardware_fingerprint.HardwareFingerprint()

    hive = "HKEY_LOCAL_MACHINE"
    # Hardware profile GUID

    logger.debug("Hardware Profiles\\0001 HwProfileGuid")
    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
                                value_name="HwProfileGuid",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=hardware_fp.random_hw_profile_guid())

    # Machine GUID
    logger.debug("Microsoft\\Cryptography MachineGuid")
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Cryptography",
                                value_name="MachineGuid",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=hardware_fp.random_machine_guid())

    # Windows Update GUID
    logger.debug("CurrentVersion\\WindowsUpdate SusClientId")
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
                                value_name="SusClientId",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=hardware_fp.random_win_update_guid())

    logger.debug("CurrentVersion\\WindowsUpdate SusClientIDValidation")
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
                                value_name="SusClientIDValidation",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(hardware_fp.random_client_id_validation()))

    dir_name = os.path.join(os.path.dirname(__file__), "bin")
    volume_id = random_utils.random_volume_id()
    logger.info("VolumeID={0}".format(volume_id))
    volume_id_path = os.path.join(dir_name, "VolumeID{0}.exe C: {1}".format("64" if is_x64os() else "", volume_id))
    os.system(volume_id_path)

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

    parser = argparse.ArgumentParser(description='Command-line parameters')

    parser.add_argument('--telemetry',
                        help='Generate Windows 10 Telemetry IDs',
                        action='store_true',
                        required=False,
                        default=False)

    parser.add_argument('--network',
                        help='Generate network-related fingerprint',
                        action='store_true',
                        required=False,
                        default=False)

    parser.add_argument('--system',
                        help='Generate fingerprint based on system version and identifiers',
                        action='store_true',
                        required=False,
                        default=False)

    parser.add_argument('--hardware',
                        help='Generate fingerprint based on hardware identifiers',
                        action='store_true',
                        required=False,
                        default=False)

    args = parser.parse_args()

    # Selected nothing means select all
    if args.telemetry is False and args.network is False and args.system is False and args.hardware is False:
        args.network = True
        args.system = True
        args.hardware = True

    if args.telemetry:
        generate_telemetry_fingerprint()
    if args.network:
        generate_network_fingerprint()
    if args.system:
        generate_windows_fingerprint()
    if args.hardware:
        generate_hardware_fingerprint()

    return 0


###########################################################################
if __name__ == '__main__':
    sys.exit(main())
