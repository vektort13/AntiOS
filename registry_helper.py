import logging
import log_helper
import winreg
import enum

from system_utils import is_x64os

logger = log_helper.setup_logger(name="registry_helper", level=logging.DEBUG, log_to_file=False)


__doc__ = """File contains registry-related functions, for creating, enumerating, editing and removing Windows 
registry keys and values. enums and dictionaries with registry-related integer values, imported from winreg module
Also is_x64os() helper function provided
"""

HIVES_MAP = {
    "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
    "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
    "HKEY_USERS": winreg.HKEY_USERS,
    "HKEY_PERFORMANCE_DATA": winreg.HKEY_PERFORMANCE_DATA,
    "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
    "HKEY_DYN_DATA": winreg.HKEY_DYN_DATA
}


class RegistryKeyType(enum.IntEnum):
    # Binary data in any form
    REG_BINARY = 0

    # 32-bit number
    REG_DWORD = 1

    # A 32-bit number in little-endian format. Equivalent to REG_DWORD
    REG_DWORD_LITTLE_ENDIAN = 2

    # A 32-bit number in big-endian format
    REG_DWORD_BIG_ENDIAN = 3

    # Null-terminated string containing references to environment variables (%PATH%)
    REG_EXPAND_SZ = 4

    # A Unicode symbolic link
    REG_LINK = 5

    # A sequence of null-terminated strings, terminated by two null characters,
    # Python handles this termination automatically
    REG_MULTI_SZ = 6

    # No defined value type
    REG_NONE = 7

    # A 64-bit number
    REG_QWORD = 8

    # A 64-bit number in little-endian format. Equivalent to REG_QWORD
    REG_QWORD_LITTLE_ENDIAN = 9

    # A device-driver resource list
    REG_RESOURCE_LIST = 10

    # A hardware setting
    REG_FULL_RESOURCE_DESCRIPTOR = 11

    # A hardware resource list
    REG_RESOURCE_REQUIREMENTS_LIST = 12

    # A null-terminated string
    REG_SZ = 13


TYPES_MAP = {
    RegistryKeyType.REG_BINARY: winreg.REG_BINARY,
    RegistryKeyType.REG_DWORD: winreg.REG_DWORD,
    RegistryKeyType.REG_DWORD_LITTLE_ENDIAN: winreg.REG_DWORD_LITTLE_ENDIAN,
    RegistryKeyType.REG_DWORD_BIG_ENDIAN: winreg.REG_DWORD_BIG_ENDIAN,
    RegistryKeyType.REG_EXPAND_SZ: winreg.REG_EXPAND_SZ,
    RegistryKeyType.REG_LINK: winreg.REG_LINK,
    RegistryKeyType.REG_MULTI_SZ: winreg.REG_MULTI_SZ,
    RegistryKeyType.REG_NONE: winreg.REG_NONE,
    RegistryKeyType.REG_QWORD: winreg.REG_QWORD,
    RegistryKeyType.REG_QWORD_LITTLE_ENDIAN: winreg.REG_QWORD_LITTLE_ENDIAN,
    RegistryKeyType.REG_RESOURCE_LIST: winreg.REG_RESOURCE_LIST,
    RegistryKeyType.REG_FULL_RESOURCE_DESCRIPTOR: winreg.REG_FULL_RESOURCE_DESCRIPTOR,
    RegistryKeyType.REG_RESOURCE_REQUIREMENTS_LIST: winreg.REG_RESOURCE_REQUIREMENTS_LIST,
    RegistryKeyType.REG_SZ: winreg.REG_SZ
}


class Wow64RegistryEntry(enum.IntEnum):

    # Directly access 32-bit Registry entry
    KEY_WOW32 = 0

    # Directly access 64-bit Registry entry
    KEY_WOW64 = 1

    # Indirectly access both 32-bit and Registry entries
    KEY_WOW32_64 = 2


WOW64_MAP = {
    Wow64RegistryEntry.KEY_WOW32: winreg.KEY_WOW64_32KEY,
    Wow64RegistryEntry.KEY_WOW64: winreg.KEY_WOW64_64KEY,
    Wow64RegistryEntry.KEY_WOW32_64: 0
}


def is_key_exist(key_hive, key_path, access_type=Wow64RegistryEntry.KEY_WOW64):
    """
    Check if registry key exist
    :param key_hive: Windows registry hive to edit, e.g. HKEY_CURRENT_USER
    :param key_path: Path Windows registry key inside the hive, for example "SOFTWARE\Microsoft\Windows"
    :param access_type: Access type for 32/64 bit registry sub-entries in HKLM/SOFTWARE key.
    :return: True is key exist, False if not or unable to access
    """
    if access_type == Wow64RegistryEntry.KEY_WOW32_64:
        raise RuntimeError("Use either KEY_WOW64 or KEY_WOW32 with create_key()")

    try:
        key_hive_value = HIVES_MAP[key_hive]
        wow64_flags = WOW64_MAP[access_type]
        winreg.OpenKey(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_READ))
        return True
    except WindowsError as e:
        # FileNotFound = 2
        if e.winerror == 2:
            return False
        logger.error("is_key_exist %s\\%s: LastError=%d [%s]".format(key_hive, key_path, e.winerror, e.strerror))
        return False


def enumerate_key_values(key_hive, key_path, access_type=Wow64RegistryEntry.KEY_WOW64):
    """
    Enumerate Windows Registry key (only subkeys, no values)
    :param key_hive: Windows registry hive to edit, e.g. HKEY_CURRENT_USER
    :param key_path: Path Windows registry key inside the hive, for example "SOFTWARE\Microsoft\Windows"
    :param access_type: Access type for 32/64 bit registry sub-entries in HKLM/SOFTWARE key.
    :return: List of registry subkeys
    """
    if access_type == Wow64RegistryEntry.KEY_WOW32_64:
        raise RuntimeError("Use either KEY_WOW64 or KEY_WOW32 with enumerate_key_values()")

    entry_num = 0
    try:
        key_hive_value = HIVES_MAP[key_hive]
        wow64_flags = WOW64_MAP[access_type]
        registry_key = winreg.OpenKey(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_READ))
        result = []
        for entry_num in range(0, winreg.QueryInfoKey(registry_key)[1]):
            result.append(winreg.EnumValue(registry_key, entry_num))
        return result
    except WindowsError as e:
        logger.error("Unable to enumerate registry key subkeys %s\\%s with LastError=%d [%s], entry=%d",
                     key_hive, key_path, e.winerror, e.strerror, entry_num)
        return None


def enumerate_key_subkeys(key_hive, key_path, access_type=Wow64RegistryEntry.KEY_WOW64):
    """
    Enumerate Windows Registry key (only values, no subkeys)
    :param key_hive: Windows registry hive to edit, e.g. HKEY_CURRENT_USER
    :param key_path: Path Windows registry key inside the hive, for example "SOFTWARE\Microsoft\Windows"
    :param access_type: Access type for 32/64 bit registry sub-entries in HKLM/SOFTWARE key.
    :return: List of tuples (RegValue, Data, Type)
    """
    if access_type == Wow64RegistryEntry.KEY_WOW32_64:
        raise RuntimeError("Use either KEY_WOW64 or KEY_WOW32 with enumerate_key_subkeys()")
    entry_num = 0
    try:
        key_hive_value = HIVES_MAP[key_hive]
        wow64_flags = WOW64_MAP[access_type]
        registry_key = winreg.OpenKey(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_READ))
        result = []
        for entry_num in range(0, winreg.QueryInfoKey(registry_key)[0]):
            result.append(winreg.EnumKey(registry_key, entry_num))
        return result
    except WindowsError as e:
        logger.error("Unable to enumerate registry key values %s\\%s with LastError=%d [%s], entry=%d",
                     key_hive, key_path, e.winerror, e.strerror, entry_num)
        return None


def create_key(key_hive, key_path, access_type=Wow64RegistryEntry.KEY_WOW64):
    """
    Create registry key
    :param key_hive: Windows registry hive to edit, e.g. HKEY_CURRENT_USER
    :param key_path: Path Windows registry key inside the hive, for example "SOFTWARE\Microsoft\Windows"
    :param access_type: Access type for 32/64 bit registry sub-entries in HKLM/SOFTWARE key.
    :return: Key handle if created successfully, None otherwise
    """
    if access_type == Wow64RegistryEntry.KEY_WOW32_64:
        raise RuntimeError("Use either KEY_WOW64 or KEY_WOW32 with create_key()")

    try:
        key_hive_value = HIVES_MAP[key_hive]
        wow64_flags = WOW64_MAP[access_type]
        registry_key = winreg.CreateKeyEx(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_WRITE))
        return registry_key
    except WindowsError as e:
        logger.error("Unable to create registry key %s\\%s with LastError=%d [%s]",
                     key_hive, key_path, e.winerror, e.strerror)
        return None


def delete_key(key_hive, key_path, access_type=Wow64RegistryEntry.KEY_WOW64):
    """
    Delete registry key
    :param key_hive: Windows registry hive to edit, e.g. HKEY_CURRENT_USER
    :param key_path: Path Windows registry key inside the hive, for example "SOFTWARE\Microsoft\Windows"
    :param access_type: Access type for 32/64 bit registry sub-entries in HKLM/SOFTWARE key.
    :return: True if success, False otherwise
    """
    if access_type == Wow64RegistryEntry.KEY_WOW32_64:
        raise RuntimeError("Use either KEY_WOW64 or KEY_WOW32 with delete_key()")

    try:
        key_hive_value = HIVES_MAP[key_hive]
        wow64_flags = WOW64_MAP[access_type]
        winreg.DeleteKeyEx(key_hive_value, key_path, (wow64_flags | winreg.KEY_WRITE), 0)
        return True
    except WindowsError as e:
        logger.error("Unable to delete registry key %s\\%s with LastError=%d [%s]",
                     key_hive, key_path, e.winerror, e.strerror)
        return None


def create_value(key_hive, key_path, value_name, value_type, key_value, access_type=Wow64RegistryEntry.KEY_WOW64):
    """
    Create registry value in the existing key
    :param key_hive: Windows registry hive to edit, e.g. HKEY_CURRENT_USER
    :param key_path: Path Windows registry key inside the hive, for example "SOFTWARE\Microsoft\Windows"
    :param value_name: Value name to edit
    :param value_type: Value type, e.g. REG_SZ, REG_DWORD, REG_BINARY... Could be both RegistryKeyType or winreg type
    :param key_value: Actual value we want to write
    :param access_type:
    :return:
    """
    if access_type == Wow64RegistryEntry.KEY_WOW32_64:
        raise RuntimeError("Use either KEY_WOW64 or KEY_WOW32 with create_value()")

    registry_key = None
    wow64_flags = WOW64_MAP[access_type]
    try:
        key_hive_value = HIVES_MAP[key_hive]

        if isinstance(value_type, RegistryKeyType):
            value_type = TYPES_MAP[value_type]

        registry_key = winreg.OpenKey(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_WRITE))
        winreg.SetValueEx(registry_key, value_name, 0, value_type, key_value)
        winreg.CloseKey(registry_key)
        return True
    except WindowsError as e:
        logger.error("Unable to write to registry path %s\\%s with LastError=%d [%s]",
                     key_hive, key_path, e.winerror, e.strerror)
        if registry_key is not None:
            winreg.CloseKey(registry_key)
        return False


def delete_value(key_hive, key_path, value_name, access_type=Wow64RegistryEntry.KEY_WOW64):
    """
    Delete registry value
    :param key_hive: Windows registry hive to edit, e.g. HKEY_CURRENT_USER
    :param key_path: Path Windows registry key inside the hive, for example "SOFTWARE\Microsoft\Windows"
    :param access_type: Access type for 32/64 bit registry sub-entries in HKLM/SOFTWARE key
    :param value_name: Value name to delete
    :return: True if success, False otherwise
    """
    if access_type == Wow64RegistryEntry.KEY_WOW32_64:
        raise RuntimeError("Use either KEY_WOW64 or KEY_WOW32 with delete_value()")

    try:
        key_hive_value = HIVES_MAP[key_hive]
        wow64_flags = WOW64_MAP[access_type]
        registry_key = winreg.OpenKey(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_WRITE))
        winreg.DeleteValue(registry_key, value_name)
        return True
    except WindowsError as e:
        logger.error("Unable to delete registry value %s\\%s with LastError=%d [%s]",
                     key_hive, key_path, e.winerror, e.strerror)
        return None


def read_value(key_hive, key_path, value_name, access_type=Wow64RegistryEntry.KEY_WOW64):
    """
    :param key_hive: Windows registry hive to edit, e.g. HKEY_CURRENT_USER
    :param key_path: Path Windows registry key inside the hive, for example "SOFTWARE\Microsoft\Windows"
    :param value_name: Value name we want to read
    :param access_type: Access type for 32/64 bit registry sub-entries in HKLM/SOFTWARE and HKCU/SOFTWARE keys.
    Exclusively 32/64 bit, or both. Does not affect 32-bit system and in other cases which are not applicable
    :return: Tuple if succeed, 4 values (2 tuples by 2) if both WOW64_32 and WOW64_64 registry entries requested,
    2 values otherwise. None if read operation failed
    """
    if is_x64os() and access_type == Wow64RegistryEntry.KEY_WOW32_64:
        value32, regtype32 = read_value(key_hive, key_path, value_name, Wow64RegistryEntry.KEY_WOW32)
        value64, regtype64 = read_value(key_hive, key_path, value_name, Wow64RegistryEntry.KEY_WOW64)
        return (value32, regtype32), (value64, regtype64)

    wow64_flags = WOW64_MAP[access_type]
    registry_key = None
    try:
        key_hive_value = HIVES_MAP[key_hive]
        registry_key = winreg.OpenKey(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_READ))
        value, regtype = winreg.QueryValueEx(registry_key, value_name)
        winreg.CloseKey(registry_key)
        return value, regtype
    except WindowsError as e:
        logger.error("Unable to read from registry path %s\\%s with LastError=%d [%s]",
                     key_hive, key_path, e.winerror, e.strerror)
        if registry_key is not None:
            winreg.CloseKey(registry_key)
        return None


def write_value(key_hive, key_path, value_name, value_type, key_value, access_type=Wow64RegistryEntry.KEY_WOW64):
    """
    :param key_hive: Windows registry hive to edit, e.g. HKEY_CURRENT_USER
    :param key_path: Path Windows registry key inside the hive, for example "SOFTWARE\Microsoft\Windows"
    :param value_name: Value name to edit
    :param value_type: Value type, e.g. REG_SZ, REG_DWORD, REG_BINARY... Could be both RegistryKeyType or winreg type
    :param key_value: Actual value we want to write
    :param access_type: Access type for 32/64 bit registry sub-entries in HKLM/SOFTWARE key.
    Exclusively 32/64 bit, or both. Does not affect 32-bit system and in other cases which are not applicable
    :return: Boolean success flag, True if succeed, False otherwise
    """
    if is_x64os() and access_type == Wow64RegistryEntry.KEY_WOW32_64:
        write_value(key_hive, key_path, value_name, value_type, key_value, Wow64RegistryEntry.KEY_WOW32)
        write_value(key_hive, key_path, value_name, value_type, key_value, Wow64RegistryEntry.KEY_WOW64)
        return

    registry_key = None
    wow64_flags = WOW64_MAP[access_type]
    try:
        key_hive_value = HIVES_MAP[key_hive]
        if isinstance(value_type, RegistryKeyType):
            value_type = TYPES_MAP[value_type]

        registry_key = winreg.OpenKey(key_hive_value, key_path, 0, (wow64_flags | winreg.KEY_WRITE))
        winreg.SetValueEx(registry_key, value_name, 0, value_type, key_value)
        winreg.CloseKey(registry_key)
        return True
    except WindowsError as e:
        logger.error("Unable to write to registry path %s\\%s with LastError=%d [%s]",
                     key_hive, key_path, e.winerror, e.strerror)
        if registry_key is not None:
            winreg.CloseKey(registry_key)
        return False
