import os
import logging
import log_helper
import random
import uuid
import string
import random_utils

logger = log_helper.setup_logger(name="system_fingerpring", level=logging.INFO, log_to_file=False)


class WinFingerprint:
    """
    Windows-related fingerprinting identifiers, like edition, version, build, updates
    """
    EDITIONS = {
        7: [["Starter", "Starter"],
            ["HomeBasic", "Home Basic"],
            ["HomePremium", "Home Premium"],
            ["Professional", "Professional"],
            ["ProfessionalN", "Professional N"],
            ["ProfessionalKN", "Professional KN"],
            ["Enterprise", "Enterprise"],
            ["Ultimate", "Ultimate"]],
        8: [["Core", "Core"],
            ["Pro", "Pro"],
            ["ProN", "Pro N"],
            ["Enterprise", "Enterprise"],
            ["EnterpriseN", "Enterprise N"],
            ["OEM", "OEM"],
            ["withBing", "with Bing"]],
        10: [["Home", "Home"],
             ["Pro", "Pro"],
             ["ProEducation", "Pro Education"],
             ["Enterprise", "Enterprise"],
             ["EnterpriseLTSB", "Enterprise LTSB"],
             ["Education", "Education"],
             ["IoTCore", "IoT Core", ],
             ["IoTEnterprise", "IoT Enterprise", ],
             ["S", "S"]]
    }

    EDITION_ID = 0
    EDITION_NAME = 1

    BUILDS = {
        7: ["Windows 7", "6.1", "7601", "7601.win7sp1_ldr.170913-0600", "7601.23915.amd64fre.win7sp1_ldr.170913-0600"],
        8: ["Windows 8.1", "7.1", "9600", "9600.winblue_r4.141028-1500", "9600.17415.amd64fre.winblue_r4.141028-1500"],
        10: ["Windows 10", "9.0", "16299", "16299.rs3_release.170928-1534", "16299.15.amd64fre.rs3_release.170928-1534"]
    }

    PRODUCT_NAME = 0
    CURRENT_VERSION = 1
    CURRENT_BUILD = 2
    BUILD_LAB = 3
    BUILD_LAB_EX = 4

    IE_SERVICE_UPDATES = ["KB2841134", "KB4088835", "KB4032782", "KB4016446", "KB3210694",
                          "KB3200006", "KB3199375", "KB3192665", "KB4096040", "KB4089187",
                          "KB4074736", "KB4056568", "KB4052978", "KB4047206", "KB4040685",
                          "KB4036586", "KB4034733", "KB4025252", "KB4021558", "KB4018271",
                          "KB4014661", "KB4012204", "KB3185319", "KB3175443", "KB3170106",
                          "KB3160005", "KB3154070", "KB3148198"]

    def __init__(self):
        self.windows_version = random.choice([7, 8, 10])
        self.oem_version = random.randint(0, 1)
        self.product_name = WinFingerprint.BUILDS[self.windows_version][WinFingerprint.PRODUCT_NAME]
        self.current_version = WinFingerprint.BUILDS[self.windows_version][WinFingerprint.CURRENT_VERSION]
        self.current_build = WinFingerprint.BUILDS[self.windows_version][WinFingerprint.CURRENT_BUILD]
        self.build_lab = WinFingerprint.BUILDS[self.windows_version][WinFingerprint.BUILD_LAB]
        self.build_lab_ex = WinFingerprint.BUILDS[self.windows_version][WinFingerprint.BUILD_LAB_EX]
        random_edition = random.choice(WinFingerprint.EDITIONS[self.windows_version])
        self.edition_id = random_edition[WinFingerprint.EDITION_ID]
        if self.edition_id == "OEM":
            self.oem_version = 1
        self.edition_product_name = random_edition[WinFingerprint.EDITION_NAME]
        self.install_date = random_utils.random_unix_time("01.01.2012", "01.01.2018")
        self.pid1 = random_utils.random_digit_string(5)
        self.pid2 = "OEM" if self.oem_version else random_utils.random_digit_string(3)
        self.pid3 = random_utils.random_digit_string(7)
        self.pid4 = random_utils.random_digit_string(5)
        self.retail_oem = "OEM" if self.oem_version else "Retail"
        self.build_guid = str(uuid.uuid4()) if self.windows_version == 7 else "ffffffff-ffff-ffff-ffff-ffffffffffff"
        self.uuid_id4 = str(uuid.uuid4())
        self.ie_service_update = random.choice(WinFingerprint.IE_SERVICE_UPDATES)
        self.ie_install_date = bytearray(os.urandom(8))
        self.digital_product_id = []
        self.digital_product_id4 = []
        self.product_id = self.__random_product_id()
        self.digital_product_id = self.__random_digital_product_id()
        self.digital_product_id4 = self.__random_digital_product_id4()

    def random_build_guid(self):
        """
        :return: BuildGUID param
        """
        return self.build_guid

    def random_current_version(self):
        """
        :return: Windows version number (in format looks like 6.1, 7.0, ...)
        """
        return self.current_version

    def random_current_build(self):
        """
        :return: Windows build number (in format "7601", "9600", ....)
        """
        return self.current_build

    def random_build_lab(self):
        """
        :return: BuildLab param (part of the CurrentVersion)
        """
        return self.build_lab

    def random_build_lab_ex(self):
        """
        :return: BuildLabEx param (part of the CurrentVersion)
        """
        return self.build_lab_ex

    def random_edition_id(self):
        """
        :return: Windows edition ID (depend on actual random version)
        """
        return self.edition_id

    def random_install_date(self):
        """
        :return: Install date in Unix timestamp format
        """
        return self.install_date

    def random_product_name(self):
        """
        :return: Full Windows Product name with edition
        """
        return "{0} {1}".format(self.product_name, self.edition_product_name)

    def random_product_id(self):
        """
        Format of Product ID is a dash-separated string of digits, which lengths consequently 5-3-7-5
        :return: Windows Product ID
        """
        return self.product_id

    def random_ie_service_update(self):
        """
        Internet Explorer Service Update (SvcKBNumber)
        :return: String in format "KBNNNNNNN"
        """
        return self.ie_service_update

    def random_ie_install_date(self):
        """
        Internet Explorer Service install date
        :return: List of 2 elements
        """
        return self.ie_install_date

    def random_digital_product_id(self):
        """
        Windows Digital Product ID is 164-bytes length binary
        :return: Windows DigitalProductID
        """
        return self.digital_product_id

    def random_digital_product_id4(self):
        """
        Windows Digital Product ID4 is 1272-bytes length binary
        :return: Windows DigitalProductID4
        """
        return self.digital_product_id4

    #############################################################################
    # Internal methods

    def __random_product_id(self):
        return "{0}-{1}-{2}-{3}".format(self.pid1, self.pid2, self.pid3, self.pid4)

    def __random_digital_product_id(self):
        random_digital_id = random.sample(range(0, 255), k=164)
        random_digital_id[0x00:0x07] = [0xA4, 0, 0, 0, 0x3, 0, 0, 0]
        random_digital_id[0x08:0x19] = list(self.product_id)
        random_digital_id[0xA0:0xA3] = [0xB9, 0xEC, 0x21, 0x73]
        return random_digital_id

    @staticmethod
    def __random_product_id4():
        # 5-5-3-6-2-4-4-1rnd-0000-YYYY
        normal_string = "{0}-{1}-{2}-{3}-{4}-{5}-{6}x00002018".format(
            random_utils.random_digit_string(5),
            random_utils.random_digit_string(5),
            random_utils.random_digit_string(3),
            random_utils.random_digit_string(6),
            random_utils.random_digit_string(2),
            random_utils.random_digit_string(4),
            random_utils.random_digit_string(4)
        )
        dispersed_list = random_utils.disperse_string(normal_string)
        dispersed_list[70] = random.randint(0, 0xFF)
        dispersed_list[-2] = ['5', '6', '7', '8'][random.randint(0, 3)]
        return dispersed_list

    def __random_digital_product_id4(self):
        random_digital_id4 = [0] * 1272
        random_digital_id4[0] = 0xF8
        random_digital_id4[1] = 0x04
        # 0x08 - ID
        random_id1 = WinFingerprint.__random_product_id4()
        random_digital_id4[0x08:0x08 + len(random_id1) + 1] = random_id1
        # 0x88 - UUID
        product_guid_id4 = random_utils.disperse_string(self.uuid_id4)
        random_digital_id4[0x88:0x88 + len(product_guid_id4) + 1] = product_guid_id4
        # 0x0118 - Edition
        product_edition = random_utils.disperse_string(self.edition_id)
        random_digital_id4[0x0118:0x0118 + len(product_edition) + 1] = product_edition
        # 0x0328 - random length 80
        random_block = random.sample(range(0, 0xFF), 80)
        random_digital_id4[0x0328:0x0328 + len(random_block) + 1] = random_block
        # 0x0378 - XNN-NNNNN
        random_id2_string = "{0}{1}-{2}".format(
            ''.join(random.sample(string.ascii_uppercase, 1)),
            random_utils.random_digit_string(2),
            random_utils.random_digit_string(5)
        )
        random_id2 = random_utils.disperse_string(random_id2_string)
        random_digital_id4[0x0378:0x0378 + len(random_id2) + 1] = random_id2
        # 0x03F8 - Retail/OEM
        # 0x0478 - Retail/OEM
        retail_oem = random_utils.disperse_string(self.retail_oem)
        random_digital_id4[0x03F8:0x03F8 + len(retail_oem) + 1] = retail_oem
        random_digital_id4[0x0478:0x0478 + len(retail_oem) + 1] = retail_oem
        return random_digital_id4
