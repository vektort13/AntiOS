"""Published AntiOS starter catalog and pinned Ed25519 verification key.

The indicator data contains NCSC public sector information licensed under OGL v3.0.
See NOTICE for attribution.
"""

PUBLIC_KEY = bytes.fromhex("8f54c4b2c7d99a51c6686a1e46e12e3544c9b675d137233c91ac4e4bbbc4901b")

# Tables 3 and 4 of CISA/FBI AA24-109A identify these exact Windows and ELF samples.
# https://www.cisa.gov/sites/default/files/2024-04/aa24-109a-stopransomware-akira-ransomware_2.pdf
# A newer signed catalog can supersede this supplement.
AKIRA_SUPPLEMENT = (
    "03aa12ac2884251aa24bf0ccd854047de403591a8537e6aba19e822807e06a45",
    "0b5b31af5956158bfbd14f6cbf4f1bca23c5d16a40dbf3758f3289146c565f43",
    "0d700ca5f6cc093de4abba9410480ee7a8870d5e8fe86c9ce103eec3872f225f",
    "2e88e55cc8ee364bf90e7a51671366efb3dac3e9468005b044164ba0f1624422",
    "3d2b58ef6df743ce58669d7387ff94740ceb0122c4fc1c4ffd81af00e72e60a4",
    "40221e1c2e0c09bc6104548ee847b6ec790413d6ece06ad675fff87e5b8dc1d5",
    "5ea65e2bb9d245913ad69ce90e3bd9647eb16d992301145372565486c77568a2",
    "643061ac0b51f8c77f2ed202dc91afb9879f796ddd974489209d45f84f644562",
    "6f9d50bab16b2532f4683eeb76bd25449d83bdd6c85bf0b05f716a4b49584f84",
    "74f497088b49b745e6377b32ed5d9dfaef3c84c7c0bb50fabf30363ad2e0bfb1",
    "a2df5477cf924bd41241a3326060cc2f913aff2379858b148ddec455e4da67bc",
    "e1321a4b2b104f31aceaf4b19c5559e40ba35b73a754d3ae13d8e90c53146c0f",
    "fef09b0aa37cbdb6a8f60a6bd8b473a7e5bffdc7fd2e952444f781574abccf64",
)

# CISA Code & Media Analysis reports from 2025 identify these exact artifacts
# as malicious payloads/webshells/trojans. Keep them as exact-hash confirmations;
# behavioral/YARA-style observations remain review-only elsewhere in AntiOS.
# Sources:
# - MAR-25993211.r1.v1 (RESURGE / SPAWNSLOTH)
# - MAR-251132.c1.v1 (credential theft / webshell / PowerShell dropper artifacts)
CISA_2025_SUPPLEMENT = {
    "52bbc44eb451cb5e16bf98bc5b1823d2f47a18d71f14543b460395a1c1b1aeda":
        "RESURGE malware (CISA MAR-25993211)",
    "3526af9189533470bc0e90d54bafb0db7bda784be82a372ce112e361f7c7b104":
        "SPAWNSLOTH malware (CISA MAR-25993211)",
    "60a37499f9b02c203af24c2dfd7fdb3834cea707c4c56b410a7e68376938c4b7":
        "Encoded .NET credential-theft payload (CISA MAR-251132)",
    "92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514":
        "ASPX credential-theft payload (CISA MAR-251132)",
    "9340bf7378234db5bca0dc5378bf764b6a24bb87a42b05fa21a996340608fbd7":
        "Base64 PowerShell dropper artifact (CISA MAR-251132)",
    "675a10e87c248d0f629da864ba8b7fd92b62323c406a69dec35a0e6e1552ecbc":
        "ASPX webshell payload (CISA MAR-251132)",
    "d9c4dd5a8317d1d83b5cc3482e95602f721d58e3ba624d131a9472f927d33b00":
        "ASPX PowerShell webshell (CISA MAR-251132)",
}

BUNDLED_PACKAGE = b"""
{
  "catalog": {
    "published": "2026-11-10",
    "schema": 1,
    "sha256": {
      "03563997eb552d8a7278aa6aecffd05717dc36a1480795d06685ba7f1df3675f": {
        "label": "Rhythmic Parry",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Rhythmic-Parry-indicators.csv",
        "source_date": "2022-01-10"
      },
      "0df3b6e2535f8bb564183ab4e5e47d9b30ffc0204cc5bda1bae8984cdc418410": {
        "label": "Jolly Jellyfish",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Jolly-Jellyfish-indicators.csv",
        "source_date": "2021-12-15"
      },
      "12a29373c1f493f7757b755099bde4770c310af3fde376176b6d792cd1c5e150": {
        "label": "Goofy Guineapig",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Goofy-Guineapig-indicators.csv",
        "source_date": "2022-12-13"
      },
      "14930488158df5fca4cba80b1089f41dc296e19bebf41e2ff6e5b32770ac0f1e": {
        "label": "COLDSTEEL",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cold-Steel-indicators.csv",
        "source_date": "2023-01-31"
      },
      "190293440fce95f45eb8bf5d40334b41dd68c79578d06fe9b34670298daea7f3": {
        "label": "Umbrella Stand",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-umbrella-stand-indicators.csv",
        "source_date": "2025-06-18"
      },
      "19cef7f32e42cc674f7c76be3a5c691c543f4e018486c29153e7dde1a48af34c": {
        "label": "Goofy Guineapig",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Goofy-Guineapig-indicators.csv",
        "source_date": "2022-12-13"
      },
      "22a8b4a7c7a467ea7fcf0a3930c99ecb482095093839683b400f58e2cdda176f": {
        "label": "Cheeky Chipmunk",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cheeky-Chipmunk-indicators.csv",
        "source_date": "2022-01-24"
      },
      "27e7d2054a68510c974add24f33c1c7ef06ef68028cca021cd6b5e67363e2bea": {
        "label": "Cheeky Chipmunk",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cheeky-Chipmunk-indicators.csv",
        "source_date": "2022-01-24"
      },
      "2d19e015412ef8f8f7932b1ad18a5992d802b5ac62e59344f3aea2e00e0804ad": {
        "label": "Infamous Chisel",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Infamous-Chisel-indicators.csv",
        "source_date": "2023-08-31"
      },
      "31a8a2762b42a1fe4be2aed9d112a169f791bd86a85e68d738aea51312096442": {
        "label": "Damascened Peacock",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-damascened-peacock-indicators.csv",
        "source_date": "2025-04-11"
      },
      "338f8b447c95ba1c3d8d730016f0847585a7840c0a71d5054eb51cc612f13853": {
        "label": "Infamous Chisel",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Infamous-Chisel-indicators.csv",
        "source_date": "2023-08-31"
      },
      "3cf2de421c64f57c173400b2c50bbd9e59c58b778eba2eb56482f0c54636dd29": {
        "label": "Infamous Chisel",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Infamous-Chisel-indicators.csv",
        "source_date": "2023-08-31"
      },
      "454e6c3d8c1c982cd301b4dd82ec3431935c28adea78ed8160d731ab0bed6cb7": {
        "label": "Cheeky Chipmunk",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cheeky-Chipmunk-indicators.csv",
        "source_date": "2022-01-24"
      },
      "4a43fa8a3305c2a17f6a383fb68f02515f589ba112c6e95f570ce421cc690910": {
        "label": "Jolly Jellyfish",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Jolly-Jellyfish-indicators.csv",
        "source_date": "2021-12-15"
      },
      "50838e12e58a2d96b1a2ebdb53a25151cc22cbd458dba49fcb355ccfc82e0e63": {
        "label": "COLDSTEEL",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cold-Steel-indicators.csv",
        "source_date": "2023-01-31"
      },
      "5866e1fa5e262ade874c4b869d57870a88e6a8f9d5b9c61bd5d6a323e763e021": {
        "label": "Infamous Chisel",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Infamous-Chisel-indicators.csv",
        "source_date": "2023-08-31"
      },
      "591d60c1d356da827a26f4141fa431d3663af91746d5371014695b1c89bac2b2": {
        "label": "Umbrella Stand",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-umbrella-stand-indicators.csv",
        "source_date": "2025-06-18"
      },
      "5c5323bd17fd857a0e77be4e637841dad5c4367a72ac0a64cc054f78f530ba37": {
        "label": "Infamous Chisel",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Infamous-Chisel-indicators.csv",
        "source_date": "2023-08-31"
      },
      "6455de74ae15071fa98f18cdbc3148c967755e69df7dee747bc31d0387751162": {
        "label": "Pygmy Goat",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-pygmy-goat-indicators.csv",
        "source_date": "2024-10-30"
      },
      "6a3abc19f324a475d4ce01fcc69797fc90e1a47970ed90e9cb01f540f3000b4e": {
        "label": "Umbrella Stand",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-umbrella-stand-indicators.csv",
        "source_date": "2025-06-18"
      },
      "6b52fd7ee1442b4ed2c675f958a42a6c793bfe14a75de0988c4381367284f085": {
        "label": "Busy Buzzard",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Busy-Buzzard-indicators.csv",
        "source_date": "2022-03-25"
      },
      "6c121f2b2efa6592c2c22b29218157ec9e63f385e7a1d7425857d603ddef8c59": {
        "label": "Smooth Operator",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Smooth-Operator-indicators.csv",
        "source_date": "2023-06-29"
      },
      "722fa0c893b39fef787b7bc277c979d29adc1525d77dd952f0cc61cd4d0597cc": {
        "label": "Cheeky Chipmunk",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cheeky-Chipmunk-indicators.csv",
        "source_date": "2022-01-24"
      },
      "7ce2909bf205c1a574ac3dcac5891e31aa59dd4cad6c41d7159ad017c837903c": {
        "label": "COLDSTEEL",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cold-Steel-indicators.csv",
        "source_date": "2023-01-31"
      },
      "804dc9c037e9d0e5426cb1f0df8dde61cd43cf6ea4c27cf526c2d6ac50ba3e95": {
        "label": "Damascened Peacock",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-damascened-peacock-indicators.csv",
        "source_date": "2025-04-11"
      },
      "823b079c75f4e6a5905d9eea9a60c62e1f0995bfc25764d1ba0407a5bd78c962": {
        "label": "Pygmy Goat",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-pygmy-goat-indicators.csv",
        "source_date": "2024-10-30"
      },
      "83030f299a776114878bcd2ade585d97836ef4ddb6943cb796be2c88bcb83a83": {
        "label": "Busy Buzzard",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Busy-Buzzard-indicators.csv",
        "source_date": "2022-03-25"
      },
      "8bacd5df99476328321a7e8e2fc0124c20f7a7ebf3e8f151c050387038515b70": {
        "label": "Umbrella Stand",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-umbrella-stand-indicators.csv",
        "source_date": "2025-06-18"
      },
      "968d26244b3243a25c66170900b815123469822385cab610267c3a65e755d1ba": {
        "label": "COLDSTEEL",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cold-Steel-indicators.csv",
        "source_date": "2023-01-31"
      },
      "97f66bcdd73917a8b59d9a1dcac21a58936bcaf91e757a9dfb8e5c320af40f56": {
        "label": "Goofy Guineapig",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Goofy-Guineapig-indicators.csv",
        "source_date": "2022-12-13"
      },
      "9d6e14cd244f6c49e11d2b47f12116b5848aaed7a6aaa218fb023b33f7c12a3b": {
        "label": "Busy Buzzard",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Busy-Buzzard-indicators.csv",
        "source_date": "2022-03-25"
      },
      "a64b41e98e3e1066f41fbff5d4f99f6d34b792d35fe2be7e5d9fa8f3f8b93739": {
        "label": "Umbrella Stand",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-umbrella-stand-indicators.csv",
        "source_date": "2025-06-18"
      },
      "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67": {
        "label": "Smooth Operator",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Smooth-Operator-indicators.csv",
        "source_date": "2023-06-29"
      },
      "a7e9e2bec3ad283a9a0b130034e822c8b6dfd26dda855f883a3a4ff785514f97": {
        "label": "Jolly Jellyfish",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Jolly-Jellyfish-indicators.csv",
        "source_date": "2021-12-15"
      },
      "a9fa8e8609872cdcea241e3aab726b02b124c82de4c77ad3c3722d7c6b93b9b5": {
        "label": "COLDSTEEL",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cold-Steel-indicators.csv",
        "source_date": "2023-01-31"
      },
      "b75208393fa17c0bcbc1a07857686b8c0d7e0471d00a167a07fd0d52e1fc9054": {
        "label": "Small Sieve",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Small-Sieve-indicators.csv",
        "source_date": "2022-01-27"
      },
      "bf090cf7078414c9e157da7002ca727f06053b39fa4e377f9a0050f2af37d3a2": {
        "label": "Small Sieve",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Small-Sieve-indicators.csv",
        "source_date": "2022-01-27"
      },
      "ca9bcf268330a4fffcec025920514e0071651c35895b15b2f1dab8813c8b8e99": {
        "label": "Busy Buzzard",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Busy-Buzzard-indicators.csv",
        "source_date": "2022-03-25"
      },
      "d86f7d63bf8faa7070ba096523cf114947b55570dc50b0583797c9897ba3559c": {
        "label": "Cheeky Chipmunk",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cheeky-Chipmunk-indicators.csv",
        "source_date": "2022-01-24"
      },
      "e0b107be8034976f6e91cfcc2bbc792b49ea61a071166968fec775af28b1f19c": {
        "label": "SparrowDoor",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Sparrow-Door-indicators.csv",
        "source_date": "2022-02-28"
      },
      "e6bbc33815b9f20b0cf832d7401dd893fbc467c800728b5891336706da0dbcec": {
        "label": "Smooth Operator",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Smooth-Operator-indicators.csv",
        "source_date": "2023-06-29"
      },
      "e92d4e58dfae7c1aadeef42056d5e2e5002814ee3b9b5ab1a48229bf00f3ade6": {
        "label": "COLDSTEEL",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Cold-Steel-indicators.csv",
        "source_date": "2023-01-31"
      },
      "ef466e714d5250e934e681bda6ebdecd314670bb141f12a1b02c9afddbd93428": {
        "label": "Infamous Chisel",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Infamous-Chisel-indicators.csv",
        "source_date": "2023-08-31"
      },
      "f0449c41bc3eebb8ea025fafc5b0cd1fcbe9a2d80c447ecc00cf3cab43e1c311": {
        "label": "Jolly Jellyfish",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Jolly-Jellyfish-indicators.csv",
        "source_date": "2021-12-15"
      },
      "f19bb3b49d548bce4d35e9cf83fba112ef8e087a422b86d1376a395466fdff2d": {
        "label": "SparrowDoor",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Sparrow-Door-indicators.csv",
        "source_date": "2022-02-28"
      },
      "f21a9c69bfca6f0633ba1e669e5cf86bd8fc55b2529cd9b064ff9e2e129525e8": {
        "label": "Jolly Jellyfish",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Jolly-Jellyfish-indicators.csv",
        "source_date": "2021-12-15"
      },
      "ff3ec235c80df9e9b340cdddc4d253b2c495446dd27158f9afb88d9b604a1dac": {
        "label": "Rhythmic Parry",
        "source": "https://www.ncsc.gov.uk/sites/default/files/documents/NCSC-MAR-Rhythmic-Parry-indicators.csv",
        "source_date": "2022-01-10"
      }
    },
    "version": 3
  },
  "signature": "15f85d1a2226ba10d1b6a51fbb1c49f7d0b96e69c7fce68c52a9d2165b02643fe77363906c5d7b1d0b4272ba9369979ee1cb28b453c6ebac76a9698cfeadd401"
}
"""
