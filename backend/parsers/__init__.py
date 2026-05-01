from .cisco_ios import CiscoIOSParser
from .aruba import ArubaParser

PARSERS = {
    "cisco_ios": CiscoIOSParser,
    "cisco_iosxe": CiscoIOSParser,
    "aruba_aoscx": ArubaParser,
    "aruba_aos": ArubaParser,
}

def get_parser(vendor: str):
    return PARSERS.get(vendor.lower(), CiscoIOSParser)()
