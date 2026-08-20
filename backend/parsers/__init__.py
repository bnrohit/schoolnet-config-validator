from .cisco_ios import CiscoIOSParser
from .aruba import ArubaParser
from .generic import GenericNetworkParser, detect_vendor, VENDOR_NAMES


SPECIALIZED_PARSERS = {
    "cisco_ios": CiscoIOSParser,
    "cisco_iosxe": CiscoIOSParser,
    "aruba_aoscx": ArubaParser,
    "aruba_aos": ArubaParser,
}

SUPPORTED_VENDOR_IDS = [
    "auto",
    "cisco_ios",
    "cisco_iosxe",
    "cisco_nxos",
    "cisco_asa",
    "arista_eos",
    "juniper_junos",
    "aruba_aoscx",
    "aruba_aos",
    "hpe_comware",
    "extreme_exos",
    "extreme_voss",
    "brocade_fastiron",
    "dell_os10",
    "dell_os9",
    "mikrotik_routeros",
    "vyos",
    "fortios",
    "paloalto_panos",
    "sonic",
    "linux_frr",
    "ubiquiti_edgeos",
    "generic",
]


class SpecializedParserAdapter:
    """Keep detailed parsing while adding universal metadata used by expert rules."""

    def __init__(self, vendor: str, parser_cls, detection=None):
        self.vendor = vendor
        self.parser_cls = parser_cls
        self.detection = detection or {
            "vendor": vendor,
            "name": VENDOR_NAMES.get(vendor, vendor),
            "confidence": 0.90,
            "evidence": ["operator supplied vendor hint"],
        }

    def parse(self, config_text: str):
        result = self.parser_cls().parse(config_text)
        generic = GenericNetworkParser(self.vendor).parse(config_text)
        result["vendor"] = self.vendor
        result["vendor_name"] = self.detection.get("name", self.vendor)
        result["routing"] = generic.get("routing", {})
        result["analysis"] = {
            "mode": "specialized",
            "parser_confidence": self.detection.get("confidence", 0.90),
            "detection_evidence": self.detection.get("evidence", []),
            "structured_l2": True,
            "safe_to_auto_remediate": False,
        }
        return result


class AutoNetworkParser:
    def parse(self, config_text: str):
        detected = detect_vendor(config_text)
        vendor = detected["vendor"]
        parser_cls = SPECIALIZED_PARSERS.get(vendor)
        if parser_cls:
            return SpecializedParserAdapter(vendor, parser_cls, detected).parse(config_text)
        return GenericNetworkParser(vendor).parse(config_text)


def get_parser(vendor: str):
    vendor_id = (vendor or "auto").lower()
    if vendor_id == "auto":
        return AutoNetworkParser()
    parser_cls = SPECIALIZED_PARSERS.get(vendor_id)
    if parser_cls:
        return SpecializedParserAdapter(vendor_id, parser_cls)
    return GenericNetworkParser(vendor_id)
