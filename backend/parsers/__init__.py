from .cisco_ios import CiscoIOSParser
from .aruba import ArubaParser
from .generic import GenericNetworkParser, detect_vendor, VENDOR_NAMES


# Platforms with mature structured parsing keep their specialized parser. Other
# platforms use the universal normalizer plus conservative vendor-neutral rules.
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


class AutoNetworkParser:
    def parse(self, config_text: str):
        detected = detect_vendor(config_text)
        vendor = detected["vendor"]
        parser_cls = SPECIALIZED_PARSERS.get(vendor)
        if parser_cls:
            result = parser_cls().parse(config_text)
            result["vendor"] = vendor
            result["vendor_name"] = detected.get("name", vendor)
            result["analysis"] = {
                "mode": "specialized",
                "parser_confidence": detected.get("confidence", 0.85),
                "detection_evidence": detected.get("evidence", []),
                "structured_l2": True,
                "safe_to_auto_remediate": False,
            }
            return result
        return GenericNetworkParser(vendor).parse(config_text)


def get_parser(vendor: str):
    vendor_id = (vendor or "auto").lower()
    if vendor_id == "auto":
        return AutoNetworkParser()
    parser_cls = SPECIALIZED_PARSERS.get(vendor_id)
    if parser_cls:
        return parser_cls()
    return GenericNetworkParser(vendor_id)
