"""SchoolNet Change Impact Lab.

Offline, vendor-neutral pre-change analysis for a before/after configuration pair.
The engine never executes commands. It highlights evidence-backed risk, probable
blast-radius domains, management-lockout concerns, and rollback-aware validation.
"""
from __future__ import annotations

import difflib
import hashlib
import re
from typing import Any, Dict, Iterable, List, Tuple


CATEGORY_PATTERNS: Dict[str, Tuple[str, ...]] = {
    "management": (r"\bssh\b", r"\btelnet\b", r"\bhttp(?:s)?\b", r"\baaa\b", r"\btacacs\b", r"\bradius\b", r"\busername\b", r"management"),
    "routing": (r"\brouter\s+(?:bgp|ospf|ospfv3|isis|eigrp|rip)\b", r"\bprotocols\s+(?:bgp|ospf|isis)\b", r"\bbgp\b", r"\bospf\b", r"\bisis\b", r"\bneighbor\b", r"\bip\s+route\b", r"\bipv6\s+route\b", r"\broute-map\b", r"\bprefix-list\b", r"\bvrf\b", r"\b0\.0\.0\.0/0\b"),
    "layer2": (r"\bvlan\b", r"\bswitchport\b", r"\btrunk\b", r"\bnative\b", r"\bpvid\b", r"\bspanning-tree\b", r"\bstp\b", r"\bmstp\b", r"\brstp\b", r"\bchannel-group\b", r"\bport-channel\b", r"\blacp\b", r"\bvpc\b", r"\bmlag\b"),
    "security_policy": (r"\baccess-list\b", r"\baccess-group\b", r"\bfirewall\b", r"\bsecurity-policy\b", r"\bpolicy\b", r"\bnat\b", r"\bobject-group\b", r"\bzone\b"),
    "services": (r"\bhelper-address\b", r"\bdhcp\b", r"\bdns\b", r"\bntp\b", r"\blogging\b", r"\bsyslog\b", r"\bsnmp\b", r"\bsource-interface\b"),
    "interface": (r"^\s*interface\b", r"\bshutdown\b", r"\bdisable\b", r"\bip\s+address\b", r"\bipv6\s+address\b", r"\bmtu\b", r"\bspeed\b", r"\bduplex\b", r"\bdescription\b"),
}

HIGH_RISK_RULES: List[Dict[str, Any]] = [
    {"id": "routing_disabled", "severity": "critical", "score": 80, "pattern": r"(?:^|\s)(?:no\s+ip\s+routing|ip\s+routing\s+disable|disable\s+ip\s+routing)(?:$|\s)", "message": "Layer-3 routing appears to be disabled", "impact": "Inter-VLAN and routed connectivity can fail immediately on a routing device.", "domain": "routing"},
    {"id": "stp_disabled", "severity": "critical", "score": 80, "pattern": r"(?:no\s+spanning-tree|spanning-tree\s+disable|disable\s+stp|disable\s+stpd)", "message": "Loop-prevention behavior is being disabled or reduced", "impact": "A Layer-2 loop can create a broadcast storm and campus-wide outage.", "domain": "layer2"},
    {"id": "interface_shutdown", "severity": "high", "score": 28, "pattern": r"^\s*(?:shutdown|disable)\s*$", "message": "An interface is being administratively disabled", "impact": "Connected uplinks, APs, phones, servers, or user segments may lose service.", "domain": "interface"},
    {"id": "default_route_change", "severity": "high", "score": 30, "pattern": r"(?:ip\s+route\s+0\.0\.0\.0\s+0\.0\.0\.0|0\.0\.0\.0/0|default-route|route\s+0\.0\.0\.0)", "message": "Default routing behavior is changing", "impact": "Internet, WAN, management, or upstream reachability may shift or fail.", "domain": "routing"},
    {"id": "routing_peer_change", "severity": "high", "score": 25, "pattern": r"(?:router\s+(?:bgp|ospf|ospfv3|isis)|\bneighbor\s+\S+|peer\s+\S+|protocols\s+(?:bgp|ospf|isis))", "message": "Dynamic routing adjacency or policy configuration is changing", "impact": "Route convergence, reachability, preferred paths, and failover behavior can change.", "domain": "routing"},
    {"id": "native_vlan_change", "severity": "high", "score": 25, "pattern": r"(?:native\s+vlan|native-vlan|pvid)", "message": "Native/PVID VLAN behavior is changing", "impact": "A mismatch between peers can cause loss of untagged traffic, control traffic, or management access.", "domain": "layer2"},
    {"id": "trunk_change", "severity": "high", "score": 22, "pattern": r"(?:trunk\s+allowed|allowed\s+vlan|permit\s+vlan|vlan\s+trunk)", "message": "Trunk VLAN propagation is changing", "impact": "One or more VLANs can be pruned, unintentionally extended, or isolated.", "domain": "layer2"},
    {"id": "security_policy_change", "severity": "high", "score": 22, "pattern": r"(?:access-list|access-group|security-policy|firewall\s+policy|policy\s+from-zone|object-group|\bnat\b)", "message": "Traffic-filtering or security-policy behavior is changing", "impact": "Required applications can be blocked or unintended network access can be introduced.", "domain": "security_policy"},
    {"id": "management_plane_change", "severity": "high", "score": 28, "pattern": r"(?:aaa\b|tacacs|radius|transport\s+input|service\s+ssh|services\s+ssh|management\s+access|username)", "message": "Management-plane authentication or access is changing", "impact": "Administrators and automation may be locked out if dependencies or source restrictions are wrong.", "domain": "management"},
    {"id": "address_change", "severity": "high", "score": 25, "pattern": r"(?:\bip\s+address\b|\bipv6\s+address\b|set\s+interfaces\s+\S+.*address)", "message": "An interface Layer-3 address is changing", "impact": "Gateway, management, routing-neighbor, DHCP relay, or application reachability may be affected.", "domain": "interface"},
    {"id": "dhcp_relay_change", "severity": "high", "score": 22, "pattern": r"(?:helper-address|dhcp\s+relay|relay-address)", "message": "DHCP relay behavior is changing", "impact": "Clients may fail to obtain or renew addresses on affected VLANs.", "domain": "services"},
]


def _clean_lines(text: str) -> List[str]:
    return [line.rstrip() for line in text.splitlines() if line.strip() and line.strip() not in ("!", "#")]


def _semantic_fingerprint(text: str) -> str:
    normalized = []
    for line in _clean_lines(text):
        value = re.sub(r"\s+", " ", line.strip().lower())
        if not re.search(r"\b(last changed|generated|timestamp|time:)\b", value):
            normalized.append(value)
    return hashlib.sha256("\n".join(sorted(normalized)).encode()).hexdigest()[:20]


def _line_diff(before: str, after: str) -> Tuple[List[str], List[str], List[str]]:
    diff = list(difflib.unified_diff(_clean_lines(before), _clean_lines(after), fromfile="before", tofile="after", lineterm=""))
    added = [line[1:] for line in diff if line.startswith("+") and not line.startswith("+++")]
    removed = [line[1:] for line in diff if line.startswith("-") and not line.startswith("---")]
    return added, removed, diff


def _classify(lines: Iterable[str]) -> Dict[str, int]:
    counts = {name: 0 for name in CATEGORY_PATTERNS}
    for line in lines:
        for category, patterns in CATEGORY_PATTERNS.items():
            if any(re.search(pattern, line, re.I) for pattern in patterns):
                counts[category] += 1
    return counts


def _extract_vlan_ids(text: str) -> List[int]:
    values = set()
    for pattern in (r"(?im)^\s*vlan\s+(\d+)\b", r"(?im)\bvlan-id\s+(\d+)\b"):
        for match in re.finditer(pattern, text):
            try:
                values.add(int(match.group(1)))
            except ValueError:
                pass
    return sorted(values)


def _extract_protocols(text: str) -> List[str]:
    checks = {
        "BGP": r"(?im)(router\s+bgp|protocols\s+bgp|routing\s+bgp|config\s+router\s+bgp)",
        "OSPF": r"(?im)(router\s+ospf|protocols\s+ospf|routing\s+ospf|config\s+router\s+ospf)",
        "OSPFv3": r"(?im)(ospfv3|ospf3)", "IS-IS": r"(?im)(router\s+isis|protocols\s+isis|\bisis\b)",
        "EIGRP": r"(?im)router\s+eigrp", "PIM": r"(?im)(ip\s+pim|protocols\s+pim|\bpim\s+(?:sparse|dense))",
        "VRRP": r"(?im)\bvrrp\b", "HSRP": r"(?im)(\bstandby\s+\d+\s+ip\b|\bhsrp\b)",
    }
    return [name for name, pattern in checks.items() if re.search(pattern, text)]


def _high_risk_events(added: List[str], removed: List[str]) -> List[Dict[str, Any]]:
    events, seen = [], set()
    for direction, lines in (("added", added), ("removed", removed)):
        for line in lines:
            for rule in HIGH_RISK_RULES:
                if re.search(rule["pattern"], line, re.I):
                    key = (rule["id"], direction, line.strip().lower())
                    if key not in seen:
                        seen.add(key)
                        events.append({**rule, "direction": direction, "evidence": line[:300]})
    return events


def _risk_label(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "minimal"


def _gate(score: int, events: List[Dict[str, Any]]) -> Dict[str, str]:
    if any(event["severity"] == "critical" for event in events) or score >= 75:
        return {"status": "BLOCK", "reason": "Critical-impact change indicators require explicit engineering review, verified OOB recovery, and a maintenance window."}
    if score >= 50:
        return {"status": "HOLD", "reason": "High-impact changes should not proceed until dependencies, peer state, rollback, and service validation are confirmed."}
    if score >= 25:
        return {"status": "CAUTION", "reason": "Moderate operational risk detected. Perform the generated pre-checks and preserve rollback."}
    return {"status": "REVIEW", "reason": "No major risk signature was detected, but the change still requires human review and post-change validation."}


def analyze_change(before: str, after: str, vendor: str = "auto") -> Dict[str, Any]:
    added, removed, unified = _line_diff(before, after)
    changed = added + removed
    categories = _classify(changed)
    events = _high_risk_events(added, removed)

    before_vlans, after_vlans = set(_extract_vlan_ids(before)), set(_extract_vlan_ids(after))
    removed_vlans, added_vlans = sorted(before_vlans - after_vlans), sorted(after_vlans - before_vlans)
    before_protocols, after_protocols = set(_extract_protocols(before)), set(_extract_protocols(after))
    protocol_delta = {"added": sorted(after_protocols - before_protocols), "removed": sorted(before_protocols - after_protocols), "present_after": sorted(after_protocols)}

    if removed_vlans:
        events.append({"id": "vlan_removed", "severity": "high", "score": min(24, len(removed_vlans) * 6), "message": f"VLAN definition(s) removed: {', '.join(map(str, removed_vlans[:20]))}", "impact": "Ports, trunks, SVIs, DHCP scopes, or routed services tied to these VLANs may lose connectivity.", "domain": "layer2", "direction": "removed", "evidence": f"removed VLANs: {removed_vlans[:20]}"})

    raw_score = sum(int(event["score"]) for event in events)
    raw_score += min(12, categories["security_policy"] * 2) + min(12, categories["routing"] * 2) + min(8, categories["management"] * 2)
    # Critical evidence must never be represented as merely medium risk.
    if any(event["severity"] == "critical" for event in events):
        raw_score = max(raw_score, 80)
    elif any(event["severity"] == "high" for event in events):
        raw_score = max(raw_score, 30)
    score = min(100, raw_score)

    affected_domains = [name for name, count in categories.items() if count]
    if removed_vlans and "layer2" not in affected_domains:
        affected_domains.append("layer2")

    pre_checks = [
        "Capture current device health, interface status/errors, CPU/memory, logs, and uptime.",
        "Save/export the current configuration and verify console or out-of-band recovery access.",
        "Identify connected peers and confirm current CDP/LLDP, trunk, LAG, and routing-neighbor state.",
    ]
    if categories["routing"] or protocol_delta["added"] or protocol_delta["removed"]:
        pre_checks += ["Capture routing table, default route, protocol neighbors, advertised/received prefixes, and route-policy counters.", "Confirm redundant paths and expected convergence behavior before modifying routing policy or adjacency settings."]
    if categories["layer2"] or removed_vlans:
        pre_checks += ["Capture STP root/blocked ports, VLAN forwarding state, trunk allowed/native VLANs, and port-channel health.", "Validate both ends of every trunk/native-VLAN/LAG change before implementation."]
    if categories["management"]:
        pre_checks.append("Open a second verified management session and confirm AAA/TACACS/RADIUS dependencies before touching management access.")
    if categories["security_policy"]:
        pre_checks.append("Record policy hit counts and test representative allowed/denied flows before changing ACL/firewall/NAT policy.")
    if categories["services"]:
        pre_checks.append("Validate DHCP, DNS, NTP, logging/SIEM, SNMP, and other service dependencies referenced by the change.")

    change_sequence = [
        "Use a maintenance/change window appropriate to the highest detected risk.",
        "Keep the current management session open and make the smallest reversible change first.",
        "Change one failure domain at a time; avoid simultaneous peer-side changes unless the protocol requires coordination.",
        "Pause after each high-risk step and validate control-plane and user-service health before continuing.",
    ]
    if categories["management"]:
        change_sequence.insert(1, "Validate replacement management/AAA access in a second session before removing the old access path.")
    if categories["layer2"]:
        change_sequence.append("For trunks/native VLAN/STP/LAG changes, coordinate link peers and verify topology before moving to the next link.")
    if categories["routing"]:
        change_sequence.append("For routing changes, verify neighbor state and route-table deltas before changing additional peers or policies.")

    rollback = ["Retain the exact pre-change configuration and a console/OOB path.", "If a critical validation check fails, stop the change and restore the affected section before proceeding.", "Do not save/commit a failed state; confirm recovery and service restoration first."]
    post_checks = ["Compare interface, VLAN/trunk, STP/LAG, routing, and log state against the pre-change baseline.", "Test management access from the approved management network in a new session.", "Test representative paths: DHCP, DNS, gateway, internal applications, internet/WAN, and critical voice/wireless services.", "Monitor error counters, topology changes, routing flaps, CPU, logs, and alerts through the observation period."]

    baseline_count = max(1, len(_clean_lines(before)))
    change_density = round((len(changed) / baseline_count) * 100, 1)
    before_dna, after_dna = _semantic_fingerprint(before), _semantic_fingerprint(after)

    return {
        "mode": "offline_change_impact", "vendor_selection": vendor, "executable": False,
        "risk_score": score, "risk_label": _risk_label(score), "change_gate": _gate(score, events),
        "configuration_dna": {"before": before_dna, "after": after_dna, "changed": before_dna != after_dna},
        "change_summary": {"added_lines": len(added), "removed_lines": len(removed), "total_changed_lines": len(changed), "change_density_percent": change_density, "affected_domains": affected_domains, "category_counts": categories},
        "blast_radius": {
            "management_plane": categories["management"] > 0,
            "routing_control_plane": categories["routing"] > 0 or bool(protocol_delta["added"] or protocol_delta["removed"]),
            "layer2_forwarding": categories["layer2"] > 0 or bool(removed_vlans or added_vlans),
            "security_policy": categories["security_policy"] > 0,
            "network_services": categories["services"] > 0,
            "interface_connectivity": categories["interface"] > 0,
        },
        "vlan_delta": {"added": added_vlans, "removed": removed_vlans},
        "routing_protocol_delta": protocol_delta,
        "high_risk_events": events,
        "pre_change_checks": pre_checks,
        "controlled_change_sequence": change_sequence,
        "rollback_plan": rollback,
        "post_change_validation": post_checks,
        "diff_preview": unified[:240],
        "disclaimer": "Change Impact Lab is an offline engineering aid. It cannot know every physical topology, dependency, vendor defect, or runtime state from configuration text alone. Human approval and live validation remain required.",
    }
