"""SchoolNet Network Safety Graph.

Offline, evidence-based multi-device topology inference and peer-aware change analysis.
The engine intentionally avoids pretending that configuration files are a perfect
runtime digital twin. It combines configuration facts, optional neighbor evidence,
and conservative heuristics to expose likely relationships, single points of
failure, cross-device inconsistencies, and change propagation risk.

Nothing in this module executes network commands.
"""
from __future__ import annotations

from collections import defaultdict, deque
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from parsers import get_parser
from change_impact import analyze_change


CONFIDENCE = {
    "observed_neighbor": 0.98,
    "bgp_peer": 0.94,
    "shared_transit": 0.90,
    "described_peer": 0.78,
    "shared_vlan_hint": 0.55,
}

SEVERITY_WEIGHT = {"critical": 90, "high": 65, "medium": 35, "low": 15, "info": 5}


def _safe_name(value: str, fallback: str) -> str:
    value = (value or "").strip()
    return value[:96] if value else fallback


def _mask_to_prefix(mask: str) -> Optional[int]:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except Exception:
        return None


def _parse_ip(value: str, mask: Optional[str] = None) -> Optional[ipaddress._BaseInterface]:
    try:
        if "/" in value:
            return ipaddress.ip_interface(value)
        if mask:
            prefix = _mask_to_prefix(mask)
            if prefix is not None:
                return ipaddress.ip_interface(f"{value}/{prefix}")
        return ipaddress.ip_interface(f"{value}/32")
    except ValueError:
        return None


def _interface_blocks(text: str) -> List[Tuple[str, List[str]]]:
    """Extract common interface/edit blocks without assuming one vendor syntax."""
    blocks: List[Tuple[str, List[str]]] = []
    current_name: Optional[str] = None
    current: List[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        match = re.match(r"^(?:interface|edit)\s+[\"']?([^\"']+?)[\"']?$", stripped, re.I)
        if match and not stripped.lower().startswith("interface range"):
            if current_name:
                blocks.append((current_name, current))
            current_name = match.group(1).strip()
            current = [stripped]
            continue
        if current_name is None:
            continue
        if stripped in ("!", "exit", "next"):
            current.append(stripped)
            blocks.append((current_name, current))
            current_name, current = None, []
            continue
        current.append(stripped)
    if current_name:
        blocks.append((current_name, current))
    return blocks


def _extract_ip_interfaces(text: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()

    def add(name: str, iface: ipaddress._BaseInterface, source: str) -> None:
        key = (name, str(iface))
        if key in seen:
            return
        seen.add(key)
        results.append({
            "interface": name,
            "address": str(iface.ip),
            "prefix": iface.network.prefixlen,
            "network": str(iface.network),
            "version": iface.version,
            "source": source,
        })

    for name, lines in _interface_blocks(text):
        block = "\n".join(lines)
        for match in re.finditer(r"(?im)^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+\.\d+\.\d+\.\d+)|/(\d+))", block):
            ip = match.group(1)
            mask = match.group(2)
            prefix = match.group(3)
            iface = _parse_ip(f"{ip}/{prefix}" if prefix else ip, mask)
            if iface:
                add(name, iface, "interface_block")
        for match in re.finditer(r"(?im)^\s*ipv6\s+address\s+([0-9a-f:]+/\d+)", block):
            iface = _parse_ip(match.group(1))
            if iface:
                add(name, iface, "interface_block")
        # FortiOS: set ip A.B.C.D 255.255.255.0
        match = re.search(r"(?im)^\s*set\s+ip\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", block)
        if match:
            iface = _parse_ip(match.group(1), match.group(2))
            if iface:
                add(name, iface, "interface_block")

    # Junos/VyOS/EdgeOS set-style addresses.
    for match in re.finditer(r"(?im)^set\s+interfaces\s+(?:ethernet|bonding|loopback|wireguard|vlan|ge-|xe-|et-)?\s*([^\s]+).*?\baddress\s+([0-9a-f:.]+/\d+)", text):
        iface = _parse_ip(match.group(2))
        if iface:
            add(match.group(1), iface, "set_syntax")

    # MikroTik exports.
    for match in re.finditer(r"(?im)^add\s+address=([0-9a-f:.]+/\d+).*?interface=([^\s]+)", text):
        iface = _parse_ip(match.group(1))
        if iface:
            add(match.group(2), iface, "routeros_export")

    return results


def _extract_routing(text: str) -> Dict[str, Any]:
    protocols: List[str] = []
    patterns = {
        "BGP": r"(?im)(router\s+bgp|protocols\s+bgp|routing\s+bgp|config\s+router\s+bgp)",
        "OSPF": r"(?im)(router\s+ospf|protocols\s+ospf|routing\s+ospf|config\s+router\s+ospf)",
        "OSPFv3": r"(?im)(ospfv3|ospf3)",
        "IS-IS": r"(?im)(router\s+isis|protocols\s+isis|\bisis\b)",
        "EIGRP": r"(?im)router\s+eigrp",
        "PIM": r"(?im)(ip\s+pim|protocols\s+pim|\bpim\s+(?:sparse|dense))",
        "VRRP": r"(?im)\bvrrp\b",
        "HSRP": r"(?im)(\bstandby\s+\d+\s+ip\b|\bhsrp\b)",
    }
    for name, pattern in patterns.items():
        if re.search(pattern, text):
            protocols.append(name)

    bgp_neighbors = []
    for match in re.finditer(r"(?im)^\s*neighbor\s+([0-9a-f:.]+)\s+remote-as\s+(\d+)", text):
        bgp_neighbors.append({"address": match.group(1), "remote_as": match.group(2)})
    for match in re.finditer(r"(?im)^set\s+protocols\s+bgp\s+group\s+\S+\s+neighbor\s+([0-9a-f:.]+)", text):
        bgp_neighbors.append({"address": match.group(1), "remote_as": None})

    ospf_areas = sorted(set(re.findall(r"(?im)\barea\s+([0-9.]+)\b", text)))
    return {"protocols": protocols, "bgp_neighbors": bgp_neighbors, "ospf_areas": ospf_areas}


def _extract_vlan_ids(text: str, parsed: Dict[str, Any]) -> List[int]:
    values: Set[int] = set()
    for vlan in parsed.get("vlans", []) or []:
        try:
            values.add(int(vlan.get("id")))
        except (TypeError, ValueError):
            pass
    for pattern in (
        r"(?im)^\s*vlan\s+(\d+)\b",
        r"(?im)\bvlan-id\s+(\d+)\b",
        r"(?im)\binterface\s+vlan\s*(\d+)\b",
        r"(?im)\binterface\s+Vlan(\d+)\b",
    ):
        for match in re.finditer(pattern, text):
            try:
                values.add(int(match.group(1)))
            except ValueError:
                pass
    return sorted(v for v in values if 1 <= v <= 4094)


def _trunk_facts(parsed: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    trunks: Dict[str, Dict[str, Any]] = {}
    for iface in parsed.get("interfaces", []) or []:
        if iface.get("is_trunk"):
            name = str(iface.get("name") or "unknown")
            trunks[name] = {
                "interface": name,
                "allowed_vlans": sorted(set(iface.get("allowed_vlans") or [])),
                "native_vlan": iface.get("native_vlan"),
                "port_channel": iface.get("port_channel"),
            }
    return trunks


def _extract_svis(text: str, ip_interfaces: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    svis: List[Dict[str, Any]] = []
    for item in ip_interfaces:
        match = re.search(r"(?i)(?:vlan|irb\.?|ve\s*|vlanif)(\d+)", item["interface"].replace(" ", ""))
        if match:
            svis.append({**item, "vlan": int(match.group(1))})
    # Cisco-style interface VlanX detection catches cases where parser-normalized
    # names do not use spaces.
    by_name = {item["interface"].lower(): item for item in ip_interfaces}
    for match in re.finditer(r"(?im)^interface\s+Vlan(\d+)\s*$", text):
        name = f"vlan{match.group(1)}"
        item = by_name.get(name)
        if item and not any(x["interface"].lower() == name for x in svis):
            svis.append({**item, "vlan": int(match.group(1))})
    return svis


def _device_role(vendor: str, routing: Dict[str, Any], trunks: Dict[str, Any], svis: List[Dict[str, Any]], text: str) -> str:
    if vendor in {"cisco_asa", "fortios", "paloalto_panos"}:
        return "security_gateway"
    route_protocols = set(routing.get("protocols", []))
    if "BGP" in route_protocols or len(route_protocols.intersection({"OSPF", "OSPFv3", "IS-IS", "EIGRP"})) >= 1:
        if len(svis) >= 4 or len(trunks) >= 3:
            return "core_distribution"
        return "router"
    if re.search(r"(?im)^\s*ip\s+routing\s*$", text) and len(svis) >= 3:
        return "layer3_switch"
    if len(trunks) >= 3 or len(svis) >= 3:
        return "distribution_switch"
    if trunks:
        return "access_switch"
    return "network_device"


def _fhrp_vlans(text: str) -> Set[int]:
    result: Set[int] = set()
    current_vlan: Optional[int] = None
    for line in text.splitlines():
        match = re.match(r"(?i)^\s*interface\s+Vlan(\d+)", line)
        if match:
            current_vlan = int(match.group(1))
            continue
        if current_vlan and re.search(r"(?i)\b(?:standby\s+\d+\s+ip|vrrp\s+\d+\s+ip|hsrp)\b", line):
            result.add(current_vlan)
        if line.strip() == "!":
            current_vlan = None
    return result


def _build_facts(device: Dict[str, Any], index: int, proposed: bool = False) -> Dict[str, Any]:
    text_key = "proposed_config" if proposed else "config_text"
    text = device.get(text_key) or (device.get("config_text") if proposed else "") or ""
    vendor_hint = device.get("vendor") or "auto"
    parsed = get_parser(vendor_hint).parse(text)
    ip_interfaces = _extract_ip_interfaces(text)
    routing = _extract_routing(text)
    trunks = _trunk_facts(parsed)
    svis = _extract_svis(text, ip_interfaces)
    name = _safe_name(device.get("name") or parsed.get("hostname"), f"device-{index + 1}")
    vendor = parsed.get("vendor") or vendor_hint
    return {
        "id": f"d{index + 1}",
        "name": name,
        "hostname": parsed.get("hostname") or name,
        "vendor": vendor,
        "vendor_name": parsed.get("vendor_name") or vendor,
        "parser_confidence": parsed.get("analysis", {}).get("parser_confidence"),
        "role": _device_role(vendor, routing, trunks, svis, text),
        "vlans": _extract_vlan_ids(text, parsed),
        "trunks": trunks,
        "ip_interfaces": ip_interfaces,
        "svis": svis,
        "routing": routing,
        "fhrp_vlans": sorted(_fhrp_vlans(text)),
        "neighbor_text": device.get("neighbor_text") or "",
        "raw": text,
    }


def _name_aliases(fact: Dict[str, Any]) -> Set[str]:
    values = {fact["name"], fact.get("hostname") or ""}
    aliases = set()
    for value in values:
        value = value.strip().lower()
        if not value:
            continue
        aliases.add(value)
        aliases.add(value.split(".")[0])
    return aliases


def _find_local_interface_for_peer(text: str, peer_aliases: Iterable[str]) -> Optional[str]:
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        lower = line.lower()
        if not any(alias and alias in lower for alias in peer_aliases):
            continue
        # Common LLDP/CDP summary rows often include an interface token.
        candidates = re.findall(r"\b(?:Gi|Te|Twe|Fa|Eth|Ethernet|xe-|ge-|et-|1/1/|port\s*)[A-Za-z0-9/._:-]*", line, re.I)
        if candidates:
            return candidates[0].replace("port ", "").strip()
        # CDP detail provides Interface on a nearby line.
        for nearby in lines[max(0, idx - 4): idx + 5]:
            match = re.search(r"(?i)(?:Interface|Local\s+Intf)\s*[: ]\s*([^,\s]+)", nearby)
            if match:
                return match.group(1)
    return None


def _described_interface(text: str, peer_aliases: Iterable[str]) -> Optional[str]:
    current: Optional[str] = None
    for line in text.splitlines():
        match = re.match(r"(?i)^\s*interface\s+([^\s]+)", line)
        if match:
            current = match.group(1)
            continue
        if current and re.match(r"(?i)^\s*description\s+", line):
            low = line.lower()
            if any(alias and alias in low for alias in peer_aliases):
                return current
        if line.strip() == "!":
            current = None
    return None


def _ip_owner_map(facts: List[Dict[str, Any]]) -> Dict[str, Tuple[str, str]]:
    owners: Dict[str, Tuple[str, str]] = {}
    for fact in facts:
        for item in fact["ip_interfaces"]:
            owners[item["address"]] = (fact["id"], item["interface"])
    return owners


def _edge_key(a: str, b: str, kind: str) -> Tuple[str, str, str]:
    return (min(a, b), max(a, b), kind)


def _infer_edges(facts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    edges: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    owners = _ip_owner_map(facts)

    def add(a: Dict[str, Any], b: Dict[str, Any], kind: str, confidence: float, evidence: str,
            a_if: Optional[str] = None, b_if: Optional[str] = None, network: Optional[str] = None) -> None:
        key = _edge_key(a["id"], b["id"], kind)
        candidate = {
            "id": f"e{len(edges) + 1}",
            "source": a["id"], "target": b["id"], "source_name": a["name"], "target_name": b["name"],
            "kind": kind, "confidence": round(confidence, 2), "evidence": evidence[:360],
            "source_interface": a_if, "target_interface": b_if, "network": network,
        }
        if key not in edges or candidate["confidence"] > edges[key]["confidence"]:
            edges[key] = candidate

    # Explicit neighbor evidence and description-based relationships.
    for i, a in enumerate(facts):
        for b in facts[i + 1:]:
            a_alias, b_alias = _name_aliases(a), _name_aliases(b)
            a_neighbor = any(alias in a["neighbor_text"].lower() for alias in b_alias if alias)
            b_neighbor = any(alias in b["neighbor_text"].lower() for alias in a_alias if alias)
            if a_neighbor or b_neighbor:
                a_if = _find_local_interface_for_peer(a["neighbor_text"], b_alias) if a_neighbor else None
                b_if = _find_local_interface_for_peer(b["neighbor_text"], a_alias) if b_neighbor else None
                add(a, b, "observed_neighbor", CONFIDENCE["observed_neighbor"], "Peer hostname appears in supplied CDP/LLDP neighbor evidence", a_if, b_if)
                continue
            a_if = _described_interface(a["raw"], b_alias)
            b_if = _described_interface(b["raw"], a_alias)
            if a_if or b_if:
                add(a, b, "described_peer", CONFIDENCE["described_peer"], "Interface description references peer hostname", a_if, b_if)

    # Shared point-to-point/transit networks.
    for i, a in enumerate(facts):
        for b in facts[i + 1:]:
            for ai in a["ip_interfaces"]:
                try:
                    anet = ipaddress.ip_network(ai["network"], strict=False)
                except ValueError:
                    continue
                if anet.prefixlen == anet.max_prefixlen or anet.is_loopback:
                    continue
                for bi in b["ip_interfaces"]:
                    if ai["version"] != bi["version"]:
                        continue
                    try:
                        bnet = ipaddress.ip_network(bi["network"], strict=False)
                    except ValueError:
                        continue
                    if anet == bnet and ai["address"] != bi["address"]:
                        confidence = CONFIDENCE["shared_transit"] if anet.prefixlen >= (29 if anet.version == 4 else 125) else 0.72
                        add(a, b, "shared_transit", confidence, f"Both devices have addresses in {anet}", ai["interface"], bi["interface"], str(anet))

    # BGP peer IP ownership is strong relationship evidence even when the link is multihop.
    by_id = {fact["id"]: fact for fact in facts}
    for a in facts:
        for neighbor in a["routing"]["bgp_neighbors"]:
            owner = owners.get(neighbor["address"])
            if owner and owner[0] != a["id"]:
                b = by_id[owner[0]]
                add(a, b, "bgp_peer", CONFIDENCE["bgp_peer"], f"BGP neighbor {neighbor['address']} belongs to {b['name']}", None, owner[1])

    # Re-number stable ids after de-duplication.
    result = list(edges.values())
    result.sort(key=lambda e: (-e["confidence"], e["source_name"], e["target_name"], e["kind"]))
    for idx, edge in enumerate(result, 1):
        edge["id"] = f"e{idx}"
    return result


def _connected_components(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[List[str]]:
    adjacency: Dict[str, Set[str]] = defaultdict(set)
    for edge in edges:
        adjacency[edge["source"]].add(edge["target"])
        adjacency[edge["target"]].add(edge["source"])
    remaining = {node["id"] for node in nodes}
    result: List[List[str]] = []
    while remaining:
        start = next(iter(remaining))
        queue = deque([start])
        component: List[str] = []
        remaining.remove(start)
        while queue:
            node = queue.popleft()
            component.append(node)
            for peer in adjacency[node]:
                if peer in remaining:
                    remaining.remove(peer)
                    queue.append(peer)
        result.append(sorted(component))
    return result


def _bridges(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    adjacency: Dict[str, List[str]] = defaultdict(list)
    for edge in edges:
        adjacency[edge["source"]].append(edge["target"])
        adjacency[edge["target"]].append(edge["source"])
    timer = 0
    disc: Dict[str, int] = {}
    low: Dict[str, int] = {}
    parent: Dict[str, Optional[str]] = {}
    found: List[Tuple[str, str]] = []

    def dfs(u: str) -> None:
        nonlocal timer
        timer += 1
        disc[u] = low[u] = timer
        for v in adjacency[u]:
            if v not in disc:
                parent[v] = u
                dfs(v)
                low[u] = min(low[u], low[v])
                if low[v] > disc[u]:
                    found.append((u, v))
            elif parent.get(u) != v:
                low[u] = min(low[u], disc[v])

    for node in nodes:
        if node["id"] not in disc:
            parent[node["id"]] = None
            dfs(node["id"])
    return found


def _current_findings(facts: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    by_id = {fact["id"]: fact for fact in facts}
    degree = defaultdict(int)
    for edge in edges:
        degree[edge["source"]] += 1
        degree[edge["target"]] += 1

    for fact in facts:
        if fact["role"] in {"security_gateway", "router", "core_distribution", "layer3_switch"} and degree[fact["id"]] <= 1 and len(facts) > 1:
            findings.append({
                "severity": "high", "type": "single_connectivity_path", "device": fact["name"],
                "message": f"{fact['name']} appears to have only {degree[fact['id']]} inferred network relationship(s)",
                "impact": "If this is the only real path, failure or maintenance can isolate routed, gateway, or security services.",
                "confidence": "medium", "recommendation": "Confirm physical/logical redundancy with LLDP/CDP and routing state before treating this as a single point of failure.",
            })

    for a_id, b_id in _bridges(facts, edges):
        a, b = by_id[a_id], by_id[b_id]
        findings.append({
            "severity": "medium", "type": "bridge_link", "device": f"{a['name']} ↔ {b['name']}",
            "message": "This inferred relationship is a graph bridge: removing it partitions the observed topology",
            "impact": "If the inference matches runtime topology, this link/path may be a structural single point of failure.",
            "confidence": "medium", "recommendation": "Verify a redundant physical or routed path and test failover behavior.",
        })

    # Gateway concentration per VLAN. FHRP lowers confidence of a single-gateway warning.
    vlan_gateways: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for fact in facts:
        for svi in fact["svis"]:
            vlan_gateways[svi["vlan"]].append(fact)
    for vlan, owners in sorted(vlan_gateways.items()):
        unique = {owner["id"]: owner for owner in owners}
        if len(unique) == 1:
            owner = next(iter(unique.values()))
            fhrp = vlan in set(owner["fhrp_vlans"])
            findings.append({
                "severity": "low" if fhrp else "medium", "type": "gateway_concentration", "device": owner["name"],
                "message": f"VLAN {vlan} gateway is visible on only one supplied device",
                "impact": "The bundle may be missing a redundant gateway, or this VLAN may depend on a single Layer-3 device.",
                "confidence": "low" if fhrp else "medium", "recommendation": "Supply both gateway configs/runtime evidence and verify HSRP/VRRP/VRRP-E or equivalent first-hop redundancy.",
            })

    # Pair-level native/allowed VLAN checks only when both local interfaces are known.
    for edge in edges:
        if not edge.get("source_interface") or not edge.get("target_interface"):
            continue
        a, b = by_id[edge["source"]], by_id[edge["target"]]
        at = a["trunks"].get(edge["source_interface"])
        bt = b["trunks"].get(edge["target_interface"])
        if not at or not bt:
            continue
        if at.get("native_vlan") and bt.get("native_vlan") and at["native_vlan"] != bt["native_vlan"]:
            findings.append({
                "severity": "critical", "type": "native_vlan_mismatch", "device": f"{a['name']} ↔ {b['name']}",
                "message": f"Native/PVID mismatch inferred: {a['name']} {at['native_vlan']} vs {b['name']} {bt['native_vlan']}",
                "impact": "Untagged traffic and some control-plane traffic can be misdelivered or dropped; loops/security exposure are possible.",
                "confidence": "high", "recommendation": "Verify both live ports before changing either side; coordinate a peer-side correction with rollback/OOB access.",
            })
        a_allowed, b_allowed = set(at.get("allowed_vlans") or []), set(bt.get("allowed_vlans") or [])
        if a_allowed and b_allowed:
            missing_a = sorted(b_allowed - a_allowed)
            missing_b = sorted(a_allowed - b_allowed)
            if missing_a or missing_b:
                findings.append({
                    "severity": "medium", "type": "trunk_vlan_asymmetry", "device": f"{a['name']} ↔ {b['name']}",
                    "message": "Peer trunk allowed-VLAN lists are asymmetric",
                    "impact": "VLANs can become one-sided or fail to traverse the link if the asymmetry is not intentional.",
                    "confidence": "high", "evidence": {"missing_on_source": missing_a[:30], "missing_on_target": missing_b[:30]},
                    "recommendation": "Confirm intended VLAN service matrix and peer state before pruning or extending VLANs.",
                })
    return findings


def _propagate_change(changed_id: str, domains: Iterable[str], edges: List[Dict[str, Any]], by_id: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    domains = set(domains)
    adjacency: Dict[str, Set[str]] = defaultdict(set)
    for edge in edges:
        adjacency[edge["source"]].add(edge["target"])
        adjacency[edge["target"]].add(edge["source"])
    max_depth = 2 if domains.intersection({"routing", "layer2", "security_policy"}) else 1
    queue = deque([(changed_id, 0)])
    visited = {changed_id}
    impacts = []
    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for peer in adjacency[node]:
            if peer in visited:
                continue
            visited.add(peer)
            nd = depth + 1
            queue.append((peer, nd))
            impacts.append({
                "device_id": peer,
                "device": by_id[peer]["name"],
                "distance": nd,
                "confidence": "high" if nd == 1 else "medium",
                "reason": f"Within {nd} inferred hop(s) of a change affecting {', '.join(sorted(domains)) or 'device behavior'}",
            })
    return impacts


def _cross_device_change_findings(current: List[Dict[str, Any]], proposed: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    cur = {f["id"]: f for f in current}
    aft = {f["id"]: f for f in proposed}

    for edge in edges:
        a0, b0 = cur[edge["source"]], cur[edge["target"]]
        a1, b1 = aft[edge["source"]], aft[edge["target"]]
        # If a known shared routed network disappears after the proposed bundle,
        # flag it before implementation.
        if edge["kind"] == "shared_transit" and edge.get("network"):
            network = edge["network"]
            a_has = any(item["network"] == network for item in a1["ip_interfaces"])
            b_has = any(item["network"] == network for item in b1["ip_interfaces"])
            if not (a_has and b_has):
                findings.append({
                    "severity": "high", "type": "transit_relationship_break", "device": f"{a0['name']} ↔ {b0['name']}",
                    "message": f"Proposed configs no longer preserve the inferred transit network {network} on both peers",
                    "impact": "A routed adjacency or next-hop relationship may fail.", "confidence": "high",
                    "recommendation": "Validate both peer addresses, routing neighbors, next hops, and rollback before changing the transit link.",
                })

        # Peer-aware trunk checks if both interface identities are available.
        ai, bi = edge.get("source_interface"), edge.get("target_interface")
        if ai and bi:
            at, bt = a1["trunks"].get(ai), b1["trunks"].get(bi)
            if at and bt:
                if at.get("native_vlan") and bt.get("native_vlan") and at["native_vlan"] != bt["native_vlan"]:
                    findings.append({
                        "severity": "critical", "type": "proposed_native_vlan_mismatch", "device": f"{a0['name']} ↔ {b0['name']}",
                        "message": f"Proposed peer native/PVID values do not match ({at['native_vlan']} vs {bt['native_vlan']})",
                        "impact": "The change can immediately disrupt untagged/control traffic and may destabilize Layer 2.", "confidence": "high",
                        "recommendation": "BLOCK until both peer configs are coordinated and OOB recovery is verified.",
                    })
                a_allowed, b_allowed = set(at.get("allowed_vlans") or []), set(bt.get("allowed_vlans") or [])
                if a_allowed and b_allowed and a_allowed != b_allowed:
                    findings.append({
                        "severity": "high", "type": "proposed_trunk_asymmetry", "device": f"{a0['name']} ↔ {b0['name']}",
                        "message": "Proposed peer trunk VLAN lists are asymmetric",
                        "impact": "Some VLANs may fail to cross the link or become unintentionally one-sided.", "confidence": "high",
                        "evidence": {"source_only": sorted(a_allowed - b_allowed)[:30], "target_only": sorted(b_allowed - a_allowed)[:30]},
                        "recommendation": "Reconcile the intended service VLAN list on both peers before implementation.",
                    })

        # Routing protocol disappearance on one peer while the other retains it.
        before_common = set(a0["routing"]["protocols"]).intersection(b0["routing"]["protocols"])
        after_common = set(a1["routing"]["protocols"]).intersection(b1["routing"]["protocols"])
        lost = sorted(before_common - after_common)
        if lost and edge["kind"] in {"shared_transit", "bgp_peer", "observed_neighbor"}:
            findings.append({
                "severity": "high", "type": "routing_relationship_change", "device": f"{a0['name']} ↔ {b0['name']}",
                "message": f"Common routing protocol evidence disappears after the proposal: {', '.join(lost)}",
                "impact": "Adjacency, reachability, convergence, or failover behavior may change across the peer relationship.",
                "confidence": "medium", "recommendation": "Capture neighbor/route state and verify the peer-side protocol design before implementation.",
            })
    return findings


def _network_gate(score: int, findings: List[Dict[str, Any]], device_changes: List[Dict[str, Any]]) -> Dict[str, str]:
    if any(f.get("severity") == "critical" for f in findings) or any(c.get("change_gate", {}).get("status") == "BLOCK" for c in device_changes) or score >= 80:
        return {"status": "BLOCK", "reason": "Critical cross-device or device-level change evidence requires explicit engineering review, coordinated peer changes, and verified OOB recovery."}
    if any(f.get("severity") == "high" for f in findings) or any(c.get("change_gate", {}).get("status") == "HOLD" for c in device_changes) or score >= 55:
        return {"status": "HOLD", "reason": "High-impact network relationships may be affected. Validate dependencies, peers, rollback, and failover before proceeding."}
    if score >= 25 or device_changes:
        return {"status": "CAUTION", "reason": "Proposed changes need generated pre-checks and post-change proof before implementation."}
    return {"status": "REVIEW", "reason": "No major cross-device risk signature was detected; human review is still required because inferred topology may be incomplete."}


def analyze_network_bundle(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not 2 <= len(devices) <= 50:
        raise ValueError("Network Safety Graph requires between 2 and 50 devices per bundle.")
    for idx, device in enumerate(devices):
        if not (device.get("config_text") or "").strip():
            raise ValueError(f"Device {idx + 1} is missing config_text.")

    current = [_build_facts(device, idx, proposed=False) for idx, device in enumerate(devices)]
    proposed = [_build_facts(device, idx, proposed=True) for idx, device in enumerate(devices)]
    edges = _infer_edges(current)
    current_findings = _current_findings(current, edges)
    by_id = {fact["id"]: fact for fact in current}

    device_changes: List[Dict[str, Any]] = []
    propagation: List[Dict[str, Any]] = []
    for idx, device in enumerate(devices):
        before = device.get("config_text") or ""
        after = device.get("proposed_config") or ""
        if not after.strip() or after.strip() == before.strip():
            continue
        impact = analyze_change(before, after, device.get("vendor") or "auto")
        compact = {
            "device_id": current[idx]["id"],
            "device": current[idx]["name"],
            "risk_score": impact.get("risk_score", 0),
            "risk_label": impact.get("risk_label", "minimal"),
            "change_gate": impact.get("change_gate", {}),
            "affected_domains": impact.get("change_summary", {}).get("affected_domains", []),
            "high_risk_events": impact.get("high_risk_events", []),
            "vlan_delta": impact.get("vlan_delta", {}),
            "protocol_delta": impact.get("protocol_delta", {}),
            "configuration_dna": impact.get("configuration_dna", {}),
            "pre_change_checks": impact.get("pre_change_checks", []),
            "change_sequence": impact.get("change_sequence", []),
            "rollback": impact.get("rollback", []),
            "post_change_checks": impact.get("post_change_checks", []),
        }
        device_changes.append(compact)
        propagation.extend([
            {"origin_device_id": compact["device_id"], "origin_device": compact["device"], **entry}
            for entry in _propagate_change(compact["device_id"], compact["affected_domains"], edges, by_id)
        ])

    cross_findings = _cross_device_change_findings(current, proposed, edges) if device_changes else []
    all_findings = current_findings + cross_findings

    max_device_score = max([int(change.get("risk_score") or 0) for change in device_changes], default=0)
    finding_score = max([SEVERITY_WEIGHT.get(f.get("severity", "info"), 0) for f in cross_findings], default=0)
    topology_score = max([SEVERITY_WEIGHT.get(f.get("severity", "info"), 0) for f in current_findings], default=0)
    network_score = min(100, max(max_device_score, finding_score, topology_score) + min(15, len(cross_findings) * 3))

    node_degree = defaultdict(int)
    for edge in edges:
        node_degree[edge["source"]] += 1
        node_degree[edge["target"]] += 1
    nodes = []
    for fact in current:
        nodes.append({
            "id": fact["id"], "name": fact["name"], "hostname": fact["hostname"], "vendor": fact["vendor"],
            "vendor_name": fact["vendor_name"], "role": fact["role"], "parser_confidence": fact["parser_confidence"],
            "degree": node_degree[fact["id"]], "vlans": fact["vlans"], "routing_protocols": fact["routing"]["protocols"],
            "gateway_vlans": sorted({svi["vlan"] for svi in fact["svis"]}), "trunk_count": len(fact["trunks"]),
            "ip_interface_count": len(fact["ip_interfaces"]), "has_proposed_change": any(c["device_id"] == fact["id"] for c in device_changes),
        })

    components = _connected_components(nodes, edges)
    edge_confidence = round(sum(edge["confidence"] for edge in edges) / len(edges), 2) if edges else 0.0
    neighbor_evidence_devices = sum(1 for fact in current if fact["neighbor_text"].strip())
    configured_links = sum(1 for edge in edges if edge["kind"] in {"observed_neighbor", "described_peer"})

    # Collapse propagation duplicates while preserving the closest/strongest path.
    unique_propagation: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in propagation:
        key = (item["origin_device_id"], item["device_id"])
        if key not in unique_propagation or item["distance"] < unique_propagation[key]["distance"]:
            unique_propagation[key] = item

    return {
        "mode": "offline_network_safety_graph",
        "executable": False,
        "network_risk_score": network_score,
        "network_risk_label": "critical" if network_score >= 80 else "high" if network_score >= 55 else "medium" if network_score >= 25 else "low" if network_score > 0 else "minimal",
        "network_change_gate": _network_gate(network_score, cross_findings, device_changes),
        "topology": {
            "nodes": nodes,
            "edges": edges,
            "components": components,
            "component_count": len(components),
            "average_edge_confidence": edge_confidence,
            "inference_quality": "high" if edge_confidence >= 0.9 and neighbor_evidence_devices >= max(1, len(devices) // 2) else "medium" if edge_confidence >= 0.7 else "limited",
        },
        "coverage": {
            "device_count": len(devices),
            "devices_with_neighbor_evidence": neighbor_evidence_devices,
            "inferred_relationships": len(edges),
            "relationships_with_interface_context": sum(1 for e in edges if e.get("source_interface") or e.get("target_interface")),
            "configured_or_observed_links": configured_links,
            "devices_with_proposed_changes": len(device_changes),
        },
        "current_findings": current_findings,
        "cross_device_change_findings": cross_findings,
        "device_changes": device_changes,
        "impact_propagation": list(unique_propagation.values()),
        "network_pre_change_contract": [
            "Supply CDP/LLDP or equivalent neighbor evidence for critical links whenever possible; config-only topology inference is incomplete.",
            "Capture routing neighbors/routes, STP topology, trunks, LAG state, gateway/FHRP state, interface errors, CPU, logs, and monitoring health before high-risk changes.",
            "Verify console/OOB recovery for every device in the affected change wave.",
            "Coordinate peer-side trunk/native VLAN/transit/routing changes in the same approved maintenance plan.",
            "Define explicit stop conditions and rollback ownership before implementation.",
        ],
        "network_post_change_proof": [
            "Re-run the Network Safety Graph using post-change configs/evidence and compare topology plus Configuration DNA.",
            "Verify every expected routing adjacency and route/default-route path.",
            "Verify STP root/blocked ports, LAG members, trunk native/allowed VLANs, gateway/FHRP state, and interface counters.",
            "Test representative paths for DHCP, DNS, gateway, internal applications, WAN/internet, voice, wireless, and management.",
            "Observe monitoring/logs through the agreed stabilization window and rollback on defined failure criteria.",
        ],
        "limitations": [
            "This is an inferred safety graph, not a packet-level or protocol-state digital twin.",
            "Configuration files cannot prove cabling, optics, runtime neighbor state, route selection, policy hit counts, or undocumented dependencies.",
            "Low-confidence edges and missing peer evidence must be verified before production decisions.",
            "No commands are executed or automatically pushed by this analysis.",
        ],
    }
