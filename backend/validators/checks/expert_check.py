"""Vendor-neutral expert checks with conservative, evidence-based findings.

These rules intentionally avoid claiming a missing feature when the syntax cannot
be proven. Every risky change is framed as a review plan with pre-checks,
rollback, and post-checks. Nothing here is automatically pushed to a device.
"""
import re
from typing import Any, Dict, List, Optional
from ..engine import Finding, Severity, CheckType


class NetworkExpertCheck:
    def _line(self, text: str, match: re.Match) -> int:
        return text.count("\n", 0, match.start()) + 1

    def _finding(
        self,
        *,
        check_type: CheckType,
        severity: Severity,
        message: str,
        remediation: str,
        evidence: str,
        line_number: Optional[int] = None,
        confidence: str = "high",
        impact: str = "",
        pre_checks: Optional[List[str]] = None,
        change_plan: Optional[List[str]] = None,
        rollback: Optional[List[str]] = None,
        post_checks: Optional[List[str]] = None,
    ) -> Finding:
        return Finding(
            check_type=check_type,
            severity=severity,
            interface=None,
            message=message,
            remediation=remediation,
            line_number=line_number,
            confidence=confidence,
            impact=impact,
            evidence=evidence[:500],
            pre_checks=pre_checks or [],
            change_plan=change_plan or [],
            rollback=rollback or [],
            post_checks=post_checks or [],
            automation_safe=False,
        )

    def _first(self, pattern: str, text: str):
        return re.search(pattern, text, re.I | re.M)

    def run(self, parsed_config: Dict[str, Any], raw_config: str) -> List[Finding]:
        findings: List[Finding] = []
        vendor = parsed_config.get("vendor", "generic")
        analysis = parsed_config.get("analysis", {})

        # 1. Plaintext remote management.
        telnet = self._first(
            r"(transport\s+input[^\n]*telnet|set\s+system\s+services\s+telnet|telnet\s+server\s+enable|enable\s+telnet|/ip\s+service\s+set\s+telnet[^\n]*disabled=no)",
            raw_config,
        )
        if telnet:
            findings.append(self._finding(
                check_type=CheckType.MANAGEMENT_PLANE,
                severity=Severity.CRITICAL,
                message="Plaintext Telnet management is enabled",
                remediation="Migrate administrative access to SSH/HTTPS only after confirming an alternate encrypted management path works.",
                evidence=telnet.group(0),
                line_number=self._line(raw_config, telnet),
                impact="Credentials and administrative sessions can be exposed in plaintext.",
                pre_checks=["Confirm SSH/HTTPS is enabled and reachable from the management network", "Confirm at least two administrator accounts can authenticate", "Save/export the current configuration"],
                change_plan=["Restrict management access to trusted management subnets", "Disable Telnet only after encrypted access is verified", "Keep the current session open until a second session succeeds"],
                rollback=["Re-enable the prior management service from console/OOB access if encrypted access fails"],
                post_checks=["Open a new SSH/HTTPS session", "Verify AAA/login and privilege level", "Confirm monitoring and configuration backup access"],
            ))

        # 2. Unencrypted HTTP management.
        http = self._first(
            r"(^|\n)\s*(ip\s+http\s+server|set\s+system\s+services\s+web-management\s+http|web-management\s+http|/ip\s+service\s+set\s+www[^\n]*disabled=no)",
            raw_config,
        )
        https = re.search(r"(ip\s+http\s+secure-server|web-management\s+https|www-ssl|https)", raw_config, re.I)
        if http:
            findings.append(self._finding(
                check_type=CheckType.MANAGEMENT_PLANE,
                severity=Severity.HIGH,
                message="Unencrypted HTTP management is configured",
                remediation="Prefer HTTPS/SSH and management-plane ACLs. Verify secure access before disabling HTTP.",
                evidence=http.group(0),
                line_number=self._line(raw_config, http),
                confidence="high" if https else "medium",
                impact="Administrative traffic may be readable or modifiable in transit.",
                pre_checks=["Verify HTTPS certificate/access and SSH reachability", "Confirm management ACL/firewall policy"],
                change_plan=["Enable/validate HTTPS first", "Limit management to approved subnets", "Disable cleartext HTTP after validation"],
                rollback=["Restore HTTP only from console/OOB if secure management becomes unreachable"],
                post_checks=["Validate HTTPS and SSH", "Verify configuration backup and monitoring integrations"],
            ))

        # 3. Default/weak SNMP communities.
        for match in re.finditer(r"(?im)(snmp-server\s+community\s+|snmp-agent\s+community\s+(?:read|write)\s+|set\s+snmp\s+community\s+)(public|private|cisco)(?:\s|$)", raw_config):
            findings.append(self._finding(
                check_type=CheckType.MANAGEMENT_PLANE,
                severity=Severity.HIGH,
                message=f"Default/weak SNMP community '{match.group(2)}' is configured",
                remediation="Create a monitored migration to SNMPv3 authPriv or a restricted read-only community before removing the old community.",
                evidence=match.group(0),
                line_number=self._line(raw_config, match),
                impact="Predictable SNMP credentials can expose device information or permit changes when write access exists.",
                pre_checks=["Inventory monitoring systems using this community", "Confirm whether the community is read-only or read-write", "Prepare SNMPv3 credentials in the monitoring platform"],
                change_plan=["Add the replacement SNMPv3/read-only configuration", "Confirm polling succeeds", "Remove the weak community after dependency validation"],
                rollback=["Restore the prior read-only community with source restrictions if monitoring breaks"],
                post_checks=["Verify monitoring polls", "Verify no unexpected SNMP write access", "Review logs for failed SNMP authentication"],
            ))

        # 4. Explicit SNMP write access.
        snmp_rw = self._first(r"(?im)(snmp-server\s+community\s+\S+\s+RW|snmp-agent\s+community\s+write\s+\S+|authorization\s+read-write)", raw_config)
        if snmp_rw:
            findings.append(self._finding(
                check_type=CheckType.MANAGEMENT_PLANE,
                severity=Severity.HIGH,
                message="SNMP write access is configured",
                remediation="Use SNMPv3 with least privilege and source restrictions; remove write access where it is not operationally required.",
                evidence=snmp_rw.group(0),
                line_number=self._line(raw_config, snmp_rw),
                impact="Compromise of SNMP credentials may allow configuration changes.",
                pre_checks=["Identify systems that require SNMP write operations", "Confirm an out-of-band recovery path"],
                change_plan=["Replace broad write access with least-privilege SNMPv3", "Restrict source addresses", "Remove legacy write community only after testing"],
                rollback=["Restore previous restricted access temporarily if a documented dependency fails"],
                post_checks=["Verify monitoring", "Confirm unauthorized sources cannot perform SNMP operations"],
            ))

        # 5. Plaintext/local reversible passwords visibly present.
        weak_secret = self._first(r"(?im)^(enable\s+password\s+\S+|username\s+\S+.*\bpassword\s+0\s+\S+|password\s+0\s+\S+)", raw_config)
        if weak_secret:
            findings.append(self._finding(
                check_type=CheckType.CONFIG_HYGIENE,
                severity=Severity.CRITICAL,
                message="A plaintext or weakly protected administrative secret appears in the configuration",
                remediation="Rotate the credential through the platform's supported secret/hash mechanism and remove exposed copies from backups and tickets.",
                evidence=re.sub(r"(password\s+0\s+|enable\s+password\s+)(\S+)", r"\1<redacted>", weak_secret.group(0), flags=re.I),
                line_number=self._line(raw_config, weak_secret),
                impact="Anyone with configuration access may recover an administrative credential.",
                pre_checks=["Confirm a second working administrator credential", "Confirm console/OOB recovery", "Identify dependent automation using the credential"],
                change_plan=["Create/verify replacement credential", "Update dependent systems", "Rotate the exposed credential", "Purge unsafe copies according to retention policy"],
                rollback=["Use the verified secondary administrator or console/OOB path if authentication fails"],
                post_checks=["Test new login in a separate session", "Verify automation/monitoring", "Confirm old credential no longer authenticates"],
            ))

        # 6. Dynamic trunk negotiation can unexpectedly form trunks.
        dynamic_trunk = self._first(r"(?im)switchport\s+mode\s+dynamic\s+(auto|desirable)", raw_config)
        if dynamic_trunk:
            findings.append(self._finding(
                check_type=CheckType.MISSING_TRUNK,
                severity=Severity.MEDIUM,
                message="Dynamic trunk negotiation is enabled",
                remediation="Use explicit access/trunk mode after verifying the peer and allowed VLAN design.",
                evidence=dynamic_trunk.group(0),
                line_number=self._line(raw_config, dynamic_trunk),
                impact="A port can negotiate an unintended trunk and expand Layer-2 reachability.",
                pre_checks=["Identify the connected peer using CDP/LLDP", "Record current operational trunk state and allowed VLANs"],
                change_plan=["Set the intended static port mode", "Restrict allowed VLANs on trunks", "Disable negotiation where supported"],
                rollback=["Restore the original port mode if the peer loses connectivity"],
                post_checks=["Verify trunk/access operational state", "Verify expected VLAN reachability only", "Check STP and interface errors"],
            ))

        # 7. Explicit all-VLAN trunks.
        all_vlan = self._first(r"(?im)(switchport\s+trunk\s+allowed\s+vlan\s+all|port\s+trunk\s+permit\s+vlan\s+all|allow-pass\s+vlan\s+all)", raw_config)
        if all_vlan:
            findings.append(self._finding(
                check_type=CheckType.MISSING_TRUNK,
                severity=Severity.HIGH,
                message="A trunk explicitly permits all VLANs",
                remediation="Build the required VLAN list from the peer and service dependencies, then prune unused VLANs in a staged change.",
                evidence=all_vlan.group(0),
                line_number=self._line(raw_config, all_vlan),
                impact="Unnecessary VLAN propagation increases blast radius, loop risk, and lateral movement opportunity.",
                pre_checks=["Capture current trunk VLAN forwarding state", "Identify peer device and required VLANs", "Check STP root/blocked ports per VLAN"],
                change_plan=["Create an explicit required VLAN list", "Apply during a maintenance window", "Change one side/one link at a time when redundancy exists"],
                rollback=["Restore the previous allowed-VLAN list if required services fail"],
                post_checks=["Verify required VLANs forward", "Verify no unexpected STP topology change", "Check DHCP/DNS/application reachability"],
            ))

        # 8. Explicit native VLAN 1 on trunks.
        native1 = self._first(r"(?im)(switchport\s+trunk\s+native\s+vlan\s+1\b|native-vlan-id\s+1\b|pvid\s+1\b)", raw_config)
        if native1:
            findings.append(self._finding(
                check_type=CheckType.NATIVE_VLAN_MISMATCH,
                severity=Severity.MEDIUM,
                message="Native/PVID VLAN 1 is explicitly configured on a trunk",
                remediation="If policy requires a non-default native VLAN, coordinate both ends and verify control-plane/native traffic before changing it.",
                evidence=native1.group(0),
                line_number=self._line(raw_config, native1),
                impact="Default native VLAN use can increase exposure to VLAN hopping/mismatch and operational ambiguity.",
                pre_checks=["Verify native/PVID configuration on both ends", "Identify untagged control/management dependencies"],
                change_plan=["Choose an unused/approved native VLAN", "Change both ends in the same maintenance window", "Do not change a remote-only link without OOB access"],
                rollback=["Restore VLAN 1 native/PVID on both ends if the link or management path fails"],
                post_checks=["Verify trunk state", "Check native VLAN mismatch logs", "Verify management and dependent services"],
            ))

        # 9. Explicit STP disablement.
        stp_off = self._first(r"(?im)(no\s+spanning-tree\s+vlan\s+\S+|disable\s+stpd|spanning-tree\s+disable|stp\s+disable)", raw_config)
        if stp_off:
            findings.append(self._finding(
                check_type=CheckType.LOOP_PROTECTION,
                severity=Severity.CRITICAL,
                message="Spanning-tree/loop protection is explicitly disabled for part of the Layer-2 domain",
                remediation="Do not simply enable STP blindly. Map the topology, root design, vendor interop, and redundant links first, then restore loop protection in a controlled window.",
                evidence=stp_off.group(0),
                line_number=self._line(raw_config, stp_off),
                impact="A physical or logical Layer-2 loop can create a broadcast storm and widespread outage.",
                pre_checks=["Map all redundant Layer-2 links", "Record STP mode/root priorities on neighboring switches", "Confirm vendor interoperability and MST/VLAN mapping"],
                change_plan=["Define intended STP mode and root placement", "Enable loop protection incrementally from core/distribution outward", "Monitor topology-change counters"],
                rollback=["Restore the previous STP state only if the planned topology is destabilized; retain OOB access"],
                post_checks=["Verify expected root/blocked ports", "Check topology-change rate", "Check CPU, broadcast, and interface error levels"],
            ))

        # 10. Half duplex explicitly configured.
        half = self._first(r"(?im)^\s*duplex\s+half\s*$", raw_config)
        if half:
            findings.append(self._finding(
                check_type=CheckType.DUPLEX_MISMATCH,
                severity=Severity.HIGH,
                message="Half-duplex is explicitly configured",
                remediation="Verify peer speed/duplex capability and counters before changing both sides consistently or returning to auto-negotiation.",
                evidence=half.group(0),
                line_number=self._line(raw_config, half),
                impact="A duplex mismatch can cause collisions, retransmissions, severe latency, and apparent packet loss.",
                pre_checks=["Capture interface counters and negotiated state on both ends", "Identify peer device and maintenance impact"],
                change_plan=["Correct both ends consistently or use auto-negotiation where supported", "Change during a maintenance window if the link is critical"],
                rollback=["Restore the previous speed/duplex settings if link negotiation fails"],
                post_checks=["Verify link state/speed/duplex", "Check CRC/collision/error counters", "Run a controlled throughput/latency test"],
            ))

        # 11. Directed broadcast / source-route legacy exposure.
        legacy_ip = self._first(r"(?im)^\s*(ip\s+directed-broadcast|ip\s+source-route)\s*$", raw_config)
        if legacy_ip:
            findings.append(self._finding(
                check_type=CheckType.SECURITY_GAP,
                severity=Severity.HIGH,
                message="A legacy IP feature with abuse potential is enabled",
                remediation="Confirm there is no documented dependency, then disable the feature using vendor-supported syntax during a controlled change.",
                evidence=legacy_ip.group(0),
                line_number=self._line(raw_config, legacy_ip),
                impact="Legacy forwarding behavior can increase spoofing or amplification risk.",
                pre_checks=["Search change records for a dependency", "Confirm traffic telemetry does not show legitimate use"],
                change_plan=["Disable only the confirmed unnecessary feature", "Monitor affected routing/interface telemetry"],
                rollback=["Restore the previous command if a documented service fails"],
                post_checks=["Verify routing and application reachability", "Review security/traffic telemetry"],
            ))

        # 12. Routing protocols found: provide a non-alarm operational review item.
        protocols = parsed_config.get("routing", {}).get("protocols", [])
        if protocols:
            findings.append(self._finding(
                check_type=CheckType.ROUTING_RISK,
                severity=Severity.INFO,
                message=f"Dynamic/redundancy routing features detected: {', '.join(protocols)}",
                remediation="Before changing routing, capture neighbors, route counts, default routes, timers, authentication, redistribution, and failover state.",
                evidence=f"Detected protocols: {', '.join(protocols)}",
                confidence="medium",
                impact="Routing changes can affect multiple sites even when a local interface remains up.",
                pre_checks=["Capture neighbor/adja­cency state", "Capture route table and default route", "Record metrics, areas/ASNs, redistribution, filters, and authentication", "Confirm redundant path/failover state"],
                change_plan=["Make one routing change at a time", "Avoid simultaneous changes on redundant peers", "Use explicit rollback criteria and timer"],
                rollback=["Restore the saved routing stanza/config checkpoint if adjacency or route count deviates unexpectedly"],
                post_checks=["Verify all expected neighbors", "Compare route counts and default route", "Test representative site/application reachability"],
            ))

        # 13. Observability signals. Only flag when the config explicitly disables them.
        logging_off = self._first(r"(?im)^\s*(no\s+logging\s+on|logging\s+disable|disable\s+syslog)\s*$", raw_config)
        if logging_off:
            findings.append(self._finding(
                check_type=CheckType.OBSERVABILITY,
                severity=Severity.MEDIUM,
                message="System logging is explicitly disabled",
                remediation="Restore local/remote logging with rate limits and a trusted collector after confirming storage and source-interface settings.",
                evidence=logging_off.group(0),
                line_number=self._line(raw_config, logging_off),
                impact="Loss of logs reduces incident detection, troubleshooting evidence, and change accountability.",
                pre_checks=["Verify collector reachability and storage", "Choose management source interface/VRF if required"],
                change_plan=["Enable logging at an appropriate severity", "Add remote collector(s)", "Avoid debug-level logging during normal operation"],
                rollback=["Reduce logging severity/rate if CPU or transport load becomes excessive"],
                post_checks=["Verify timestamped messages at the collector", "Confirm device CPU and log-drop counters remain healthy"],
            ))

        # 14. Universal parser confidence notice for unknown syntax.
        confidence = float(analysis.get("parser_confidence", 0.0) or 0.0)
        if analysis.get("mode") == "universal" and confidence < 0.60:
            findings.append(self._finding(
                check_type=CheckType.CONFIG_HYGIENE,
                severity=Severity.INFO,
                message="Platform syntax was not identified with high confidence",
                remediation="Treat findings as conservative evidence-based checks. Select the exact platform if known and review vendor documentation before applying any change.",
                evidence=f"Detected vendor={vendor}, parser_confidence={confidence:.2f}",
                confidence="low",
                impact="Unsupported syntax may hide platform-specific risks; the tool intentionally avoids guessing.",
                pre_checks=["Confirm vendor, OS family, model, and software version", "Use the vendor-specific selection if available"],
                post_checks=["Re-run validation after selecting the exact platform"],
            ))

        return findings
