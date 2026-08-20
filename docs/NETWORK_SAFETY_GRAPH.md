# Network Safety Graph — SchoolNet v1.5

The **Network Safety Graph** is an offline, multi-device network engineering safety layer. It accepts a bundle of sanitized device configurations, optional proposed configurations, and optional read-only neighbor evidence such as CDP/LLDP output.

It is designed to answer a harder question than a normal config validator:

> **If these devices are related, what network relationships and services appear to depend on them, and what could a proposed change affect beyond the device being edited?**

## What it infers

SchoolNet builds confidence-scored nodes and relationships using evidence such as:

- peer hostnames visible in supplied CDP/LLDP/equivalent neighbor output
- interface descriptions that reference another supplied device
- shared routed transit networks
- BGP neighbor IP addresses that belong to another supplied device
- trunk, native/PVID VLAN and allowed-VLAN facts
- VLAN/SVI/gateway presence
- OSPF, OSPFv3, BGP, IS-IS, EIGRP, PIM, VRRP and HSRP evidence

It also identifies possible topology concerns such as graph bridge links, gateway concentration, inferred single connectivity paths, native VLAN mismatches and peer trunk asymmetry.

## Peer-aware proposed-change analysis

If a device also contains a `proposed_config`, the graph combines the v1.4 Change Impact Lab with peer context. It can identify:

- proposed native/PVID mismatch across a known peer link
- proposed allowed-VLAN asymmetry
- a currently shared routed transit network disappearing from one peer
- common routing protocol evidence disappearing across a relationship
- potentially affected first-hop and second-hop devices
- a network-level change gate: `BLOCK`, `HOLD`, `CAUTION`, or `REVIEW`

The result contains a network pre-change contract and post-change proof checklist.

## API

Production endpoint:

```text
POST /api/v1/network-graph
```

Example request:

```json
{
  "devices": [
    {
      "name": "CORE1",
      "vendor": "cisco_iosxe",
      "config_text": "hostname CORE1\n...",
      "proposed_config": "",
      "neighbor_text": "Device ID: ACCESS1\nInterface: GigabitEthernet1/0/48 ..."
    },
    {
      "name": "ACCESS1",
      "vendor": "cisco_ios",
      "config_text": "hostname ACCESS1\n...",
      "proposed_config": "hostname ACCESS1\n...",
      "neighbor_text": "Device ID: CORE1\nInterface: GigabitEthernet1/0/48 ..."
    }
  ]
}
```

The API accepts 2–50 devices per bundle. The web editor is optimized for smaller change reviews and currently allows up to 12 manually edited devices in one screen.

## Evidence confidence

Relationship confidence is intentionally explicit:

| Evidence | Typical confidence |
|---|---:|
| Supplied neighbor evidence | 98% |
| BGP peer IP ownership | 94% |
| Shared point-to-point/transit network | 90% |
| Peer hostname in interface description | 78% |
| Broad/shared VLAN hint | low / advisory only |

Confidence is not probability of correctness in a mathematical sense. It is an engineering evidence-strength indicator.

## Safety boundary

The Network Safety Graph is **not** a packet-level or protocol-state digital twin. Configuration files cannot prove:

- actual cabling or optics
- current STP forwarding/blocking state
- actual routing adjacency state or best-path selection
- firewall/ACL policy hit counts
- application dependencies
- software defects or transient runtime failures
- out-of-band recovery availability

For high-risk changes, provide current read-only evidence and verify the inferred relationships before implementation.

## Production workflow

1. Export/sanitize current configs for the devices in the change domain.
2. Add CDP/LLDP/equivalent neighbor output for critical links when available.
3. Add proposed configs only for devices that will change.
4. Build the Network Safety Graph.
5. Resolve `BLOCK` / `HOLD` findings before the maintenance window.
6. Capture the generated pre-change evidence.
7. Confirm rollback ownership and OOB/console recovery.
8. Implement the smallest reversible change wave.
9. Run post-change validation.
10. Re-run the graph with post-change configs/evidence and compare topology plus Configuration DNA.

## Security

- Use sanitized config and read-only output.
- Do not submit passwords, private keys, tokens or unreviewed configuration backups.
- Network Safety Graph analysis is offline and does not SSH into devices.
- The result is non-executable and never automatically pushes configuration.
