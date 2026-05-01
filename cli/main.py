#!/usr/bin/env python3
"""
SchoolNet Config Validator - CLI Tool
Validate configs and troubleshoot live switches from the command line

Usage:
    python -m cli validate --file config.txt --vendor cisco_ios
    python -m cli troubleshoot --host 192.168.1.10 --username admin --check vlan
    python -m cli fix --file config.txt --output fix.txt
"""
import argparse
import sys
import json
import os

# Add parent to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.parsers import get_parser
from backend.validators.engine import ValidationEngine
from backend.troubleshoot.ssh_client import SwitchSSHClient
from backend.troubleshoot.commands import TroubleshootCommands

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║           🏫 SchoolNet Config Validator v1.0                 ║
║     Catch switch misconfigs before they cause outages        ║
╚══════════════════════════════════════════════════════════════╝
""")

def print_findings(result, verbose=False):
    data = result.to_dict()
    summary = data["summary"]

    print(f"\n📊 Results for {data['hostname'] or 'unknown'}")
    print(f"   Vendor: {data['vendor']} | Lines: {data['total_lines']}")
    print(f"   Interfaces: {len(data['parsed_interfaces'])} | VLANs: {len(data['parsed_vlans'])}")

    print(f"\n🚨 Findings Summary:")
    print(f"   Critical: {summary['critical']} | High: {summary['high']} | Medium: {summary['medium']}")
    print(f"   Low: {summary['low']} | Info: {summary['info']} | Total: {summary['total']}")

    if not data["findings"]:
        print("\n✅ No issues found! Configuration looks good.")
        return

    print(f"\n📋 Detailed Findings:")
    print("-" * 70)

    for i, finding in enumerate(data["findings"], 1):
        severity_emoji = {
            "critical": "🔴", "high": "🟠", "medium": "🟡", 
            "low": "🔵", "info": "⚪"
        }.get(finding["severity"], "⚪")

        iface_str = f" [{finding['interface']}]" if finding["interface"] else ""
        print(f"\n{i}. {severity_emoji} [{finding['severity'].upper()}] {finding['check_type']}{iface_str}")
        print(f"   📝 {finding['message']}")
        print(f"   🔧 Fix: {finding['remediation']}")

        if verbose and finding.get("raw_config"):
            print(f"   📄 Config snippet:")
            for line in finding["raw_config"].split("\n")[:5]:
                print(f"      {line}")

def cmd_validate(args):
    """Validate a configuration file"""
    if not os.path.exists(args.file):
        print(f"❌ File not found: {args.file}")
        sys.exit(1)

    with open(args.file, 'r') as f:
        config_text = f.read()

    print(f"🔍 Validating {args.file} ({args.vendor})...")

    parser = get_parser(args.vendor)
    parsed = parser.parse(config_text)

    engine = ValidationEngine()
    result = engine.validate(parsed, config_text)

    print_findings(result, verbose=args.verbose)

    # Save JSON if requested
    if args.json:
        json_path = args.file.replace(".txt", "_report.json").replace(".cfg", "_report.json")
        with open(json_path, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"\n💾 JSON report saved: {json_path}")

    # Exit with error code if critical findings
    if result.critical_count > 0:
        sys.exit(2)
    elif result.high_count > 0:
        sys.exit(1)

def cmd_troubleshoot(args):
    """Run live troubleshooting on a switch"""
    print(f"🔌 Connecting to {args.host} ({args.device_type})...")

    client = SwitchSSHClient(
        host=args.host,
        username=args.username,
        password=args.password or input("Password: "),
        device_type=args.device_type,
        port=args.port,
        secret=args.secret or ""
    )

    try:
        with client:
            print("✅ Connected! Running checks...\n")

            if args.check == "all":
                results = TroubleshootCommands.run_all(client)
            else:
                results = [TroubleshootCommands.run_check(client, args.check)]

            for category in results:
                print(f"\n{'='*60}")
                print(f"📂 {category['description'].upper()}")
                print(f"{'='*60}")

                for cmd_result in category.get("results", []):
                    print(f"\n$ {cmd_result['command']}")
                    print("-" * 40)
                    output = cmd_result.get("raw", cmd_result.get("output", ""))
                    if isinstance(output, list):
                        for item in output:
                            print(json.dumps(item, indent=2))
                    else:
                        print(output[:2000] if len(str(output)) > 2000 else output)

        print("\n✅ Troubleshooting complete.")

    except ConnectionError as e:
        print(f"\n❌ Connection failed: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user.")
        sys.exit(130)

def cmd_fix(args):
    """Generate remediation script from config"""
    if not os.path.exists(args.file):
        print(f"❌ File not found: {args.file}")
        sys.exit(1)

    with open(args.file, 'r') as f:
        config_text = f.read()

    print(f"🔧 Analyzing {args.file} for remediation...")

    parser = get_parser(args.vendor)
    parsed = parser.parse(config_text)

    engine = ValidationEngine()
    result = engine.validate(parsed, config_text)

    if not result.findings:
        print("✅ No issues found - no remediation needed!")
        return

    # Generate script
    script_lines = ["! SchoolNet Auto-Remediation Script", "! Generated automatically - REVIEW BEFORE APPLYING", "!"]

    for finding in result.findings:
        severity = finding.severity.value
        iface = finding.interface

        script_lines.append(f"!")
        script_lines.append(f"! [{severity.upper()}] {finding.check_type.value}")

        if iface:
            script_lines.append(f"interface {iface}")

        # Extract commands from remediation text
        rem = finding.remediation
        if "Configure:" in rem:
            cmd = rem.split("Configure:")[1].strip()
            script_lines.append(f"  {cmd}")
        elif "Enable:" in rem:
            cmd = rem.split("Enable:")[1].strip()
            script_lines.append(cmd)
        elif "switchport" in rem.lower():
            # Try to extract switchport commands
            for word in rem.split():
                if word.startswith("switchport"):
                    script_lines.append(f"  {word}")

        if iface:
            script_lines.append(" exit")

    script_lines.extend(["!", "end", "write memory"])
    script = "\n".join(script_lines)

    # Output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(script)
        print(f"✅ Remediation script saved: {args.output}")
    else:
        print("\n📜 Generated Script:")
        print("=" * 50)
        print(script)

    print(f"\n📊 Fixed {len(result.findings)} issues")

def cmd_parse(args):
    """Parse and display structured config"""
    with open(args.file, 'r') as f:
        config_text = f.read()

    parser = get_parser(args.vendor)
    parsed = parser.parse(config_text)

    print(json.dumps(parsed, indent=2, default=str))

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="SchoolNet Config Validator - CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Validate config:    python -m cli validate -f switch.txt
  Troubleshoot live:  python -m cli troubleshoot -H 10.0.0.1 -u admin -c all
  Generate fix:       python -m cli fix -f broken.txt -o fix.txt
  Parse only:         python -m cli parse -f switch.txt --json
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate a config file")
    validate_parser.add_argument("-f", "--file", required=True, help="Config file path")
    validate_parser.add_argument("-v", "--vendor", default="cisco_ios", 
                                choices=["cisco_ios", "cisco_iosxe", "aruba_aoscx", "aruba_aos"])
    validate_parser.add_argument("--json", action="store_true", help="Save JSON report")
    validate_parser.add_argument("--verbose", action="store_true", help="Show config snippets")

    # Troubleshoot command
    troubleshoot_parser = subparsers.add_parser("troubleshoot", help="Run live troubleshooting")
    troubleshoot_parser.add_argument("-H", "--host", required=True, help="Switch IP/hostname")
    troubleshoot_parser.add_argument("-u", "--username", required=True, help="SSH username")
    troubleshoot_parser.add_argument("-p", "--password", default="", help="SSH password (prompt if empty)")
    troubleshoot_parser.add_argument("-P", "--port", type=int, default=22, help="SSH port")
    troubleshoot_parser.add_argument("-d", "--device-type", default="cisco_ios",
                                   choices=["cisco_ios", "cisco_iosxe", "aruba_aoscx"])
    troubleshoot_parser.add_argument("-c", "--check", default="all",
                                   choices=["basic", "interfaces", "vlan", "stp", "mac", 
                                           "arp", "errors", "neighbors", "poe", "security", "all"])
    troubleshoot_parser.add_argument("-s", "--secret", default="", help="Enable secret password")

    # Fix command
    fix_parser = subparsers.add_parser("fix", help="Generate remediation script")
    fix_parser.add_argument("-f", "--file", required=True, help="Config file path")
    fix_parser.add_argument("-o", "--output", help="Output file (print to stdout if omitted)")
    fix_parser.add_argument("-v", "--vendor", default="cisco_ios",
                          choices=["cisco_ios", "cisco_iosxe", "aruba_aoscx", "aruba_aos"])

    # Parse command
    parse_parser = subparsers.add_parser("parse", help="Parse config to JSON")
    parse_parser.add_argument("-f", "--file", required=True, help="Config file path")
    parse_parser.add_argument("-v", "--vendor", default="cisco_ios",
                            choices=["cisco_ios", "cisco_iosxe", "aruba_aoscx", "aruba_aos"])

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "validate": cmd_validate,
        "troubleshoot": cmd_troubleshoot,
        "fix": cmd_fix,
        "parse": cmd_parse
    }

    commands[args.command](args)

if __name__ == "__main__":
    main()
