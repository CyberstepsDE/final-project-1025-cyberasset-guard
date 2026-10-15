#!/usr/bin/env python3
"""Command-line entrypoint for the Monitoring module — handy for testing
without starting the web server.

Examples:
    python cli.py discover 127.0.0.1
    python cli.py scans
    python cli.py scan 1
    python cli.py assets
"""
import argparse
import json
import sys

from app import config, database
from app.monitoring import diff, scanner, scheduler, service


def main() -> int:
    parser = argparse.ArgumentParser(description="CyberAsset Guard — Monitoring CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_disc = sub.add_parser("discover", help="Part 1: discovery / reachability scan")
    p_disc.add_argument("target", help="host, CIDR, range, or comma list")

    p_port = sub.add_parser("portscan", help="Part 2: open ports & services scan")
    p_port.add_argument("target", help="host, CIDR, range, or space-separated list")
    p_port.add_argument("-p", "--ports", help="port spec, e.g. 22,80,443 or 1-1024")

    p_ver = sub.add_parser("versionscan", help="Part 3: software / version detection")
    p_ver.add_argument("target", help="host, CIDR, range, or space-separated list")
    p_ver.add_argument("-p", "--ports", help="port spec, e.g. 22,80,443 or 1-1024")

    sub.add_parser("scans", help="list recent scans")

    p_scan = sub.add_parser("scan", help="show one scan with host results")
    p_scan.add_argument("scan_id", type=int)

    sub.add_parser("assets", help="list known assets")

    p_sadd = sub.add_parser("schedule-add", help="Part 4: add a recurring scan schedule")
    p_sadd.add_argument("scan_type", choices=["discovery", "port", "version"])
    p_sadd.add_argument("target", help="host, CIDR, range, or space-separated list")
    p_sadd.add_argument("interval_seconds", type=int, help="run interval in seconds")
    p_sadd.add_argument("-p", "--ports", help="port spec for port/version scans")

    sub.add_parser("schedules", help="list scan schedules")

    p_srm = sub.add_parser("schedule-rm", help="remove a scan schedule")
    p_srm.add_argument("schedule_id", type=int)

    p_chg = sub.add_parser("changes", help="Part 5: show the scan-to-scan change log")
    p_chg.add_argument("scan_id", type=int, nargs="?", help="filter to one scan")

    args = parser.parse_args()
    database.configure(config.DB_PATH)
    database.init_models()

    if args.cmd == "discover":
        try:
            scan_id = service.run_discovery(args.target)
        except scanner.ScannerError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(service.get_scan(scan_id), indent=2))
    elif args.cmd == "portscan":
        try:
            scan_id = service.run_port_scan(args.target, args.ports)
        except scanner.ScannerError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(service.get_scan(scan_id), indent=2))
    elif args.cmd == "versionscan":
        try:
            scan_id = service.run_version_scan(args.target, args.ports)
        except scanner.ScannerError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(service.get_scan(scan_id), indent=2))
    elif args.cmd == "scans":
        print(json.dumps(service.list_scans(), indent=2))
    elif args.cmd == "scan":
        scan = service.get_scan(args.scan_id)
        if scan is None:
            print("scan not found", file=sys.stderr)
            return 1
        print(json.dumps(scan, indent=2))
    elif args.cmd == "assets":
        print(json.dumps(service.list_assets(), indent=2))
    elif args.cmd == "schedule-add":
        try:
            sched = scheduler.add_schedule(
                args.scan_type, args.target, args.interval_seconds, args.ports
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(sched, indent=2))
        print("note: schedule stored; the server executes it on startup.", file=sys.stderr)
    elif args.cmd == "schedules":
        print(json.dumps(scheduler.list_schedules(), indent=2))
    elif args.cmd == "schedule-rm":
        ok = scheduler.remove_schedule(args.schedule_id)
        print(json.dumps({"deleted": args.schedule_id if ok else None}))
    elif args.cmd == "changes":
        print(json.dumps(diff.list_changes(args.scan_id), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
