"""Part 5 — change detection.

Compares a completed scan against the previous completed scan of the *same
type and target*, and records what changed into the `changes` table:

  host_up / host_down   - a host's reachability flipped
  host_new / host_gone  - a host appeared / disappeared between scans
  port_open / port_closed - a port opened / closed on a known host
  service_change        - the service name on a port changed
  version_change        - the product/version on a port changed

`detect_changes` is called automatically at the end of every scan (see
service._run_scan), so the change log builds up over time and feeds the
Risk Engine (block 4).
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from ..database import session_scope
from .models import Change, HostResult, PortResult, Scan, as_dict


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _previous_scan_id(session, scan_type: str, target: str, before_id: int) -> int | None:
    """Most recent completed scan of the same type+target before `before_id`."""
    return session.scalar(
        select(Scan.id)
        .where(Scan.scan_type == scan_type, Scan.target == target,
               Scan.status == "completed", Scan.id < before_id)
        .order_by(Scan.id.desc()).limit(1)
    )


def _load_state(session, scan_id: int) -> dict[str, dict]:
    """Return {ip: {state, asset_id, ports: {(port, proto): {service, product, version}}}}."""
    state: dict[str, dict] = {}
    for h in session.execute(
        select(HostResult.ip, HostResult.state, HostResult.asset_id)
        .where(HostResult.scan_id == scan_id)
    ):
        state[h.ip] = {"state": h.state, "asset_id": h.asset_id, "ports": {}}

    for p in session.execute(
        select(PortResult.ip, PortResult.port, PortResult.protocol,
               PortResult.service, PortResult.product, PortResult.version)
        .where(PortResult.scan_id == scan_id)
    ):
        host = state.setdefault(p.ip, {"state": "up", "asset_id": None, "ports": {}})
        host["ports"][(p.port, p.protocol)] = {
            "service": p.service, "product": p.product, "version": p.version,
        }
    return state


def _version_str(info: dict) -> str:
    """Human-readable product/version, e.g. 'nginx 1.25.3' or '-'."""
    parts = [info.get("product"), info.get("version")]
    text = " ".join(p for p in parts if p)
    return text or "-"


def _diff_states(old: dict, new: dict) -> list[dict]:
    """Produce change records (without scan ids / timestamps) from two states."""
    changes: list[dict] = []

    def add(ip, change_type, asset_id, detail, port=None, protocol=None):
        changes.append({
            "ip": ip, "change_type": change_type, "asset_id": asset_id,
            "port": port, "protocol": protocol, "detail": detail,
        })

    for ip in sorted(set(old) | set(new)):
        o, n = old.get(ip), new.get(ip)

        # Host appeared / disappeared between scans.
        if o is None:
            if n["state"] == "up":
                add(ip, "host_new", n["asset_id"], "host first seen (up)")
            continue
        if n is None:
            if o["state"] == "up":
                add(ip, "host_gone", o["asset_id"], "host no longer in scan")
            continue

        # Reachability flip.
        if o["state"] != n["state"]:
            ctype = "host_up" if n["state"] == "up" else "host_down"
            add(ip, ctype, n["asset_id"], f"state {o['state']} -> {n['state']}")

        # Port-level diffs only make sense when the host is up in both scans.
        if o["state"] != "up" or n["state"] != "up":
            continue

        op, np = o["ports"], n["ports"]
        for key in sorted(set(op) | set(np)):
            port, proto = key
            oi, ni = op.get(key), np.get(key)
            if oi is None:
                add(ip, "port_open", n["asset_id"],
                    f"{port}/{proto} opened ({ni['service'] or 'unknown'})", port, proto)
            elif ni is None:
                add(ip, "port_closed", n["asset_id"],
                    f"{port}/{proto} closed (was {oi['service'] or 'unknown'})", port, proto)
            else:
                if (oi["service"] or "") != (ni["service"] or ""):
                    add(ip, "service_change", n["asset_id"],
                        f"{port}/{proto} service {oi['service'] or '-'} -> {ni['service'] or '-'}",
                        port, proto)
                ov, nv = _version_str(oi), _version_str(ni)
                if ov != nv:
                    add(ip, "version_change", n["asset_id"],
                        f"{port}/{proto} version {ov} -> {nv}", port, proto)
    return changes


def detect_changes(new_scan_id: int) -> list[dict]:
    """Diff a scan against the previous comparable one; store and return changes."""
    with session_scope() as session:
        scan = session.get(Scan, new_scan_id)
        if scan is None:
            return []

        prev_id = _previous_scan_id(session, scan.scan_type, scan.target, new_scan_id)
        if prev_id is None:
            return []  # first scan of this target+type — nothing to compare against

        records = _diff_states(_load_state(session, prev_id), _load_state(session, new_scan_id))

        detected_at = _now()
        for r in records:
            session.add(Change(
                scan_id=new_scan_id, prev_scan_id=prev_id, asset_id=r["asset_id"], ip=r["ip"],
                change_type=r["change_type"], port=r["port"], protocol=r["protocol"],
                detail=r["detail"], detected_at=detected_at,
            ))
    return records


def list_changes(scan_id: int | None = None, limit: int = 100) -> list[dict]:
    """Return recorded changes, newest first; optionally filtered to one scan."""
    with session_scope() as session:
        query = select(Change).order_by(Change.id.desc()).limit(limit)
        if scan_id is not None:
            query = (select(Change).where(Change.scan_id == scan_id)
                     .order_by(Change.id.desc()).limit(limit))
        return [as_dict(c) for c in session.scalars(query).all()]
