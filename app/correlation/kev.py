"""S5.3 - CISA Known Exploited Vulnerabilities (KEV) catalogue.

The catalogue is stored in the database, so findings keep their KEV flag offline
(the last cached copy is used until a refresh succeeds).
"""
from __future__ import annotations

import json
import logging
import re
from datetime import date, timedelta
from functools import partial

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..database import utcnow
from .models import Cve, FeedSync, KevEntry
from .nvd import MAX_RESPONSE_BYTES, Fetch, urllib_fetch

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FEED_NAME = "cisa_kev"
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")

log = logging.getLogger(__name__)


class KevError(RuntimeError):
    pass


def _date(value) -> date | None:
    try:
        return date.fromisoformat(value) if isinstance(value, str) and value else None
    except ValueError:
        return None


def parse_catalogue(body: bytes) -> list[dict]:
    """Validate the feed and return its well-formed entries."""
    if len(body) > MAX_RESPONSE_BYTES:
        raise KevError("KEV feed exceeds the size limit")
    try:
        data = json.loads(body)
    except ValueError:
        raise KevError("KEV feed is not valid JSON") from None
    items = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise KevError("KEV feed has an unexpected format")
    valid = [i for i in items if isinstance(i, dict) and isinstance(i.get("cveID"), str)
             and _CVE_ID.fullmatch(i["cveID"]) and _date(i.get("dateAdded"))]
    if items and not valid:
        raise KevError("KEV feed contains no valid entries")
    return valid


def store_catalogue(session: Session, items: list[dict]) -> int:
    """Replace the cached catalogue and re-flag CVEs. Returns the entry count."""
    existing = {e.cve_id: e for e in session.scalars(select(KevEntry))}
    for item in items:
        entry = existing.get(item["cveID"]) or KevEntry(cve_id=item["cveID"])
        entry.vendor_project = str(item.get("vendorProject", ""))[:200]
        entry.product = str(item.get("product", ""))[:200]
        entry.date_added = _date(item.get("dateAdded"))
        entry.due_date = _date(item.get("dueDate"))
        entry.ransomware_use = str(item.get("knownRansomwareCampaignUse", "Unknown"))[:20]
        existing[entry.cve_id] = entry
        session.add(entry)
    session.flush()

    session.execute(update(Cve).values(known_exploited=False, kev_date_added=None))
    for cve in session.scalars(select(Cve).where(Cve.id.in_(list(existing)))):
        cve.known_exploited = True
        cve.kev_date_added = existing[cve.id].date_added

    sync = session.get(FeedSync, FEED_NAME) or FeedSync(name=FEED_NAME)
    sync.last_synced = utcnow()
    sync.item_count = len(existing)
    session.add(sync)
    session.commit()                       # the catalogue is kept even if rescoring fails
    from ..risk import service as risk  # lazy: risk depends on the correlation models
    try:
        risk.rescore_all(session)          # KEV listing and catalogue freshness feed the risk score
        from ..dashboard import service as dashboard
        dashboard.record_snapshot_safely(session)
        session.commit()
    except Exception:  # noqa: BLE001
        session.rollback()
        log.exception("risk rescoring after the KEV refresh failed - previous risk kept")
    return len(existing)


def refresh(session: Session, fetch: Fetch = partial(urllib_fetch, follow_redirects=True),
            max_age: timedelta | None = None) -> int:
    """Download and store the catalogue unless the cached copy is younger than `max_age`."""
    sync = session.get(FeedSync, FEED_NAME)
    if max_age is not None and sync and utcnow() - sync.last_synced < max_age:
        return sync.item_count
    try:
        status, body = fetch(KEV_URL, {})
    except OSError as exc:
        raise KevError(f"KEV feed unreachable ({type(exc).__name__})") from None
    if status != 200:
        raise KevError(f"KEV feed returned HTTP {status}")
    return store_catalogue(session, parse_catalogue(body))
