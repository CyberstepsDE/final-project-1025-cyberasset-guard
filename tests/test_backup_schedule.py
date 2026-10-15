"""Scheduled backups and retention (ASSET-88)."""
import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import config, maintenance
from app.monitoring import scheduler

NOW = datetime(2026, 11, 1, tzinfo=UTC)   # fixed "today" so test dates are in the past


def _touch(directory: Path, stamp: str, stem: str = "cyberasset_guard") -> Path:
    f = directory / f"{stem}-{stamp}.db"
    f.write_bytes(b"x")
    return f


def test_retention_keeps_daily_and_weekly(tmp_path):
    # 20 consecutive days, two backups per day (06:00 and 18:00), newest 2026-10-20
    for day in range(1, 21):
        for hour in ("060000", "180000"):
            _touch(tmp_path, f"202610{day:02d}T{hour}Z")
    other = tmp_path / "notes.txt"
    other.write_text("keep me")
    foreign = _touch(tmp_path, "garbage", stem="x")              # not a backup name pattern -> untouched

    result = maintenance.prune_backups(tmp_path, keep_daily=7, keep_weekly=4, stem="cyberasset_guard", now=NOW)
    kept = sorted(Path(p).name for p in result["kept"])
    # daily: newest backup of Oct 14..20; weekly (ISO weeks 43, 42, 41, 40): Oct 20, 18, 11, 4
    expected_days = [14, 15, 16, 17, 18, 19, 20] + [11, 4]
    assert kept == sorted(f"cyberasset_guard-202610{d:02d}T180000Z.db" for d in expected_days)
    assert other.exists() and foreign.exists()
    assert all(not Path(p).exists() for p in result["deleted"])
    assert len(result["deleted"]) == 40 - len(kept)


def test_weekly_retention_reaches_back_further(tmp_path):
    for day in (1, 8, 15, 22, 29):                                # one backup per week in October
        _touch(tmp_path, f"202610{day:02d}T120000Z")
    kept = {Path(p).name for p in maintenance.prune_backups(tmp_path, keep_daily=1, keep_weekly=3, stem="cyberasset_guard", now=NOW)["kept"]}
    assert kept == {"cyberasset_guard-20261029T120000Z.db", "cyberasset_guard-20261022T120000Z.db",
                    "cyberasset_guard-20261015T120000Z.db"}


def test_newest_backup_is_always_kept(tmp_path):
    f = _touch(tmp_path, "20261001T000000Z")
    assert maintenance.prune_backups(tmp_path, keep_daily=1, keep_weekly=0, stem="cyberasset_guard", now=NOW)["kept"] == [str(f)]
    with pytest.raises(maintenance.MaintenanceError):
        maintenance.prune_backups(tmp_path, keep_daily=0)


@pytest.mark.sqlite_only
def test_scheduled_backup_writes_and_prunes(client, make_asset, tmp_path, monkeypatch):
    make_asset()
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    for day in range(1, 11):
        _touch(backup_dir, f"202601{day:02d}T000000Z", stem="test")
    monkeypatch.setattr(config, "BACKUP_KEEP_DAILY", 2)
    monkeypatch.setattr(config, "BACKUP_KEEP_WEEKLY", 0)
    maintenance.scheduled_backup()
    remaining = sorted(p.name for p in backup_dir.glob("*.db"))
    assert len(remaining) == 2 and not remaining[-1].startswith("test-2026010")   # the fresh backup survives


def test_scheduled_backup_failure_is_logged_not_raised(monkeypatch, caplog):
    def boom(*a, **k):
        raise maintenance.MaintenanceError("disk full")
    monkeypatch.setattr(maintenance, "backup", boom)
    monkeypatch.setattr(logging.getLogger("app"), "propagate", True)
    with caplog.at_level(logging.ERROR, logger="app"):
        maintenance.scheduled_backup()
    assert "scheduled backup failed" in caplog.text


@pytest.mark.sqlite_only
def test_backup_job_is_registered_when_enabled(app, monkeypatch):
    monkeypatch.setattr(config, "BACKUP_INTERVAL_HOURS", 24)
    with TestClient(app):
        job = scheduler.get_scheduler().get_job("cag-backup")
        assert job is not None and job.trigger.interval.total_seconds() == 24 * 3600
    monkeypatch.setattr(config, "BACKUP_INTERVAL_HOURS", 0)
    scheduler.get_scheduler().remove_all_jobs()
    with TestClient(app):
        assert scheduler.get_scheduler().get_job("cag-backup") is None


def test_prune_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "BACKUP_DIR", tmp_path)
    for day in range(1, 6):
        _touch(tmp_path, f"202609{day:02d}T000000Z", stem="test")      # conftest database is test.db; past dates
    assert maintenance.main(["prune-backups", "--keep-daily", "2", "--keep-weekly", "0"]) == 0
    assert "kept 2 backup(s), deleted 3" in capsys.readouterr().out


def test_prune_only_touches_backups_of_this_database(tmp_path):
    """Security review F4/F5: other files, safety copies, odd names and future stamps are never deleted."""
    for day in range(1, 6):
        _touch(tmp_path, f"202610{day:02d}T000000Z")
    survivors = [
        _touch(tmp_path, "20260901T000000Z", stem="other_app"),                    # other database
        tmp_path / "cyberasset_guard.pre-restore-20260901T000000Z.db",             # restore safety copy
        _touch(tmp_path, "20261399T000000Z"),                                      # unparseable (month 13)
        _touch(tmp_path, "29991231T000000Z"),                                      # future timestamp
    ]
    survivors[1].write_bytes(b"x")
    (tmp_path / "cyberasset_guard-20260101T000000Z.db").mkdir()                    # a directory, not a file
    result = maintenance.prune_backups(tmp_path, keep_daily=1, keep_weekly=0, stem="cyberasset_guard", now=NOW)
    assert [Path(p).name for p in result["kept"]] == ["cyberasset_guard-20261005T000000Z.db"]
    assert len(result["deleted"]) == 4 and result["failed"] == []
    assert all(f.exists() for f in survivors)
    assert (tmp_path / "cyberasset_guard-20260101T000000Z.db").is_dir()
