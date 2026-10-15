"""Infrastructure tests: dependencies, configuration, database, startup, health,
persistence, error handling, backup / restore, isolation and (opt-in) Docker."""
from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import sys
import time
from importlib import metadata
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from packaging.requirements import Requirement

from app import config, database, maintenance
from app.assets.models import Asset
from app.audit.service import SYSTEM
from app.auth.permissions import Role
from app.auth.service import create_user
from conftest import TEST_DATABASE_URL, TEST_PASSWORD, login

ROOT = Path(__file__).resolve().parent.parent


def _requirements(name: str) -> list[Requirement]:
    reqs = []
    for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith("-"):
            reqs.append(Requirement(line))
    return reqs


# 1. dependencies and configuration ---------------------------------------------------------

def test_python_version_is_supported():
    assert sys.version_info >= config.MIN_PYTHON


@pytest.mark.parametrize("req", _requirements("requirements.txt") + _requirements("requirements-dev.txt"),
                         ids=str)
def test_declared_dependencies_are_installed_in_range(req):
    installed = metadata.version(req.name)
    assert req.specifier.contains(installed, prereleases=True), f"{req.name} {installed} !~ {req.specifier}"


def test_constraints_are_consistent_with_requirements():
    pins = {}
    for line in (ROOT / "constraints.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            name, version = line.split("==")
            pins[name.lower().replace("_", "-")] = version
    for req in _requirements("requirements.txt") + _requirements("requirements-dev.txt"):
        key = req.name.lower().replace("_", "-")
        assert key in pins, f"{req.name} is not pinned in constraints.txt"
        assert req.specifier.contains(pins[key]), f"constraints pin {req.name}=={pins[key]} violates {req.specifier}"


def test_runtime_and_dev_dependencies_are_separated():
    runtime = {r.name.lower() for r in _requirements("requirements.txt")}
    assert not runtime & {"pytest", "httpx"}
    assert "-r requirements.txt" in (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")


def _import_config(env: dict) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", "import app.config"], cwd=ROOT, capture_output=True,
                          text=True, env={**os.environ, **env}, timeout=60)


@pytest.mark.parametrize("env, message", [
    ({"CAG_SCAN_TIMEOUT": "abc"}, "CAG_SCAN_TIMEOUT must be an integer, got 'abc'"),
    ({"CAG_SCAN_TIMEOUT": "0"}, "CAG_SCAN_TIMEOUT must be >= 1"),
    ({"CAG_LOG_LEVEL": "verbose"}, "CAG_LOG_LEVEL must be one of DEBUG, INFO, WARNING, ERROR"),
])
def test_invalid_configuration_is_reported_clearly(env, message):
    result = _import_config(env)
    assert result.returncode != 0
    assert "ConfigError" in result.stderr and message in result.stderr


def test_validate_runtime_rejects_unusable_database_path(tmp_path):
    with pytest.raises(config.ConfigError, match="points to a directory"):
        config.validate_runtime(tmp_path)
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(config.ConfigError, match="cannot be created"):
        config.validate_runtime(blocker / "sub" / "db.sqlite")


def test_secrets_and_local_data_are_ignored_by_git():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (".env", "*.db", "*.db-wal", "backups/", "data/", "!.env.example"):
        assert pattern in ignore
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert not re.search(r"(?i)(password|secret|token|api_key)\s*=", example)


def test_debug_mode_is_off():
    from app.main import app
    assert app.debug is False
    for path in ("Dockerfile", "docker-compose.yml"):
        assert "--reload" not in (ROOT / path).read_text(encoding="utf-8")


# 2./3. database initialization and connectivity ---------------------------------------------

@pytest.mark.sqlite_only
def test_database_initialization_is_idempotent_and_complete(isolated_database):
    assert not database.check_ready()                      # empty file: schema missing
    message = maintenance.init_database()
    assert "database ready" in message
    maintenance.init_database()                            # second run is a no-op
    assert database.check_ready()
    info = maintenance.verify_backup(isolated_database)    # integrity + required tables
    assert {"asset_inventory", "asset_tags", "scans", "assets"} <= set(info.tables)


@pytest.mark.sqlite_only
def test_sqlalchemy_connects_to_the_configured_database(client, isolated_database):
    assert Path(database.get_engine().url.database) == isolated_database
    with database.get_engine().connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        assert conn.exec_driver_sql("PRAGMA busy_timeout").scalar() == 5000


# 4./5. startup and health ------------------------------------------------------------------

def test_startup_and_shutdown_are_logged(isolated_database, monkeypatch, caplog):
    monkeypatch.setattr(logging.getLogger("app"), "propagate", True)
    from app.main import app
    with caplog.at_level(logging.INFO, logger="app"), TestClient(app):
        pass
    messages = [r.getMessage() for r in caplog.records]
    assert any(m.startswith("starting CyberAsset Guard") for m in messages)
    assert "startup complete" in messages and "shutdown complete" in messages


def test_liveness(client):
    for path in ("/health", "/health/live"):
        r = client.get(path)
        assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_readiness_ok(client):
    r = client.get("/health/ready")
    assert r.status_code == 200
    assert r.json() == {"status": "ready", "checks": {"database": "ok"}}


def test_readiness_fails_without_leaking_details(client, tmp_path):
    database.configure(tmp_path / "empty.db")              # reachable, but schema missing
    r = client.get("/health/ready")
    assert r.status_code == 503
    assert r.json() == {"status": "not_ready", "checks": {"database": "unavailable"}}
    assert str(tmp_path) not in r.text
    assert client.get("/health/live").status_code == 200   # liveness is independent


# 6./7. persistence ------------------------------------------------------------------------

def test_assets_persist_across_sessions_and_engines(make_asset, isolated_database):
    created = make_asset(name="persisted", ip_address="10.1.1.1", tags=["pci"])
    database.configure(TEST_DATABASE_URL or isolated_database)                   # brand-new engine / connection pool
    with next(database.get_session()) as session:
        asset = session.get(Asset, created["id"])
        assert (asset.name, asset.ip_address, asset.tags) == ("persisted", "10.1.1.1", ["pci"])


def test_assets_survive_application_restart_in_process(isolated_database, app, make_user):
    make_user("operator", "analyst")
    with TestClient(app) as c:
        login(c, "operator")
        asset_id = c.post("/assets", json={"name": "restart-me", "asset_type": "server",
                                           "environment": "test", "criticality": "low"}).json()["id"]
    database.configure(TEST_DATABASE_URL or isolated_database)
    with TestClient(app) as c:                               # users and sessions survive as well
        login(c, "operator")
        assert c.get(f"/assets/{asset_id}").json()["name"] == "restart-me"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _server_env(db_path: Path) -> dict:
    return {**os.environ, "CAG_DB_PATH": str(db_path), "CAG_BACKUP_DIR": str(db_path.parent / "bk")}


def _cli_create_user(db_path: Path, username: str, role: str) -> None:
    """Creates a user exactly as documented: python -m app.maintenance create-user ... --password-stdin"""
    result = subprocess.run(
        [sys.executable, "-m", "app.maintenance", "create-user", username, "--role", role, "--password-stdin"],
        cwd=ROOT, env=_server_env(db_path), input=TEST_PASSWORD + "\n", capture_output=True, text=True,
        timeout=120)
    assert result.returncode == 0, result.stderr
    assert f"created user '{username}'" in result.stdout


def _start_server(db_path: Path, port: int, log_file: Path) -> subprocess.Popen:
    env = _server_env(db_path)
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, env=env, stdout=log_file.open("w"), stderr=subprocess.STDOUT)


def _wait_ready(port: int, proc: subprocess.Popen, timeout: float = 30) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"server exited with {proc.returncode}")
        try:
            if httpx.get(f"http://127.0.0.1:{port}/health/ready", timeout=1).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    raise AssertionError("server did not become ready")


def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def test_real_server_process_start_and_restart_keeps_data(tmp_path):
    """Starts uvicorn exactly as documented, twice, against the same database file."""
    db_path, port = tmp_path / "srv" / "app.db", _free_port()
    _cli_create_user(db_path, "admin", "admin")              # real scrypt cost, real CLI
    base = f"http://127.0.0.1:{port}"
    log_file = tmp_path / "server.log"
    proc = _start_server(db_path, port, log_file)
    try:
        _wait_ready(port, proc)
        with httpx.Client(base_url=base) as http:
            assert http.get("/assets").status_code == 401
            assert http.post("/auth/login", json={"username": "admin", "password": TEST_PASSWORD}).status_code == 200
            r = http.post("/assets", json={"name": "survivor", "asset_type": "database",
                                           "environment": "production", "criticality": "critical"})
            assert r.status_code == 201
            asset_id = r.json()["id"]
    finally:
        _stop(proc)
    assert "startup complete" in log_file.read_text()

    proc = _start_server(db_path, port, tmp_path / "server2.log")
    try:
        _wait_ready(port, proc)
        with httpx.Client(base_url=base) as http:
            http.post("/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
            r = http.get(f"/assets/{asset_id}")
            assert r.status_code == 200 and r.json()["name"] == "survivor"
    finally:
        _stop(proc)


def test_startup_failure_produces_understandable_log(tmp_path):
    bad = tmp_path / "is_a_directory.db"
    bad.mkdir()
    port = _free_port()
    log_file = tmp_path / "fail.log"
    proc = _start_server(bad, port, log_file)
    try:
        assert proc.wait(timeout=60) != 0
    finally:
        if proc.poll() is None:
            proc.kill()
    output = log_file.read_text()
    assert "startup aborted - configuration problem" in output
    assert "CAG_DB_PATH points to a directory" in output


# 8. error handling --------------------------------------------------------------------------

def test_unexpected_errors_return_generic_500(client, monkeypatch):
    from app.assets import service

    def boom(*args, **kwargs):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(service, "list_assets", boom)
    c = TestClient(client.app, raise_server_exceptions=False, cookies=client.cookies)
    r = c.get("/assets")
    assert r.status_code == 500
    assert r.json() == {"detail": "Internal server error."}
    assert "secret" not in r.text and "Traceback" not in r.text


def test_database_unavailable_is_handled_safely(client, tmp_path):
    database.configure(tmp_path / "empty.db")              # tables missing -> OperationalError
    r = client.get("/assets")
    assert r.status_code == 500
    assert r.json() == {"detail": "A database error occurred. Please try again later."}
    assert "asset_inventory" not in r.text and "SELECT" not in r.text


# 9./10. backup and restore -----------------------------------------------------------------------

def _snapshot(db_file: Path) -> list[tuple]:
    import sqlite3
    conn = sqlite3.connect(db_file)      # note: `with sqlite3.connect()` would not close it
    try:
        assets = conn.execute("SELECT * FROM asset_inventory ORDER BY id").fetchall()
        tags = conn.execute("SELECT asset_id, tag FROM asset_tags ORDER BY asset_id, tag").fetchall()
    finally:
        conn.close()
    return assets + tags


@pytest.mark.sqlite_only
def test_backup_is_consistent_verified_and_separate(make_asset, isolated_database, tmp_path):
    make_asset(name="a", tags=["pci"])
    make_asset(name="b")
    info = maintenance.backup()                              # app is running: online backup
    assert info.path.parent == tmp_path / "backups"
    assert info.path.parent != isolated_database.parent
    assert info.integrity == "ok" and info.assets == 2
    assert re.fullmatch(r"test-\d{8}T\d{6}Z\.db", info.path.name)
    assert _snapshot(info.path) == _snapshot(isolated_database)
    assert not list(info.path.parent.glob("*.partial"))


def test_backup_refuses_missing_database(tmp_path):
    with pytest.raises(maintenance.MaintenanceError, match="does not exist"):
        maintenance.backup(db_path=tmp_path / "nope.db", output_dir=tmp_path / "out")


@pytest.mark.sqlite_only
def test_restore_into_isolated_target_keeps_records_intact(make_asset, isolated_database, tmp_path, client):
    make_asset(name="keep-me", ip_address="10.9.9.9", tags=["dmz", "pci"])
    original = _snapshot(isolated_database)
    info = maintenance.backup()

    target = tmp_path / "restore-test" / "restored.db"
    result = maintenance.restore(info.path, target)
    assert result["assets"] == 1 and result["safety_copy"] is None
    assert _snapshot(target) == original
    assert _snapshot(isolated_database) == original          # active database untouched

    # The restored file works as a database for the application.
    database.configure(target)
    assert client.get("/assets?q=keep-me").json()["total"] == 1


@pytest.mark.sqlite_only
def test_restore_never_overwrites_silently(isolated_database, tmp_path, app):
    body = {"asset_type": "server", "environment": "test", "criticality": "low"}
    database.init_models()                                   # schema + a user, without starting the app
    with next(database.get_session()) as s:
        create_user(s, SYSTEM, "operator", TEST_PASSWORD, Role.ANALYST)
    with TestClient(app) as c:                               # application running
        login(c, "operator")
        c.post("/assets", json={"name": "v1", **body})
        backup_v1 = maintenance.backup().path
        c.post("/assets", json={"name": "v2", **body})
        before = _snapshot(isolated_database)

        with pytest.raises(maintenance.MaintenanceError, match="already exists"):
            maintenance.restore(backup_v1, isolated_database)
        assert _snapshot(isolated_database) == before
        with pytest.raises(maintenance.MaintenanceError, match="same file"):
            maintenance.restore(backup_v1, backup_v1, force=True)
    # application stopped (lifespan shutdown disposed all connections)

    result = maintenance.restore(backup_v1, isolated_database, force=True)
    assert result["assets"] == 1
    safety = Path(result["safety_copy"])
    assert safety.exists() and _snapshot(safety) == before   # previous state kept


def test_corrupt_or_foreign_backups_are_rejected(tmp_path):
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not a database" * 100)
    with pytest.raises(maintenance.MaintenanceError, match="not a readable SQLite database"):
        maintenance.restore(junk, tmp_path / "t.db")
    import sqlite3
    foreign = tmp_path / "foreign.db"
    sqlite3.connect(foreign).execute("CREATE TABLE x (id INTEGER)").connection.close()
    with pytest.raises(maintenance.MaintenanceError, match="not a CyberAsset Guard database"):
        maintenance.restore(foreign, tmp_path / "t.db")
    assert not (tmp_path / "t.db").exists()


@pytest.mark.sqlite_only
def test_maintenance_cli(make_asset, tmp_path, capsys):
    make_asset()
    assert maintenance.main(["check"]) == 0
    assert maintenance.main(["backup"]) == 0
    backup_file = next((tmp_path / "backups").glob("*.db"))
    assert maintenance.main(["verify", str(backup_file)]) == 0
    assert maintenance.main(["restore", str(backup_file), "--target", str(tmp_path / "r.db")]) == 0
    assert maintenance.main(["restore", str(backup_file), "--target", str(tmp_path / "r.db")]) == 1
    out = capsys.readouterr()
    assert "backup written" in out.out and "restored 1 assets" in out.out
    assert "already exists" in out.err


# 11. test isolation ---------------------------------------------------------------------------

def test_tests_never_use_the_development_database(client, isolated_database, tmp_path):
    dev_db = config.BASE_DIR / "cyberasset_guard.db"
    before = dev_db.stat().st_mtime_ns if dev_db.exists() else None
    client.post("/assets", json={"name": "iso", "asset_type": "other", "environment": "test",
                                 "criticality": "low"})
    assert isolated_database.is_relative_to(tmp_path)
    assert Path(database.get_engine().url.database) != dev_db
    assert (dev_db.stat().st_mtime_ns if dev_db.exists() else None) == before


# 12. Docker deployment (opt-in: CAG_TEST_DOCKER=1, needs a running Docker engine) ------------------

def _docker(*args: str, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], cwd=ROOT, capture_output=True, text=True,
                          timeout=timeout, check=check)


@pytest.mark.skipif(os.environ.get("CAG_TEST_DOCKER") != "1",
                    reason="set CAG_TEST_DOCKER=1 to run the Docker deployment test")
def test_docker_tls_profile():
    """HTTPS via Caddy: Secure cookie, HSTS, HTTP->HTTPS redirect, app port not published (ASSET-87)."""
    project, https_port, http_port = f"cagtls{os.getpid()}", str(_free_port()), str(_free_port())
    files = ["-f", "docker-compose.yml", "-f", "docker-compose.tls.yml"]
    env = {**os.environ, "CAG_DOMAIN": "localhost", "CAG_TLS": "internal", "CAG_HTTPS_PORT": https_port,
           "CAG_HTTP_PORT": http_port, "CAG_HTTPS_BIND": "127.0.0.1", "CAG_HTTP_BIND": "127.0.0.1"}
    compose = ["docker", "compose", "-p", project, *files]
    try:
        subprocess.run([*compose, "up", "-d", "--build", "--wait"], cwd=ROOT, env=env, check=True,
                       capture_output=True, text=True, timeout=900)
        created = subprocess.run([*compose, "exec", "-T", "app", "python", "-m", "app.maintenance", "create-user",
                                  "admin", "--role", "admin", "--password-stdin"], cwd=ROOT, env=env,
                                 input=TEST_PASSWORD + "\n", capture_output=True, text=True, timeout=120)
        assert created.returncode == 0, created.stderr
        base = f"https://localhost:{https_port}"
        with httpx.Client(base_url=base, verify=False, timeout=10) as http:     # Caddy internal CA
            assert http.get("/health/ready").status_code == 200
            r = http.post("/auth/login", json={"username": "admin", "password": TEST_PASSWORD},
                          headers={"Origin": base})
            assert r.status_code == 200
            cookie = r.headers["set-cookie"].lower()
            assert "secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie
            assert "max-age=" in r.headers["strict-transport-security"]
            assert "server" not in {k.lower() for k in r.headers}
            assert http.get("/assets").status_code == 200                       # session works over HTTPS
        redirect = httpx.get(f"http://localhost:{http_port}/", follow_redirects=False, timeout=10)
        assert redirect.status_code in (301, 308) and redirect.headers["location"].startswith("https://")
        port = subprocess.run([*compose, "port", "app", "8000"], cwd=ROOT, env=env, capture_output=True, text=True)
        assert port.stdout.strip() in ("", ":0")                               # app not reachable directly
    finally:
        subprocess.run([*compose, "down", "-v"], cwd=ROOT, env=env, capture_output=True,
                       timeout=300)


@pytest.mark.skipif(os.environ.get("CAG_TEST_DOCKER") != "1",
                    reason="set CAG_TEST_DOCKER=1 to run the Docker deployment test")
def test_docker_deployment_persists_data_across_recreation():
    project, port = f"cagtest{os.getpid()}", str(_free_port())
    compose = ["compose", "-p", project]
    env_port = {**os.environ, "CAG_PORT": port}

    def up(*extra):
        subprocess.run(["docker", *compose, "up", "-d", "--build", "--wait", *extra], cwd=ROOT,
                       env=env_port, check=True, capture_output=True, text=True, timeout=900)

    try:
        up()
        base = f"http://127.0.0.1:{port}"
        assert httpx.get(f"{base}/health/ready", timeout=5).status_code == 200
        created = subprocess.run(["docker", *compose, "exec", "-T", "app", "python", "-m", "app.maintenance",
                                  "create-user", "admin", "--role", "admin", "--password-stdin"],
                                 cwd=ROOT, input=TEST_PASSWORD + "\n", capture_output=True, text=True, timeout=120)
        assert created.returncode == 0, created.stderr
        credentials = {"username": "admin", "password": TEST_PASSWORD}
        with httpx.Client(base_url=base, timeout=10) as http:
            assert http.get("/assets").status_code == 401
            assert http.post("/auth/login", json=credentials).status_code == 200
            asset_id = http.post("/assets", json={"name": "in-docker", "asset_type": "container",
                                                  "environment": "staging", "criticality": "medium"}).json()["id"]

        backup = _docker(*compose, "exec", "-T", "app", "python", "-m", "app.maintenance", "backup")
        assert "backup written: /backups/" in backup.stdout

        up("--force-recreate")                                # new container, same volumes
        with httpx.Client(base_url=base, timeout=10) as http:  # users survive as well
            assert http.post("/auth/login", json=credentials).status_code == 200
            r = http.get(f"/assets/{asset_id}")
            assert r.status_code == 200 and r.json()["name"] == "in-docker"
        user = _docker(*compose, "exec", "-T", "app", "id", "-u").stdout.strip()
        assert user == "10001"                                # not root
    finally:
        _docker(*compose, "down", "-v", check=False)


@pytest.mark.skipif(os.environ.get("CAG_TEST_DOCKER") != "1",
                    reason="set CAG_TEST_DOCKER=1 to run the Docker deployment test")
def test_docker_image_includes_nmap_and_scans_as_non_root():
    """nmap ships in the image and the Monitoring scanner runs a version scan from
    inside the compose network, as the unprivileged uid 10001 (ASSET-67)."""
    project, port = f"cagnmap{os.getpid()}", str(_free_port())
    compose = ["compose", "-p", project]
    env_port = {**os.environ, "CAG_PORT": port}
    try:
        subprocess.run(["docker", *compose, "up", "-d", "--build", "--wait"], cwd=ROOT,
                       env=env_port, check=True, capture_output=True, text=True, timeout=900)
        base = f"http://127.0.0.1:{port}"
        assert httpx.get(f"{base}/health/ready", timeout=5).status_code == 200

        # nmap is installed and runs as the unprivileged runtime user (no root).
        version = _docker(*compose, "exec", "-T", "app", "nmap", "--version")
        assert "Nmap version" in version.stdout, version.stderr or version.stdout
        assert _docker(*compose, "exec", "-T", "app", "id", "-u").stdout.strip() == "10001"

        # A real version scan of the app's own HTTP service (127.0.0.1 is in the
        # default allow-list) through the Monitoring scanner — the full -sT -sV path.
        probe = (
            "from app.monitoring import scanner;"
            "r = scanner.version_scan('127.0.0.1', '8000');"
            "p = [pr for h in r.hosts for pr in h.ports if pr.port == 8000];"
            "print('OPEN' if p and p[0].state.startswith('open') else 'CLOSED')"
        )
        scan = _docker(*compose, "exec", "-T", "app", "python", "-c", probe)
        assert "OPEN" in scan.stdout, scan.stderr or scan.stdout
    finally:
        _docker(*compose, "down", "-v", check=False)
