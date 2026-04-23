#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RPC_URL = "http://127.0.0.1:8545"
TRAP_URL = "http://127.0.0.1:8123"
DASHBOARD_URL = "http://127.0.0.1:9123"


def rpc_ready():
    payload = json.dumps({"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1}).encode()
    request = urllib.request.Request(RPC_URL, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=1) as response:
            return response.status == 200
    except Exception:
        return False


def wait_for(predicate, label, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for {label}")


def run(command, **kwargs):
    print(f"[run] {' '.join(command)}")
    completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, **kwargs)
    if completed.returncode != 0:
        print(completed.stdout)
        print(completed.stderr, file=sys.stderr)
        raise RuntimeError(f"Command failed: {' '.join(command)}")
    return completed.stdout


def open_url(base_url, path, data=None, headers=None, expected_status=None):
    request_data = None
    if data is not None:
        request_data = urllib.parse.urlencode(data).encode()
    request = urllib.request.Request(base_url + path, data=request_data, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode()
            status = response.status
    except urllib.error.HTTPError as error:
        body = error.read().decode()
        status = error.code
    if expected_status and status != expected_status:
        raise RuntimeError(f"{path} returned {status}, expected {expected_status}")
    return status, body


def main():
    ganache = None
    app = None
    db_path = Path(tempfile.gettempdir()) / f"honeypot-test-{os.getpid()}.db"

    try:
        if not rpc_ready():
            print("[start] Ganache")
            ganache = subprocess.Popen(
                ["npm", "run", "blockchain:ganache"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            wait_for(rpc_ready, "Ganache RPC", timeout=30)
        else:
            print("[ok] Ganache already running")

        run(["npm", "run", "blockchain:deploy"])

        env = os.environ.copy()
        env["HONEYPOT_DB_PATH"] = str(db_path)
        print("[start] Honeypot trap/dashboard app on ports 8123 and 9123")
        app = subprocess.Popen(
            ["python3", "app.py", "--trap-port", "8123", "--dashboard-port", "9123"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_for(lambda: open_url(TRAP_URL, "/", expected_status=200), "trap server", timeout=20)
        wait_for(lambda: open_url(DASHBOARD_URL, "/dashboard", expected_status=200), "dashboard server", timeout=20)

        open_url(TRAP_URL, "/admin", expected_status=200)
        open_url(
            TRAP_URL,
            "/admin",
            data={"username": "admin", "password": "SuperSecret123"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            expected_status=401,
        )
        open_url(TRAP_URL, "/api/internal/config", expected_status=503)

        open_url(TRAP_URL, "/dashboard", expected_status=404)
        open_url(DASHBOARD_URL, "/admin", expected_status=404)

        _, events_body = open_url(DASHBOARD_URL, "/api/events", expected_status=200)
        events = json.loads(events_body)
        event_count = len(events["events"])
        anchored = sum(1 for event in events["events"] if event["blockchain_status"] == "anchored")
        if event_count < 3:
            raise RuntimeError(f"Expected at least 3 events, got {event_count}")
        if anchored < 3:
            raise RuntimeError(f"Expected at least 3 anchored events, got {anchored}")
        if "Verified 3 event(s)" not in events["integrity"]:
            raise RuntimeError(f"Unexpected integrity status: {events['integrity']}")

        status_output = run(["npm", "run", "blockchain:status"])
        status = json.loads(status_output[status_output.index("{") :])
        if int(status["eventCount"]) < anchored:
            raise RuntimeError("Blockchain event count is lower than anchored local events")

        print("[pass] Full system test passed")
        print(f"[pass] Events recorded: {event_count}")
        print(f"[pass] Blockchain anchored: {anchored}")
        print(f"[pass] Contract: {status['contractAddress']}")
    finally:
        if app:
            app.terminate()
            app.wait(timeout=5)
        if ganache:
            ganache.terminate()
            ganache.wait(timeout=5)
        if db_path.exists():
            db_path.unlink()


if __name__ == "__main__":
    main()
