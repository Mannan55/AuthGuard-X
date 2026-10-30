import os
import sys
import json
import base64
import time
import subprocess
import tempfile
import urllib.request
from pathlib import Path
import websocket

BASE_DIR = Path(__file__).resolve().parent.parent
SCREENSHOTS_DIR = BASE_DIR / "docs" / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
if not Path(CHROME_PATH).exists():
    CHROME_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"


class CDPClient:
    def __init__(self, port=9225):
        self.port = port
        self.proc = None
        self.ws = None
        self.msg_id = 0
        self.tmp_dir = None

    def start_browser(self, width=1440, height=1080):
        self.tmp_dir = tempfile.mkdtemp()
        cmd = [
            CHROME_PATH,
            f"--remote-debugging-port={self.port}",
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            f"--user-data-dir={self.tmp_dir}",
            f"--window-size={width},{height}",
            "http://127.0.0.1:5000/"
        ]
        print(f"[*] Starting headless browser: {' '.join(cmd)}")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2.5)

        for _ in range(12):
            try:
                req = urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/list", timeout=2)
                tabs = json.loads(req.read().decode())
                # Filter specifically for page tab (not extensions or background pages)
                pages = [t for t in tabs if t.get("type") == "page"]
                if pages:
                    ws_url = pages[0]["webSocketDebuggerUrl"]
                    print(f"[+] Connecting WebSocket to page: {ws_url}")
                    self.ws = websocket.create_connection(ws_url, timeout=15)
                    print("[+] WebSocket connected successfully!")
                    return
            except Exception:
                time.sleep(1)
        raise RuntimeError("Failed to connect to browser CDP port.")

    def send_cmd(self, method, params=None):
        self.msg_id += 1
        msg = {"id": self.msg_id, "method": method, "params": params or {}}
        self.ws.send(json.dumps(msg))
        while True:
            raw = self.ws.recv()
            resp = json.loads(raw)
            if "id" in resp and resp["id"] == self.msg_id:
                if "error" in resp:
                    raise RuntimeError(f"CDP Error in {method}: {resp['error']}")
                return resp.get("result", {})

    def evaluate(self, expression):
        res = self.send_cmd("Runtime.evaluate", {
            "expression": expression,
            "awaitPromise": True,
            "returnByValue": True
        })
        return res.get("result", {}).get("value")

    def capture_screenshot(self, filename):
        filepath = SCREENSHOTS_DIR / filename
        res = self.send_cmd("Page.captureScreenshot", {"format": "png"})
        img_data = base64.b64decode(res["data"])
        with open(filepath, "wb") as f:
            f.write(img_data)
        print(f"[+] Screenshot captured: {filepath} ({len(img_data)} bytes)")

    def close(self):
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                self.proc.kill()


def run_evidence_capture():
    # 1. Start Desktop browser session (1440x1080)
    client = CDPClient(port=9225)
    try:
        client.start_browser(width=1440, height=1080)
        time.sleep(2)

        # 1. Capture Login View
        print("[*] Capturing 01_login_view.png...")
        client.capture_screenshot("01_login_view.png")

        # Authenticate
        print("[*] Authenticating with demo credentials...")
        client.evaluate("window.Auth.fillDemoCredentials();")
        time.sleep(0.5)
        client.evaluate("document.getElementById('login-submit-btn').click();")
        time.sleep(2.5)

        # Trigger attack simulations to seed metrics & incidents
        print("[*] Simulating attack vectors...")
        client.evaluate("window.Dashboard.triggerSimulation('Brute Force Credential Spray', 85, 'high_velocity_login');")
        time.sleep(1)
        client.evaluate("window.Dashboard.triggerSimulation('Credential Stuffing Bot', 65, 'automated_stuffing');")
        time.sleep(1)
        client.evaluate("window.Dashboard.triggerSimulation('Suspicious Geolocation Travel', 35, 'geographic_velocity');")
        time.sleep(2)

        # 2. Capture Overview Dashboard
        print("[*] Capturing 02_dashboard_overview.png...")
        client.capture_screenshot("02_dashboard_overview.png")

        # 3. Switch to Incidents Table view
        print("[*] Navigating to Incidents Table view...")
        client.evaluate("switchView('incidents');")
        time.sleep(1.5)
        print("[*] Capturing 03_incidents_table.png...")
        client.capture_screenshot("03_incidents_table.png")

        # 4. Open Incident Detail Modal
        print("[*] Opening Incident Detail modal...")
        client.evaluate("""
            const firstRow = document.querySelector('.view-detail-trigger');
            if (firstRow) firstRow.click();
        """)
        time.sleep(1.5)
        print("[*] Capturing 04_incident_detail_modal.png...")
        client.capture_screenshot("04_incident_detail_modal.png")

        # Close modal
        client.evaluate("window.UI.closeModal('incident-modal');")
        time.sleep(0.5)

    finally:
        client.close()

    # 5. Mobile Layout session (390x844 iPhone-style width)
    print("[*] Starting Mobile Headless session (390x844)...")
    mobile_client = CDPClient(port=9226)
    try:
        mobile_client.start_browser(width=390, height=844)
        time.sleep(2)
        # Login
        mobile_client.evaluate("window.Auth.fillDemoCredentials();")
        time.sleep(0.5)
        mobile_client.evaluate("document.getElementById('login-submit-btn').click();")
        time.sleep(2.5)
        print("[*] Capturing 05_mobile_layout.png...")
        mobile_client.capture_screenshot("05_mobile_layout.png")
    finally:
        mobile_client.close()

    print("[SUCCESS] All Sprint 1 evidence screenshots successfully captured!")


if __name__ == "__main__":
    run_evidence_capture()
