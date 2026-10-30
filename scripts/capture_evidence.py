import os
import sys
import json
import base64
import time
import subprocess
import urllib.request
from pathlib import Path
import websocket

BASE_DIR = Path(__file__).resolve().parent.parent
SCREENSHOTS_DIR = BASE_DIR / "docs" / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
if not Path(CHROME_PATH).exists():
    CHROME_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

USER_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", "C:/Temp")) / "Temp" / "chrome_cdp_profile"
USER_DATA_DIR.mkdir(parents=True, exist_ok=True)


class CDPClient:
    def __init__(self, port=9222):
        self.port = port
        self.proc = None
        self.ws = None
        self.msg_id = 0

    def start_browser(self):
        cmd = [
            CHROME_PATH,
            f"--remote-debugging-port={self.port}",
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            f"--user-data-dir={USER_DATA_DIR}",
            "--window-size=1440,1080",
            "about:blank"
        ]
        print(f"[*] Starting headless browser: {' '.join(cmd)}")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)

        for _ in range(10):
            try:
                req = urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/list", timeout=2)
                tabs = json.loads(req.read().decode())
                if tabs:
                    ws_url = tabs[0]["webSocketDebuggerUrl"]
                    print(f"[+] Connecting WebSocket to: {ws_url}")
                    self.ws = websocket.create_connection(ws_url, timeout=15)
                    print("[+] WebSocket connected successfully!")
                    return
            except Exception as e:
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
            # else it's an event notification, keep reading

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


def run_flow():
    client = CDPClient()
    try:
        client.start_browser()

        # 1. Navigate to AuthGuard-X Login page
        print("[*] Navigating to http://127.0.0.1:5000/...")
        client.send_cmd("Page.navigate", {"url": "http://127.0.0.1:5000/"})
        time.sleep(2)

        # 1. Capture Login Screen
        client.capture_screenshot("01_login_view.png")

        # 2. Perform Login: fill demo credentials and click login
        print("[*] Autofilling credentials and authenticating...")
        client.evaluate("fillDemo();")
        time.sleep(0.5)
        client.evaluate("login();")
        time.sleep(2)

        # 3. Simulate attacks
        print("[*] Simulating attacks...")
        client.evaluate("simulateAttack('Brute Force Credential Spray', 85, 'high_velocity_login');")
        time.sleep(1)
        client.evaluate("simulateAttack('Credential Stuffing Bot', 65, 'automated_stuffing');")
        time.sleep(1)
        client.evaluate("simulateAttack('Suspicious Geolocation Anomaly', 35, 'anomalous_travel');")
        time.sleep(2)

        # 2. Capture Dashboard Overview
        client.capture_screenshot("02_dashboard_overview.png")

        # 4. Toggle Hacker Mode
        print("[*] Toggling Hacker Mode...")
        client.evaluate("toggleMode();")
        time.sleep(1)
        client.capture_screenshot("03_hacker_mode.png")

        # Toggle back to normal SOC mode
        client.evaluate("toggleMode();")
        time.sleep(0.5)

        # 5. Resolve an incident
        print("[*] Resolving highest risk incident...")
        client.evaluate("""
            const resolveBtn = document.querySelector('.btn-resolve');
            if (resolveBtn) resolveBtn.click();
        """)
        time.sleep(2)
        client.capture_screenshot("04_incident_resolved.png")

        print("[SUCCESS] All 4 evidence screenshots captured successfully!")

    finally:
        client.close()


if __name__ == "__main__":
    run_flow()
