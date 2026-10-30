import os
import sys
import json
import base64
import time
import threading
import tempfile
import urllib.request
from pathlib import Path
import websocket

# Set up paths
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "backend"))
import app as flask_module

SCREENSHOTS_DIR = BASE_DIR / "docs" / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
if not Path(CHROME_PATH).exists():
    CHROME_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"


class ServerRunner:
    def __init__(self, port=5000):
        self.port = port
        self.server_thread = None
        self.server = None

    def start(self):
        from werkzeug.serving import make_server
        self.server = make_server("127.0.0.1", self.port, flask_module.app)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        print(f"[+] Flask test server listening on http://127.0.0.1:{self.port}")

        # Wait until responding
        for _ in range(15):
            try:
                res = urllib.request.urlopen(f"http://127.0.0.1:{self.port}/api/auth/status", timeout=1)
                if res.status == 200:
                    print("[+] Backend healthcheck verified!")
                    return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError("Flask backend failed to respond within timeout.")

    def stop(self):
        if self.server:
            self.server.shutdown()
            print("[+] Flask test server stopped.")


class CDPBrowser:
    def __init__(self, port=9230):
        self.port = port
        self.proc = None
        self.ws = None
        self.msg_id = 0
        self.tmp_dir = None

    def launch(self, width=1440, height=900):
        self.tmp_dir = tempfile.mkdtemp()
        import subprocess
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
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2.5)

        for _ in range(15):
            try:
                req = urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/list", timeout=2)
                tabs = json.loads(req.read().decode())
                pages = [t for t in tabs if t.get("type") == "page"]
                if pages:
                    ws_url = pages[0]["webSocketDebuggerUrl"]
                    self.ws = websocket.create_connection(ws_url, timeout=15)
                    print(f"[+] Chrome CDP connected ({width}x{height})")
                    return
            except Exception:
                time.sleep(0.8)
        raise RuntimeError("Failed to connect to Chrome CDP.")

    def send_cmd(self, method, params=None):
        self.msg_id += 1
        msg = {"id": self.msg_id, "method": method, "params": params or {}}
        self.ws.send(json.dumps(msg))
        while True:
            raw = self.ws.recv()
            resp = json.loads(raw)
            if "id" in resp and resp["id"] == self.msg_id:
                if "error" in resp:
                    raise RuntimeError(f"CDP Error ({method}): {resp['error']}")
                return resp.get("result", {})

    def evaluate(self, js):
        res = self.send_cmd("Runtime.evaluate", {
            "expression": js,
            "awaitPromise": True,
            "returnByValue": True
        })
        return res.get("result", {}).get("value")

    def resize(self, width, height):
        self.send_cmd("Emulation.setDeviceMetricsOverride", {
            "width": width,
            "height": height,
            "deviceScaleFactor": 1,
            "mobile": width <= 768
        })
        time.sleep(0.5)

    def screenshot(self, filename):
        path = SCREENSHOTS_DIR / filename
        res = self.send_cmd("Page.captureScreenshot", {"format": "png"})
        data = base64.b64decode(res["data"])
        with open(path, "wb") as f:
            f.write(data)
        print(f"[+] Saved screenshot: {filename} ({len(data)} bytes)")

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


def run_full_suite():
    server = ServerRunner(port=5000)
    server.start()
    browser = CDPBrowser(port=9230)
    results = {"assertions": [], "screenshots": []}

    try:
        browser.launch(width=1440, height=900)
        time.sleep(2)

        # ── Test 1: Login Screen & Visual Restraint ───────────
        print("\n--- Testing Login View ---")
        login_display = browser.evaluate("window.getComputedStyle(document.getElementById('login-page')).display")
        app_display = browser.evaluate("window.getComputedStyle(document.getElementById('app-shell')).display")
        print(f"Login display: {login_display}, App-shell display: {app_display}")
        assert login_display != "none", "Login page should be visible initially"
        assert app_display == "none", "App shell should be hidden before login"
        results["assertions"].append("Initial auth gating: PASS")

        # Capture Login screenshot
        browser.screenshot("01_login_view.png")
        results["screenshots"].append("01_login_view.png")

        # ── Test 2: Authenticate ──────────────────────────────
        print("\n--- Authenticating Session ---")
        browser.evaluate("window.Auth.fillDemoCredentials();")
        time.sleep(0.5)
        browser.evaluate("document.getElementById('login-submit-btn').click();")
        time.sleep(3)

        user_info = browser.evaluate("window.Auth.getCurrentUser();")
        print(f"Authenticated user: {user_info}")
        assert user_info is not None, "User should be authenticated"
        results["assertions"].append("Authentication flow: PASS")

        # ── Test 3: SVG Size Bounds Check ─────────────────────
        print("\n--- Testing SVG Sizing Constraints ---")
        svg_stats = browser.evaluate("""
            (() => {
                const svgs = Array.from(document.querySelectorAll('svg'));
                return svgs.map(s => {
                    const rect = s.getBoundingClientRect();
                    return {
                        cls: s.className.baseVal || '',
                        width: Math.round(rect.width),
                        height: Math.round(rect.height)
                    };
                });
            })()
        """)
        oversized = [s for s in svg_stats if s['width'] > 48 or s['height'] > 48]
        print(f"Total SVGs verified: {len(svg_stats)}")
        for s in svg_stats:
            print(f"  SVG [{s['cls']}]: {s['width']}x{s['height']}px")
        assert len(oversized) == 0, f"Found oversized SVGs: {oversized}"
        results["assertions"].append(f"SVG bounds constraint ({len(svg_stats)} SVGs <= 48px): PASS")

        # ── Test 4: Navigation Links Styling (No Blue / Underline)
        print("\n--- Testing Sidebar Navigation Styling ---")
        nav_stats = browser.evaluate("""
            (() => {
                const links = Array.from(document.querySelectorAll('.sidebar-nav .nav-link'));
                return links.map(l => {
                    const style = window.getComputedStyle(l);
                    return {
                        text: l.innerText.trim(),
                        color: style.color,
                        textDecoration: style.textDecorationLine
                    };
                });
            })()
        """)
        for n in nav_stats:
            print(f"  Nav item '{n['text']}': color={n['color']}, decoration={n['textDecoration']}")
            assert n['textDecoration'] == 'none', f"Link {n['text']} has underline: {n['textDecoration']}"
            assert n['color'] != 'rgb(0, 0, 238)', f"Link {n['text']} has default blue link color"
        results["assertions"].append(f"Navigation styling ({len(nav_stats)} links cleanly styled): PASS")

        # ── Test 5: Single View Visibility ────────────────────
        print("\n--- Testing Single View Visibility ---")
        view_states = browser.evaluate("""
            (() => {
                const panels = Array.from(document.querySelectorAll('.view-panel'));
                return panels.map(p => ({
                    id: p.id,
                    display: window.getComputedStyle(p).display
                }));
            })()
        """)
        print("View panel states:", view_states)
        active_panels = [p for p in view_states if p['display'] != 'none']
        assert len(active_panels) == 1, f"Expected exactly 1 active view panel, got {len(active_panels)}: {active_panels}"
        assert active_panels[0]['id'] == 'view-overview', "Default view must be overview"
        results["assertions"].append("Single view visibility: PASS")

        # ── Test 6: Modals Overlay & Initial Hidden State ─────
        print("\n--- Testing Modal Visibility ---")
        modal_states = browser.evaluate("""
            (() => {
                const modals = Array.from(document.querySelectorAll('.modal'));
                return modals.map(m => ({
                    id: m.id,
                    display: window.getComputedStyle(m).display
                }));
            })()
        """)
        print("Modal states:", modal_states)
        for m in modal_states:
            assert m['display'] == 'none', f"Modal {m['id']} should be hidden initially"
        results["assertions"].append("Modal overlays initially hidden: PASS")

        # ── Test 7: Seed Simulation Data & Capture Overview ───
        print("\n--- Seeding Telemetry Simulations ---")
        browser.evaluate("window.Dashboard.triggerSimulation('Brute Force Credential Spray', 85, 'high_velocity_login');")
        time.sleep(1)
        browser.evaluate("window.Dashboard.triggerSimulation('Credential Stuffing Bot', 65, 'automated_stuffing');")
        time.sleep(1)
        browser.evaluate("window.Dashboard.triggerSimulation('Suspicious Geolocation Travel', 35, 'geographic_velocity');")
        time.sleep(2)

        # Overview screenshot
        browser.screenshot("02_dashboard_overview.png")
        results["screenshots"].append("02_dashboard_overview.png")

        # ── Test 8: Incidents View & Table Pagination ──────────
        print("\n--- Switching to Incidents Table ---")
        browser.evaluate("switchView('incidents');")
        time.sleep(1.5)
        incidents_view_display = browser.evaluate("window.getComputedStyle(document.getElementById('view-incidents')).display")
        overview_view_display = browser.evaluate("window.getComputedStyle(document.getElementById('view-overview')).display")
        assert incidents_view_display != "none", "Incidents view should be visible"
        assert overview_view_display == "none", "Overview view should now be hidden"

        table_rows = browser.evaluate("document.querySelectorAll('#incidents-tbody tr').length")
        print(f"Table rendered rows: {table_rows}")
        assert table_rows > 0, "Incident table should render seeded incident rows"
        browser.screenshot("03_incidents_table.png")
        results["screenshots"].append("03_incidents_table.png")
        results["assertions"].append(f"Incidents table view ({table_rows} rows): PASS")

        # ── Test 9: Incident Detail Modal ─────────────────────
        print("\n--- Opening Incident Detail Modal ---")
        browser.evaluate("document.querySelector('.view-detail-trigger').click();")
        time.sleep(1.5)
        modal_display = browser.evaluate("window.getComputedStyle(document.getElementById('incident-modal')).display")
        print(f"Detail modal display: {modal_display}")
        assert modal_display == "flex" or modal_display == "block", f"Modal should be visible, got {modal_display}"
        browser.screenshot("04_incident_detail_modal.png")
        results["screenshots"].append("04_incident_detail_modal.png")
        results["assertions"].append("Incident detail modal overlay: PASS")

        # Close modal
        browser.evaluate("window.UI.closeModal('incident-modal');")
        time.sleep(0.5)

        # ── Test 10: Multi-Viewport Responsive Verification ───
        print("\n--- Testing Viewport Responsiveness ---")
        viewports = [
            ("Desktop 1920", 1920, 1080),
            ("Desktop 1440", 1440, 900),
            ("Tablet 768", 768, 1024),
            ("Mobile 390", 390, 844)
        ]

        browser.evaluate("switchView('overview');")
        time.sleep(1)

        for name, w, h in viewports:
            browser.resize(w, h)
            time.sleep(0.8)
            overflow = browser.evaluate("""
                (() => {
                    const docW = document.documentElement.scrollWidth;
                    const winW = window.innerWidth;
                    return { docW, winW, hasHScroll: docW > winW };
                })()
            """)
            print(f"  Viewport {name} ({w}x{h}): scrollWidth={overflow['docW']}, innerWidth={overflow['winW']}, hasHScroll={overflow['hasHScroll']}")
            assert not overflow['hasHScroll'], f"Horizontal overflow detected on {name}: {overflow}"
            results["assertions"].append(f"Responsive layout on {name} (no horizontal overflow): PASS")

        # Capture Mobile Layout
        browser.resize(390, 844)
        time.sleep(1)
        browser.screenshot("05_mobile_layout.png")
        results["screenshots"].append("05_mobile_layout.png")

        print("\n========================================")
        print("ALL REAL-BROWSER ASSERTIONS PASSED (10/10)")
        print(f"Generated {len(results['screenshots'])} evidence screenshots in docs/screenshots/")
        print("========================================")

    finally:
        browser.close()
        server.stop()


if __name__ == "__main__":
    run_full_suite()
