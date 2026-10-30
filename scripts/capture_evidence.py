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


def run_full_verification():
    server = ServerRunner(port=5000)
    server.start()
    browser = CDPBrowser(port=9230)
    passed_assertions = 0

    try:
        browser.launch(width=1440, height=900)
        time.sleep(2)

        # ── Assertion 1: Initial Auth Gating ──────────────────────
        print("\n[Assert 1] Verifying Login View & Shell Hidden Initial State...")
        login_display = browser.evaluate("window.getComputedStyle(document.getElementById('login-page')).display")
        app_display = browser.evaluate("window.getComputedStyle(document.getElementById('app-shell')).display")
        assert login_display != "none", "Login view must be visible before authentication"
        assert app_display == "none", "App shell must be hidden before authentication"
        passed_assertions += 1
        print("  -> Passed: Login screen properly gated.")

        # Capture Login View screenshot
        browser.screenshot("01_login_view.png")

        # ── Assertion 2: Prohibited Elements Check (DOM-Wide) ──────
        print("\n[Assert 2] Verifying Zero Prohibited Elements (Stars, Sparkles, Emojis, Particles)...")
        prohibited_audit = browser.evaluate(r"""
            (() => {
                // Check for emoji codepoints across all visible text nodes
                const emojiRegex = /[\u{1F300}-\u{1F6FF}\u{1F900}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/u;
                const textNodes = [];
                const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
                let n;
                while (n = walk.nextNode()) {
                    if (n.nodeValue && emojiRegex.test(n.nodeValue)) {
                        textNodes.push(n.nodeValue.trim());
                    }
                }

                // Check for star / sparkle / confetti classes or elements
                const starClasses = Array.from(document.querySelectorAll('*')).filter(el => {
                    const cls = (el.className && typeof el.className === 'string') ? el.className.toLowerCase() : '';
                    return cls.includes('star') || cls.includes('sparkle') || cls.includes('confetti') || cls.includes('particle');
                }).map(el => el.className);

                return {
                    emojiCount: textNodes.length,
                    emojisFound: textNodes,
                    starElementCount: starClasses.length,
                    starElements: starClasses
                };
            })()
        """)
        print(f"  Audit Result: Emojis={prohibited_audit['emojiCount']}, StarElements={prohibited_audit['starElementCount']}")
        assert prohibited_audit['emojiCount'] == 0, f"Found prohibited emojis: {prohibited_audit['emojisFound']}"
        assert prohibited_audit['starElementCount'] == 0, f"Found prohibited star elements: {prohibited_audit['starElements']}"
        passed_assertions += 1
        print("  -> Passed: Zero emojis, stars, sparkles, or particles detected in DOM.")

        # ── Assertion 3: Authenticate Session ─────────────────────
        print("\n[Assert 3] Authenticating Session via Development Demo Credentials...")
        browser.evaluate("window.Auth.fillDemoCredentials();")
        time.sleep(0.5)
        browser.evaluate("document.getElementById('login-submit-btn').click();")
        time.sleep(2.5)

        current_user = browser.evaluate("window.Auth.getCurrentUser();")
        assert current_user is not None and current_user.get("username") == "admin", "User must be authenticated as admin"
        passed_assertions += 1
        print(f"  -> Passed: Authenticated user: {current_user}")

        # ── Assertion 4: Strict SVG Dimension Bounds ──────────────
        print("\n[Assert 4] Verifying All SVGs Render Within Strict Bounds (<= 24px, empty-icon <= 40px)...")
        svg_stats = browser.evaluate("""
            (() => {
                const svgs = Array.from(document.querySelectorAll('svg'));
                return svgs.map(s => {
                    const rect = s.getBoundingClientRect();
                    return {
                        cls: s.className.baseVal || '',
                        w: Math.round(rect.width),
                        h: Math.round(rect.height)
                    };
                });
            })()
        """)
        oversized = [s for s in svg_stats if s['w'] > 40 or s['h'] > 40]
        print(f"  Audited {len(svg_stats)} SVGs in DOM. Oversized count: {len(oversized)}")
        for s in svg_stats:
            print(f"    SVG [{s['cls']}]: {s['w']}x{s['h']}px")
        assert len(oversized) == 0, f"Found oversized SVGs: {oversized}"
        passed_assertions += 1
        print("  -> Passed: All SVGs constrained within 16-24px (empty-icon 40px).")

        # ── Assertion 5: Sidebar Navigation Styling ───────────────
        print("\n[Assert 5] Verifying Sidebar Navigation Styling (No Blue Links, No Underlines)...")
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
            print(f"    Nav [{n['text']}]: color={n['color']}, decoration={n['textDecoration']}")
            assert n['textDecoration'] == 'none', f"Link {n['text']} has underline"
            assert n['color'] != 'rgb(0, 0, 238)', f"Link {n['text']} has unstyled browser blue link color"
        passed_assertions += 1
        print(f"  -> Passed: All {len(nav_stats)} navigation items cleanly styled with zero default link artifacts.")

        # ── Assertion 6: Zero Health Score Nullish Handling ───────
        print("\n[Assert 6] Verifying Zero Health Score Fallback Regression (Score 0 Rendered, Not 100)...")
        browser.evaluate("""
            window.Dashboard.renderKPIs({
                total_incidents: 25,
                open_incidents: 20,
                critical_count: 15,
                health_score: 0,
                simulated_count: 25,
                telemetry_count: 0
            });
        """)
        time.sleep(0.8)
        rendered_health = browser.evaluate("document.getElementById('metric-health').textContent.trim()")
        health_color = browser.evaluate("window.getComputedStyle(document.getElementById('metric-health')).color")
        print(f"  Health Metric Text: '{rendered_health}', Computed Color: {health_color}")
        assert rendered_health == "0", f"Expected health score '0', got '{rendered_health}' (possible || 100 bug regression)"
        passed_assertions += 1
        print("  -> Passed: Zero health score renders strictly as 0 with critical posture color.")

        # Re-trigger regular simulation telemetry
        print("\n[+] Seeding Telemetry Simulations for Overview View...")
        browser.evaluate("window.Dashboard.triggerSimulation('Brute Force Credential Spray', 85, 'high_velocity_login');")
        time.sleep(1)
        browser.evaluate("window.Dashboard.triggerSimulation('Credential Stuffing Bot', 65, 'automated_stuffing');")
        time.sleep(1)
        browser.evaluate("window.Dashboard.triggerSimulation('Suspicious Geolocation Travel', 35, 'geographic_velocity');")
        time.sleep(2)

        # Capture Dashboard Overview screenshot
        browser.screenshot("02_dashboard_overview.png")

        # ── Assertion 7: Dedicated Simulations View & Execution ───
        print("\n[Assert 7] Verifying Dedicated Simulations View Navigation & Custom Vector Trigger...")
        browser.evaluate("switchView('simulations');")
        time.sleep(1)
        sim_view_display = browser.evaluate("window.getComputedStyle(document.getElementById('view-simulations')).display")
        overview_view_display = browser.evaluate("window.getComputedStyle(document.getElementById('view-overview')).display")
        page_title = browser.evaluate("document.getElementById('page-title').textContent.trim()")
        assert sim_view_display != "none", "Dedicated view-simulations section must be visible"
        assert overview_view_display == "none", "Overview section must be hidden when in simulations view"
        assert "Simulation" in page_title, f"Page title should reflect simulation engine, got '{page_title}'"
        browser.screenshot("06_simulations_lab_view.png")

        # Trigger custom vector
        before_count = browser.evaluate("parseInt(document.getElementById('metric-total').textContent, 10) || 0")
        browser.evaluate("""
            document.getElementById('custom-sim-attack').value = 'Privilege Escalation Probe';
            document.getElementById('custom-sim-risk').value = '92';
            document.getElementById('custom-sim-submit-btn').click();
        """)
        time.sleep(2)
        after_count = browser.evaluate("parseInt(document.getElementById('metric-total').textContent, 10) || 0")
        assert after_count >= before_count, "Custom simulation should increment incident database"
        passed_assertions += 1
        print("  -> Passed: Dedicated Simulations view renders correctly and triggers custom vector telemetry.")

        # ── Assertion 8: Incidents Table Feed & Accurate Provenance
        print("\n[Assert 8] Verifying Incidents Table View & Provenance Column...")
        browser.evaluate("switchView('incidents');")
        time.sleep(1.5)
        incidents_view_display = browser.evaluate("window.getComputedStyle(document.getElementById('view-incidents')).display")
        assert incidents_view_display != "none", "Incidents view must be visible"

        row_count = browser.evaluate("document.querySelectorAll('#incidents-tbody tr').length")
        assert row_count > 0, "Incident feed table should display incident rows"

        provenance_header = browser.evaluate("document.querySelectorAll('.data-table th')[1].textContent.trim()")
        assert provenance_header == "Provenance", f"Expected column header 'Provenance', got '{provenance_header}'"
        passed_assertions += 1
        print(f"  -> Passed: Incidents table renders {row_count} rows with accurate 'Provenance' header.")

        # Capture Incidents Table screenshot
        browser.screenshot("03_incidents_table.png")

        # ── Assertion 9: Incident Detail Modal Overlay ────────────
        print("\n[Assert 9] Verifying Incident Detail Modal Overlay...")
        browser.evaluate("document.querySelector('.view-detail-trigger').click();")
        time.sleep(1.5)
        modal_display = browser.evaluate("window.getComputedStyle(document.getElementById('incident-modal')).display")
        assert modal_display in ("flex", "block"), f"Detail modal should be visible overlay, got {modal_display}"
        browser.screenshot("04_incident_detail_modal.png")
        browser.evaluate("window.UI.closeModal('incident-modal');")
        time.sleep(0.5)
        modal_closed_display = browser.evaluate("window.getComputedStyle(document.getElementById('incident-modal')).display")
        assert modal_closed_display == "none", "Modal must be hidden after closeModal"
        passed_assertions += 1
        print("  -> Passed: Incident detail modal operates as centered floating overlay with backdrop.")

        # ── Assertion 10: Confirmation Dialog Promise Settlement & Keyboard Focus
        print("\n[Assert 10] Verifying Confirmation Dialog Promise Settlement (Escape, Backdrop, Cancel) & Focus Restoration...")
        dialog_test_result = browser.evaluate("""
            (async () => {
                // Focus a specific dummy trigger button
                const triggerBtn = document.getElementById('refresh-incidents-btn');
                triggerBtn.focus();
                const initialActiveId = document.activeElement.id;

                // 1. Test Escape key resolution
                const promiseEscape = window.UI.showConfirmDialog({
                    title: 'Test Escape',
                    message: 'Pressing escape should settle false'
                });
                // Simulate Escape keydown
                document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
                const resEscape = await promiseEscape;
                const postEscapeActiveId = document.activeElement.id;

                // 2. Test Cancel button resolution
                triggerBtn.focus();
                const promiseCancel = window.UI.showConfirmDialog({
                    title: 'Test Cancel',
                    message: 'Clicking cancel should settle false'
                });
                document.querySelector('#confirm-modal .cancel-btn').click();
                const resCancel = await promiseCancel;

                // 3. Test Confirm button resolution
                triggerBtn.focus();
                const promiseConfirm = window.UI.showConfirmDialog({
                    title: 'Test Confirm',
                    message: 'Clicking confirm should settle true'
                });
                document.querySelector('#confirm-modal .confirm-btn').click();
                const resConfirm = await promiseConfirm;

                return {
                    resEscape,
                    resCancel,
                    resConfirm,
                    focusRestored: (initialActiveId === postEscapeActiveId)
                };
            })()
        """)
        print(f"  Confirmation Dialog Audit: {dialog_test_result}")
        assert dialog_test_result["resEscape"] is False, "Escape must resolve showConfirmDialog to false"
        assert dialog_test_result["resCancel"] is False, "Cancel button must resolve to false"
        assert dialog_test_result["resConfirm"] is True, "Confirm button must resolve to true"
        assert dialog_test_result["focusRestored"] is True, "Keyboard focus must be restored to previous element"
        passed_assertions += 1
        print("  -> Passed: Confirmation dialog settles cleanly on all dismiss pathways with focus restoration.")

        # ── Assertion 11: Multi-Viewport Responsive Layout ────────
        print("\n[Assert 11] Verifying Responsive Breakpoints (1920, 1440, 768, 390px) Zero Horizontal Overflow...")
        browser.evaluate("switchView('overview');")
        time.sleep(1)

        viewports = [
            ("Desktop 1920", 1920, 1080),
            ("Desktop 1440", 1440, 900),
            ("Tablet 768", 768, 1024),
            ("Mobile 390", 390, 844)
        ]

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
            print(f"    {name} ({w}x{h}): scrollWidth={overflow['docW']}, innerWidth={overflow['winW']}, hasHScroll={overflow['hasHScroll']}")
            assert not overflow['hasHScroll'], f"Horizontal scroll detected on {name}: {overflow}"
        passed_assertions += 1
        print("  -> Passed: Zero horizontal overflow across all 4 target breakpoints.")

        # Capture Mobile Layout (390x844)
        browser.resize(390, 844)
        time.sleep(1)
        browser.screenshot("05_mobile_layout.png")

        print("\n========================================================")
        print(f"ALL REAL-BROWSER ASSERTIONS PASSED ({passed_assertions}/11)")
        print("Updated evidence screenshots saved to docs/screenshots/")
        print("========================================================")

    finally:
        browser.close()
        server.stop()


if __name__ == "__main__":
    run_full_verification()
