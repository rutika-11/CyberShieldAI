"""
Step 4 checks: URL validation, expert-system results, and GUI navigation.
Run: python test_step4_gui.py
"""

from __future__ import annotations

import time

from database.database import authenticate_user, initialize_database, register_user
from expert_system.expert_system import CyberShieldExpertSystem
from gui.authentication import CyberShieldApp
from gui.website_detector import validate_website_url, _on_analyze


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"CHECK OK: {message}")


def collect_texts(widget) -> str:
    parts: list[str] = []

    def walk(node) -> None:
        try:
            text = node.cget("text")
        except Exception:
            text = ""
        if text:
            parts.append(str(text))
        for child in node.winfo_children():
            walk(child)

    walk(widget)
    return "\n".join(parts)


def wait_idle(app: CyberShieldApp, ms: int = 80) -> None:
    app.update()
    app.update_idletasks()
    deadline = time.time() + (ms / 1000)
    while time.time() < deadline:
        app.update()
        time.sleep(0.01)


def main() -> None:
    expert = CyberShieldExpertSystem()

    check(validate_website_url("") == "Please enter a website URL.", "Empty URL validation")
    check(validate_website_url("   ") == "Please enter a website URL.", "Whitespace-only URL validation")
    check(
        validate_website_url("not a url") == "Please enter a valid website URL.",
        "Invalid URL validation",
    )
    check(validate_website_url("https://example.com") is None, "Accept https://example.com")
    check(validate_website_url("http://example.com/login") is None, "Accept http login URL")
    check(
        validate_website_url("https://www.example.com/account") is None,
        "Accept https www account URL",
    )
    check(validate_website_url("http://192.168.1.10/login") is None, "Accept IP URL")

    r1 = expert.analyze_url("https://www.example.com")
    check(r1["risk_level"] == "LOW", f"TEST 1 risk level LOW (got {r1['risk_level']}, score {r1['score']})")
    check(r1["score"] <= 24, f"TEST 1 relatively low score ({r1['score']})")

    r2 = expert.analyze_url("http://example.com/login")
    check("URL does not use HTTPS" in r2["triggered_rules"], f"TEST 2 HTTP rule ({r2['triggered_rules']})")

    r3 = expert.analyze_url("http://192.168.1.10/login")
    check("URL contains an IP address" in r3["triggered_rules"], f"TEST 3 IP rule ({r3['triggered_rules']})")

    r4 = expert.analyze_url("http://example.com/verify-account-login")
    check(
        "Suspicious keyword detected" in r4["triggered_rules"],
        f"TEST 4 keyword rule ({r4['triggered_rules']})",
    )

    initialize_database()
    register_user("step4tester", "Step4Pass!")  # duplicate username is ignored for this check
    ok, _msg = authenticate_user("step4tester", "Step4Pass!")
    check(ok, "Database login still works")

    app = CyberShieldApp()
    app.update()
    try:
        app.show_login()
        wait_idle(app)
        check(app._username_entry is not None, "Login screen has username field")

        app._username_entry.insert(0, "step4tester")
        app._password_entry.insert(0, "Step4Pass!")
        app._on_login()
        wait_idle(app)
        dashboard = collect_texts(app.screen_host)
        check("Website Scam Detector" in dashboard, "Dashboard shows Website Scam Detector")
        check("Scam Message Detector" in dashboard, "Dashboard shows Scam Message Detector")
        check("Logout" in dashboard, "Dashboard shows Logout")

        app._open_website_detector()
        wait_idle(app)
        detector = collect_texts(app.screen_host)
        check("Website Scam Detector" in detector, "Detector screen title")
        check("Analyze a website URL using rule-based expert system detection." in detector, "Detector description")
        check(app._url_entry is not None, "URL entry exists")

        app._url_entry.delete(0, "end")
        _on_analyze(app)
        wait_idle(app, 120)
        check(app._status_label.cget("text") == "Please enter a website URL.", "TEST 5 empty input in GUI")

        app._url_entry.delete(0, "end")
        app._url_entry.insert(0, "not-a-valid-url")
        _on_analyze(app)
        wait_idle(app, 120)
        check(app._status_label.cget("text") == "Please enter a valid website URL.", "TEST 6 invalid URL in GUI")

        app._url_entry.delete(0, "end")
        app._url_entry.insert(0, "https://www.example.com")
        _on_analyze(app)
        wait_idle(app, 250)
        result_text = collect_texts(app.screen_host)
        check("RISK SCORE" in result_text, "Score label shown")
        check("LOW" in result_text, "LOW risk shown for example.com")
        check("Likely Safe" in result_text, "Decision shown")
        check("RECOMMENDATION" in result_text, "Recommendation section shown")
        check("REASONING" in result_text, "Reasoning section shown")
        check("TRIGGERED RULES" in result_text, "Triggered rules section shown")

        from gui.website_detector import _back_to_dashboard

        _back_to_dashboard(app)
        wait_idle(app)
        back = collect_texts(app.screen_host)
        check("Website Scam Detector" in back and "Logout" in back, "TEST 7 back to dashboard")

        app._on_logout()
        wait_idle(app)
        login = collect_texts(app.screen_host)
        check("Login" in login, "TEST 8 logout returns to login")
        check(app.current_user is None, "Logout clears current user")
    finally:
        app.destroy()

    print("\nAll Step 4 checks passed.")


if __name__ == "__main__":
    main()
