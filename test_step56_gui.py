"""
Steps 5–6 checks: authentication, dashboard, both detectors, single-window navigation.
Run: python test_step56_gui.py
"""

from __future__ import annotations

import time
import uuid

from database.database import authenticate_user, initialize_database, register_user
from expert_system.expert_system import CyberShieldExpertSystem
from gui.authentication import CyberShieldApp
from gui.message_detector import _on_analyze as analyze_message_gui
from gui.message_detector import validate_message
from gui.website_detector import _on_analyze as analyze_url_gui
from gui.website_detector import validate_website_url


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


def extra_windows(app) -> list:
    extras = []

    def walk(node) -> None:
        for child in node.winfo_children():
            cls = child.winfo_class()
            if cls in ("Toplevel", "CTkToplevel"):
                extras.append(child)
            walk(child)

    walk(app)
    return extras


def fill_message(app, text: str) -> None:
    app._message_box.delete("1.0", "end")
    app._message_box.insert("1.0", text)


def main() -> None:
    expert = CyberShieldExpertSystem()
    username = f"step6_{uuid.uuid4().hex[:8]}"
    password = "Step6Pass!"

    initialize_database()

    ok, msg = register_user(username, password)
    check(ok, f"AUTH 1 register new user ({msg})")

    ok, msg = authenticate_user(username, password)
    check(ok, f"AUTH 2 correct credentials ({msg})")

    ok, msg = authenticate_user(username, "wrong-password")
    check(not ok, f"AUTH 3 wrong credentials ({msg})")

    check(validate_website_url("") == "Please enter a website URL.", "WEB 9 empty URL")
    check(validate_website_url("not a url") == "Please enter a valid website URL.", "WEB 10 invalid URL")
    check(validate_message("") == "Please enter a message to analyze.", "MSG empty validation")
    check(validate_message("   ") == "Please enter a message to analyze.", "MSG whitespace validation")

    r1 = expert.analyze_url("https://www.example.com")
    check(r1["risk_level"] == "LOW", f"WEB 5 LOW ({r1['risk_level']}, score {r1['score']})")

    r2 = expert.analyze_url("http://example.com/login")
    check("URL does not use HTTPS" in r2["triggered_rules"], f"WEB 6 HTTP rule ({r2['triggered_rules']})")

    r3 = expert.analyze_url("http://192.168.1.10/login")
    check("URL contains an IP address" in r3["triggered_rules"], f"WEB 7 IP rule ({r3['triggered_rules']})")

    r4 = expert.analyze_url("http://example.com/verify-account-login")
    check("Suspicious keyword detected" in r4["triggered_rules"], f"WEB 8 keyword ({r4['triggered_rules']})")

    m11 = expert.analyze_message("Hi, are we meeting at 5 PM today?")
    check(m11["risk_level"] == "LOW", f"MSG 11 LOW ({m11['risk_level']}, score {m11['score']})")

    m12 = expert.analyze_message(
        "Congratulations! You have won a ₹50,000 prize. Click the link to claim your reward."
    )
    check("Prize or reward language detected" in m12["triggered_rules"], f"MSG 12 prize ({m12['triggered_rules']})")
    check("Suspicious link detected" in m12["triggered_rules"], f"MSG 12 link ({m12['triggered_rules']})")

    m13 = expert.analyze_message(
        "URGENT! Your bank account will be blocked today. Verify your account immediately."
    )
    check("Urgent language detected" in m13["triggered_rules"], f"MSG 13 urgent ({m13['triggered_rules']})")
    check("Threat or fear language detected" in m13["triggered_rules"], f"MSG 13 threat ({m13['triggered_rules']})")
    check("Banking context detected" in m13["triggered_rules"], f"MSG 13 banking ({m13['triggered_rules']})")

    m14 = expert.analyze_message(
        "Your account needs verification. Send the OTP and password immediately."
    )
    check("OTP request detected" in m14["triggered_rules"], f"MSG 14 OTP ({m14['triggered_rules']})")
    check("Password request detected" in m14["triggered_rules"], f"MSG 14 password ({m14['triggered_rules']})")
    check("Urgent language detected" in m14["triggered_rules"], f"MSG 14 urgency ({m14['triggered_rules']})")

    m15 = expert.analyze_message("Pay ₹5,000 immediately to avoid account suspension.")
    check("Payment request detected" in m15["triggered_rules"], f"MSG 15 payment ({m15['triggered_rules']})")
    check("Urgent language detected" in m15["triggered_rules"], f"MSG 15 urgency ({m15['triggered_rules']})")
    check("Threat or fear language detected" in m15["triggered_rules"], f"MSG 15 threat ({m15['triggered_rules']})")

    app = CyberShieldApp()
    app.update()
    try:
        wait_idle(app)
        login = collect_texts(app.screen_host)
        check("Login" in login, "Starts on login")

        app._username_entry.insert(0, username)
        app._password_entry.insert(0, "wrong-password")
        app._on_login()
        wait_idle(app)
        check("Incorrect username or password." in (app._status_label.cget("text") if app._status_label else ""), "GUI wrong login")
        check(app.current_user is None, "Failed login does not open a session")

        app._password_entry.delete(0, "end")
        app._password_entry.insert(0, password)
        app._on_login()
        wait_idle(app)
        dashboard = collect_texts(app.screen_host)
        check("CYBERSHIELD AI" in dashboard, "NAV 16 dashboard title")
        check("Expert System for Scam and Phishing Detection" in dashboard, "Dashboard subtitle")
        check("Website Scam Detector" in dashboard, "Dashboard website card")
        check("Scam Message Detector" in dashboard, "Dashboard message card")
        check("Logout" in dashboard, "Dashboard logout")
        check(len(extra_windows(app)) == 0, "No extra windows after login")

        app._open_website_detector()
        wait_idle(app)
        web = collect_texts(app.screen_host)
        check("Website Scam Detector" in web, "NAV 17 website detector")
        check("Analyze Website" in web, "Website analyze button")
        check("Back to Dashboard" in web, "Website back button")

        app._url_entry.delete(0, "end")
        analyze_url_gui(app)
        wait_idle(app, 120)
        check(app._status_label.cget("text") == "Please enter a website URL.", "GUI empty URL")

        app._url_entry.insert(0, "not-a-valid-url")
        analyze_url_gui(app)
        wait_idle(app, 120)
        check(app._status_label.cget("text") == "Please enter a valid website URL.", "GUI invalid URL")

        app._url_entry.delete(0, "end")
        app._url_entry.insert(0, "https://www.example.com")
        analyze_url_gui(app)
        wait_idle(app, 250)
        result_text = collect_texts(app.screen_host)
        check("RISK SCORE" in result_text and "LOW" in result_text, "Website result from expert system")
        check("TRIGGERED RULES" in result_text and "RECOMMENDATION" in result_text, "Website result sections")

        app.return_to_dashboard()
        wait_idle(app)
        back = collect_texts(app.screen_host)
        check("Logout" in back and "Scam Message Detector" in back, "NAV 18 back from website")

        app._open_message_detector()
        wait_idle(app)
        msg_screen = collect_texts(app.screen_host)
        check("Scam Message Detector" in msg_screen, "NAV 19 message detector")
        check("Analyze a message using rule-based expert system detection." in msg_screen, "Message description")
        check("Analyze Message" in msg_screen, "Analyze Message button")
        check("Back to Dashboard" in msg_screen, "Message back button")

        fill_message(app, "")
        analyze_message_gui(app)
        wait_idle(app, 120)
        check(app._status_label.cget("text") == "Please enter a message to analyze.", "GUI empty message")

        fill_message(app, "Hi, are we meeting at 5 PM today?")
        analyze_message_gui(app)
        wait_idle(app, 250)
        normal = collect_texts(app.screen_host)
        check("LOW" in normal, "GUI normal message LOW")
        check("Likely Safe" in normal, "GUI normal decision")

        fill_message(app, "Your account needs verification. Send the OTP and password immediately.")
        analyze_message_gui(app)
        wait_idle(app, 250)
        otp = collect_texts(app.screen_host)
        check("OTP request detected" in otp, "GUI OTP rule displayed")
        check("Password request detected" in otp, "GUI password rule displayed")
        check("REASONING" in otp and "RECOMMENDATION" in otp, "GUI message result sections")

        app.return_to_dashboard()
        wait_idle(app)
        dash2 = collect_texts(app.screen_host)
        check("Website Scam Detector" in dash2, "NAV 20 back from message")

        for _ in range(3):
            app._open_website_detector()
            wait_idle(app)
            app.return_to_dashboard()
            wait_idle(app)
            app._open_message_detector()
            wait_idle(app)
            app.return_to_dashboard()
            wait_idle(app)
        check(len(extra_windows(app)) == 0, "NAV 22 no duplicate windows after repeated navigation")

        app._on_logout()
        wait_idle(app)
        after_logout = collect_texts(app.screen_host)
        check("Login" in after_logout, "NAV 21 logout returns to login")
        check(app.current_user is None, "AUTH 4 logout clears session")
        check(app._username_entry.get() == "", "Logout clears username field")
        check(app._password_entry.get() == "", "Logout clears password field")
    finally:
        app.destroy()

    print("\nAll Step 5–6 checks passed.")


if __name__ == "__main__":
    main()
