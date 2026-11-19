"""
CYBERSHIELD AI
Expert System for Scam and Phishing Detection

Desktop application: authentication, dashboard, website detector, and
message detector, all connected to the existing rule-based expert system.
"""

from gui.authentication import CyberShieldApp


def main() -> None:
    app = CyberShieldApp()
    app.mainloop()


if __name__ == "__main__":
    main()
