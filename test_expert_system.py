"""
Independent tests for the CYBERSHIELD AI expert system.

This script does not use the GUI. Run:
    python test_expert_system.py
"""

from __future__ import annotations

from expert_system.expert_system import CyberShieldExpertSystem
from expert_system.feature_extractor import extract_message_features, extract_url_features
from expert_system.risk_engine import calculate_risk_score, get_risk_level


def print_result(title: str, result: dict) -> None:
    print("=" * 72)
    print(title)
    print("-" * 72)
    print(f"Type:           {result['type']}")
    print(f"Score:          {result['score']}")
    print(f"Risk level:     {result['risk_level']}")
    print(f"Decision:       {result['decision']}")
    print("Triggered rules:")
    if result["triggered_rules"]:
        for name in result["triggered_rules"]:
            print(f"  - {name}")
    else:
        print("  (none)")
    print("Reasons:")
    for reason in result["reasons"]:
        print(f"  - {reason}")
    print(f"Recommendation: {result['recommendation']}")
    features = result.get("features") or {}
    interesting = {key: value for key, value in features.items() if value not in (False, 0, "", [], None)}
    print(f"Key features:   {interesting}")
    print()


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"CHECK OK: {message}")


def main() -> None:
    expert = CyberShieldExpertSystem()
    failures: list[str] = []

    long_url = "https://www.example.com/" + ("login-verify-path/" * 8) + "?ref=" + ("a" * 40)

    cases = [
        (
            "URL 1 — Normal HTTPS",
            "url",
            "https://www.example.com",
            {
                "max_level": "LOW",
                "must_not_contain": ["Suspicious keyword detected"],
            },
        ),
        (
            "URL 2 — HTTP URL",
            "url",
            "http://example.com/login",
            {"must_contain": ["URL does not use HTTPS"]},
        ),
        (
            "URL 3 — Suspicious keyword URL",
            "url",
            "http://example.com/verify-account-login",
            {"must_contain": ["Suspicious keyword detected"]},
        ),
        (
            "URL 4 — IP-based URL",
            "url",
            "http://192.168.1.10/login",
            {"must_contain": ["URL contains an IP address"]},
        ),
        (
            "URL 5 — Long URL",
            "url",
            long_url,
            {"must_contain": ["URL is unusually long"]},
        ),
        (
            "URL 6 — Suspicious TLD",
            "url",
            "http://example.xyz",
            {"must_contain": ["Suspicious TLD detected"]},
        ),
        (
            "MSG 7 — Normal message",
            "message",
            "Hi, are we meeting at 5 PM today?",
            {"max_level": "LOW"},
        ),
        (
            "MSG 8 — Prize scam",
            "message",
            "Congratulations! You have won a ₹50,000 prize. Click the link to claim your reward.",
            {
                "must_contain": [
                    "Prize or reward language detected",
                    "Suspicious link detected",
                ]
            },
        ),
        (
            "MSG 9 — Urgent banking scam",
            "message",
            "URGENT! Your bank account will be blocked today. Verify your account immediately.",
            {
                "must_contain": [
                    "Urgent language detected",
                    "Threat or fear language detected",
                    "Banking context detected",
                ]
            },
        ),
        (
            "MSG 10 — OTP scam",
            "message",
            "Your account needs verification. Send the OTP and password immediately.",
            {
                "must_contain": [
                    "OTP request detected",
                    "Password request detected",
                    "Urgent language detected",
                ]
            },
        ),
        (
            "MSG 11 — Payment scam",
            "message",
            "Pay ₹5,000 immediately to avoid account suspension.",
            {
                "must_contain": [
                    "Payment request detected",
                    "Urgent language detected",
                    "Threat or fear language detected",
                ]
            },
        ),
    ]

    level_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    for title, kind, sample, checks in cases:
        if kind == "url":
            features = extract_url_features(sample)
            result = expert.analyze_url(sample)
        else:
            features = extract_message_features(sample)
            result = expert.analyze_message(sample)

        print_result(title, result)

        try:
            expect(result["type"] == kind, f"{title}: type is {kind}")
            expect(0 <= result["score"] <= 100, f"{title}: score is between 0 and 100")
            expect(
                result["score"] == calculate_risk_score(result["score"]),
                f"{title}: score is capped by the risk engine",
            )
            expect(
                result["risk_level"] == get_risk_level(result["score"]),
                f"{title}: risk level matches the score",
            )
            expect(bool(result["recommendation"]), f"{title}: recommendation is present")
            expect(isinstance(features, dict) and features, f"{title}: feature extraction returned data")

            for rule_name in checks.get("must_contain", []):
                expect(
                    rule_name in result["triggered_rules"],
                    f"{title}: triggered '{rule_name}'",
                )
            for rule_name in checks.get("must_not_contain", []):
                expect(
                    rule_name not in result["triggered_rules"],
                    f"{title}: did not trigger '{rule_name}'",
                )
            if "max_level" in checks:
                expect(
                    level_rank[result["risk_level"]] <= level_rank[checks["max_level"]],
                    f"{title}: risk is {checks['max_level']} or lower (got {result['risk_level']})",
                )
        except AssertionError as error:
            failures.append(str(error))
            print(f"CHECK FAILED: {error}")

    print("=" * 72)
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED")
        for item in failures:
            print(f" - {item}")
        raise SystemExit(1)

    print("ALL EXPERT SYSTEM TESTS PASSED")


if __name__ == "__main__":
    main()
