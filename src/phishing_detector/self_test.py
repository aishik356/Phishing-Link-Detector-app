"""Safe, deterministic checks for LinkShield's URL analyzer."""

from dataclasses import dataclass

from .analyzer import analyze_url


@dataclass(frozen=True)
class SelfTestCase:
    name: str
    url: str
    expected_risk: str | None
    expected_finding: str | None
    description: str


@dataclass(frozen=True)
class SelfTestResult:
    case: SelfTestCase
    actual: str
    passed: bool
    detail: str


SELF_TEST_CASES = (
    SelfTestCase(
        "Clean example domain",
        "https://safe.example/",
        "No obvious warning signs",
        "No obvious URL warning signs",
        "A reserved example domain over HTTPS should not trigger a URL warning.",
    ),
    SelfTestCase(
        "Unencrypted HTTP",
        "http://plain.example/",
        "Some warning signs",
        "Unencrypted connection",
        "HTTP should be reported as a warning, not proof of phishing.",
    ),
    SelfTestCase(
        "Sensitive action path",
        "https://service.example/account/verify",
        "No obvious warning signs",
        "Sensitive-action wording",
        "Account wording in a URL path should be shown as a clue.",
    ),
    SelfTestCase(
        "Brand-lookalike domain",
        "https://paypal.example/login",
        "Some warning signs",
        "Possible brand impersonation",
        "A brand name on an unrelated reserved domain should be flagged as a possible disguise.",
    ),
    SelfTestCase(
        "Embedded credentials",
        "https://paypal.com@secure-login-paypal.example/account",
        "High risk indicators",
        "Unexpected sign-in details in link",
        "Text before @ should not be mistaken for the destination domain.",
    ),
    SelfTestCase(
        "Documentation IP address",
        "http://192.0.2.1/verify",
        "High risk indicators",
        "Link uses an IP address",
        "A documentation-only IP address and HTTP should trigger URL warnings.",
    ),
    SelfTestCase(
        "Internationalized domain",
        "https://раypal.example/",
        "Some warning signs",
        "Internationalized domain name",
        "Unicode domain names should be identified for careful inspection.",
    ),
    SelfTestCase(
        "Malformed domain",
        "https://bad_domain.example/",
        None,
        None,
        "An invalid domain should be rejected with a helpful validation error.",
    ),
)


def run_safe_self_test() -> tuple[SelfTestResult, ...]:
    """Run local-only examples; none of the sample URLs are requested."""
    results = []
    for case in SELF_TEST_CASES:
        try:
            analysis = analyze_url(case.url)
        except ValueError as error:
            passed = case.expected_risk is None
            results.append(
                SelfTestResult(
                    case=case,
                    actual="Rejected as invalid",
                    passed=passed,
                    detail=str(error) if passed else "Valid example was unexpectedly rejected.",
                )
            )
            continue

        if case.expected_risk is None:
            results.append(
                SelfTestResult(
                    case=case,
                    actual=analysis.risk,
                    passed=False,
                    detail="Malformed example was unexpectedly accepted.",
                )
            )
            continue

        matching_finding = any(
            finding.title == case.expected_finding
            for finding in analysis.findings
        )
        passed = analysis.risk == case.expected_risk and matching_finding
        detail = (
            case.description
            if passed
            else (
                f"Expected “{case.expected_risk}” and finding "
                f"“{case.expected_finding}”."
            )
        )
        results.append(
            SelfTestResult(
                case=case,
                actual=analysis.risk,
                passed=passed,
                detail=detail,
            )
        )
    return tuple(results)
