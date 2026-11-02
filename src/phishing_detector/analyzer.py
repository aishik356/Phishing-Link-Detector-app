"""Offline URL checks. This module never opens or requests the supplied URL."""

from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Finding:
    title: str
    detail: str


@dataclass(frozen=True)
class AnalysisResult:
    url: str
    domain: str
    risk: str
    score: int
    findings: tuple[Finding, ...]
    possible_impersonation: str | None
    page_hint: str


_BRAND_DOMAINS = {
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.in"),
    "apple": ("apple.com",),
    "facebook": ("facebook.com",),
    "google": ("google.com", "google.co.uk", "google.ca", "google.de", "google.in"),
    "instagram": ("instagram.com",),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com"),
    "netflix": ("netflix.com",),
    "paypal": ("paypal.com", "paypal.co.uk", "paypal.ca", "paypal.de", "paypal.in"),
}
_SUSPICIOUS_TERMS = (
    "account",
    "confirm",
    "login",
    "password",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
)
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ACTION_TERM = re.compile(
    rf"(?:^|[^a-z0-9])(?:{'|'.join(map(re.escape, _SUSPICIOUS_TERMS))})(?:$|[^a-z0-9])",
    re.IGNORECASE,
)


def _page_hint(path: str, query: str) -> str:
    text = f"{path} {query}".lower()
    hints = {
        "login": ("login", "signin", "sign-in", "log-in"),
        "account verification or update": ("verify", "verification", "update-account"),
        "payment or billing": ("payment", "billing", "invoice", "checkout"),
        "file download": ("download", "file"),
    }
    for label, terms in hints.items():
        if any(term in text for term in terms):
            return f"The URL path suggests {label}; the page itself was not opened."
    return "The page contents are unknown because the link was not opened."


def analyze_url(value: str) -> AnalysisResult:
    """Assess URL characteristics without making any network requests."""
    if not isinstance(value, str):
        raise ValueError("Enter a web link to analyze.")
    supplied = value.strip()
    if not supplied:
        raise ValueError("Enter a web link to analyze.")
    if any(character.isspace() or ord(character) < 32 for character in supplied):
        raise ValueError("The link must not contain spaces.")
    if "\\" in supplied:
        raise ValueError("The link must use forward slashes, not backslashes.")

    candidate = supplied if "://" in supplied else f"https://{supplied}"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError
    except ValueError as error:
        raise ValueError("This does not look like a valid web link.") from error

    if parsed.scheme.lower() not in ("http", "https") or not hostname:
        raise ValueError("Enter a link that starts with http:// or https://.")

    try:
        domain = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as error:
        raise ValueError("The link contains an invalid domain name.") from error
    if "%" in domain:
        raise ValueError("The domain contains invalid percent-encoded characters.")
    if not domain or "." not in domain and not _is_ip_address(domain):
        raise ValueError("Enter a complete web domain, such as example.com.")
    if not _is_ip_address(domain):
        labels = domain.split(".")
        if (
            len(domain) > 253
            or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels)
        ):
            raise ValueError("The link contains an invalid domain name.")

    findings: list[Finding] = []
    score = 0

    def add(points: int, title: str, detail: str) -> None:
        nonlocal score
        score += points
        findings.append(Finding(title, detail))

    if parsed.scheme.lower() == "http":
        add(15, "Unencrypted connection", "This link uses HTTP instead of HTTPS.")
    if parsed.username is not None or parsed.password is not None:
        add(30, "Unexpected sign-in details in link", "The URL contains text before the @ symbol that can disguise its real destination.")
    if _is_ip_address(domain):
        add(28, "Link uses an IP address", "The destination is a numeric address rather than a recognizable domain.")
    if "xn--" in domain:
        add(20, "Internationalized domain name", "The domain uses encoded characters that can resemble letters from another alphabet.")

    labels = domain.split(".")
    if len(labels) >= 5:
        add(12, "Many domain sections", "The destination has several subdomains, which can make its true owner harder to spot.")
    if len(re.findall(r"-", domain)) >= 3:
        add(8, "Unusually many hyphens", "The domain contains several hyphens.")

    if len(supplied) > 180:
        add(12, "Very long link", "Long links can hide the actual destination or contain unnecessary tracking.")
    elif len(supplied) > 100:
        add(6, "Long link", "Check the full destination carefully before trusting it.")

    searchable_text = f"{domain} {parsed.path}"
    matched_terms = (
        [
            term
            for term in _SUSPICIOUS_TERMS
            if re.search(
                rf"(?:^|[^a-z0-9]){re.escape(term)}(?:$|[^a-z0-9])",
                searchable_text,
                re.IGNORECASE,
            )
        ]
        if _ACTION_TERM.search(searchable_text)
        else []
    )
    if matched_terms:
        add(8, "Sensitive-action wording", f"The link includes wording often used to prompt account or payment actions: {', '.join(matched_terms[:4])}.")

    possible_impersonation = None
    for brand, trusted_domains in _BRAND_DOMAINS.items():
        if brand in domain and not any(domain == trusted or domain.endswith(f".{trusted}") for trusted in trusted_domains):
            possible_impersonation = brand.title()
            add(24, "Possible brand impersonation", f"The domain includes “{brand}” but does not end in a known {brand.title()} domain.")
            break

    score = min(score, 100)
    if score >= 40:
        risk = "High risk indicators"
    elif score >= 15:
        risk = "Some warning signs"
    else:
        risk = "No obvious warning signs"

    if not findings:
        findings.append(Finding("No obvious URL warning signs", "This is only a basic URL check; a clean result does not guarantee that a site is safe."))
    findings.append(
        Finding(
            "How to read this result",
            "The score is a heuristic based on URL patterns, not a probability or confirmation that the site is malicious.",
        )
    )

    return AnalysisResult(
        url=candidate,
        domain=domain,
        risk=risk,
        score=score,
        findings=tuple(findings),
        possible_impersonation=possible_impersonation,
        page_hint=_page_hint(parsed.path, parsed.query),
    )


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
