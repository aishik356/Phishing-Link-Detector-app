"""Optional, exact-match checks against the public OpenPhish URL feed."""

from dataclasses import dataclass
import ssl
from time import monotonic
from urllib.error import URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

import certifi


FEED_URL = "https://openphish.com/feed.txt"
_ALLOWED_FEED_HOSTS = {
    "openphish.com",
    "www.openphish.com",
    "raw.githubusercontent.com",
}
_FEED_CACHE_SECONDS = 15 * 60
_MAX_FEED_BYTES = 5 * 1024 * 1024


class ReputationFeedError(Exception):
    """Raised when the phishing feed cannot be safely retrieved or read."""


@dataclass(frozen=True)
class FeedResult:
    listed: bool
    entries_checked: int


def _canonicalize_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("A valid HTTP or HTTPS link is required for a feed check.")

    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port
    except (UnicodeError, ValueError) as error:
        raise ValueError("The link has an invalid domain or port.") from error

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Links containing embedded credentials cannot be feed-checked.")

    if ":" in hostname:
        hostname = f"[{hostname}]"
    netloc = hostname
    if port is not None and not (
        parsed.scheme.lower() == "https" and port == 443
        or parsed.scheme.lower() == "http" and port == 80
    ):
        netloc = f"{netloc}:{port}"

    return urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


class OpenPhishFeedChecker:
    """Compare URLs locally against a cached public feed; never submit the URL."""

    def __init__(self) -> None:
        self._feed_urls: frozenset[str] | None = None
        self._loaded_at = 0.0

    def check(self, url: str) -> FeedResult:
        normalized_url = _canonicalize_url(url)
        feed_urls = self._get_feed()
        return FeedResult(
            listed=normalized_url in feed_urls,
            entries_checked=len(feed_urls),
        )

    def _get_feed(self) -> frozenset[str]:
        if (
            self._feed_urls is not None
            and monotonic() - self._loaded_at < _FEED_CACHE_SECONDS
        ):
            return self._feed_urls

        request = Request(
            FEED_URL,
            headers={"User-Agent": "LinkShield/0.1 (public-feed lookup)"},
        )
        try:
            with urlopen(
                request,
                timeout=10,
                context=ssl.create_default_context(cafile=certifi.where()),
            ) as response:
                final_url = urlsplit(response.geturl())
                final_host = (final_url.hostname or "").lower()
                if (
                    final_url.scheme.lower() != "https"
                    or final_host not in _ALLOWED_FEED_HOSTS
                ):
                    raise ReputationFeedError(
                        "The phishing feed redirected to an unexpected destination."
                    )
                if getattr(response, "status", 200) != 200:
                    raise ReputationFeedError(
                        f"The phishing feed returned HTTP {response.status}."
                    )
                content = response.read(_MAX_FEED_BYTES + 1)
        except URLError as error:
            raise ReputationFeedError(
                f"Could not retrieve the OpenPhish feed: {error.reason}"
            ) from error
        except OSError as error:
            raise ReputationFeedError(
                f"Could not retrieve the OpenPhish feed: {error}"
            ) from error

        if len(content) > _MAX_FEED_BYTES:
            raise ReputationFeedError("The phishing feed exceeded the size limit.")
        try:
            feed_text = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ReputationFeedError(
                "The phishing feed response was not valid UTF-8."
            ) from error

        feed_urls: set[str] = set()
        for line in feed_text.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            try:
                feed_urls.add(_canonicalize_url(candidate))
            except ValueError:
                continue

        if not feed_urls:
            raise ReputationFeedError(
                "The phishing feed did not contain any valid URLs."
            )

        self._feed_urls = frozenset(feed_urls)
        self._loaded_at = monotonic()
        return self._feed_urls
