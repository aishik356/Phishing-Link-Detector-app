import json
import unittest
from unittest.mock import patch

from phishing_detector.analyzer import analyze_url
from phishing_detector.gemini import (
    API_URL,
    GeminiApiError,
    GeminiExplainer,
    build_explanation_prompt,
)
from phishing_detector.reputation import (
    OpenPhishFeedChecker,
    ReputationFeedError,
)
from phishing_detector.self_test import SELF_TEST_CASES, run_safe_self_test


class FakeFeedResponse:
    status = 200

    def __init__(self, content, final_url="https://openphish.com/feed.txt"):
        self.content = content
        self.final_url = final_url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def geturl(self):
        return self.final_url

    def read(self, limit):
        return self.content[:limit]


class FakeGeminiResponse:
    status = 200

    def __init__(self, content, final_url=API_URL):
        self.content = content
        self.final_url = final_url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def geturl(self):
        return self.final_url

    def read(self, limit):
        return self.content[:limit]


class FakeGeminiOpener:
    def __init__(self, response):
        self.response = response
        self.request = None

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        return self.response


class AnalyzeUrlTests(unittest.TestCase):
    def test_normalizes_domain_without_scheme(self):
        result = analyze_url("Example.com")
        self.assertEqual(result.url, "https://Example.com")
        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.risk, "No obvious warning signs")

    def test_flags_plain_http(self):
        result = analyze_url("http://example.com")
        self.assertEqual(result.risk, "Some warning signs")
        self.assertTrue(any("Unencrypted" in item.title for item in result.findings))

    def test_flags_credentials_and_brand_impersonation(self):
        result = analyze_url("https://paypal.com@secure-login-paypal.example.net/account")
        self.assertEqual(result.risk, "High risk indicators")
        self.assertEqual(result.possible_impersonation, "Paypal")
        self.assertTrue(any("sign-in details" in item.title for item in result.findings))

    def test_https_is_not_penalized(self):
        result = analyze_url("https://example.com/")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.risk, "No obvious warning signs")

    def test_brand_domain_is_not_flagged_as_impersonation(self):
        result = analyze_url("https://www.paypal.com/signin")
        self.assertIsNone(result.possible_impersonation)

    def test_brand_name_in_deceptive_domain_is_flagged(self):
        result = analyze_url("https://paypal.example.org")
        self.assertEqual(result.possible_impersonation, "Paypal")

    def test_plain_action_word_in_query_does_not_add_warning(self):
        result = analyze_url("https://example.com/?next=login")
        self.assertEqual(result.score, 0)

    def test_action_words_in_path_are_reported(self):
        result = analyze_url("https://example.com/account/verify")
        self.assertTrue(any("Sensitive-action" in item.title for item in result.findings))

    def test_ip_address_destination_is_reported(self):
        result = analyze_url("http://192.0.2.1/login")
        self.assertEqual(result.domain, "192.0.2.1")
        self.assertTrue(any("IP address" in item.title for item in result.findings))

    def test_idn_domain_is_reported(self):
        result = analyze_url("https://раypal.example")
        self.assertTrue(any("Internationalized" in item.title for item in result.findings))

    def test_reports_page_hint_without_opening_page(self):
        result = analyze_url("https://example.com/signin")
        self.assertIn("login", result.page_hint)
        self.assertIn("not opened", result.page_hint)

    def test_rejects_empty_or_non_web_inputs(self):
        for value in ("", "ftp://example.com", "not a link", "https://exa_mple.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                analyze_url(value)

    def test_rejects_backslashes_and_control_characters(self):
        for value in ("https://example.com\\@evil.example", "https://example.com/\nlogin"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                analyze_url(value)

    def test_rejects_invalid_port(self):
        with self.assertRaisesRegex(ValueError, "valid web link"):
            analyze_url("https://example.com:bad")

    def test_rejects_non_string_input(self):
        with self.assertRaisesRegex(ValueError, "Enter a web link"):
            analyze_url(None)


class SafeSelfTestTests(unittest.TestCase):
    def test_all_safe_self_test_examples_pass(self):
        results = run_safe_self_test()

        self.assertEqual(len(results), len(SELF_TEST_CASES))
        self.assertTrue(
            all(result.passed for result in results),
            [result for result in results if not result.passed],
        )

    def test_examples_are_reserved(self):
        for case in SELF_TEST_CASES:
            with self.subTest(case=case.name):
                self.assertTrue(
                    case.url.endswith(".example/")
                    or ".example/" in case.url
                    or ".example?" in case.url
                    or "192.0.2.1" in case.url
                )

    @patch("phishing_detector.reputation.urlopen")
    def test_self_test_never_fetches_the_online_feed(self, mocked_urlopen):
        run_safe_self_test()

        mocked_urlopen.assert_not_called()


class GeminiExplainerTests(unittest.TestCase):
    def setUp(self):
        self.analysis = analyze_url(
            "https://paypal.example/login?token=do-not-send#private"
        )

    def test_prompt_excludes_full_url_path_query_and_fragment(self):
        prompt = build_explanation_prompt(self.analysis)

        self.assertIn("paypal.example", prompt)
        self.assertNotIn("/login", prompt)
        self.assertNotIn("do-not-send", prompt)
        self.assertNotIn("private", prompt)

    def test_missing_api_key_fails_before_network_request(self):
        with patch("phishing_detector.gemini.build_opener") as build_opener:
            with self.assertRaisesRegex(GeminiApiError, "Set a Gemini API key"):
                GeminiExplainer().explain(self.analysis)

        build_opener.assert_not_called()

    def test_api_key_rejects_whitespace(self):
        explainer = GeminiExplainer()
        with self.assertRaisesRegex(ValueError, "whitespace"):
            explainer.set_api_key("invalid key")

    @patch("phishing_detector.gemini.build_opener")
    def test_sends_only_limited_evidence_to_fixed_https_api(self, build_opener):
        fake_opener = FakeGeminiOpener(
            FakeGeminiResponse(
                b'{"output_text":"The URL has a lookalike domain. Be cautious."}'
            )
        )
        build_opener.return_value = fake_opener
        explainer = GeminiExplainer("test-api-key")

        explanation = explainer.explain(self.analysis)

        self.assertEqual(
            explanation.text,
            "The URL has a lookalike domain. Be cautious.",
        )
        self.assertEqual(fake_opener.request.full_url, API_URL)
        self.assertEqual(fake_opener.timeout, 20)
        self.assertEqual(
            fake_opener.request.get_header("X-goog-api-key"),
            "test-api-key",
        )
        request_payload = json.loads(fake_opener.request.data.decode("utf-8"))
        self.assertEqual(request_payload["model"], "gemini-3.8-flash")
        self.assertFalse(request_payload["store"])
        self.assertIn("paypal.example", request_payload["input"])
        self.assertNotIn("do-not-send", request_payload["input"])
        self.assertNotIn("/login", request_payload["input"])

    @patch("phishing_detector.gemini.build_opener")
    def test_extracts_text_content_from_interaction_output(self, build_opener):
        build_opener.return_value = FakeGeminiOpener(
            FakeGeminiResponse(
                b'{"output":[{"type":"text","text":"First sentence."},'
                b'{"type":"text","text":"Second sentence."}]}'
            )
        )

        explanation = GeminiExplainer("test-api-key").explain(self.analysis)

        self.assertEqual(
            explanation.text,
            "First sentence.\nSecond sentence.",
        )

    @patch("phishing_detector.gemini.build_opener")
    def test_rejects_redirects_instead_of_following_them(self, build_opener):
        fake_opener = FakeGeminiOpener(
            FakeGeminiResponse(
                b'{"output_text":"unexpected"}',
                final_url="https://attacker.example/",
            )
        )
        build_opener.return_value = fake_opener

        with self.assertRaisesRegex(GeminiApiError, "unexpected destination"):
            GeminiExplainer("test-api-key").explain(self.analysis)

    @patch("phishing_detector.gemini.build_opener")
    def test_rejects_empty_ai_response(self, build_opener):
        build_opener.return_value = FakeGeminiOpener(FakeGeminiResponse(b"{}"))

        with self.assertRaisesRegex(GeminiApiError, "did not return a text"):
            GeminiExplainer("test-api-key").explain(self.analysis)


class OpenPhishFeedTests(unittest.TestCase):
    @patch("phishing_detector.reputation.urlopen")
    def test_exact_url_match_is_found_without_submitting_input(self, mocked_urlopen):
        mocked_urlopen.return_value = FakeFeedResponse(
            b"https://fake.example/login\nhttps://other.example/path\n"
        )
        checker = OpenPhishFeedChecker()

        result = checker.check("https://fake.example/login#tracking")

        self.assertTrue(result.listed)
        self.assertEqual(result.entries_checked, 2)
        request = mocked_urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://openphish.com/feed.txt")
        self.assertNotIn("fake.example", request.full_url)

    @patch("phishing_detector.reputation.urlopen")
    def test_non_match_is_not_reported_as_safe(self, mocked_urlopen):
        mocked_urlopen.return_value = FakeFeedResponse(
            b"https://known-phish.example/login\n"
        )

        result = OpenPhishFeedChecker().check("https://ordinary.example/")

        self.assertFalse(result.listed)

    @patch("phishing_detector.reputation.urlopen")
    def test_feed_is_cached_for_multiple_checks(self, mocked_urlopen):
        mocked_urlopen.return_value = FakeFeedResponse(
            b"https://known-phish.example/login\n"
        )
        checker = OpenPhishFeedChecker()

        checker.check("https://first.example")
        checker.check("https://second.example")

        mocked_urlopen.assert_called_once()

    @patch("phishing_detector.reputation.urlopen")
    def test_rejects_redirect_to_unexpected_host(self, mocked_urlopen):
        mocked_urlopen.return_value = FakeFeedResponse(
            b"https://known-phish.example/login\n",
            final_url="https://untrusted.example/feed.txt",
        )

        with self.assertRaisesRegex(ReputationFeedError, "unexpected destination"):
            OpenPhishFeedChecker().check("https://ordinary.example")

    @patch("phishing_detector.reputation.urlopen")
    def test_rejects_http_feed_redirect(self, mocked_urlopen):
        mocked_urlopen.return_value = FakeFeedResponse(
            b"https://known-phish.example/login\n",
            final_url="http://openphish.com/feed.txt",
        )

        with self.assertRaisesRegex(ReputationFeedError, "unexpected destination"):
            OpenPhishFeedChecker().check("https://ordinary.example")

    def test_rejects_urls_with_embedded_credentials(self):
        with self.assertRaisesRegex(ValueError, "embedded credentials"):
            OpenPhishFeedChecker().check(
                "https://user:password@example.com/"
            )


if __name__ == "__main__":
    unittest.main()
