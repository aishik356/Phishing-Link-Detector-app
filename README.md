# Phishing Link Detector

A Python desktop app that checks URLs for common phishing indicators. It provides a local URL-pattern analysis, an optional exact-match check against the OpenPhish public feed, and an optional Gemini explanation of the detector's findings.

> **Important:** LinkShield is an educational helper, not a guarantee of safety. Its score is a heuristic, not a probability. A clean result does not prove a site is safe, and the URL alone cannot confirm a page's contents or who created a link.

## Features

- Desktop interface with URL analysis, expandable details, mouse-wheel scrolling, and copy/paste actions.
- Local checks for malformed URLs, HTTP, embedded credentials, IP-address destinations, internationalized domains, long or complex URLs, action wording, and possible brand impersonation.
- Optional safe self-test using reserved example domains. It never opens sample links.
- Optional OpenPhish public-feed check. The feed is downloaded and compared locally; the URL being checked is not submitted to the feed service.
- Optional Gemini explanation of existing findings. Gemini does not decide the detector's risk rating.

## Run from source

Requires Python 3.10 or later and Tkinter.

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

In VS Code, choose **Run and Debug** and select **Run LinkShield GUI**, or press **F5**. To run from PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m phishing_detector
```

Select **Run safe self-test** in the window if you do not have a phishing URL to try. The examples use reserved `.example` domains and the documentation-only IP `192.0.2.1`; they are not real phishing sites.

## Optional Gemini explanation

1. Create a Gemini API key in [Google AI Studio](https://aistudio.google.com/apikey).
2. In LinkShield, select **Set Gemini API key** and enter it. The key stays in memory for the current session and is not saved to disk.
3. Analyze a URL, select **Explain with Gemini**, and review the consent prompt. Each request requires confirmation.

You can also provide the key through the `LINKSHIELD_GEMINI_API_KEY` environment variable before launching the Python app.

After you confirm, LinkShield sends Gemini only the destination domain, HTTP/HTTPS scheme, detector rating, score, and URL-pattern findings. It does **not** send the full URL, path, query parameters, fragment, or embedded credentials, and it never opens the site. Requests use Gemini's stateless `store=false` option. Review Google's current terms and privacy policy; API usage may be subject to quotas or charges.

AI explanations can be inaccurate. They are for understanding the existing evidence and do not change the detector's verdict.

## Optional OpenPhish check

Select **Check OpenPhish feed** after analyzing a URL. The public feed is downloaded over HTTPS, cached in memory for 15 minutes, and compared on your device. The URL being checked is not sent to OpenPhish. An exact match is a strong warning; no match does not mean the URL is safe. The feed is community-sourced, may be incomplete or out of date, and only matches exact URLs.

Source: [OpenPhish public feed](https://openphish.com/feed.txt).

## Privacy and limitations

- Local analysis does not open or request the URL.
- The optional reputation check contacts the feed host to download its list, not to submit the URL.
- Gemini is off until configured, and no explanation request is sent until you confirm it.
- The app does not verify site ownership, inspect page contents, or identify who created a link.
- URL-pattern examples and unit tests verify expected software behavior, not real-world phishing-detection accuracy.

## Tests

The test suite covers URL parsing, warning indicators, safe self-test cases, and mocked OpenPhish/Gemini responses. Tests do not require a real phishing URL or Gemini API key and do not make real Gemini requests.

```powershell
python -m unittest discover -s tests -v
```

## Windows executable (optional)

This repository contains the Python source. If you choose to build a standalone Windows executable later, install the build dependencies and run:

```powershell
python -m pip install -r requirements-build.txt
python -m PyInstaller --noconfirm --clean LinkShield.spec
```

The executable is written to `dist/LinkShield.exe`. Build the executable on Windows for Windows. The generated `dist/` folder is ignored by Git.
