# privacy-label

Privacy nutrition label for any website. One command.

```
pip install privacy-label
privacy-label reddit.com
```

## What it does

Scans any website and generates a privacy nutrition label showing:

- **Trackers** — ad networks, analytics, fingerprinting, social widgets
- **Data collection** — form fields, API access, browser fingerprinting
- **Cookies** — tracking cookies detected on first visit
- **Third parties** — how many external domains your data goes to
- **Security** — HTTPS, security headers, privacy policy, cookie banner
- **Score** — 0-100 privacy score with A+ to F grade

## Usage

```bash
# Scan one site
privacy-label reddit.com

# Compare multiple sites
privacy-label reddit.com twitter.com github.com

# Explicit compare mode
privacy-label --compare reddit.com discord.com
```

## Example output

```
reddit.com — Privacy Nutrition Label
============================================================

  Privacy Score: 42/100 (C)
  ████████░░░░░░░░░░░░

┌─────────────────── Trackers Found ───────────────────┐
│ Type │ Name              │ Category    │ Via         │
│ AD   │ Google Ads         │ advertising │ script     │
│ AD   │ Facebook Pixel     │ advertising │ inline     │
│ AN   │ Google Analytics   │ analytics   │ script     │
│ AN   │ Segment            │ analytics   │ script     │
│ MK   │ HubSpot            │ marketing   │ script     │
└──────────────────────────────────────────────────────┘

  Third-Party Domains: 14
  HTTPS: Yes
  Privacy Policy: Found
  Cookie Banner: Yes
  DNT Respected: No
  Security Headers: 4/6

╭─── Verdict ───╮
│ This site collects significant data about you.       │
│ 5 trackers, 14 third parties, 2 ad networks.        │
╰───────────────╯
```

## Compare sites

```bash
privacy-label reddit.com github.com duckduckgo.com
```

Shows a side-by-side table with scores, tracker counts, and the winner.

## What it checks

| Check | What | Impact |
|-------|------|--------|
| Ad trackers | Google Ads, Facebook Pixel, Criteo, etc. | -8 per tracker |
| Fingerprinting | FingerprintJS, canvas, WebGL, audio | -10 per script |
| Marketing | HubSpot, Drift, etc. | -5 per tracker |
| Analytics | GA, Mixpanel, Amplitude, etc. | -3 per tracker |
| Tracking cookies | _ga, _fbp, IDE, etc. | -3 per cookie |
| Third-party domains | External requests | -3 to -15 |
| Data collection | Forms, APIs, storage | -1 to -4 |
| **Bonuses** | Privacy policy, cookie banner, security headers | +2 to +5 |

## Limitations

- Static HTML analysis only — doesn't execute JavaScript (use a browser extension for full JS tracking)
- Cookie detection is first-party response only — doesn't capture third-party cookies set by scripts
- Scores are relative, not absolute — useful for comparing sites, not as legal compliance

## Privacy

This tool runs locally. No data is sent anywhere except to the website you're scanning. No telemetry.
